BEGIN;

-- Distinguishes a session issued to the mobile companion app from a normal
-- (web dashboard / API) session. A mobile-scoped access token must never be
-- usable against operator-account-management endpoints, regardless of the
-- underlying account's role - this column (checked server-side on every
-- request, not just a JWT claim) is what makes that guarantee hold even if
-- a stolen/replayed token has its claims tampered with, since require_operator
-- re-derives everything from this row, not from trusting the JWT payload alone.
ALTER TABLE operator_sessions
    ADD COLUMN IF NOT EXISTS scope VARCHAR(16) NOT NULL DEFAULT 'full';

ALTER TABLE operator_sessions
    DROP CONSTRAINT IF EXISTS operator_sessions_scope_check;

ALTER TABLE operator_sessions
    ADD CONSTRAINT operator_sessions_scope_check
        CHECK (scope IN ('full', 'mobile'));

COMMENT ON COLUMN operator_sessions.scope IS
    'full = web dashboard / general API session. mobile = client-manager Android app session, structurally barred from operator-account-management endpoints.';

-- One row per (account, device installation) FCM registration. An account
-- may have more than one phone; a token is replaced in place (upsert) rather
-- than accumulating stale rows as the app reinstalls/token-rotates.
CREATE TABLE IF NOT EXISTS mobile_push_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES operator_accounts(id) ON DELETE CASCADE,
    fcm_token TEXT NOT NULL,
    platform VARCHAR(16) NOT NULL DEFAULT 'android',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    CONSTRAINT mobile_push_tokens_platform_check
        CHECK (platform IN ('android', 'ios'))
);

CREATE UNIQUE INDEX IF NOT EXISTS mobile_push_tokens_token_uidx
    ON mobile_push_tokens (fcm_token);

CREATE INDEX IF NOT EXISTS mobile_push_tokens_account_idx
    ON mobile_push_tokens (account_id)
    WHERE revoked_at IS NULL;

COMMENT ON TABLE mobile_push_tokens IS
    'FCM registration tokens for the client-manager Android app, tied to the operator account that registered them.';

-- Debounce state for the four server-health conditions the RDS/Proxmox
-- watcher scripts report. is_active flips on state *change* only - the
-- watchers report current state on every poll, but a push is only sent
-- (in directory-api, not here) when a row's is_active value actually
-- changes, so a condition that stays down doesn't spam a notification
-- every poll interval.
CREATE TABLE IF NOT EXISTS health_alert_state (
    condition_key VARCHAR(64) PRIMARY KEY,
    is_active BOOLEAN NOT NULL,
    detail TEXT,
    first_active_at TIMESTAMPTZ,
    last_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_reported_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE health_alert_state IS
    'Debounce/edge-detection state for the four watched server-health conditions (docker container down, backup job failure, relay guard staged, disk/cert warnings). Populated by the internal health-event endpoint, not queried directly by the app.';

COMMIT;
