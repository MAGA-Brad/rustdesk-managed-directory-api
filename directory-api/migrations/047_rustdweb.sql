-- RustDWeb: browser access to RDC Clients through the RustDWeb gateway.
-- Only Viewer accounts (RustDWeb users) sign in there, with their RDS account + TOTP, and only there;
-- Owners and Managers never sign in at RustDWeb.

-- RustDWeb sign-ins are their own session scope: an ops/mobile token is never valid at RustDWeb and
-- a RustDWeb token is never valid anywhere else.
ALTER TABLE operator_sessions DROP CONSTRAINT IF EXISTS operator_sessions_scope_check;
ALTER TABLE operator_sessions ADD CONSTRAINT operator_sessions_scope_check
    CHECK (scope IN ('full', 'mobile', 'rustdweb'));

-- Failed RustDWeb sign-ins are counted apart from ops console failures; reaching the RustDWeb limit
-- locks the account itself (locked_until) and blocks the client IP. The last accepted TOTP step stops
-- a code from being replayed at RustDWeb.
ALTER TABLE operator_accounts ADD COLUMN IF NOT EXISTS rustdweb_failed_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operator_accounts ADD COLUMN IF NOT EXISTS rustdweb_totp_last_step BIGINT;
ALTER TABLE operator_accounts DROP CONSTRAINT IF EXISTS operator_accounts_rustdweb_failed_count_check;
ALTER TABLE operator_accounts ADD CONSTRAINT operator_accounts_rustdweb_failed_count_check
    CHECK (rustdweb_failed_count >= 0);

-- Per-client-IP failures and blocks for RustDWeb sign-ins.
CREATE TABLE IF NOT EXISTS rustdweb_ip_blocks (
    ip INET PRIMARY KEY,
    failures INTEGER NOT NULL DEFAULT 0 CHECK (failures >= 0),
    first_failure_at TIMESTAMPTZ,
    last_failure_at TIMESTAMPTZ,
    blocked_until TIMESTAMPTZ,
    blocked_count INTEGER NOT NULL DEFAULT 0 CHECK (blocked_count >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS rustdweb_ip_blocks_blocked_until_idx ON rustdweb_ip_blocks (blocked_until)
    WHERE blocked_until IS NOT NULL;

-- One row per remote connection a RustDWeb user opened through the gateway.
CREATE TABLE IF NOT EXISTS rustdweb_connections (
    id UUID PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES operator_sessions(id) ON DELETE CASCADE,
    account_id UUID NOT NULL REFERENCES operator_accounts(id) ON DELETE CASCADE,
    target_device_id UUID REFERENCES managed_devices(id) ON DELETE SET NULL,
    target_rustdesk_id VARCHAR(32) NOT NULL,
    target_name TEXT,
    method VARCHAR(16) NOT NULL CHECK (method IN ('password_totp', 'accepted', 'pending')),
    client_ip INET,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at TIMESTAMPTZ,
    end_reason VARCHAR(64),
    CHECK (ended_at IS NULL OR ended_at >= started_at)
);
CREATE INDEX IF NOT EXISTS rustdweb_connections_account_idx ON rustdweb_connections (account_id, started_at DESC);
CREATE INDEX IF NOT EXISTS rustdweb_connections_open_idx ON rustdweb_connections (account_id) WHERE ended_at IS NULL;
