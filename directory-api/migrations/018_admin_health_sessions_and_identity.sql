-- the admin dashboard operational visibility and managed-client identity hardening.
-- Additive/idempotent migration.  No existing device or audit history is deleted.

-- Production relay authorization is permanently enforced through the admin dashboard/API.
-- A root administrator may still change this database value manually for
-- emergency recovery, but there is no normal web/API mode-change route.
INSERT INTO security_settings(setting_key, setting_value, updated_at)
VALUES ('relay_guard_mode', 'enforced', NOW())
ON CONFLICT (setting_key) DO UPDATE
SET setting_value = 'enforced',
    updated_at = NOW();

-- Friendly names are presentation labels, not security identities.  Reserve a
-- nonblank name case-insensitively while a device is Pending, Approved, or
-- Blocked.  Revoked and Denied records release the name for reuse.
CREATE UNIQUE INDEX IF NOT EXISTS managed_devices_reserved_friendly_name_uidx
ON managed_devices (LOWER(BTRIM(friendly_name)))
WHERE friendly_name IS NOT NULL
  AND BTRIM(friendly_name) <> ''
  AND status IN ('pending', 'approved', 'blocked');

-- Receiving-side session telemetry.  The server counts only fresh heartbeats
-- from Approved managed devices.  This is metadata only; no screen, clipboard,
-- file contents, or filenames are stored.
CREATE TABLE IF NOT EXISTS device_active_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reporting_device_id UUID NOT NULL
        REFERENCES managed_devices(id) ON DELETE CASCADE,
    session_key VARCHAR(128) NOT NULL,
    session_type VARCHAR(24) NOT NULL
        CHECK (session_type IN ('remote_desktop', 'file_transfer')),
    peer_rustdesk_id VARCHAR(64),
    source_ip INET,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMPTZ,
    CHECK (ended_at IS NULL OR ended_at >= started_at),
    UNIQUE (reporting_device_id, session_key)
);

CREATE INDEX IF NOT EXISTS device_active_sessions_fresh_idx
ON device_active_sessions (last_heartbeat_at DESC)
WHERE ended_at IS NULL;

CREATE INDEX IF NOT EXISTS device_active_sessions_device_idx
ON device_active_sessions (reporting_device_id, started_at DESC);

INSERT INTO directory_settings(setting_key, setting_value)
VALUES
    ('client.session_telemetry_enabled', 'true'::jsonb),
    ('client.session_heartbeat_seconds', '15'::jsonb)
ON CONFLICT (setting_key) DO UPDATE
SET setting_value = EXCLUDED.setting_value,
    updated_at = NOW();
