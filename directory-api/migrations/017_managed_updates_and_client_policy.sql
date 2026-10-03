-- Reproduce the live Owner-authorized re-enrollment table on a fresh
-- installation. Older live deployments may already have this table because
-- the feature was introduced before a migration was captured.
CREATE TABLE IF NOT EXISTS device_reenrollment_authorizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
    requested_by UUID NOT NULL REFERENCES operator_accounts(id),
    reason TEXT NOT NULL CHECK (LENGTH(BTRIM(reason)) > 0),
    source_ip INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    consumed_ip INET,
    revoked_at TIMESTAMPTZ,
    CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS device_reenrollment_authorizations_active_idx
    ON device_reenrollment_authorizations (device_id, expires_at)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS device_reenrollment_authorizations_device_idx
    ON device_reenrollment_authorizations (device_id, created_at DESC);

CREATE TABLE IF NOT EXISTS device_reenrollment_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_ip INET,
    expires_at TIMESTAMPTZ NOT NULL,
    fulfilled_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    CHECK (expires_at > requested_at),
    CHECK (fulfilled_at IS NULL OR cancelled_at IS NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS device_reenrollment_requests_one_open_idx
    ON device_reenrollment_requests (device_id)
    WHERE fulfilled_at IS NULL AND cancelled_at IS NULL;

CREATE INDEX IF NOT EXISTS device_reenrollment_requests_device_idx
    ON device_reenrollment_requests (device_id, requested_at DESC);

-- Managed client hardening / update policy v1.
-- Values use JSONB so the client can consume the same policy document returned
-- by /v1/directory and /v1/device/heartbeat.
INSERT INTO directory_settings(setting_key, setting_value)
VALUES
    ('client.remote_control_enabled', 'true'::jsonb),
    ('client.file_transfer_enabled', 'true'::jsonb),
    ('client.clipboard_enabled', 'true'::jsonb),
    ('client.audio_enabled', 'false'::jsonb),
    ('client.camera_enabled', 'false'::jsonb),
    ('client.terminal_enabled', 'false'::jsonb),
    ('client.remote_printing_enabled', 'false'::jsonb),
    ('client.recording_enabled', 'false'::jsonb),
    ('client.tunneling_enabled', 'false'::jsonb),
    ('client.direct_ip_enabled', 'false'::jsonb),
    ('client.lan_discovery_enabled', 'false'::jsonb),
    ('client.privacy_mode_enabled', 'false'::jsonb),
    ('client.block_local_input_enabled', 'false'::jsonb),
    ('client.network_menu_visible', 'false'::jsonb),
    ('client.cloud_account_features_enabled', 'false'::jsonb),
    ('client.local_mouse_override_seconds', '3'::jsonb),
    ('client.receiver_connection_notice_required', 'true'::jsonb),
    ('client.local_accept_default_permission', to_jsonb('view_only'::text)),
    ('client.password_authenticated_default_permission', to_jsonb('full_control'::text)),
    ('client.update_channel', to_jsonb('stable'::text)),
    ('admin.auto_logoff_enabled', 'true'::jsonb),
    ('admin.auto_logoff_seconds', '28800'::jsonb)
ON CONFLICT (setting_key) DO UPDATE
SET setting_value = EXCLUDED.setting_value,
    updated_at = NOW();


CREATE OR REPLACE VIEW admin_device_overview AS
SELECT
    d.id,
    d.rustdesk_id,
    d.hostname,
    d.friendly_name,
    d.status,
    d.status_reason,
    d.status_changed_at,
    d.last_ip,
    d.last_seen_at,
    d.created_at,
    EXISTS (
        SELECT 1
        FROM device_credentials c
        WHERE c.device_id = d.id
          AND c.revoked_at IS NULL
          AND (c.expires_at IS NULL OR c.expires_at > NOW())
    ) AS has_active_credential,
    EXISTS (
        SELECT 1
        FROM device_reenrollment_requests r
        WHERE r.device_id = d.id
          AND r.fulfilled_at IS NULL
          AND r.cancelled_at IS NULL
          AND r.expires_at > NOW()
    ) AS reenrollment_requested
FROM managed_devices d;
