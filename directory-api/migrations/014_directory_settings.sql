CREATE TABLE directory_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value JSONB NOT NULL,
    updated_by UUID REFERENCES operator_accounts(id),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (BTRIM(setting_key) <> '')
);

CREATE OR REPLACE FUNCTION set_directory_setting_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER directory_settings_set_updated_at
BEFORE UPDATE
ON directory_settings
FOR EACH ROW EXECUTE FUNCTION set_directory_setting_updated_at();

INSERT INTO directory_settings (
    setting_key,
    setting_value
)
VALUES
    (
        'client.id_server',
        to_jsonb('wrze868.ddns.me:21116'::TEXT)
    ),
    (
        'client.server_public_key',
        to_jsonb(
            'cpFFGxDbJWh8dult3XRAdQrBAOugEXyPJ5GgREz8EWk='::TEXT
        )
    ),
    (
        'client.directory_refresh_seconds',
        '300'::JSONB
    ),
    (
        'client.local_accept_default_permission',
        to_jsonb('view_only'::TEXT)
    ),
    (
        'client.password_authenticated_default_permission',
        to_jsonb('full_control'::TEXT)
    ),
    (
        'client.receiver_connection_notice_required',
        'true'::JSONB
    ),
    (
        'client.file_transfer_enabled',
        'true'::JSONB
    ),
    (
        'security.new_device_default_status',
        to_jsonb('pending'::TEXT)
    ),
    (
        'security.require_installer_enrollment_password',
        'true'::JSONB
    ),
    (
        'security.block_unapproved_unattended_access',
        'true'::JSONB
    ),
    (
        'security.require_owner_password_and_totp_for_owner_promotion',
        'true'::JSONB
    ),
    (
        'directory.listen_address',
        to_jsonb('127.0.0.1:21120'::TEXT)
    )
ON CONFLICT (setting_key) DO NOTHING;
