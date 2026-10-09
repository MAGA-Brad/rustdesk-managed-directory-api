-- 041: Cloudflare mTLS client certificates for the RDS edge (devices, operator browsers, mobile app).
CREATE TABLE IF NOT EXISTS edge_client_certs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind text NOT NULL CHECK (kind IN ('device', 'browser', 'mobile')),
    device_id uuid REFERENCES managed_devices(id) ON DELETE SET NULL,
    operator_account_id uuid,
    label text NOT NULL DEFAULT '',
    cf_cert_id text NOT NULL UNIQUE,
    serial_number text,
    fingerprint_sha256 text,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    revoke_reason text
);
CREATE INDEX IF NOT EXISTS edge_client_certs_device_active ON edge_client_certs (device_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS edge_client_certs_operator ON edge_client_certs (operator_account_id);

