CREATE TABLE device_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL
        REFERENCES managed_devices(id) ON DELETE CASCADE,
    issued_by UUID NOT NULL
        REFERENCES operator_accounts(id),
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revoked_by UUID
        REFERENCES operator_accounts(id),
    revocation_reason TEXT,
    signing_key_version INTEGER NOT NULL DEFAULT 1,
    CHECK (expires_at IS NULL OR expires_at > issued_at),
    CHECK (
        (revoked_at IS NULL AND revoked_by IS NULL)
        OR
        (revoked_at IS NOT NULL AND revoked_by IS NOT NULL)
    )
);

CREATE UNIQUE INDEX device_credentials_one_active_per_device_uidx
    ON device_credentials (device_id)
    WHERE revoked_at IS NULL;

CREATE INDEX device_credentials_device_id_idx
    ON device_credentials (device_id);
