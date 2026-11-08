CREATE TABLE enrollment_secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    label VARCHAR(128) NOT NULL,
    password_hash TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    max_uses INTEGER,
    use_count INTEGER NOT NULL DEFAULT 0,
    created_by UUID NOT NULL REFERENCES operator_accounts(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revoked_by UUID REFERENCES operator_accounts(id),
    revocation_reason TEXT,

    CHECK (BTRIM(label) <> ''),
    CHECK (max_uses IS NULL OR max_uses > 0),
    CHECK (use_count >= 0),
    CHECK (max_uses IS NULL OR use_count <= max_uses),
    CHECK (expires_at IS NULL OR expires_at > created_at),

    CHECK (
        (revoked_at IS NULL AND revoked_by IS NULL)
        OR
        (
            revoked_at IS NOT NULL
            AND revoked_by IS NOT NULL
            AND is_active = FALSE
        )
    )
);

CREATE INDEX enrollment_secrets_active_idx
    ON enrollment_secrets (is_active, expires_at);

CREATE TABLE device_enrollment_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID
        REFERENCES managed_devices(id) ON DELETE SET NULL,
    enrollment_secret_id UUID
        REFERENCES enrollment_secrets(id) ON DELETE SET NULL,
    rustdesk_id VARCHAR(64) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    device_public_key_sha256 CHAR(64) NOT NULL,
    source_ip INET,
    client_version VARCHAR(64),

    result VARCHAR(32) NOT NULL
        CHECK (
            result IN (
                'accepted_pending',
                'rejected_bad_secret',
                'rejected_expired',
                'rejected_revoked',
                'rejected_limit',
                'duplicate',
                'error'
            )
        ),

    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX device_enrollment_events_created_at_idx
    ON device_enrollment_events (created_at DESC);

CREATE INDEX device_enrollment_events_rustdesk_id_idx
    ON device_enrollment_events (rustdesk_id);
