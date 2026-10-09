CREATE TABLE operator_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    account_id UUID NOT NULL
        REFERENCES operator_accounts(id) ON DELETE CASCADE,

    access_token_hash BYTEA NOT NULL UNIQUE,
    refresh_token_hash BYTEA NOT NULL UNIQUE,
    mfa_verified_at TIMESTAMPTZ,
    source_ip INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revoked_by UUID REFERENCES operator_accounts(id),
    revocation_reason TEXT,

    CHECK (expires_at > created_at),

    CHECK (
        (revoked_at IS NULL AND revoked_by IS NULL)
        OR
        (revoked_at IS NOT NULL AND revoked_by IS NOT NULL)
    )
);

CREATE INDEX operator_sessions_account_id_idx
    ON operator_sessions (account_id);

CREATE INDEX operator_sessions_expires_at_idx
    ON operator_sessions (expires_at)
    WHERE revoked_at IS NULL;
