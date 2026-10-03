CREATE TABLE operator_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(64) NOT NULL,
    display_name VARCHAR(128) NOT NULL,
    password_hash TEXT NOT NULL,
    totp_secret_ciphertext BYTEA,
    totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    role VARCHAR(16) NOT NULL
        CHECK (role IN ('owner', 'approver', 'viewer')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    must_change_password BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID REFERENCES operator_accounts(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX operator_accounts_username_lower_uidx
    ON operator_accounts (LOWER(username));
