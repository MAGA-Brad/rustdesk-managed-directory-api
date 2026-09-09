BEGIN;

-- Outbound mail configuration (first step toward Mailcow integration for
-- system notification email). Single-row singleton table - id is always 1,
-- enforced by the CHECK constraint, so the app can always upsert against a
-- known key rather than tracking a row id separately.
--
-- password_ciphertext uses the same pgp_sym_encrypt/pgp_sym_decrypt pattern
-- already established for TOTP secrets (see TOTP_ENCRYPTION_SECRET /
-- totp_secret_ciphertext) - encryption key comes from the new
-- SMTP_ENCRYPTION_SECRET env var, never stored in the database itself.
-- The plaintext password is never returned to any client once saved; the
-- admin UI only ever sees whether a password is currently set.
CREATE TABLE IF NOT EXISTS smtp_config (
    id SMALLINT PRIMARY KEY DEFAULT 1,
    host TEXT,
    port INTEGER,
    use_tls BOOLEAN NOT NULL DEFAULT TRUE,
    username TEXT,
    password_ciphertext BYTEA,
    from_address TEXT,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by_account_id UUID REFERENCES operator_accounts(id),
    CONSTRAINT smtp_config_singleton CHECK (id = 1)
);

COMMENT ON TABLE smtp_config IS
    'Singleton outbound-mail configuration. Access is restricted server-side to Brad''s protected account specifically (require_brad_only), not the owner role in general - other owner-role accounts (michael, bradpixel, brady) cannot view or change mail credentials.';

COMMIT;
