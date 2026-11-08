-- RDC Mobile Manager phones bound to an operator account by a hardware key (app/mobile_keys.py):
-- single-use pairing codes baked into an app build, the paired public keys, replay protection for
-- signed sign-ins, and which phone each mobile session came from.
CREATE TABLE IF NOT EXISTS mobile_pairing_codes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id uuid NOT NULL REFERENCES operator_accounts(id) ON DELETE CASCADE,
    code_hash bytea NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    used_by_key uuid
);

CREATE TABLE IF NOT EXISTS mobile_device_keys (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id uuid NOT NULL REFERENCES operator_accounts(id) ON DELETE CASCADE,
    public_key bytea NOT NULL,
    device_name text,
    paired_ip inet,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    last_ip inet,
    revoked_at timestamptz,
    revoked_by uuid
);

CREATE UNLOGGED TABLE IF NOT EXISTS mobile_key_nonces (
    nonce_hash bytea PRIMARY KEY,
    seen_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE operator_sessions ADD COLUMN IF NOT EXISTS mobile_key_id uuid;
