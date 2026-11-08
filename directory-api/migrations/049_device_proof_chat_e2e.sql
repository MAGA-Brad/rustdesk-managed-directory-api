-- sec8 Phase E: device key proof (X-RDC-Proof) on every device call and
-- the chat WebSocket, and end-to-end chat bodies ("rdce1:"). Both switches start in Log.

-- Proof nonces already used (SHA-256 of the 16 raw bytes); a second use is a replay. Rows only need to
-- outlast the 600 s skew window on both sides, so they are dropped after 30 minutes and the table is
-- not WAL-logged (losing it in a crash only reopens that short window).
CREATE UNLOGGED TABLE IF NOT EXISTS device_proof_nonces (
    nonce_hash bytea PRIMARY KEY,
    seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS device_proof_nonces_seen_at_idx ON device_proof_nonces (seen_at);

-- Each device's latest proof outcomes, written at most once a minute per device and outcome.
-- "no key" (a proof but no identity key on file) is recorded as invalid with reason no_key.
ALTER TABLE managed_devices
    ADD COLUMN IF NOT EXISTS proof_last_ok_at timestamptz,
    ADD COLUMN IF NOT EXISTS proof_last_missing_at timestamptz,
    ADD COLUMN IF NOT EXISTS proof_last_invalid_at timestamptz,
    ADD COLUMN IF NOT EXISTS proof_last_invalid_reason text;

-- Sealed vs plain chat sends, counted for the Config page (still no content).
ALTER TABLE chat_message_send_events ADD COLUMN IF NOT EXISTS end_to_end boolean NOT NULL DEFAULT false;

INSERT INTO directory_settings (setting_key, setting_value)
VALUES
    ('security.device_proof', to_jsonb('log'::TEXT)),
    ('security.chat_e2e', to_jsonb('log'::TEXT)),
    ('security.phase_e_test_ids', to_jsonb(''::TEXT))
ON CONFLICT (setting_key) DO NOTHING;
