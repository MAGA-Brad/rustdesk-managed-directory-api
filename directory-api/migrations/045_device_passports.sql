-- Device passports: job queue to the CA VM, passports it issued, its last status,
-- and each device's identity key. Nothing here is enforced yet (log mode).
CREATE TABLE IF NOT EXISTS ca_jobs (
    id BIGSERIAL PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('issue', 'renew', 'revoke', 'keyupdate')),
    device_id UUID REFERENCES managed_devices(id) ON DELETE CASCADE,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    picked_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0,
    done_at TIMESTAMPTZ,
    ok BOOLEAN,
    error TEXT
);
CREATE INDEX IF NOT EXISTS ca_jobs_pending ON ca_jobs (id) WHERE done_at IS NULL;
CREATE INDEX IF NOT EXISTS ca_jobs_device ON ca_jobs (device_id, id DESC);

CREATE TABLE IF NOT EXISTS device_passports (
    serial TEXT PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    passport TEXT NOT NULL,
    nbf TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    job_id BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS device_passports_device ON device_passports (device_id, expires_at DESC);

CREATE TABLE IF NOT EXISTS ca_status (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    status JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE managed_devices
    ADD COLUMN IF NOT EXISTS identity_public_key TEXT,
    ADD COLUMN IF NOT EXISTS identity_key_alg TEXT,
    ADD COLUMN IF NOT EXISTS key_protection TEXT,
    ADD COLUMN IF NOT EXISTS passport_serial TEXT,
    ADD COLUMN IF NOT EXISTS passport_expires_at TIMESTAMPTZ;
