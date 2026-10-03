CREATE TABLE managed_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rustdesk_id VARCHAR(64) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    friendly_name VARCHAR(128),
    device_public_key BYTEA NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'denied', 'blocked', 'revoked')),
    status_reason TEXT,
    status_changed_by UUID REFERENCES operator_accounts(id),
    status_changed_at TIMESTAMPTZ,
    last_ip INET,
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX managed_devices_rustdesk_id_uidx
    ON managed_devices (rustdesk_id);

CREATE UNIQUE INDEX managed_devices_public_key_uidx
    ON managed_devices (device_public_key);

CREATE INDEX managed_devices_status_idx
    ON managed_devices (status);
