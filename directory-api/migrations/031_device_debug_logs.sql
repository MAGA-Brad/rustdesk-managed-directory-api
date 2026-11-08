CREATE TABLE device_debug_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    client_version VARCHAR(64),
    hardware_info JSONB,
    log_content TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    redacted_line_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX device_debug_logs_device_id_idx
    ON device_debug_logs (device_id);

CREATE INDEX device_debug_logs_uploaded_at_idx
    ON device_debug_logs (uploaded_at);
