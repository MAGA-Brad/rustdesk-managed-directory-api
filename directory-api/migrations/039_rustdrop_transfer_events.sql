BEGIN;

-- Durable, append-only log of successfully-delivered RustDrop transfers -
-- one row per drop the recipient fully downloaded and hash-verified
-- (mirrors chat_message_send_events, which backs the Messages Sent
-- dashboard card the same way). Deliberately independent of
-- filedrop_drops: that table's rows get deleted by the TTL sweep or an
-- immediate decline, so a lifetime dashboard counter computed live
-- against it would silently shrink over time. drop_id is not a foreign
-- key for the same reason - the row it names may already be gone.

CREATE TABLE IF NOT EXISTS filedrop_transfer_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    drop_id UUID NOT NULL,
    sender_device_id UUID NOT NULL REFERENCES managed_devices(id),
    recipient_device_id UUID NOT NULL REFERENCES managed_devices(id),
    bytes BIGINT NOT NULL CHECK (bytes >= 0),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE filedrop_transfer_events IS
    'One row per RustDrop transfer the recipient successfully downloaded and hash-verified (inserted by rustdrop.py''s complete_drop endpoint). Feeds the RustDrop card on /ops/api/dashboard-summary. Never deleted - this is the audit trail filedrop_drops itself cannot be, since that table is swept on TTL expiry.';

CREATE INDEX IF NOT EXISTS filedrop_transfer_events_occurred_idx ON filedrop_transfer_events(occurred_at);

COMMIT;
