-- Counts messages sent, for dashboard/Client Management stats. Deliberately
-- has no body/content column at all - chat_messages itself is a delivery
-- mailbox that purges content on delivery (see managed_chat.py's module
-- comment), and this table must never become a second place message
-- content could leak into. One row per successful send, forever - the
-- "lifetime" stat needs full history, matching the existing unbounded
-- device_activity_events table's own retention approach.
CREATE TABLE IF NOT EXISTS chat_message_send_events (
    id BIGSERIAL PRIMARY KEY,
    sender_device_id UUID NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
    sent_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS chat_message_send_events_sender_idx
    ON chat_message_send_events(sender_device_id, sent_at);

CREATE INDEX IF NOT EXISTS chat_message_send_events_time_idx
    ON chat_message_send_events(sent_at);
