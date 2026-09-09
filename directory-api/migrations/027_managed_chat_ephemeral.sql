BEGIN;

-- Managed chat is now a delivery mailbox, not a permanent chat log: once a
-- message has been delivered to every recipient's device, the server row is
-- purged (see managed_chat.py's _purge_if_fully_delivered). Long-term
-- scrollback lives only on each client's own machine, at whatever retention
-- that client's user has chosen per-conversation - the server never sees or
-- enforces that setting. "Read" is therefore a purely local concept too:
-- the server only ever needs to know whether a message reached a device,
-- not whether a human looked at it, so read_at has no remaining purpose.

DROP INDEX IF EXISTS chat_message_receipts_unread_idx;

ALTER TABLE chat_message_receipts DROP COLUMN IF EXISTS read_at;

COMMENT ON TABLE chat_messages IS
    'In-flight chat messages awaiting delivery. Rows are deleted once every recipient in chat_message_receipts has a non-null delivered_at (see _purge_if_fully_delivered), and unconditionally after CHAT_MESSAGE_MAX_AGE regardless of delivery status, so this table is a mailbox queue, not a permanent log - long-term history is the receiving client''s own local, user-controlled responsibility.';

COMMENT ON TABLE chat_message_receipts IS
    'Per-recipient delivery tracking for a chat_message. A row is created for every participant except the sender at send time; delivered_at is set once the message content has actually reached that device (a live WebSocket push, or a catch-up fetch after reconnecting) - not merely attempted. Once every row for a message has a non-null delivered_at, the message is purged.';

COMMIT;
