BEGIN;

-- Managed chat: out-of-session 1:1 (and future group) messaging between
-- managed devices. Separate from RustDesk's own in-session text chat -
-- this works whether or not a remote-control session is active, relayed
-- entirely through RDS's own WebSocket connection to each online device
-- rather than through hbbs/hbbr, so it never touches core relay/
-- rendezvous infrastructure shared by every connection in the fleet.

CREATE TABLE IF NOT EXISTS chat_conversations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_type TEXT NOT NULL CHECK (conversation_type IN ('direct', 'group')),
    name TEXT,
    direct_pair_key TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by_device_id UUID REFERENCES managed_devices(id)
);

COMMENT ON TABLE chat_conversations IS
    'A conversation between managed devices. A direct (1:1) conversation always has exactly two chat_participants rows and a non-null direct_pair_key; group conversations may have more participants, a NULL direct_pair_key, and an optional name.';

COMMENT ON COLUMN chat_conversations.direct_pair_key IS
    'For conversation_type=''direct'' only: the two participant device_ids sorted (least::text || '':'' || greatest::text) and set by the application at insert time, so a unique index can enforce at most one direct conversation per device pair regardless of which device initiates. NULL for group conversations.';

CREATE UNIQUE INDEX IF NOT EXISTS chat_conversations_direct_pair_uidx
    ON chat_conversations(direct_pair_key)
    WHERE direct_pair_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS chat_participants (
    conversation_id UUID NOT NULL REFERENCES chat_conversations(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (conversation_id, device_id)
);

CREATE INDEX IF NOT EXISTS chat_participants_device_idx ON chat_participants(device_id);

COMMENT ON TABLE chat_participants IS
    'Membership of a device in a chat_conversation. The device_id index supports "list my conversations" lookups (join from device_id to conversation_id to chat_conversations).';

CREATE TABLE IF NOT EXISTS chat_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL REFERENCES chat_conversations(id) ON DELETE CASCADE,
    sender_device_id UUID NOT NULL REFERENCES managed_devices(id),
    body TEXT NOT NULL,
    sent_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS chat_messages_conversation_idx ON chat_messages(conversation_id, sent_at);

COMMENT ON TABLE chat_messages IS
    'Persisted chat messages, retained indefinitely for scrollback. No separate delivery-queue table - delivery/read state lives in chat_message_receipts, and "undelivered" is simply the absence of a receipt row for a given (message, recipient) pair.';

CREATE TABLE IF NOT EXISTS chat_message_receipts (
    message_id UUID NOT NULL REFERENCES chat_messages(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
    delivered_at TIMESTAMPTZ,
    read_at TIMESTAMPTZ,
    PRIMARY KEY (message_id, device_id)
);

CREATE INDEX IF NOT EXISTS chat_message_receipts_unread_idx ON chat_message_receipts(device_id) WHERE read_at IS NULL;

COMMENT ON TABLE chat_message_receipts IS
    'Per-recipient delivery/read tracking for a chat_message. A row is created for every participant except the sender at send time; delivered_at is set once pushed to that device over the messaging WebSocket (or immediately if the sender was the only online participant at send time - no separate offline queue), read_at once the recipient''s client reports the conversation viewed. The partial index over unread rows supports fast per-device unread-count queries.';

COMMIT;
