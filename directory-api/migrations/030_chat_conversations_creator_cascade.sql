-- Same bug class as migration 029: chat_conversations.created_by_device_id
-- was missing ON DELETE CASCADE. Cascading the conversation row itself
-- (and, via chat_participants/chat_messages's own existing cascades from
-- chat_conversations, everything under it) when its creator device is
-- deleted is consistent with the mailbox model: the server's copy of a
-- conversation is routing bookkeeping, not the durable record - that
-- lives on each device's own local store, untouched by this.
ALTER TABLE chat_conversations DROP CONSTRAINT chat_conversations_created_by_device_id_fkey;
ALTER TABLE chat_conversations
    ADD CONSTRAINT chat_conversations_created_by_device_id_fkey
    FOREIGN KEY (created_by_device_id) REFERENCES managed_devices(id) ON DELETE CASCADE;
