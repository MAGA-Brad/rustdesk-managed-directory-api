-- chat_messages.sender_device_id was missing ON DELETE CASCADE (unlike
-- chat_participants.device_id and chat_message_receipts.device_id, which
-- both already cascade correctly) - a device with any still-undelivered
-- message sitting in this mailbox table could never be deleted, even
-- after being blocked/revoked, failing with an opaque foreign-key
-- violation. Consistent with the mailbox model: if the device record
-- itself is gone, there's nothing left to deliver.
ALTER TABLE chat_messages DROP CONSTRAINT chat_messages_sender_device_id_fkey;
ALTER TABLE chat_messages
    ADD CONSTRAINT chat_messages_sender_device_id_fkey
    FOREIGN KEY (sender_device_id) REFERENCES managed_devices(id) ON DELETE CASCADE;
