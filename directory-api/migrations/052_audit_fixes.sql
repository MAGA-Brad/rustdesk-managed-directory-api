-- Fixes from the 2026-10-17 platform audit.

-- RDS-13: deleting any device that ever used RustDrop failed (these were the only foreign keys to
-- managed_devices with no ON DELETE action). A deleted device's drops go with it (the delete action
-- also removes their blobs from the storage VM); transfer events keep the lifetime statistics with
-- the device detached.
ALTER TABLE filedrop_drops
    DROP CONSTRAINT IF EXISTS filedrop_drops_sender_device_id_fkey,
    ADD CONSTRAINT filedrop_drops_sender_device_id_fkey
        FOREIGN KEY (sender_device_id) REFERENCES managed_devices(id) ON DELETE CASCADE,
    DROP CONSTRAINT IF EXISTS filedrop_drops_recipient_device_id_fkey,
    ADD CONSTRAINT filedrop_drops_recipient_device_id_fkey
        FOREIGN KEY (recipient_device_id) REFERENCES managed_devices(id) ON DELETE CASCADE;

ALTER TABLE filedrop_transfer_events
    ALTER COLUMN sender_device_id DROP NOT NULL,
    ALTER COLUMN recipient_device_id DROP NOT NULL,
    DROP CONSTRAINT IF EXISTS filedrop_transfer_events_sender_device_id_fkey,
    ADD CONSTRAINT filedrop_transfer_events_sender_device_id_fkey
        FOREIGN KEY (sender_device_id) REFERENCES managed_devices(id) ON DELETE SET NULL,
    DROP CONSTRAINT IF EXISTS filedrop_transfer_events_recipient_device_id_fkey,
    ADD CONSTRAINT filedrop_transfer_events_recipient_device_id_fkey
        FOREIGN KEY (recipient_device_id) REFERENCES managed_devices(id) ON DELETE SET NULL;

-- RDS-07: the "Direct/Relay" route lookup for every open session (directory, device list, device_sync
-- fingerprint) matches session_key by equality or a 'rdc-<id>-%' prefix with no usable index.
CREATE INDEX IF NOT EXISTS device_activity_events_established_session_key_idx
    ON device_activity_events (session_key text_pattern_ops)
    WHERE event_type = 'connection.established';
