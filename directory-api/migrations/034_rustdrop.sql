BEGIN;

-- RustDrop: LANDrop-style send-and-accept file drop between managed
-- devices, replacing RDC's built-in push/pull transfer. See the
-- rustdrop_architecture doc for the full design. RDS is directory +
-- signaling + metadata only - file bytes live on the storage VM's isolated
-- storage service (proxied through the API here) and are never persisted in
-- Postgres, and are themselves sender-side encrypted before upload.

CREATE TABLE IF NOT EXISTS rustdrop_registrations (
    device_id UUID PRIMARY KEY REFERENCES managed_devices(id) ON DELETE CASCADE,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE rustdrop_registrations IS
    'Marks a device as having RustDrop installed and running - upserted every time that device calls POST /v1/filedrop/register (on RustDrop startup and periodically after). A device only appears in the send-to picker while last_seen_at is within the staleness window enforced in rustdrop.py (30 days) - a heartbeat bound, not live presence, since store-and-forward means the recipient does not need to be online when a drop is sent.';

CREATE INDEX IF NOT EXISTS rustdrop_registrations_last_seen_idx ON rustdrop_registrations(last_seen_at);

CREATE TABLE IF NOT EXISTS filedrop_drops (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_device_id UUID NOT NULL REFERENCES managed_devices(id),
    recipient_device_id UUID NOT NULL REFERENCES managed_devices(id),
    filename TEXT NOT NULL,
    declared_size BIGINT NOT NULL CHECK (declared_size >= 0),
    bytes_uploaded BIGINT NOT NULL DEFAULT 0,
    storage_key UUID NOT NULL DEFAULT gen_random_uuid(),
    status TEXT NOT NULL DEFAULT 'uploading' CHECK (status IN ('uploading', 'complete', 'failed', 'declined')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ
);

COMMENT ON TABLE filedrop_drops IS
    'One RustDrop file transfer. storage_key is the blob key on the storage VM''s storage service - server-generated at insert time, never client-controlled. expires_at is set once status reaches complete (default 24h TTL from that point - see rustdrop.py''s DROP_DEFAULT_TTL) and is what the hourly sweep purges against; a drop stuck in uploading/failed forever (sender vanished mid-transfer) is swept via a created_at backstop instead, since it never gets a real expires_at. A declined drop is deleted immediately by the decline endpoint itself, never left for the sweep.';

CREATE INDEX IF NOT EXISTS filedrop_drops_recipient_idx ON filedrop_drops(recipient_device_id, status);
CREATE INDEX IF NOT EXISTS filedrop_drops_sender_idx ON filedrop_drops(sender_device_id);
CREATE INDEX IF NOT EXISTS filedrop_drops_expires_idx ON filedrop_drops(expires_at) WHERE expires_at IS NOT NULL;

COMMIT;
