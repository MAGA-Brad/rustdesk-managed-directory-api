BEGIN;

-- RustDrop's own dedicated X25519 keypair (see the rustdrop_architecture doc - deliberately
-- separate from RDC's Ed25519 device_public_key, which is a signing key and
-- wrong for Diffie-Hellman key agreement). base64-encoded raw 32-byte keys.

ALTER TABLE rustdrop_registrations ADD COLUMN IF NOT EXISTS public_key TEXT;

COMMENT ON COLUMN rustdrop_registrations.public_key IS
    'This device''s X25519 public key, base64-encoded raw 32 bytes. Sent on every /v1/filedrop/register call (cheap, idempotent) so a sender can always fetch a current key from the device picker before encrypting. NULL only very briefly - RustDrop generates its keypair before its first register call ever completes.';

ALTER TABLE filedrop_drops ADD COLUMN IF NOT EXISTS sender_public_key TEXT;

COMMENT ON COLUMN filedrop_drops.sender_public_key IS
    'Echo of the sender''s X25519 public key at the moment this drop was created, base64-encoded raw 32 bytes. Stored on the drop itself (not looked up fresh from rustdrop_registrations at download time) so decryption never depends on the sender still being registered/reachable - matches store-and-forward not requiring the sender to still be around.';

COMMIT;
