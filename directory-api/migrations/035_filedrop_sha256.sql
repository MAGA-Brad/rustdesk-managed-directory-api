BEGIN;

ALTER TABLE filedrop_drops ADD COLUMN IF NOT EXISTS content_sha256 TEXT;

COMMENT ON COLUMN filedrop_drops.content_sha256 IS
    'SHA-256 of the stored (ciphertext) bytes, computed by the storage VM''s storage service as it writes the upload and captured here once status reaches complete. Lets a receiver verify the fully reassembled file after download, including one stitched together across a resumed (Range-request) download rather than a single unbroken stream. NULL until upload finishes.';

COMMIT;
