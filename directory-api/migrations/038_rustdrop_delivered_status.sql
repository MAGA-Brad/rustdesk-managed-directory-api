BEGIN;

-- Adds a real terminal state for "recipient successfully downloaded and
-- hash-verified this drop", distinct from 'complete' (which only means
-- "fully uploaded, ready to download"). Without this, a drop sat in
-- 'complete' forever after being accepted (until TTL expiry), so it kept
-- reappearing in both the recipient's Incoming list and the sender's Sent
-- list on every poll. rustdrop.py's list_drops now excludes 'delivered'
-- from both incoming and outgoing results.

ALTER TABLE filedrop_drops DROP CONSTRAINT filedrop_drops_status_check;
ALTER TABLE filedrop_drops ADD CONSTRAINT filedrop_drops_status_check
    CHECK (status IN ('uploading', 'complete', 'delivered', 'failed', 'declined'));

COMMIT;
