-- 042: when each device last reached the RDS edge with a Cloudflare-verified client certificate.
ALTER TABLE managed_devices ADD COLUMN IF NOT EXISTS edge_cert_verified_at timestamptz;
ALTER TABLE managed_devices ADD COLUMN IF NOT EXISTS edge_cert_fingerprint text;

