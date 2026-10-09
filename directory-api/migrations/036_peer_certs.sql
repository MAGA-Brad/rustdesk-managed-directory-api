-- Managed peer authentication: the device certificate RDS last issued to each device (serial +
-- expiry), so the dashboard/health checks can flag devices whose renewal keeps failing.
ALTER TABLE managed_devices
    ADD COLUMN IF NOT EXISTS peer_cert_serial UUID,
    ADD COLUMN IF NOT EXISTS peer_cert_expires_at TIMESTAMPTZ;
