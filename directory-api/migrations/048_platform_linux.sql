-- RustDWeb gateway: a Linux RDC device ("linux-x86_64" heartbeat arch -> linux). Like Android it only
-- connects out: never a chat target, no Windows security checks, updated by hand.
ALTER TABLE managed_devices DROP CONSTRAINT IF EXISTS managed_devices_platform_check;
ALTER TABLE managed_devices ADD CONSTRAINT managed_devices_platform_check CHECK (platform IN ('windows', 'android', 'linux'));
