-- RDC for Android (controller-only): which platform each device runs, from its heartbeat
-- ("android-aarch64" arch -> android). Windows until a heartbeat says otherwise.
ALTER TABLE managed_devices ADD COLUMN IF NOT EXISTS platform TEXT NOT NULL DEFAULT 'windows';
ALTER TABLE managed_devices DROP CONSTRAINT IF EXISTS managed_devices_platform_check;
ALTER TABLE managed_devices ADD CONSTRAINT managed_devices_platform_check CHECK (platform IN ('windows', 'android'));
