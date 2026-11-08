BEGIN;

-- Build-number visibility for the future minimum-version gate. Reported on
-- every heartbeat now (see HeartbeatRequest.managed_build_number in
-- directory_enrollment.rs), not just the rare debug-log upload, so fleet-
-- wide adoption of a new build can be confirmed before any enforcement is
-- turned on. 0 means unmanaged/dev build, or a client too old to report
-- this field at all (the default, so an un-updated device's row just stays
-- 0 rather than NULL - both cases mean the same thing: "not confirmed on
-- an acceptable build").
ALTER TABLE managed_devices
    ADD COLUMN IF NOT EXISTS reported_build_number INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN managed_devices.reported_build_number IS
    'Managed build number self-reported on the device''s most recent heartbeat. 0 = unmanaged/dev build or a client older than the build that added this reporting field.';

COMMIT;
