BEGIN;

-- Owner-configurable RustDrop TTL (rustdrop_architecture doc, build order
-- step 3). Same directory_settings table and dotted-namespace convention
-- as the existing client.*/security.*/directory.* rows (014_directory_
-- settings.sql) - just the first row actually editable through an ops
-- console control rather than migration-seeded only.
INSERT INTO directory_settings (setting_key, setting_value)
VALUES ('rustdrop.default_ttl_hours', '24'::JSONB)
ON CONFLICT (setting_key) DO NOTHING;

COMMIT;
