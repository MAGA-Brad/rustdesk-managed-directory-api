BEGIN;

-- Managed endpoint contact email metadata.
-- Existing endpoints remain compatible because the field is nullable.
-- Email uniqueness is intentionally not enforced; multiple endpoints may
-- legitimately be associated with the same person/address.
ALTER TABLE managed_devices
    ADD COLUMN IF NOT EXISTS contact_email VARCHAR(320);

COMMENT ON COLUMN managed_devices.contact_email IS
    'Server-authoritative managed endpoint email address; editable by the managed endpoint and Owners.';

COMMIT;
