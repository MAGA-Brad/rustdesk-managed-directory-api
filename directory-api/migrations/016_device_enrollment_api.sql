ALTER TABLE managed_devices
    ADD COLUMN IF NOT EXISTS enrollment_poll_token_hash BYTEA,
    ADD COLUMN IF NOT EXISTS enrollment_poll_expires_at TIMESTAMPTZ;

CREATE UNIQUE INDEX IF NOT EXISTS
    managed_devices_enrollment_poll_token_uidx
ON managed_devices (enrollment_poll_token_hash)
WHERE enrollment_poll_token_hash IS NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'managed_devices_enrollment_poll_pair_check'
          AND conrelid = 'managed_devices'::regclass
    ) THEN
        ALTER TABLE managed_devices
            ADD CONSTRAINT managed_devices_enrollment_poll_pair_check
            CHECK (
                (
                    enrollment_poll_token_hash IS NULL
                    AND enrollment_poll_expires_at IS NULL
                )
                OR
                (
                    enrollment_poll_token_hash IS NOT NULL
                    AND enrollment_poll_expires_at IS NOT NULL
                    AND enrollment_poll_expires_at > created_at
                )
            );
    END IF;
END;
$$;
