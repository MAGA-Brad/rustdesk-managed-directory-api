-- Low-severity fixes from the 2026-10-17 platform audit. Apply before restarting the API on the
-- matching code: _perform_login reads operator_accounts.totp_last_step. Safe to run twice.

-- RDS-MAIN-A#6: a TOTP code is good for one sign-in. The step of the last code used on ops,
-- /v1/auth/login and mobile password sign-in; a code from that step or an older one is refused.
ALTER TABLE operator_accounts ADD COLUMN IF NOT EXISTS totp_last_step bigint;

-- CA-IDENTITY#8: a revoke job queued for a device must survive the device record being deleted
-- before the CA picks it up (the payload names the device; ca_link skips a NULL device_id). The
-- ops delete action cancels the device's other unfinished jobs first.
ALTER TABLE ca_jobs
    DROP CONSTRAINT IF EXISTS ca_jobs_device_id_fkey,
    ADD CONSTRAINT ca_jobs_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES managed_devices(id) ON DELETE SET NULL;

-- RDS-SEALED-ID#8: a push token registered by a second account no longer moves over; the old
-- binding is revoked and the new account gets its own row, so the token is unique among active
-- rows only.
CREATE UNIQUE INDEX IF NOT EXISTS mobile_push_tokens_token_active_uidx
    ON mobile_push_tokens (fcm_token) WHERE revoked_at IS NULL;
DROP INDEX IF EXISTS mobile_push_tokens_token_uidx;

-- RDS-MAIN-A#7: the device details look up a Pending device's latest enrollment event (the
-- previous and new key fingerprints of an Owner-authorized recovery).
CREATE INDEX IF NOT EXISTS device_enrollment_events_device_idx
    ON device_enrollment_events (device_id, created_at DESC)
    WHERE device_id IS NOT NULL;

-- The 048 index device_activity_events_established_session_key_idx stays: main.py now matches
-- the initiator's 'rdc-<session id>-' prefix with a byte-order range (~>=~ / ~<~), which that
-- text_pattern_ops index serves even though the prefix comes from the outer row.
