BEGIN;

ALTER TABLE operator_accounts
    ADD COLUMN email VARCHAR(320);

ALTER TABLE operator_access_resets
    DROP CONSTRAINT operator_access_resets_reset_mode_check;

ALTER TABLE operator_access_resets
    ADD CONSTRAINT operator_access_resets_reset_mode_check
    CHECK (reset_mode IN ('password_only', 'totp_only', 'password_totp'));

COMMIT;
