ALTER TABLE operator_accounts
    ADD COLUMN password_changed_at TIMESTAMPTZ,
    ADD COLUMN totp_confirmed_at TIMESTAMPTZ,
    ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN locked_until TIMESTAMPTZ,
    ADD COLUMN last_login_at TIMESTAMPTZ,
    ADD COLUMN last_login_ip INET;

ALTER TABLE operator_accounts
    ADD CONSTRAINT operator_accounts_username_not_blank
        CHECK (BTRIM(username) <> ''),
    ADD CONSTRAINT operator_accounts_display_name_not_blank
        CHECK (BTRIM(display_name) <> ''),
    ADD CONSTRAINT operator_accounts_failed_login_count_check
        CHECK (failed_login_count >= 0),
    ADD CONSTRAINT operator_accounts_totp_state_check
        CHECK (
            (totp_enabled = FALSE AND totp_confirmed_at IS NULL)
            OR
            (totp_enabled = TRUE AND totp_confirmed_at IS NOT NULL)
        );

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER operator_accounts_set_updated_at
BEFORE UPDATE ON operator_accounts
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER managed_devices_set_updated_at
BEFORE UPDATE ON managed_devices
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER directory_instance_set_updated_at
BEFORE UPDATE ON directory_instance
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE OR REPLACE FUNCTION prevent_last_active_owner_loss()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.role = 'owner' AND OLD.is_active THEN
            PERFORM 1
            FROM operator_accounts
            WHERE id <> OLD.id
              AND role = 'owner'
              AND is_active = TRUE
            LIMIT 1;

            IF NOT FOUND THEN
                RAISE EXCEPTION 'At least one active Owner must remain';
            END IF;
        END IF;

        RETURN OLD;
    END IF;

    IF OLD.role = 'owner'
       AND OLD.is_active
       AND (NEW.role <> 'owner' OR NEW.is_active = FALSE) THEN

        PERFORM 1
        FROM operator_accounts
        WHERE id <> OLD.id
          AND role = 'owner'
          AND is_active = TRUE
        LIMIT 1;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'At least one active Owner must remain';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER operator_accounts_last_owner_guard
BEFORE UPDATE OF role, is_active OR DELETE
ON operator_accounts
FOR EACH ROW EXECUTE FUNCTION prevent_last_active_owner_loss();
