\set ON_ERROR_STOP on
BEGIN;

ALTER TABLE operator_accounts
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS deleted_by UUID REFERENCES operator_accounts(id),
    ADD COLUMN IF NOT EXISTS deletion_reason TEXT;

CREATE OR REPLACE FUNCTION protect_brad_operator_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.id = 'da1c8c16-bf66-4e79-930c-f9b68496aa4a'::uuid
           OR lower(OLD.username) = 'brad' THEN
            RAISE EXCEPTION 'Brad account role, status and lifecycle are permanently protected';
        END IF;
        RETURN OLD;
    END IF;

    IF (OLD.id = 'da1c8c16-bf66-4e79-930c-f9b68496aa4a'::uuid
        OR lower(OLD.username) = 'brad')
       AND (
            NEW.role IS DISTINCT FROM OLD.role
            OR NEW.is_active IS DISTINCT FROM OLD.is_active
            OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at
            OR NEW.deleted_by IS DISTINCT FROM OLD.deleted_by
            OR NEW.deletion_reason IS DISTINCT FROM OLD.deletion_reason
       ) THEN
        RAISE EXCEPTION 'Brad account role, status and lifecycle are permanently protected';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS operator_accounts_protect_brad_lifecycle
    ON operator_accounts;
CREATE TRIGGER operator_accounts_protect_brad_lifecycle
BEFORE DELETE OR UPDATE OF role, is_active, deleted_at, deleted_by, deletion_reason
ON operator_accounts
FOR EACH ROW
EXECUTE FUNCTION protect_brad_operator_lifecycle();

DO $$
DECLARE
    brad_count INTEGER;
    brad_active BOOLEAN;
BEGIN
    SELECT COUNT(*), bool_and(is_active)
      INTO brad_count, brad_active
      FROM operator_accounts
     WHERE (id = 'da1c8c16-bf66-4e79-930c-f9b68496aa4a'::uuid
        OR lower(username) = 'brad')
       AND role = 'owner';

    IF brad_count <> 1 OR brad_active IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'Protected Brad account identity/Owner-role/active-state precondition failed';
    END IF;

    UPDATE operator_role_change_requests
       SET status = 'cancelled'
     WHERE target_account_id = 'da1c8c16-bf66-4e79-930c-f9b68496aa4a'::uuid
       AND status = 'pending';
END;
$$;

COMMIT;
