\set ON_ERROR_STOP on
BEGIN;

ALTER TABLE operator_accounts
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS deleted_by UUID REFERENCES operator_accounts(id),
    ADD COLUMN IF NOT EXISTS deletion_reason TEXT;

-- The all-zero UUID below is a placeholder for the protected owner account's
-- id; set it to your deployment's account id (the username check also matches).
CREATE OR REPLACE FUNCTION protect_brad_operator_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.id = '00000000-0000-0000-0000-000000000000'::uuid
           OR lower(OLD.username) = 'brad' THEN
            RAISE EXCEPTION 'Brad account role, status and lifecycle are permanently protected';
        END IF;
        RETURN OLD;
    END IF;

    IF (OLD.id = '00000000-0000-0000-0000-000000000000'::uuid
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
    -- Fresh installation: migrations run before the first (Creator-)Owner
    -- exists, so there is no account to check yet. The trigger above already
    -- protects that identity from the moment it is created (see
    -- deploy/sbin/rustdesk-owner-bootstrap). Existing deployments still get
    -- the strict precondition below.
    IF NOT EXISTS (SELECT 1 FROM operator_accounts)
       AND EXISTS (
            SELECT 1
              FROM directory_instance
             WHERE singleton = TRUE
               AND bootstrap_completed_at IS NULL
       ) THEN
        RAISE NOTICE 'No operator accounts yet; protected Owner precondition deferred to first-Owner bootstrap';
        RETURN;
    END IF;

    SELECT COUNT(*), bool_and(is_active)
      INTO brad_count, brad_active
      FROM operator_accounts
     WHERE (id = '00000000-0000-0000-0000-000000000000'::uuid
        OR lower(username) = 'brad')
       AND role = 'owner';

    IF brad_count <> 1 OR brad_active IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'Protected Brad account identity/Owner-role/active-state precondition failed';
    END IF;

    UPDATE operator_role_change_requests
       SET status = 'cancelled'
     WHERE target_account_id IN (
               SELECT id
                 FROM operator_accounts
                WHERE (id = '00000000-0000-0000-0000-000000000000'::uuid
                   OR lower(username) = 'brad')
                  AND role = 'owner'
           )
       AND status = 'pending';
END;
$$;

COMMIT;
