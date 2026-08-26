BEGIN;

-- Active operator accounts use only Owner / Manager / Viewer.
ALTER TABLE operator_accounts
    DROP CONSTRAINT operator_accounts_role_check;

-- Allow guarded role conversion without bypassing the existing role-change
-- protection for normal application writes.
SELECT set_config('rustdesk.role_change_authorized', '1', TRUE);

UPDATE operator_accounts
SET role = 'manager',
    updated_at = NOW()
WHERE role = 'approver';

ALTER TABLE operator_accounts
    ADD CONSTRAINT operator_accounts_role_check
    CHECK (role IN ('owner', 'manager', 'viewer'));

-- Pending workflow state is active state, so convert it. Completed/expired/
-- revoked historical workflow rows may retain the old word "approver" as
-- historical truth, but no new pending Approver workflow is allowed.
ALTER TABLE operator_invitations
    DROP CONSTRAINT operator_invitations_requested_role_check;

UPDATE operator_invitations
SET requested_role = 'manager'
WHERE requested_role = 'approver'
  AND status = 'pending';

ALTER TABLE operator_invitations
    ADD CONSTRAINT operator_invitations_requested_role_check
    CHECK (
        requested_role IN ('owner', 'manager', 'viewer')
        OR (requested_role = 'approver' AND status <> 'pending')
    );

ALTER TABLE operator_role_change_requests
    DROP CONSTRAINT operator_role_change_requests_requested_role_check;

UPDATE operator_role_change_requests
SET requested_role = 'manager'
WHERE requested_role = 'approver'
  AND status = 'pending';

ALTER TABLE operator_role_change_requests
    ADD CONSTRAINT operator_role_change_requests_requested_role_check
    CHECK (
        requested_role IN ('owner', 'manager', 'viewer')
        OR (requested_role = 'approver' AND status <> 'pending')
    );

CREATE OR REPLACE FUNCTION guard_managed_device_status() RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    actor_role VARCHAR(16);
    actor_active BOOLEAN;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'pending' THEN
            RAISE EXCEPTION
                'Every new managed device must start Pending Approval';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.status IS DISTINCT FROM OLD.status THEN
        IF NEW.status_changed_by IS NULL THEN
            RAISE EXCEPTION
                'A human operator account is required for device status changes';
        END IF;

        SELECT role, is_active
        INTO actor_role, actor_active
        FROM operator_accounts
        WHERE id = NEW.status_changed_by;

        IF NOT FOUND
           OR actor_active = FALSE
           OR actor_role NOT IN ('owner', 'manager') THEN
            RAISE EXCEPTION
                'Only active Owner or Manager accounts may change device status';
        END IF;

        NEW.status_changed_at = NOW();

        IF OLD.status = 'approved'
           AND NEW.status <> 'approved' THEN
            UPDATE device_credentials
            SET revoked_at = NOW(),
                revoked_by = NEW.status_changed_by,
                revocation_reason = COALESCE(
                    NULLIF(NEW.status_reason, ''),
                    'Automatically revoked because device status changed to '
                        || NEW.status
                )
            WHERE device_id = NEW.id
              AND revoked_at IS NULL;
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

COMMIT;
