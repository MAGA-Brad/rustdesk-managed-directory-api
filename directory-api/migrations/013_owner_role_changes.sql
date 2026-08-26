CREATE TABLE operator_role_change_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    target_account_id UUID NOT NULL
        REFERENCES operator_accounts(id),

    requested_role VARCHAR(16) NOT NULL
        CHECK (requested_role IN ('owner', 'approver', 'viewer')),

    requested_by UUID NOT NULL
        REFERENCES operator_accounts(id),

    owner_password_verified_at TIMESTAMPTZ,
    owner_totp_verified_at TIMESTAMPTZ,

    status VARCHAR(16) NOT NULL DEFAULT 'pending'
        CHECK (
            status IN (
                'pending',
                'completed',
                'rejected',
                'cancelled',
                'expired'
            )
        ),

    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    completed_by UUID REFERENCES operator_accounts(id),

    CHECK (requested_by <> target_account_id),
    CHECK (expires_at > created_at),

    CHECK (
        requested_role <> 'owner'
        OR
        (
            owner_password_verified_at IS NOT NULL
            AND owner_totp_verified_at IS NOT NULL
        )
    ),

    CHECK (
        (
            status = 'completed'
            AND completed_at IS NOT NULL
            AND completed_by IS NOT NULL
        )
        OR
        (
            status <> 'completed'
            AND completed_at IS NULL
            AND completed_by IS NULL
        )
    )
);

CREATE UNIQUE INDEX operator_role_change_requests_pending_target_uidx
    ON operator_role_change_requests (target_account_id)
    WHERE status = 'pending';

CREATE INDEX operator_role_change_requests_expires_at_idx
    ON operator_role_change_requests (expires_at)
    WHERE status = 'pending';

CREATE OR REPLACE FUNCTION validate_operator_role_change_request()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    requester_role VARCHAR(16);
    requester_active BOOLEAN;
BEGIN
    IF TG_OP = 'INSERT' AND NEW.status <> 'pending' THEN
        RAISE EXCEPTION
            'New role-change requests must start pending';
    END IF;

    SELECT role, is_active
    INTO requester_role, requester_active
    FROM operator_accounts
    WHERE id = NEW.requested_by;

    IF NOT FOUND
       OR requester_active = FALSE
       OR requester_role <> 'owner' THEN

        RAISE EXCEPTION
            'Only an active Owner may request an operator role change';
    END IF;

    IF NEW.requested_by = NEW.target_account_id THEN
        RAISE EXCEPTION 'Self-promotion is not allowed';
    END IF;

    IF NEW.requested_role = 'owner'
       AND (
            NEW.owner_password_verified_at IS NULL
            OR NEW.owner_totp_verified_at IS NULL
       ) THEN

        RAISE EXCEPTION
            'Owner password and TOTP verification are required for Owner promotion';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER operator_role_change_request_guard
BEFORE INSERT OR UPDATE OF
    requested_by,
    target_account_id,
    requested_role,
    owner_password_verified_at,
    owner_totp_verified_at
ON operator_role_change_requests
FOR EACH ROW EXECUTE FUNCTION validate_operator_role_change_request();

CREATE OR REPLACE FUNCTION guard_direct_operator_role_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    bootstrap_done TIMESTAMPTZ;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.role = 'owner' THEN
            SELECT bootstrap_completed_at
            INTO bootstrap_done
            FROM directory_instance
            WHERE singleton = TRUE;

            IF bootstrap_done IS NOT NULL
               OR EXISTS (
                    SELECT 1
                    FROM operator_accounts
                    WHERE role = 'owner'
                      AND is_active = TRUE
               ) THEN

                RAISE EXCEPTION
                    'Additional Owners must be promoted through an approved role-change request';
            END IF;

            IF NEW.totp_enabled = FALSE
               OR NEW.totp_confirmed_at IS NULL
               OR NEW.must_change_password = TRUE
               OR NEW.password_changed_at IS NULL THEN

                RAISE EXCEPTION
                    'The Creator-Owner must set their own password and TOTP before bootstrap completes';
            END IF;
        END IF;

        RETURN NEW;
    END IF;

    IF NEW.role IS DISTINCT FROM OLD.role
       AND COALESCE(
            current_setting(
                'rustdesk.role_change_authorized',
                TRUE
            ),
            ''
       ) <> '1' THEN

        RAISE EXCEPTION
            'Operator roles may only change through a completed role-change request';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER operator_accounts_role_mutation_guard
BEFORE INSERT OR UPDATE OF role
ON operator_accounts
FOR EACH ROW EXECUTE FUNCTION guard_direct_operator_role_mutation();

CREATE OR REPLACE FUNCTION complete_creator_owner_bootstrap()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.role = 'owner' THEN
        UPDATE directory_instance
        SET creator_owner_id = NEW.id,
            bootstrap_completed_at = NOW()
        WHERE singleton = TRUE
          AND bootstrap_completed_at IS NULL;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER operator_accounts_creator_owner_bootstrap
AFTER INSERT
ON operator_accounts
FOR EACH ROW EXECUTE FUNCTION complete_creator_owner_bootstrap();

CREATE OR REPLACE FUNCTION apply_completed_operator_role_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    completer_role VARCHAR(16);
    completer_active BOOLEAN;
    target_totp_enabled BOOLEAN;
    target_must_change_password BOOLEAN;
    target_active BOOLEAN;
    previous_role VARCHAR(16);
BEGIN
    IF NEW.status = 'completed'
       AND OLD.status IS DISTINCT FROM 'completed' THEN

        SELECT role, is_active
        INTO completer_role, completer_active
        FROM operator_accounts
        WHERE id = NEW.completed_by;

        IF NOT FOUND
           OR completer_active = FALSE
           OR completer_role <> 'owner' THEN

            RAISE EXCEPTION
                'Only an active Owner may complete a role change';
        END IF;

        IF NEW.completed_by = NEW.target_account_id THEN
            RAISE EXCEPTION 'Self-promotion is not allowed';
        END IF;

        SELECT
            role,
            totp_enabled,
            must_change_password,
            is_active
        INTO
            previous_role,
            target_totp_enabled,
            target_must_change_password,
            target_active
        FROM operator_accounts
        WHERE id = NEW.target_account_id;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'Target operator account does not exist';
        END IF;

        IF target_active = FALSE THEN
            RAISE EXCEPTION
                'Inactive operator accounts cannot receive a role change';
        END IF;

        IF NEW.requested_role = 'owner'
           AND (
                target_totp_enabled = FALSE
                OR target_must_change_password = TRUE
           ) THEN

            RAISE EXCEPTION
                'The new Owner must set their own password and TOTP before promotion';
        END IF;

        PERFORM set_config(
            'rustdesk.role_change_authorized',
            '1',
            TRUE
        );

        UPDATE operator_accounts
        SET role = NEW.requested_role
        WHERE id = NEW.target_account_id;

        INSERT INTO audit_events (
            actor_account_id,
            event_type,
            target_type,
            target_id,
            details
        )
        VALUES (
            NEW.completed_by,
            'operator.role_changed',
            'operator_account',
            NEW.target_account_id,
            jsonb_build_object(
                'request_id',
                NEW.id,
                'old_role',
                previous_role,
                'new_role',
                NEW.requested_role,
                'requested_by',
                NEW.requested_by
            )
        );
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER operator_role_change_apply
AFTER UPDATE OF status
ON operator_role_change_requests
FOR EACH ROW EXECUTE FUNCTION apply_completed_operator_role_change();
