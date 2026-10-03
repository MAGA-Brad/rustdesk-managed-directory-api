ALTER TABLE device_credentials
    ADD COLUMN credential_serial UUID
        NOT NULL DEFAULT gen_random_uuid();

CREATE UNIQUE INDEX device_credentials_serial_uidx
    ON device_credentials (credential_serial);

CREATE TABLE device_status_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    device_id UUID NOT NULL
        REFERENCES managed_devices(id) ON DELETE CASCADE,

    from_status VARCHAR(16)
        CHECK (
            from_status IS NULL
            OR from_status IN (
                'pending',
                'approved',
                'denied',
                'blocked',
                'revoked'
            )
        ),

    to_status VARCHAR(16) NOT NULL
        CHECK (
            to_status IN (
                'pending',
                'approved',
                'denied',
                'blocked',
                'revoked'
            )
        ),

    changed_by UUID REFERENCES operator_accounts(id),
    reason TEXT,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX device_status_history_device_id_idx
    ON device_status_history (device_id, changed_at DESC);

CREATE OR REPLACE FUNCTION guard_managed_device_status()
RETURNS TRIGGER
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
           OR actor_role NOT IN ('owner', 'approver') THEN

            RAISE EXCEPTION
                'Only active Owner or Approver accounts may change device status';
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

CREATE TRIGGER managed_devices_status_guard
BEFORE INSERT OR UPDATE OF status
ON managed_devices
FOR EACH ROW EXECUTE FUNCTION guard_managed_device_status();

CREATE OR REPLACE FUNCTION record_managed_device_status()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO device_status_history (
            device_id,
            from_status,
            to_status,
            changed_by,
            reason
        )
        VALUES (
            NEW.id,
            NULL,
            NEW.status,
            NEW.status_changed_by,
            NEW.status_reason
        );

    ELSIF NEW.status IS DISTINCT FROM OLD.status THEN
        INSERT INTO device_status_history (
            device_id,
            from_status,
            to_status,
            changed_by,
            reason
        )
        VALUES (
            NEW.id,
            OLD.status,
            NEW.status,
            NEW.status_changed_by,
            NEW.status_reason
        );
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER managed_devices_status_history
AFTER INSERT OR UPDATE OF status
ON managed_devices
FOR EACH ROW EXECUTE FUNCTION record_managed_device_status();

CREATE OR REPLACE FUNCTION enforce_active_device_credential_state()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    current_device_status VARCHAR(16);
BEGIN
    IF NEW.revoked_at IS NULL THEN
        SELECT status
        INTO current_device_status
        FROM managed_devices
        WHERE id = NEW.device_id;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'Managed device does not exist';
        END IF;

        IF current_device_status <> 'approved' THEN
            RAISE EXCEPTION
                'Active credentials may only be issued to approved devices';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER device_credentials_state_guard
BEFORE INSERT OR UPDATE OF revoked_at
ON device_credentials
FOR EACH ROW EXECUTE FUNCTION enforce_active_device_credential_state();
