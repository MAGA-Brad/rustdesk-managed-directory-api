ALTER TABLE audit_events
    ADD CONSTRAINT audit_events_event_type_not_blank
        CHECK (BTRIM(event_type) <> ''),

    ADD CONSTRAINT audit_events_target_pair_check
        CHECK (
            (target_type IS NULL AND target_id IS NULL)
            OR
            (target_type IS NOT NULL AND target_id IS NOT NULL)
        );

CREATE OR REPLACE FUNCTION deny_audit_event_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Audit events are append-only';
END;
$$;

CREATE TRIGGER audit_events_no_update_delete
BEFORE UPDATE OR DELETE
ON audit_events
FOR EACH ROW EXECUTE FUNCTION deny_audit_event_mutation();

CREATE TRIGGER audit_events_no_truncate
BEFORE TRUNCATE
ON audit_events
FOR EACH STATEMENT EXECUTE FUNCTION deny_audit_event_mutation();
