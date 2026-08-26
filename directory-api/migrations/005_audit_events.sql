CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_account_id UUID
        REFERENCES operator_accounts(id),
    event_type VARCHAR(64) NOT NULL,
    target_type VARCHAR(32),
    target_id UUID,
    source_ip INET,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX audit_events_created_at_idx
    ON audit_events (created_at DESC);

CREATE INDEX audit_events_actor_account_id_idx
    ON audit_events (actor_account_id);

CREATE INDEX audit_events_target_idx
    ON audit_events (target_type, target_id);
