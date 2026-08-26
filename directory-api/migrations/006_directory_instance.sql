CREATE TABLE directory_instance (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE
        CHECK (singleton = TRUE),
    instance_id UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    creator_owner_id UUID REFERENCES operator_accounts(id),
    bootstrap_completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
        (creator_owner_id IS NULL AND bootstrap_completed_at IS NULL)
        OR
        (creator_owner_id IS NOT NULL AND bootstrap_completed_at IS NOT NULL)
    )
);

INSERT INTO directory_instance (singleton)
VALUES (TRUE)
ON CONFLICT (singleton) DO NOTHING;
