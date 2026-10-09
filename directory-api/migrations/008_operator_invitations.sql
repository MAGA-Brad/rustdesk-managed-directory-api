CREATE TABLE operator_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_account_id UUID REFERENCES operator_accounts(id),
    proposed_username VARCHAR(64),
    proposed_display_name VARCHAR(128),
    requested_role VARCHAR(16) NOT NULL
        CHECK (requested_role IN ('owner', 'approver', 'viewer')),
    token_hash BYTEA NOT NULL UNIQUE,
    created_by UUID NOT NULL REFERENCES operator_accounts(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'accepted', 'revoked', 'expired')),
    accepted_at TIMESTAMPTZ,
    accepted_account_id UUID REFERENCES operator_accounts(id),
    revoked_at TIMESTAMPTZ,
    revoked_by UUID REFERENCES operator_accounts(id),

    CHECK (expires_at > created_at),

    CHECK (
        (target_account_id IS NOT NULL)
        <>
        (proposed_username IS NOT NULL)
    ),

    CHECK (
        target_account_id IS NULL
        OR target_account_id <> created_by
    ),

    CHECK (
        target_account_id IS NULL
        OR accepted_account_id IS NULL
        OR accepted_account_id = target_account_id
    ),

    CHECK (
        (
            status = 'accepted'
            AND accepted_at IS NOT NULL
            AND accepted_account_id IS NOT NULL
        )
        OR
        (
            status <> 'accepted'
            AND accepted_at IS NULL
            AND accepted_account_id IS NULL
        )
    ),

    CHECK (
        (
            status = 'revoked'
            AND revoked_at IS NOT NULL
            AND revoked_by IS NOT NULL
        )
        OR
        (
            status <> 'revoked'
            AND revoked_at IS NULL
            AND revoked_by IS NULL
        )
    )
);

CREATE UNIQUE INDEX operator_invitations_pending_username_uidx
    ON operator_invitations (LOWER(proposed_username))
    WHERE status = 'pending'
      AND proposed_username IS NOT NULL;

CREATE UNIQUE INDEX operator_invitations_pending_target_uidx
    ON operator_invitations (target_account_id)
    WHERE status = 'pending'
      AND target_account_id IS NOT NULL;

CREATE INDEX operator_invitations_expires_at_idx
    ON operator_invitations (expires_at)
    WHERE status = 'pending';
