-- 043: sealed transport (application-layer end-to-end encryption for managed-client API calls)
-- and the inspected-network policy that gates it.
CREATE TABLE IF NOT EXISTS sealed_replay (
    eph_hash bytea PRIMARY KEY,
    seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sealed_replay_seen_at_idx ON sealed_replay (seen_at);

ALTER TABLE managed_devices ADD COLUMN IF NOT EXISTS inspected_network_policy text NOT NULL DEFAULT 'auto';
ALTER TABLE managed_devices DROP CONSTRAINT IF EXISTS managed_devices_inspected_network_policy_check;
ALTER TABLE managed_devices ADD CONSTRAINT managed_devices_inspected_network_policy_check
    CHECK (inspected_network_policy IN ('auto', 'strict'));
ALTER TABLE managed_devices ADD COLUMN IF NOT EXISTS sealed_last_at timestamptz;
ALTER TABLE managed_devices ADD COLUMN IF NOT EXISTS sealed_last_inspected_at timestamptz;

CREATE TABLE IF NOT EXISTS inspection_networks (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    cidr cidr NOT NULL UNIQUE,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied')),
    classification text CHECK (classification IN ('school', 'hospital', 'government')),
    evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
    rdap_org text,
    rdap_network text,
    rdap_netblock cidr,
    rdap_country text,
    ptr_name text,
    ptr_confirmed boolean,
    inspector_issuer text,
    inspector_subject text,
    inspector_ca_key_id text,
    decided_by text,
    decided_at timestamptz,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    classified_at timestamptz,
    bootstrap_requests bigint NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS inspection_observations (
    network_id uuid NOT NULL REFERENCES inspection_networks(id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
    egress_ip inet NOT NULL,
    inspector_issuer text,
    inspector_ca_key_id text,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    request_count bigint NOT NULL DEFAULT 0,
    last_decision text,
    last_alert_at timestamptz,
    PRIMARY KEY (network_id, device_id)
);
