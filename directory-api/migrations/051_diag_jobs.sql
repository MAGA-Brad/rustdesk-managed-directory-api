-- Signed diagnostic scripts for build 38+ RDC clients (Brad 2026-10-14): posted on the RDS host
-- by rdc-diag-post (signed there with a root-only key), announced in the device heartbeat, run by
-- the client's service, and answered with the script's output.
CREATE TABLE IF NOT EXISTS diag_jobs (
    id uuid PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
    script text NOT NULL,
    script_sha256 text NOT NULL,
    timeout_s integer NOT NULL,
    expires_at timestamptz NOT NULL,
    signature text NOT NULL,
    note text,
    created_at timestamptz NOT NULL DEFAULT now(),
    fetched_at timestamptz,
    result_at timestamptz,
    exit_code integer,
    timed_out boolean,
    duration_ms bigint,
    output text,
    client_error text
);

CREATE INDEX IF NOT EXISTS diag_jobs_pending_idx ON diag_jobs (device_id) WHERE result_at IS NULL;
