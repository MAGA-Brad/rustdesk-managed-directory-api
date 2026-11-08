-- Power draw and per-CPU/inlet temperatures of the host, one row per report of its power watcher
-- (every 5 s), for the dashboard's power chart and the Server tab of RDC Mobile Manager. The API
-- writes a row inside internal_host_metrics and prunes rows older than 31 days. Safe to run twice.
CREATE TABLE IF NOT EXISTS host_power_samples (
    hostname text NOT NULL,
    sampled_at timestamptz NOT NULL DEFAULT now(),
    watts real,
    cpu1_c real,
    cpu2_c real,
    inlet_c real,
    PRIMARY KEY (hostname, sampled_at)
);
