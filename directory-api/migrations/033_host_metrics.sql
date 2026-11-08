CREATE TABLE host_metrics (
    hostname TEXT PRIMARY KEY,
    payload JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
