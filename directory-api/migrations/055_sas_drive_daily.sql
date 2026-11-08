-- SAS drive health history (Brad 2026-10-27): one row per drive per local day, kept for the
-- dashboard's SAS tab trends. Counters are the drive's own lifetime totals as last read that day;
-- temp_min/temp_max span the day. Written by sas_health.record_sas_daily() from the host
-- watcher's 5-minute host-metrics report, when it reports SAS drives. Safe to run twice.
CREATE TABLE IF NOT EXISTS sas_drive_daily (
    serial              text        NOT NULL,
    day                 date        NOT NULL,
    bay                 text,
    vdev                text,
    model               text,
    power_on_hours      integer,
    grown_defects       integer,
    pending_defects     integer,
    read_uncorrected    bigint,
    write_uncorrected   bigint,
    verify_uncorrected  bigint,
    read_delayed        bigint,
    write_delayed       bigint,
    verify_delayed      bigint,
    read_rereads        bigint,
    write_rereads       bigint,
    verify_rereads      bigint,
    read_gb             numeric(14, 3),
    write_gb            numeric(14, 3),
    verify_gb           numeric(14, 3),
    nonmedium_errors    bigint,
    phy_errors          bigint,
    bms_errors          integer,
    start_stop_cycles   integer,
    load_unload_cycles  integer,
    temp_min            smallint,
    temp_max            smallint,
    health_ok           boolean,
    updated_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (serial, day)
);

CREATE INDEX IF NOT EXISTS sas_drive_daily_day ON sas_drive_daily (day);
