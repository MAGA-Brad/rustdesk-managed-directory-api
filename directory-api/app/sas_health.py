"""SAS drive health for the dashboard's SAS tab (Brad 2026-10-27).

The host's 5-minute health watcher reports each drive's SMART data in its host-metrics
snapshot (SAS_HOSTNAME). SAS drives report more than a pass/fail: a grown defect list,
per-operation error counters, link (PHY) counters,
background media scan results. This module keeps one row per drive per local day in
sas_drive_daily so the tab can trend them, and serves the current values plus that history.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)

# host_metrics key the host's health watcher reports under (server_vitals.HOST_HOSTNAME).
SAS_HOSTNAME = "hypervisor"
# Where a "day" of sas_drive_daily starts and ends: set to your deployment's IANA time zone.
LOCAL_TIMEZONE = "UTC"
HISTORY_MAX_DAYS = 3660
STALE_AFTER_SECONDS = 900

_COLUMNS = (
    "bay", "vdev", "model", "power_on_hours", "grown_defects", "pending_defects",
    "read_uncorrected", "write_uncorrected", "verify_uncorrected",
    "read_delayed", "write_delayed", "verify_delayed",
    "read_rereads", "write_rereads", "verify_rereads",
    "read_gb", "write_gb", "verify_gb",
    "nonmedium_errors", "phy_errors", "bms_errors", "start_stop_cycles", "load_unload_cycles",
)


def _sas_drives(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        drive for drive in metrics.get("drives") or []
        if isinstance(drive, dict) and drive.get("protocol") == "SAS" and drive.get("serial")
        and not drive.get("error")
    ]


def _row(drive: dict[str, Any]) -> dict[str, Any]:
    errors = drive.get("errors") or {}
    row = {
        "bay": drive.get("bay"),
        "vdev": drive.get("zfs_vdev"),
        "model": drive.get("model"),
        "power_on_hours": drive.get("power_on_hours"),
        "grown_defects": drive.get("grown_defects"),
        "pending_defects": drive.get("pending_defects"),
        "nonmedium_errors": drive.get("nonmedium_errors"),
        "phy_errors": drive.get("phy_errors_total"),
        "bms_errors": drive.get("bms_errors"),
        "start_stop_cycles": (drive.get("start_stop") or {}).get("count"),
        "load_unload_cycles": (drive.get("load_unload") or {}).get("count"),
    }
    for operation in ("read", "write", "verify"):
        log = errors.get(operation) or {}
        row[f"{operation}_uncorrected"] = log.get("uncorrected")
        row[f"{operation}_delayed"] = log.get("delayed")
        row[f"{operation}_rereads"] = log.get("rereads")
        row[f"{operation}_gb"] = log.get("gb")
    return row


def record_sas_daily(cursor: Any, metrics: dict[str, Any]) -> None:
    """Upsert today's row per SAS drive; called inside internal_host_metrics' transaction.
    An odd value from a drive must never cost the host-metrics snapshot itself, so the upserts
    run under a savepoint and are dropped (and logged) on any error."""
    drives = _sas_drives(metrics)
    if not drives:
        return
    cursor.execute("SAVEPOINT sas_daily")
    try:
        for drive in drives:
            _upsert(cursor, drive)
    except Exception:
        cursor.execute("ROLLBACK TO SAVEPOINT sas_daily")
        logger.exception("sas_drive_daily upsert failed; host snapshot kept")
    else:
        cursor.execute("RELEASE SAVEPOINT sas_daily")


def _upsert(cursor: Any, drive: dict[str, Any]) -> None:
    row = _row(drive)
    temperature = drive.get("temperature_c")
    cursor.execute(
        f"""
        INSERT INTO sas_drive_daily (
            serial, day, {", ".join(_COLUMNS)}, temp_min, temp_max, health_ok, updated_at
        )
        VALUES (
            %s, (now() AT TIME ZONE %s)::date, {", ".join(["%s"] * len(_COLUMNS))}, %s, %s, %s, now()
        )
        ON CONFLICT (serial, day) DO UPDATE SET
            {", ".join(f"{column} = EXCLUDED.{column}" for column in _COLUMNS)},
            temp_min = LEAST(sas_drive_daily.temp_min, EXCLUDED.temp_min),
            temp_max = GREATEST(sas_drive_daily.temp_max, EXCLUDED.temp_max),
            health_ok = sas_drive_daily.health_ok AND EXCLUDED.health_ok,
            updated_at = now()
        """,
        (
            drive["serial"], LOCAL_TIMEZONE, *(row[column] for column in _COLUMNS),
            temperature, temperature, drive.get("smart_passed") is not False,
        ),
    )


def _bay_order(drive: dict[str, Any]) -> tuple[int, str]:
    # By the bay number after the last ":" (bay 9 before bay 10); drives with no bay last
    try:
        return int(str(drive.get("bay")).rsplit(":", 1)[1]), drive.get("serial") or ""
    except (IndexError, ValueError):
        return 10_000, drive.get("serial") or ""


def sas_overview(open_database: Callable[..., Any], days: int) -> dict[str, Any]:
    """Current SAS drives from the latest hypervisor report plus each drive's daily rows for the span."""
    days = max(1, min(int(days), HISTORY_MAX_DAYS))
    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload, updated_at FROM host_metrics WHERE hostname = %s",
                (SAS_HOSTNAME,),
            )
            snapshot = cursor.fetchone()
            cursor.execute(
                f"""
                SELECT serial, day, {", ".join(_COLUMNS)}, temp_min, temp_max, health_ok
                FROM sas_drive_daily
                WHERE day > (now() AT TIME ZONE %s)::date - %s
                ORDER BY serial, day
                """,
                (LOCAL_TIMEZONE, days),
            )
            rows = cursor.fetchall()

    history: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        entry = {key: value for key, value in row.items() if key != "serial"}
        entry["day"] = row["day"].isoformat()
        for key in ("read_gb", "write_gb", "verify_gb"):
            if entry[key] is not None:
                entry[key] = float(entry[key])
        history.setdefault(row["serial"], []).append(entry)

    payload = (snapshot or {}).get("payload") or {}
    updated_at = snapshot["updated_at"] if snapshot else None
    return {
        "now": datetime.now(timezone.utc).isoformat(),
        "days": days,
        "updated_at": updated_at.isoformat() if updated_at else None,
        "stale": updated_at is None
        or (datetime.now(timezone.utc) - updated_at).total_seconds() > STALE_AFTER_SECONDS,
        "drives": sorted(_sas_drives(payload), key=_bay_order),
        "history": history,
    }
