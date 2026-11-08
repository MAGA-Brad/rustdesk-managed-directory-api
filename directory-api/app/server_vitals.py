"""Server vitals for the hypervisor host: power/temperature history plus one summary document.

Feeds the Server tab of RDC Mobile Manager and the dashboard's power chart (Brad 2026-10-25).
Everything here reads what the host's watchers already push into host_metrics:
- POWER_HOSTNAME (5 s): power and per-CPU/inlet temperature readings, when the host reports them.
  Each report is also kept as one row in host_power_samples (31 days) for the charts.
- INFRA_HOSTNAME (30 s): guest, network-link and UPS status, running vs newest kernel.
- HOST_HOSTNAME (5 min): the host's drive, storage and hardware health readings.
- BATTERIES_HOSTNAME (1 min): UPS battery status, when a battery monitor reports it.
The health summary comes from health_alert_state, the same conditions that send alert emails.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Callable

# host_metrics keys the hypervisor's watcher scripts report under - must match what those scripts
# send (admin_ui.py's HOST_METRICS_HOSTNAME / POWER_METRICS_HOSTNAME are the same values).
HOST_HOSTNAME = "hypervisor"
POWER_HOSTNAME = "hypervisor-power"
INFRA_HOSTNAME = "hypervisor-infra"
BATTERIES_HOSTNAME = "hypervisor-batteries"
SAMPLE_RETENTION = "31 days"
PRUNE_INTERVAL_SECONDS = 3600
HISTORY_MIN_MINUTES = 5
HISTORY_MAX_MINUTES = 31 * 24 * 60
HISTORY_TARGET_POINTS = 240
# Past these ages a source is shown as stale rather than current.
STALE_AFTER_SECONDS = {POWER_HOSTNAME: 30, INFRA_HOSTNAME: 120, HOST_HOSTNAME: 900, BATTERIES_HOSTNAME: 300}
# A battery whose reads have failed this long shows no values rather than old ones.
BATTERY_READING_MAX_AGE_SECONDS = 600

_last_prune = 0.0


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def record_power_sample(cursor: Any, metrics: dict[str, Any]) -> None:
    """One history row per POWER_HOSTNAME report; called inside internal_host_metrics' transaction."""
    global _last_prune
    temps = {item.get("label"): _number(item.get("c")) for item in metrics.get("temps_c") or [] if isinstance(item, dict)}
    watts = _number(metrics.get("dcmi_instant_watts"))
    if watts is None:
        watts = _number(metrics.get("current_watts"))
    cursor.execute(
        """
        INSERT INTO host_power_samples (hostname, watts, cpu1_c, cpu2_c, inlet_c)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT DO NOTHING
        """,
        (POWER_HOSTNAME, watts, temps.get("CPU 1"), temps.get("CPU 2"), temps.get("Inlet")),
    )
    if time.monotonic() - _last_prune >= PRUNE_INTERVAL_SECONDS:
        _last_prune = time.monotonic()
        cursor.execute(
            f"DELETE FROM host_power_samples WHERE sampled_at < now() - interval '{SAMPLE_RETENTION}'"
        )


def power_history(open_database: Callable[..., Any], minutes: int) -> dict[str, Any]:
    minutes = max(HISTORY_MIN_MINUTES, min(int(minutes), HISTORY_MAX_MINUTES))
    bucket_seconds = max(5, (minutes * 60) // HISTORY_TARGET_POINTS)
    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT date_bin(make_interval(secs => %s), sampled_at, TIMESTAMPTZ '2000-01-01') AS bucket,
                       avg(watts) AS watts, max(watts) AS watts_max,
                       avg(cpu1_c) AS cpu1_c, avg(cpu2_c) AS cpu2_c, avg(inlet_c) AS inlet_c
                FROM host_power_samples
                WHERE hostname = %s AND sampled_at >= now() - make_interval(mins => %s)
                GROUP BY bucket
                ORDER BY bucket
                """,
                (bucket_seconds, POWER_HOSTNAME, minutes),
            )
            rows = cursor.fetchall()

    def rounded(value: Any, digits: int = 1) -> float | None:
        return None if value is None else round(float(value), digits)

    return {
        "minutes": minutes,
        "bucket_seconds": bucket_seconds,
        "now": datetime.now(timezone.utc).isoformat(),
        "points": [
            {
                "t": row["bucket"].isoformat(),
                "watts": rounded(row["watts"], 0),
                "watts_max": rounded(row["watts_max"], 0),
                "cpu1_c": rounded(row["cpu1_c"]),
                "cpu2_c": rounded(row["cpu2_c"]),
                "inlet_c": rounded(row["inlet_c"]),
            }
            for row in rows
        ],
    }


def _snapshot(rows: dict[str, Any], hostname: str) -> tuple[dict[str, Any], str | None, bool]:
    row = rows.get(hostname)
    if row is None:
        return {}, None, True
    age = (datetime.now(timezone.utc) - row["updated_at"]).total_seconds()
    return row["payload"] or {}, row["updated_at"].isoformat(), age > STALE_AFTER_SECONDS[hostname]


def _health_items(sweep: dict[str, Any]) -> list[dict[str, Any]]:
    bmc = sweep.get("bmc") or {}
    drives = [d for d in sweep.get("drives") or [] if isinstance(d, dict)]
    items: list[dict[str, Any]] = []

    def add(label: str, value: str, ok: bool | None) -> None:
        items.append({"label": label, "value": value, "ok": ok})

    for key, label in (("power_supplies_status", "Power supplies"), ("fans_status", "Fans")):
        value = bmc.get(key)
        if value:
            # The BMC's redundancy status, as its own text; anything but full redundancy is flagged.
            add(label, value, value == "Fully Redundant")
    for controller in sweep.get("raid_controllers") or []:
        drives_ok = controller.get("physical_drives_ok")
        reported = controller.get("physical_drives_reported")
        add(
            "RAID controller",
            f"{controller.get('status')} · {drives_ok}/{reported} drives OK",
            controller.get("status") == "OK" and drives_ok == reported,
        )
    for pool in sweep.get("zfs_pools") or []:
        errors = sum(int(pool.get(k) or 0) for k in ("read_errors", "write_errors", "checksum_errors"))
        add(f"ZFS {pool.get('name')}", f"{pool.get('health')} · {errors} errors", pool.get("health") == "ONLINE" and errors == 0)
    smart = [d for d in drives if d.get("smart_passed") is not None]
    if smart:
        passed = sum(1 for d in smart if d.get("smart_passed"))
        add("SMART", f"{passed}/{len(smart)} drives passed", passed == len(smart))
    wear = [d for d in drives if _number(d.get("wear_used_percent")) is not None]
    if wear:
        worst = max(wear, key=lambda d: _number(d.get("wear_used_percent")) or 0)
        percent = _number(worst.get("wear_used_percent")) or 0
        add("Worst SSD wear", f"{percent:.0f}% ({worst.get('device')})", percent < 50)
    amp = [d for d in drives if _number(d.get("write_amp")) is not None]
    if amp:
        worst_amp = max(amp, key=lambda d: _number(d.get("write_amp")) or 0)
        factor = _number(worst_amp.get("write_amp")) or 0
        add("Worst write amplification", f"{factor:.1f}× ({worst_amp.get('device')})", factor < 6)
    sas = [d for d in drives if d.get("protocol") == "SAS" and not d.get("error")]
    if sas:
        healthy = sum(1 for d in sas if d.get("smart_passed") is not False)
        defects = sum(int(_number(d.get("grown_defects")) or 0) for d in sas)
        uncorrected = sum(int(_number(d.get("uncorrected_total")) or 0) for d in sas)
        value = f"{healthy}/{len(sas)} healthy · {defects} grown defects"
        if uncorrected:
            value += f" · {uncorrected} uncorrected"
        add("SAS drives", value, healthy == len(sas))
    temps = [d for d in drives if _number(d.get("temperature_c")) is not None]
    if temps:
        hottest = max(temps, key=lambda d: _number(d.get("temperature_c")) or 0)
        celsius = _number(hottest.get("temperature_c")) or 0
        items.append({"label": "Hottest drive", "value": f"{hottest.get('device')}", "celsius": celsius, "ok": celsius < 55})
    sel = sweep.get("sel") or {}
    if sel.get("percent_used") is not None:
        add("BMC event log", f"{sel.get('percent_used')}% full", int(sel.get("percent_used") or 0) < 90)
    mapped_out = sweep.get("mapped_out_dimms")
    memory_errors = sweep.get("memory_errors")
    if isinstance(mapped_out, dict) and mapped_out.get("reachable"):
        count = len(mapped_out.get("mapped_out") or [])
        uncorrectable = int((memory_errors or {}).get("total_ue_count") or 0)
        value = "All in use" if count == 0 else f"{count} mapped out"
        if uncorrectable:
            value += f" · {uncorrectable} uncorrectable"
        add("Memory", value, count == 0 and uncorrectable == 0)
    return items


def _battery_items(metrics: dict[str, Any], stale: bool) -> list[dict[str, Any]]:
    """One Health row per UPS battery. The app draws these rows without knowing what they are."""
    items: list[dict[str, Any]] = []
    for battery in metrics.get("batteries") or []:
        if not isinstance(battery, dict):
            continue
        label = str(battery.get("name") or battery.get("id") or "Battery")
        values = [_number(battery.get(key)) for key in ("soc", "ah", "full_ah", "volts", "amps", "age_seconds")]
        if stale or not battery.get("read") or None in values or values[5] > BATTERY_READING_MAX_AGE_SECONDS:
            items.append({"label": label, "value": "No recent reading", "ok": None})
            continue
        soc, ah, full_ah, volts, amps, _ = values
        parts = [f"{soc:.0f}%", f"{ah:.0f}/{full_ah:.0f} Ah", f"{volts:.2f} V", f"{amps:+.1f} A"]
        low, high = _number(battery.get("cell_min")), _number(battery.get("cell_max"))
        if low is not None and high is not None:
            parts.append(f"cells {1000 * (high - low):.0f} mV apart")
        temps = [t for t in (_number(x) for x in battery.get("temps") or []) if t is not None]
        if temps:
            parts.append(f"{max(temps) * 9 / 5 + 32:.0f}°F")
        problems = [str(p) for p in battery.get("problems") or []]
        items.append({"label": label, "value": " · ".join(parts + problems), "ok": not problems})
    return items


def server_summary(open_database: Callable[..., Any]) -> dict[str, Any]:
    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT hostname, payload, updated_at FROM host_metrics WHERE hostname = ANY(%s)",
                (list(STALE_AFTER_SECONDS),),
            )
            rows = {row["hostname"]: row for row in cursor.fetchall()}
            cursor.execute(
                """
                SELECT condition_key, detail, first_active_at
                FROM health_alert_state
                WHERE is_active
                ORDER BY condition_key
                """
            )
            active = cursor.fetchall()
            cursor.execute("SELECT count(*) AS checks FROM health_alert_state")
            checks = cursor.fetchone()["checks"]

    power, power_at, power_stale = _snapshot(rows, POWER_HOSTNAME)
    infra, infra_at, infra_stale = _snapshot(rows, INFRA_HOSTNAME)
    sweep, sweep_at, sweep_stale = _snapshot(rows, HOST_HOSTNAME)
    batteries, _, batteries_stale = _snapshot(rows, BATTERIES_HOSTNAME)
    host = sweep.get("host") or {}
    kernel = infra.get("kernel") or {}
    watts_now = _number(power.get("dcmi_instant_watts"))

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "power": {
            "watts": watts_now if watts_now is not None else _number(power.get("current_watts")),
            "avg5_watts": _number(power.get("dcmi_average_watts")),
            "temps_c": power.get("temps_c") or [],
            "updated_at": power_at,
            "stale": power_stale,
        },
        "energy": {
            key: power.get(key)
            for key in ("month_key", "month_kwh", "month_cost_usd", "all_time_kwh", "all_time_cost_usd", "rate_per_kwh")
        },
        "ups": infra.get("ups") or [],
        "health": {
            "ok": not active,
            "checks": checks,
            "active": [
                {
                    "key": row["condition_key"],
                    "detail": row["detail"],
                    "since": row["first_active_at"].isoformat() if row["first_active_at"] else None,
                }
                for row in active
            ],
            "items": _health_items(sweep) + _battery_items(batteries, batteries_stale),
            "updated_at": sweep_at,
            "stale": sweep_stale,
        },
        "host": {
            "load_average": host.get("load_average"),
            "cpu_count": host.get("cpu_count"),
            "memory_used_bytes": host.get("memory_used_bytes"),
            "memory_total_bytes": host.get("memory_total_bytes"),
            "uptime_seconds": host.get("uptime_seconds"),
            "hypervisor_version": host.get("hypervisor_version"),
            "pending_updates": host.get("pending_updates"),
            "kernel_running": kernel.get("running") or host.get("kernel_version"),
            "kernel_newest": kernel.get("newest_installed"),
            "reboot_required": bool(
                host.get("reboot_required") or kernel.get("reboot_for_kernel") or kernel.get("reboot_required_file")
            ),
            "updated_at": sweep_at,
            "stale": sweep_stale,
        },
        "vms": infra.get("vms") or [],
        "wan": infra.get("wan") or {},
        "infra_updated_at": infra_at,
        "infra_stale": infra_stale,
        "infra_errors": infra.get("errors") or {},
    }
