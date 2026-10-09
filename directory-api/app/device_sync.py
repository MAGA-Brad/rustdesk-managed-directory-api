"""Change-driven sync for managed clients: instead of polling the directory, RustDrop and updates on
timers, a client learns that something changed and only then fetches it.

- Every heartbeat reply carries `versions` - short fingerprints of what the device may need to
  refetch. The client compares them with what it holds; this alone catches every change within one
  heartbeat interval and works on any network (it is part of the ordinary, sealed heartbeat).
- `POST /v1/device/wait` is held open (up to WAIT_MAX_SECONDS, under Cloudflare's 100 s limit) and
  answers the moment a version differs from the client's `known` copy, so changes arrive within
  seconds. It is an ordinary sealed call too, and if it fails the heartbeat versions still apply.

Version keys: directory (any change to what /v1/directory shows), build (latest release for the
device's arch/channel), drops (RustDrop activity involving the device), log (a debug log is
requested), status (the device's approval status).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from fastapi import Depends

WAIT_PATH = "/v1/device/wait"
WAIT_MAX_SECONDS = 50
WAIT_CHECK_SECONDS = 2.0
DIRECTORY_FINGERPRINT_TTL = 2.0


def directory_etag(payload: dict[str, Any]) -> str:
    """Per-device directory version: everything a client shows, minus what changes every request
    (generated_at) or every heartbeat without meaning anything (an online peer's last_seen_at)."""
    stable = {key: value for key, value in payload.items() if key != "generated_at"}
    stable["devices"] = [
        {key: value for key, value in device.items() if not (key == "last_seen_at" and device.get("online"))}
        for device in payload.get("devices") or []
    ]
    digest = hashlib.sha256(json.dumps(stable, sort_keys=True, default=str).encode()).hexdigest()
    return f'"{digest[:32]}"'


def register_device_sync(
    *,
    app: Any,
    open_database_handler: Callable[..., Any],
    require_device_handler: Callable[..., dict[str, Any]],
    manifests_dir: Path,
    presence_timeout_seconds: Callable[[], int],
) -> Callable[..., dict[str, Any]]:
    directory_cache: dict[str, Any] = {"value": "", "at": 0.0}
    manifest_cache: dict[str, Any] = {"stamp": None, "builds": {}}

    def _directory_fingerprint(cursor) -> str:
        # One fingerprint for the whole directory, shared by every device for a couple of
        # seconds: membership, names, keys, online state, sessions and the settings it carries.
        if time.monotonic() - directory_cache["at"] < DIRECTORY_FINGERPRINT_TTL:
            return directory_cache["value"]
        cursor.execute(
            """
            SELECT left(md5(
                coalesce((
                    SELECT string_agg(concat_ws(',', a.id, a.rustdesk_id, a.display_name, a.hostname,
                               md5(coalesce(encode(m.device_public_key, 'base64'), '')),
                               (a.last_seen_at IS NOT NULL AND a.last_seen_at >= now() - make_interval(secs => %s))),
                           '|' ORDER BY a.id)
                    FROM approved_device_directory a JOIN managed_devices m ON m.id = a.id
                ), '')
                || '#' || coalesce((
                    SELECT string_agg(concat_ws(',', s.reporting_device_id, s.peer_rustdesk_id), '|'
                           ORDER BY s.reporting_device_id, s.peer_rustdesk_id)
                    FROM device_active_sessions s
                    WHERE s.ended_at IS NULL AND s.last_heartbeat_at >= now() - make_interval(secs => %s)
                ), '')
                || '#' || coalesce((
                    SELECT string_agg(setting_key || '=' || setting_value::text, ',' ORDER BY setting_key)
                    FROM directory_settings
                ), '')
            ), 12) AS fingerprint
            """,
            (presence_timeout_seconds(), presence_timeout_seconds()),
        )
        directory_cache["value"] = cursor.fetchone()["fingerprint"]
        directory_cache["at"] = time.monotonic()
        return directory_cache["value"]

    def _latest_builds() -> dict[tuple[str, str], int]:
        paths = sorted(manifests_dir.glob("*.json"))
        stamp = tuple((path.name, path.stat().st_mtime_ns) for path in paths)
        if stamp != manifest_cache["stamp"]:
            builds: dict[tuple[str, str], int] = {}
            for path in paths:
                try:
                    manifest = json.loads(path.read_text(encoding="utf-8"))
                    builds[(str(manifest.get("channel")), str(manifest.get("arch")))] = int(manifest.get("build_number") or 0)
                except (OSError, ValueError, TypeError):
                    continue
            manifest_cache.update(stamp=stamp, builds=builds)
        return manifest_cache["builds"]

    def versions_for(device_id: uuid.UUID, arch: str | None, channel: str | None) -> dict[str, Any]:
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                directory = _directory_fingerprint(cursor)
                cursor.execute(
                    """
                    SELECT d.status,
                           d.debug_log_requested_at IS NOT NULL AS log_requested,
                           (SELECT coalesce(floor(extract(epoch FROM max(greatest(f.created_at, f.updated_at))) * 1000)::bigint, 0)
                            FROM filedrop_drops f
                            WHERE f.sender_device_id = d.id OR f.recipient_device_id = d.id) AS drops
                    FROM managed_devices d WHERE d.id = %s
                    """,
                    (device_id,),
                )
                row = cursor.fetchone()
        return {
            "directory": directory,
            "build": _latest_builds().get((channel or "stable", arch or "x86_64"), 0),
            "drops": int(row["drops"]) if row else 0,
            "log": bool(row["log_requested"]) if row else False,
            "status": row["status"] if row else "unknown",
        }

    @app.post(WAIT_PATH, include_in_schema=False)
    async def wait_for_change(payload: dict[str, Any], device: dict[str, Any] = Depends(require_device_handler)):
        known = payload.get("known") if isinstance(payload.get("known"), dict) else {}
        arch = str(payload.get("arch") or "") or None
        channel = str(payload.get("channel") or "") or None
        try:
            wait_seconds = min(max(float(payload.get("wait_seconds") or WAIT_MAX_SECONDS), 0.0), WAIT_MAX_SECONDS)
        except (TypeError, ValueError):
            wait_seconds = WAIT_MAX_SECONDS
        deadline = time.monotonic() + wait_seconds
        while True:
            versions = await asyncio.to_thread(versions_for, device["device_id"], arch, channel)
            changed = [key for key in known if key in versions and known[key] != versions[key]]
            # A client with nothing to compare yet (its first call) gets the versions right away.
            if changed or not known or time.monotonic() >= deadline:
                return {"changed": changed, "versions": versions}
            await asyncio.sleep(min(WAIT_CHECK_SECONDS, max(deadline - time.monotonic(), 0.0)))

    return versions_for
