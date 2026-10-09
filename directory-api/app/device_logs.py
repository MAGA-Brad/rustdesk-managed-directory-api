from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from datetime import timedelta
from typing import Any, Callable

from fastapi import Depends, HTTPException, status
from pydantic import BaseModel, Field

LOG_UPLOAD_PATH = "/v1/device/log-upload"

# Safety net for a device whose log is never pulled - without this, uploads
# would accumulate on RDS forever. This is a bound on how long the server
# holds an unpulled log, not the expected lifetime: Brad/Claude normally
# pull-and-delete on demand, well inside this window. 365 days, Brad's own
# call (storage can be grown if this is ever actually approached).
LOG_MAX_AGE = timedelta(days=365)
LOG_SWEEP_INTERVAL_SECONDS = 24 * 3600

# Server-side defense-in-depth, not the primary control: the client's log
# file is built entirely from status/event log lines and is confirmed to
# never include chat message bodies at the source (managed_chat.rs /
# managed_chat_store.rs on the client only ever logs event descriptions).
# This exists solely to catch a future regression there before it reaches
# storage - redacts anything shaped like a JSON message-body field, and any
# line naming the chat module alongside what looks like free text.
_CHAT_FIELD_PATTERN = re.compile(
    r'("(?:body|message_body|chat_body|message_text)"\s*:\s*)"(?:[^"\\]|\\.)*"',
    re.IGNORECASE,
)
_CHAT_LINE_PATTERN = re.compile(
    r"\b(chat[_ ]?message|managed_chat)\b.*[:=]\s*\S+", re.IGNORECASE
)

_log = logging.getLogger("device_logs")


class LogUploadRequest(BaseModel):
    log_content: str = Field(min_length=1, max_length=5_000_000)
    client_version: str | None = Field(default=None, max_length=64)
    hardware_info: dict[str, Any] | None = None


def _strip_chat_content(text: str) -> tuple[str, int]:
    redacted_count = 0
    out_lines: list[str] = []
    for line in text.splitlines():
        new_line, hits = _CHAT_FIELD_PATTERN.subn(r'\1"[REDACTED]"', line)
        if _CHAT_LINE_PATTERN.search(new_line):
            new_line = "[REDACTED: line matched chat-content safety filter]"
            hits += 1
        if hits:
            redacted_count += 1
        out_lines.append(new_line)
    return "\n".join(out_lines), redacted_count


async def _sweep_stale_logs(open_database_handler: Callable[..., Any]) -> None:
    while True:
        await asyncio.sleep(LOG_SWEEP_INTERVAL_SECONDS)
        try:
            with open_database_handler() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM device_debug_logs WHERE uploaded_at < now() - %s::interval",
                        (f"{LOG_MAX_AGE.days} days",),
                    )
                    connection.commit()
        except Exception:
            _log.exception("device debug log sweep failed")


def register_device_log_routes(
    *,
    app: Any,
    require_device_handler: Callable[..., dict[str, Any]],
    require_admin_cookie_brad_only_handler: Callable[..., dict[str, Any]],
    open_database_handler: Callable[..., Any],
) -> None:
    # Lazily started on first upload, matching managed_chat.py's sweep - this
    # FastAPI app has no startup/lifespan hook, and asyncio.create_task needs
    # a running loop that plain module-import time doesn't have.
    _sweep_started = False

    def _ensure_sweep_started() -> None:
        nonlocal _sweep_started
        if not _sweep_started:
            _sweep_started = True
            asyncio.create_task(_sweep_stale_logs(open_database_handler))

    @app.post(LOG_UPLOAD_PATH)
    async def upload_log(
        payload: LogUploadRequest,
        device: dict[str, Any] = Depends(require_device_handler),
    ):
        _ensure_sweep_started()
        self_id = device["device_id"]

        cleaned, redacted_count = _strip_chat_content(payload.log_content)
        size_bytes = len(cleaned.encode("utf-8"))

        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO device_debug_logs
                        (device_id, client_version, hardware_info, log_content, size_bytes, redacted_line_count)
                    VALUES (%s, %s, %s::jsonb, %s, %s, %s)
                    RETURNING id, uploaded_at
                    """,
                    (
                        self_id,
                        payload.client_version,
                        json.dumps(payload.hardware_info or {}),
                        cleaned,
                        size_bytes,
                        redacted_count,
                    ),
                )
                row = cursor.fetchone()

                # A fresh upload always satisfies any outstanding request,
                # regardless of whether this was that requested upload or
                # just the device's normal scheduled one - either way there
                # is nothing left to ask for.
                cursor.execute(
                    "UPDATE managed_devices SET debug_log_requested_at = NULL WHERE id = %s",
                    (self_id,),
                )
                connection.commit()

        return {"id": str(row["id"]), "uploaded_at": row["uploaded_at"].isoformat()}

    # Status-only view for the future Client Management -> Details popup:
    # deliberately no delete route anywhere in this module. Pulling and
    # deleting logs is Claude's own job, done directly against Postgres over
    # SSH when Brad asks - never exposed as an HTTP endpoint at all, so
    # there is no delete surface for the admin UI to accidentally grow one
    # onto later.
    @app.get("/ops/api/devices/{device_id}/logs")
    def list_device_logs(
        device_id: uuid.UUID,
        operator: dict[str, Any] = Depends(require_admin_cookie_brad_only_handler),
    ):
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, uploaded_at, client_version, hardware_info,
                           size_bytes, redacted_line_count
                    FROM device_debug_logs
                    WHERE device_id = %s
                    ORDER BY uploaded_at DESC
                    """,
                    (device_id,),
                )
                rows = cursor.fetchall()

        return {
            "logs": [
                {
                    "id": str(row["id"]),
                    "uploaded_at": row["uploaded_at"].isoformat(),
                    "client_version": row["client_version"],
                    "hardware_info": row["hardware_info"],
                    "size_bytes": row["size_bytes"],
                    "redacted_line_count": row["redacted_line_count"],
                }
                for row in rows
            ]
        }

    # Lets Brad (or Claude, on his behalf) ask a specific device for a fresh
    # log the moment a user reports a problem, instead of waiting for its
    # next scheduled upload. Surfaced to the client via device_heartbeat's
    # response (see main.py) - flips on there, flips off automatically the
    # next time any log from this device lands (in upload_log above), so a
    # missed/dropped heartbeat can't lose the request.
    @app.post("/ops/api/devices/{device_id}/logs/request")
    def request_device_log(
        device_id: uuid.UUID,
        operator: dict[str, Any] = Depends(require_admin_cookie_brad_only_handler),
    ):
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE managed_devices SET debug_log_requested_at = NOW() WHERE id = %s RETURNING id",
                    (device_id,),
                )
                updated = cursor.fetchone()
                connection.commit()

        if updated is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found",
            )

        return {"requested": True}

    # One-click fleet-wide version of the single-device request above, for
    # exactly this situation: a new build just published and Brad wants
    # fresh build-number confirmation from everyone without waiting on each
    # device's independent hourly upload cadence (debug_log.rs's
    # MIN_UPLOAD_INTERVAL) or clicking "Request log" one device at a time.
    # Scoped to approved devices only - pending/denied/blocked/revoked
    # devices never run the approved-cycle heartbeat loop that checks
    # debug_log_requested_at, so requesting from them would silently do
    # nothing.
    #
    # Deliberately NOT under /ops/api/devices/... : admin_ui.py's
    # register_admin_routes() registers a generic
    # POST /ops/api/devices/{device_id}/{action} (approve/deny/block/
    # revoke/delete, with a required JSON body) that is registered before
    # this module runs and matches ANY path shaped devices/<seg>/<seg> -
    # including devices/logs/request-all, which the first version of this
    # route used. Starlette picks the first full path match in
    # registration order regardless of specificity, so that generic route
    # silently won every time, failing device_id="logs" as a UUID and the
    # missing body as a second error - a 422 with two errors, which the
    # dashboard's error toast rendered as "[object Object],[object
    # Object]". The single-device route above is unaffected (6 path
    # segments vs. the generic route's 5), only this one needed to move.
    @app.post("/ops/api/device-logs/request-all")
    def request_all_device_logs(
        operator: dict[str, Any] = Depends(require_admin_cookie_brad_only_handler),
    ):
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE managed_devices SET debug_log_requested_at = NOW() "
                    "WHERE status = 'approved' RETURNING id"
                )
                updated = cursor.fetchall()
                connection.commit()

        return {"requested": True, "device_count": len(updated)}
