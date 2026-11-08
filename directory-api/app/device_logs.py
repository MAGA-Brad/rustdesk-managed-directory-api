from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
import uuid
from datetime import timedelta
from typing import Any, Callable

from fastapi import Depends, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, ValidationError
from starlette.requests import ClientDisconnect

LOG_UPLOAD_PATH = "/v1/device/log-upload"

# Safety net for a device whose log is never pulled - without this, uploads
# would accumulate on RDS forever. This is a bound on how long the server
# holds an unpulled log, not the expected lifetime: Brad/Claude normally
# pull-and-delete on demand, well inside this window. 365 days, Brad's own
# call (storage can be grown if this is ever actually approached).
LOG_MAX_AGE = timedelta(days=365)
LOG_SWEEP_INTERVAL_SECONDS = 24 * 3600
# Server-side bounds per device: the client gate once failed and one device uploaded ~40 GB.
LOG_UPLOADS_PER_WINDOW = 2
LOG_UPLOAD_WINDOW_SECONDS = 600
LOG_BYTES_KEPT_PER_DEVICE = 200 * 1024 * 1024
# Upload-limit entries kept in memory before stale ones are pruned (the pre-check is keyed by a
# hash of whatever Authorization header arrives, so its keys are caller-controlled).
LOG_UPLOAD_TRACKED_KEYS = 10_000

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
# Keyword, then (checked separately) a ':' or '=' with text after it. One regex with
# `.*[:=]` between them backtracks quadratically on a long line full of keywords and
# no separator, which froze the event loop for hours on a crafted 5 MB upload.
_CHAT_KEYWORD_PATTERN = re.compile(r"\b(chat[_ ]?message|managed_chat)\b", re.IGNORECASE)
_CHAT_VALUE_PATTERN = re.compile(r"[:=]\s*\S")
# "[2026-10-17 17:18:25.495 +00:00] INFO [src\managed_chat.rs:509] " - the source file
# name is not message content and must not trip the keyword check.
_LOG_PREFIX_PATTERN = re.compile(r"^\[[^\]\n]{0,64}\]\s+\w{1,8}\s+\[[^\]\n]{0,256}\]\s?")
# Lines logged from the chat modules themselves: the event text before the first separator
# stays, and what follows it is kept only when it is one short token (an id, a code, a count) -
# free text there is what a body logged by mistake would look like.
_CHAT_SOURCE_PATTERN = re.compile(r"managed_chat", re.IGNORECASE)
_CHAT_SAFE_VALUE_PATTERN = re.compile(r"[:=]\s*[\w.:/@#\-]{0,64}\s*")

_log = logging.getLogger("device_logs")


class LogUploadRequest(BaseModel):
    # The client sends at most 4 x 1 MiB of log text (debug_log.rs MAX_LOG_BYTES per source). JSON
    # escaping (backslashes in Windows paths, CR LF) can double that on the wire, so the route's body
    # cap (security_extension _BodySizeLimit, path_limits) must stay at 12 MiB or more for every
    # upload this model accepts to get here at all.
    log_content: str = Field(min_length=1, max_length=5_000_000)
    client_version: str | None = Field(default=None, max_length=64)
    hardware_info: dict[str, Any] | None = None


def _strip_chat_content(text: str) -> tuple[str, int]:
    redacted_count = 0
    out_lines: list[str] = []
    for line in text.splitlines():
        new_line, hits = _CHAT_FIELD_PATTERN.subn(r'\1"[REDACTED]"', line)
        prefix = _LOG_PREFIX_PATTERN.match(new_line)
        message = new_line[prefix.end():] if prefix else new_line
        keyword = _CHAT_KEYWORD_PATTERN.search(message)
        if keyword and _CHAT_VALUE_PATTERN.search(message, keyword.end()):
            new_line = "[REDACTED: line matched chat-content safety filter]"
            hits += 1
        elif prefix and _CHAT_SOURCE_PATTERN.search(prefix.group(0)):
            separator = _CHAT_VALUE_PATTERN.search(message)
            if separator and not _CHAT_SAFE_VALUE_PATTERN.fullmatch(message, separator.start()):
                new_line = new_line[: prefix.end() + separator.start() + 1] + " [REDACTED]"
                hits += 1
        if hits:
            redacted_count += 1
        out_lines.append(new_line)
    return "\n".join(out_lines), redacted_count


async def _sweep_stale_logs(open_database_handler: Callable[..., Any]) -> None:
    def delete_stale() -> None:
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM device_debug_logs WHERE uploaded_at < now() - %s::interval",
                    (f"{LOG_MAX_AGE.days} days",),
                )
                connection.commit()

    while True:
        await asyncio.sleep(LOG_SWEEP_INTERVAL_SECONDS)
        try:
            # Off the event loop: deleting a year of multi-MB rows can take a while.
            await asyncio.to_thread(delete_stale)
        except Exception:
            _log.exception("device debug log sweep failed")


def _take_upload_slot(uploads: dict[str, list[float]], key: str, now: float) -> bool:
    """Records an upload for key unless it already had LOG_UPLOADS_PER_WINDOW in the window."""
    cutoff = now - LOG_UPLOAD_WINDOW_SECONDS
    if len(uploads) > LOG_UPLOAD_TRACKED_KEYS:
        for stale in [k for k, times in uploads.items() if not times or times[-1] <= cutoff]:
            del uploads[stale]
        if len(uploads) > LOG_UPLOAD_TRACKED_KEYS:
            # A flood of distinct headers: start over (the per-device check still holds).
            uploads.clear()
    window = [t for t in uploads.get(key, []) if t > cutoff]
    if len(window) >= LOG_UPLOADS_PER_WINDOW:
        uploads[key] = window
        return False
    uploads[key] = window + [now]
    return True


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

    recent_uploads: dict[str, list[float]] = {}
    recent_uploads_by_credential: dict[str, list[float]] = {}

    def too_many_uploads() -> HTTPException:
        return HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many log uploads from this device; try again later",
        )

    async def upload_precheck(request: Request) -> None:
        # Before the credential check and before the up-to-5 MB body is read: the same limit,
        # keyed by a hash of the Authorization header (no database work, nothing stored in clear).
        # A request without the header gets its 401 from the credential check, body unread.
        authorization = request.headers.get("authorization")
        if not authorization:
            return
        key = hashlib.sha256(authorization.encode("latin-1", "replace")).hexdigest()
        if not _take_upload_slot(recent_uploads_by_credential, key, time.monotonic()):
            raise too_many_uploads()

    # The body is not a parameter, so FastAPI doesn't read and parse it before the dependencies
    # run: upload_precheck, then the credential, then the per-device limit, and only then the body.
    @app.post(LOG_UPLOAD_PATH)
    async def upload_log(
        request: Request,
        _precheck: None = Depends(upload_precheck),
        device: dict[str, Any] = Depends(require_device_handler),
    ):
        _ensure_sweep_started()
        self_id = device["device_id"]
        if not _take_upload_slot(recent_uploads, str(self_id), time.monotonic()):
            raise too_many_uploads()

        try:
            body = await request.body()
        except ClientDisconnect:
            # Includes a body cut off by the size limit (security_extension _BodySizeLimit).
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="There was an error parsing the body",
            ) from None
        try:
            payload = LogUploadRequest.model_validate_json(body)
        except ValidationError as error:
            # FastAPI's usual 422, without echoing the (possibly multi-MB) input back.
            raise RequestValidationError(
                [
                    {"type": item["type"], "loc": ("body", *item["loc"]), "msg": item["msg"]}
                    for item in error.errors()
                ]
            ) from None

        # Filtering several MB and the INSERT are blocking work; keep them off the single
        # event loop so one upload cannot stall every other RDS request.
        result = await asyncio.to_thread(_store_log, self_id, payload)
        return result

    def _store_log(self_id: Any, payload: LogUploadRequest) -> dict[str, Any]:
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
                # Keep the newest logs up to a per-device byte budget; older ones go first.
                cursor.execute(
                    """
                    DELETE FROM device_debug_logs
                    WHERE id IN (
                        SELECT id FROM (
                            SELECT id, sum(size_bytes) OVER (ORDER BY uploaded_at DESC, id) AS kept
                            FROM device_debug_logs
                            WHERE device_id = %s
                        ) newest_first
                        WHERE kept > %s
                    )
                    """,
                    (self_id, LOG_BYTES_KEPT_PER_DEVICE),
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
