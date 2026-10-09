from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import timedelta
from typing import Any, AsyncIterator, Callable

import httpx
from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field

FILEDROP_PATH = "/v1/filedrop"

# A device only appears in the send-to picker if it has registered RustDrop
# (called /register at least once) within this window - a staleness bound,
# not live presence, since store-and-forward means the recipient does not
# need to be online when a drop is sent. See rustdrop_architecture doc,
# section 03/09.
REGISTRATION_STALE_AFTER = timedelta(days=30)

# All of the settings below are owner-configurable via directory_settings
# (dotted `rustdrop.*` namespace, same convention as the original TTL
# setting) - see _get_int_setting()/_get_ttl_hours() below. Each *_FALLBACK
# constant is only used if that row is somehow missing (fresh install
# before seeding, or a manually deleted row), not the live default in
# normal operation once a row exists.
DROP_DEFAULT_TTL_HOURS_FALLBACK = 24
TTL_SETTING_KEY = "rustdrop.default_ttl_hours"
# Sanity bounds for what an Owner can set it to - a minute isn't a
# meaningful hold window and a year isn't "temporary" storage anymore.
TTL_MIN_HOURS = 1
TTL_MAX_HOURS = 24 * 30

# Backstop for a drop whose sender vanished mid-upload and never reached
# 'complete' (so never got a real expires_at) - without this it would sit
# forever. Deliberately much longer than the default TTL.
DROP_STUCK_UPLOAD_MAX_AGE_DAYS_FALLBACK = 7
STUCK_UPLOAD_BACKSTOP_SETTING_KEY = "rustdrop.stuck_upload_backstop_days"

# Kept short on purpose: TTL_MIN_HOURS is 1 hour, so a coarse poll here
# could nearly double a short-TTL drop's real lifetime before it actually
# gets swept. A cheap SELECT/DELETE against a small-scale directory DB
# every minute is negligible load.
DROP_SWEEP_INTERVAL_SECONDS_FALLBACK = 60
SWEEP_INTERVAL_SETTING_KEY = "rustdrop.sweep_interval_seconds"

# Hardening checklist item 03 (rustdrop_architecture doc, section 07): cap
# declared size and the running total actually streamed, so a sender lying
# about size can't trigger a disk-fill on the storage VM. This is a policy
# ceiling per file, not a technical one.
MAX_DROP_SIZE_BYTES_FALLBACK = 10 * 1024**3  # 10 GiB
MAX_DROP_SIZE_SETTING_KEY = "rustdrop.max_drop_size_bytes"

# Resumable-transfer tuning (client-facing - see GET {FILEDROP_PATH}/config
# below and rustdrop_transfer.rs's resumable-transport redesign). 8MiB
# balances per-part overhead against how much unconfirmed data a failed
# part throws away; 100kbit/s is the throughput floor below which a part
# can never complete inside its own timeout (client-computed as
# part_size/floor, not a separately stored number).
PART_SIZE_BYTES_FALLBACK = 8 * 1024 * 1024
PART_SIZE_SETTING_KEY = "rustdrop.part_size_bytes"
# A part must fit through Cloudflare's per-request body limit (100 MB on most plans): transfers fall back
# to the Cloudflare-fronted host when the direct filedrop host is unreachable.
PART_SIZE_BYTES_MAX = 90 * 1024 * 1024
MIN_THROUGHPUT_BPS_FALLBACK = 100_000
MIN_THROUGHPUT_SETTING_KEY = "rustdrop.min_throughput_bps"
STALL_GIVEUP_MINUTES_FALLBACK = 30
STALL_GIVEUP_SETTING_KEY = "rustdrop.stall_giveup_minutes"

# RDS<->storage VM is a local, fast LAN hop - this only needs to be generous
# enough to never clip a slow *client* upload feeding the relay (the read
# side of _bounded_request_stream reads at whatever rate the client sends),
# not to accommodate the storage VM itself being slow. The legacy single-shot path
# below still uses timeout=None (true "however long it needs"), unchanged.
PART_RELAY_TIMEOUT = httpx.Timeout(300.0)

_log = logging.getLogger("rustdrop")


def _storage_base_url() -> str:
    return os.environ["RUSTDROP_STORAGE_BASE_URL"].rstrip("/")


def _storage_auth_header() -> dict[str, str]:
    return {"Authorization": f"Bearer {os.environ['RUSTDROP_STORAGE_SECRET']}"}


def _storage_tls_verify() -> str:
    # The storage VM's cert is self-signed (or issued by a private CA) for
    # a point-to-point internal link that never touches a public
    # CA-trusted path - pin this exact file rather than relying on the
    # system trust store, same reason a plain `verify=True` wouldn't
    # validate a self-signed leaf at all and would over-trust a CA-issued
    # one for a connection this narrow.
    return os.environ["RUSTDROP_STORAGE_CERT_PATH"]


def _get_ttl_hours(cursor) -> float:
    cursor.execute(
        "SELECT setting_value FROM directory_settings WHERE setting_key = %s",
        (TTL_SETTING_KEY,),
    )
    row = cursor.fetchone()
    if row is None:
        return DROP_DEFAULT_TTL_HOURS_FALLBACK
    return float(row["setting_value"])


def _get_int_setting(cursor, key: str, fallback: int) -> int:
    cursor.execute(
        "SELECT setting_value FROM directory_settings WHERE setting_key = %s",
        (key,),
    )
    row = cursor.fetchone()
    if row is None:
        return fallback
    return int(row["setting_value"])


class RustdropSettingsRequest(BaseModel):
    # Every field optional and independently upserted (see
    # set_filedrop_settings) - the Config page's Save button only sends
    # whichever fields actually changed.
    ttl_hours: float | None = Field(default=None, ge=TTL_MIN_HOURS, le=TTL_MAX_HOURS)
    sweep_interval_seconds: int | None = Field(default=None, ge=30, le=3600)
    stuck_upload_backstop_days: int | None = Field(default=None, ge=1, le=30)
    max_drop_size_bytes: int | None = Field(default=None, ge=1 * 1024**3, le=50 * 1024**3)
    part_size_bytes: int | None = Field(default=None, ge=1 * 1024 * 1024, le=PART_SIZE_BYTES_MAX)
    min_throughput_bps: int | None = Field(default=None, ge=10_000, le=2_000_000)
    stall_giveup_minutes: int | None = Field(default=None, ge=5, le=120)


# Raw X25519 public keys are exactly 32 bytes -> 44 base64 chars with
# padding. Bounded generously rather than exact-matched here; the actual
# cryptographic validity only matters to the two clients doing the ECDH,
# never to RDS, which just stores and echoes this back opaquely.
PUBLIC_KEY_MAX_LEN = 128


class RegisterDeviceRequest(BaseModel):
    # Sent on every call (cheap, idempotent) rather than only at first
    # registration, so a device's key rotates cleanly if its local keystore
    # is ever regenerated - no separate "update my key" endpoint needed.
    public_key: str = Field(min_length=1, max_length=PUBLIC_KEY_MAX_LEN)
    client_version: str | None = Field(default=None, max_length=64)
    # What this client can receive (e.g. "zstd-chunks"); older clients send nothing, so they are
    # only ever sent the original format.
    capabilities: list[str] = Field(default_factory=list, max_length=16)


class CreateDropRequest(BaseModel):
    recipient_device_id: uuid.UUID
    filename: str = Field(min_length=1, max_length=255)
    # No static le= bound here - the live cap is enforced in create_drop()
    # itself against the current directory_settings value (owner-tunable
    # without a redeploy), not something Pydantic can check at class-
    # definition time.
    declared_size: int = Field(ge=0)
    sender_public_key: str = Field(min_length=1, max_length=PUBLIC_KEY_MAX_LEN)


def _serialize_drop(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "sender_device_id": str(row["sender_device_id"]),
        "recipient_device_id": str(row["recipient_device_id"]),
        "filename": row["filename"],
        "declared_size": row["declared_size"],
        "status": row["status"],
        "content_sha256": row.get("content_sha256"),
        "sender_public_key": row.get("sender_public_key"),
        "peer_friendly_name": row.get("peer_friendly_name"),
        "peer_hostname": row.get("peer_hostname"),
        "created_at": row["created_at"].isoformat(),
        "expires_at": row["expires_at"].isoformat() if row["expires_at"] else None,
    }


async def _sweep_expired_drops(open_database_handler: Callable[..., Any]) -> None:
    interval = DROP_SWEEP_INTERVAL_SECONDS_FALLBACK
    while True:
        await asyncio.sleep(interval)
        try:
            with open_database_handler() as connection:
                with connection.cursor() as cursor:
                    # Re-read live each cycle so a Config-page change takes
                    # effect on the next tick without a service restart -
                    # this only affects the *next* sleep duration (the one
                    # that already started can't be shortened), which is
                    # fine given the whole point is bounding worst-case lag,
                    # not instant reaction.
                    interval = _get_int_setting(
                        cursor, SWEEP_INTERVAL_SETTING_KEY, DROP_SWEEP_INTERVAL_SECONDS_FALLBACK
                    )
                    stuck_days = _get_int_setting(
                        cursor, STUCK_UPLOAD_BACKSTOP_SETTING_KEY, DROP_STUCK_UPLOAD_MAX_AGE_DAYS_FALLBACK
                    )
                    cursor.execute(
                        """
                        SELECT id, storage_key FROM filedrop_drops
                        WHERE (expires_at IS NOT NULL AND expires_at < now())
                           OR (status IN ('uploading', 'failed')
                               AND updated_at < now() - %s::interval)
                        """,
                        (f"{stuck_days} days",),
                    )
                    expired = cursor.fetchall()
                    if expired:
                        ids = [row["id"] for row in expired]
                        cursor.execute(
                            "DELETE FROM filedrop_drops WHERE id = ANY(%s::uuid[])",
                            (ids,),
                        )
                        connection.commit()
            for row in expired:
                await _delete_blob(str(row["storage_key"]))
            if expired:
                _log.info("rustdrop sweep removed %d expired drop(s)", len(expired))
        except Exception:
            _log.exception("rustdrop sweep failed")


async def _delete_blob(storage_key: str) -> None:
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=_storage_tls_verify()) as client:
            await client.delete(
                f"{_storage_base_url()}/blobs/{storage_key}",
                headers=_storage_auth_header(),
            )
    except httpx.HTTPError:
        _log.exception("failed to delete blob %s from storage VM", storage_key)


async def _bounded_request_stream(request: Request, limit: int) -> AsyncIterator[bytes]:
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Upload exceeded its declared/allowed size",
            )
        yield chunk


STORAGE_VM_HEALTH_CHECK_INTERVAL_SECONDS = 60
STORAGE_VM_HEALTH_CONDITION_KEY = "storage_vm_connectivity"


async def _watch_storage_vm_health(report_health_event_handler: Callable[..., Any]) -> None:
    # Binary up/down signal, same shape as the existing SMART/ZFS/PSU/NUT
    # checks in the hypervisor host's health-watcher script - any single
    # failed check alerts immediately (the debounce table this reports into
    # already prevents spam from a flapping condition, so no separate
    # consecutive-failure counter is needed here). Runs in-process, since
    # RDS already talks to the storage VM directly for real traffic - no
    # separate host-script watcher needed for this one.
    while True:
        await asyncio.sleep(STORAGE_VM_HEALTH_CHECK_INTERVAL_SECONDS)
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=_storage_tls_verify()) as client:
                response = await client.get(f"{_storage_base_url()}/healthz")
                response.raise_for_status()
            is_active = False
            detail = None
        except (httpx.HTTPError, ValueError) as error:
            is_active = True
            detail = f"RustDrop storage service unreachable: {error}"
        try:
            await asyncio.to_thread(
                report_health_event_handler, STORAGE_VM_HEALTH_CONDITION_KEY, is_active, detail
            )
        except Exception:
            _log.exception("rustdrop: failed to report storage VM health event")


def register_rustdrop_routes(
    *,
    app: Any,
    require_device_handler: Callable[..., dict[str, Any]],
    require_admin_cookie_brad_only_handler: Callable[..., dict[str, Any]],
    open_database_handler: Callable[..., Any],
    report_health_event_handler: Callable[..., Any],
) -> None:
    _sweep_started = False

    def _ensure_sweep_started() -> None:
        nonlocal _sweep_started
        if not _sweep_started:
            _sweep_started = True
            asyncio.create_task(_sweep_expired_drops(open_database_handler))
            asyncio.create_task(_watch_storage_vm_health(report_health_event_handler))

    def _fetch_drop(cursor, drop_id: uuid.UUID) -> dict[str, Any]:
        cursor.execute("SELECT * FROM filedrop_drops WHERE id = %s", (drop_id,))
        row = cursor.fetchone()
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Drop not found"
            )
        return dict(row)

    async def _run_db(fn: Callable[[], Any]) -> Any:
        # psycopg here is synchronous - a plain `with open_database_handler()`
        # call blocks the single asyncio event loop this whole app runs on
        # for however long the round-trip takes. Fine at the call frequency
        # every other endpoint in this file uses (once or twice per user
        # action). NOT fine for upload_drop/download_drop/head_upload_drop,
        # which the resumable-transfer redesign now calls once per PART -
        # hundreds of times for one large file - and each blocking call
        # freezes every other client's heartbeat/directory request for its
        # duration. Confirmed live 2026-09-21: a multi-GB transfer made the
        # whole fleet show "Directory Unavailable" for its duration. Running
        # the blocking call on a thread instead keeps the event loop free to
        # keep serving everyone else while this one drop's DB round-trip
        # happens in the background.
        return await asyncio.to_thread(fn)

    _storage_client: httpx.AsyncClient | None = None

    def _get_storage_client() -> httpx.AsyncClient:
        # Built once, reused for the process lifetime - every call site
        # below used to build its own `async with httpx.AsyncClient(...)`,
        # which tears the connection down at the end of every single
        # request. Harmless at once-or-twice-per-user-action frequency;
        # became the dominant per-part cost once upload_drop/
        # head_upload_drop started getting called once per PART (the
        # resumable-transfer redesign) - a fresh TCP+TLS handshake to
        # the storage VM for every ~8MiB piece. Confirmed live 2026-09-21: a 7.7GB
        # transfer, already carrying the equivalent fix on the RDC client
        # side, still showed a near-perfectly-flat ~250ms/part latency -
        # far more consistent with a repeated handshake than genuine
        # transfer time for 8MiB over LAN. Per-call timeout is still
        # passed explicitly at each call site below (this client itself
        # carries no default), so behavior otherwise matches exactly.
        nonlocal _storage_client
        if _storage_client is None:
            _storage_client = httpx.AsyncClient(verify=_storage_tls_verify())
        return _storage_client

    def _reset_storage_client() -> None:
        # Called from every relay except-branch below on a genuine
        # connect/TLS-level failure (not a plain 4xx/5xx from the storage VM
        # itself, which doesn't indicate anything wrong with the client).
        # Without this, a single storage-VM cert rotation or a wedged connection pool
        # broke every device's every upload/download/head permanently until
        # the whole RDS process was restarted - the client was never given a
        # chance to reconnect on its own.
        nonlocal _storage_client
        _storage_client = None

    @app.post(f"{FILEDROP_PATH}/register")
    async def register_device(
        payload: RegisterDeviceRequest,
        device: dict[str, Any] = Depends(require_device_handler),
    ):
        # RustDrop calls this on startup before anything else, so it's the
        # natural place to lazily start the sweep - same "first real call
        # triggers it" pattern as managed_chat.py's websocket handler and
        # device_logs.py's upload_log. Must be async def (not plain def):
        # FastAPI runs sync endpoints in a worker thread with no running
        # event loop, which asyncio.create_task() inside needs.
        _ensure_sweep_started()
        self_id = device["device_id"]
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO rustdrop_registrations (device_id, registered_at, last_seen_at, public_key, capabilities)
                    VALUES (%s, now(), now(), %s, %s)
                    ON CONFLICT (device_id) DO UPDATE SET last_seen_at = now(), public_key = EXCLUDED.public_key,
                        capabilities = EXCLUDED.capabilities
                    """,
                    (self_id, payload.public_key, [c[:32] for c in payload.capabilities]),
                )
                connection.commit()
        return {"registered": True}

    @app.get(f"{FILEDROP_PATH}/devices")
    def list_devices(device: dict[str, Any] = Depends(require_device_handler)):
        self_id = device["device_id"]
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT d.id, d.rustdesk_id, d.friendly_name, d.hostname, r.public_key, r.capabilities
                    FROM managed_devices d
                    JOIN rustdrop_registrations r ON r.device_id = d.id
                    WHERE d.status = 'approved'
                      AND d.id != %s
                      AND r.last_seen_at > now() - %s::interval
                    ORDER BY d.friendly_name NULLS LAST, d.hostname
                    """,
                    (self_id, f"{REGISTRATION_STALE_AFTER.days} days"),
                )
                rows = cursor.fetchall()
        return {
            "devices": [
                {
                    "device_id": str(row["id"]),
                    "rustdesk_id": row["rustdesk_id"],
                    "friendly_name": row["friendly_name"],
                    "hostname": row["hostname"],
                    "public_key": row["public_key"],
                    "capabilities": row["capabilities"] or [],
                }
                for row in rows
            ]
        }

    @app.get(f"{FILEDROP_PATH}/drops")
    def list_drops(device: dict[str, Any] = Depends(require_device_handler)):
        # 'delivered' (recipient fully downloaded + hash-verified) is
        # excluded from both lists - it's what makes an accepted drop stop
        # reappearing as a pending Incoming offer, and drop off the
        # sender's Sent list too, rather than sitting there until TTL
        # sweep. peer_friendly_name/peer_hostname is the *other* party in
        # the transfer either way - the sender for an incoming row, the
        # recipient for an outgoing one - so the renderer can show "From
        # X"/"To X" without knowing which side it's looking at.
        self_id = device["device_id"]
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT f.*, peer.friendly_name AS peer_friendly_name, peer.hostname AS peer_hostname
                    FROM filedrop_drops f
                    JOIN managed_devices peer ON peer.id = f.sender_device_id
                    WHERE f.recipient_device_id = %s AND f.status != 'delivered'
                    ORDER BY f.created_at DESC
                    """,
                    (self_id,),
                )
                incoming = [_serialize_drop(dict(row)) for row in cursor.fetchall()]
                cursor.execute(
                    """
                    SELECT f.*, peer.friendly_name AS peer_friendly_name, peer.hostname AS peer_hostname
                    FROM filedrop_drops f
                    JOIN managed_devices peer ON peer.id = f.recipient_device_id
                    WHERE f.sender_device_id = %s AND f.status != 'delivered'
                    ORDER BY f.created_at DESC
                    """,
                    (self_id,),
                )
                outgoing = [_serialize_drop(dict(row)) for row in cursor.fetchall()]
        return {"incoming": incoming, "outgoing": outgoing}

    @app.get(f"{FILEDROP_PATH}/config")
    def get_transfer_config(device: dict[str, Any] = Depends(require_device_handler)):
        # Client-facing resumable-transfer tuning - a compiled client can't
        # read directory_settings directly, so it fetches these once per
        # send/accept rather than using build-time constants. Any enrolled
        # device may read this (no special privilege - it's transfer
        # tuning, not sensitive), same auth as register/list/create/upload.
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                return {
                    "part_size_bytes": min(_get_int_setting(
                        cursor, PART_SIZE_SETTING_KEY, PART_SIZE_BYTES_FALLBACK
                    ), PART_SIZE_BYTES_MAX),
                    "min_throughput_bps": _get_int_setting(
                        cursor, MIN_THROUGHPUT_SETTING_KEY, MIN_THROUGHPUT_BPS_FALLBACK
                    ),
                    "stall_giveup_minutes": _get_int_setting(
                        cursor, STALL_GIVEUP_SETTING_KEY, STALL_GIVEUP_MINUTES_FALLBACK
                    ),
                }

    @app.post(f"{FILEDROP_PATH}/drops")
    def create_drop(
        payload: CreateDropRequest,
        device: dict[str, Any] = Depends(require_device_handler),
    ):
        self_id = device["device_id"]
        if payload.recipient_device_id == self_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot send a drop to yourself",
            )
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                max_size = _get_int_setting(cursor, MAX_DROP_SIZE_SETTING_KEY, MAX_DROP_SIZE_BYTES_FALLBACK)
                if payload.declared_size > max_size:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"declared_size exceeds the current max drop size ({max_size} bytes)",
                    )
                cursor.execute(
                    """
                    SELECT 1 FROM managed_devices d
                    JOIN rustdrop_registrations r ON r.device_id = d.id
                    WHERE d.id = %s AND d.status = 'approved'
                      AND r.last_seen_at > now() - %s::interval
                    """,
                    (payload.recipient_device_id, f"{REGISTRATION_STALE_AFTER.days} days"),
                )
                if cursor.fetchone() is None:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Recipient is not available for RustDrop",
                    )
                cursor.execute(
                    """
                    INSERT INTO filedrop_drops
                        (sender_device_id, recipient_device_id, filename, declared_size, sender_public_key)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING *
                    """,
                    (
                        self_id,
                        payload.recipient_device_id,
                        payload.filename,
                        payload.declared_size,
                        payload.sender_public_key,
                    ),
                )
                drop = dict(cursor.fetchone())
                connection.commit()
        return _serialize_drop(drop)

    @app.put(f"{FILEDROP_PATH}/drops/{{drop_id}}/upload")
    async def upload_drop(
        drop_id: uuid.UUID,
        request: Request,
        device: dict[str, Any] = Depends(require_device_handler),
        upload_offset: str | None = Header(default=None),
        upload_length: str | None = Header(default=None),
    ):
        # Starlette dispatches a HEAD request to this same handler (RDC's own
        # HTTP client always sends a bodyless HEAD as a connectivity/TLS probe
        # before any real request - see create_http_client_async_with_url_strict
        # in the client). Without this guard, _bounded_request_stream(request, ...)
        # below tries to read a body that does not exist, throws an exception
        # that isn't caught by the httpx.HTTPError/ValueError clause, and the
        # resulting crash appears to poison the connection the client then
        # reuses for the real PUT. Bail out before touching the request body.
        if request.method != "PUT":
            raise HTTPException(status_code=status.HTTP_405_METHOD_NOT_ALLOWED)
        self_id = device["device_id"]

        def _lookup():
            with open_database_handler() as connection:
                with connection.cursor() as cursor:
                    d = _fetch_drop(cursor, drop_id)
                    m = _get_int_setting(cursor, MAX_DROP_SIZE_SETTING_KEY, MAX_DROP_SIZE_BYTES_FALLBACK)
                    return d, m

        drop, max_size = await _run_db(_lookup)
        if drop["sender_device_id"] != self_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Drop not found")
        if drop["status"] != "uploading":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Drop is not accepting an upload (status={drop['status']})",
            )

        # min(), not the declared size alone: declared_size is checked
        # against the *current* max at create_drop time, but a Config-page
        # edit between create and upload is real (however unlikely), so
        # this stays the actual enforcement point against bytes streamed.
        limit = min(drop["declared_size"], max_size)
        storage_key = str(drop["storage_key"])
        upload_url = f"{_storage_base_url()}/blobs/{storage_key}"

        if upload_offset is None:
            # Legacy single-shot path, unchanged - a resumable-aware client
            # always sends Upload-Offset (even at 0), so this only runs for
            # a client build that predates the resumable-transfer redesign.
            # Keeping this working (not requiring every client to upgrade
            # in lockstep with this deploy) is why this branch still exists.
            try:
                client = _get_storage_client()
                response = await client.put(
                    upload_url,
                    content=_bounded_request_stream(request, limit),
                    headers=_storage_auth_header(),
                    timeout=None,
                )
                response.raise_for_status()
                upload_result = response.json()
                bytes_written = upload_result.get("bytes_written", 0)
                content_sha256 = upload_result.get("sha256")
            except HTTPException:
                await _mark_drop_failed(open_database_handler, drop_id)
                raise
            except (httpx.HTTPError, ValueError):
                _log.exception("rustdrop upload proxy failed for drop %s", drop_id)
                _reset_storage_client()
                await _mark_drop_failed(open_database_handler, drop_id)
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Upload to storage failed",
                )

            with open_database_handler() as connection:
                with connection.cursor() as cursor:
                    ttl_hours = _get_ttl_hours(cursor)
                    cursor.execute(
                        """
                        UPDATE filedrop_drops
                        SET status = 'complete',
                            bytes_uploaded = %s,
                            content_sha256 = %s,
                            expires_at = now() + %s::interval,
                            updated_at = now()
                        WHERE id = %s
                        RETURNING *
                        """,
                        (bytes_written, content_sha256, f"{ttl_hours} hours", drop_id),
                    )
                    updated = dict(cursor.fetchone())
                    connection.commit()
            return _serialize_drop(updated)

        # Resumable per-part path: relay one bounded part, 1:1, to the storage
        # VM's matching offset-aware endpoint. Never marks the drop failed here
        # for a transient relay hiccup - that would kill a multi-hour
        # transfer over one bad part; the client retries the same part on
        # its own backoff instead. The only fatal case is the storage VM reporting
        # the upload session itself is gone (410) - locally unrecoverable.
        offset = int(upload_offset)
        content_length_header = request.headers.get("content-length")
        if content_length_header is not None and offset + int(content_length_header) > limit:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Upload exceeded its declared/allowed size",
            )

        upstream_headers = _storage_auth_header()
        upstream_headers["Upload-Offset"] = upload_offset
        if upload_length is not None:
            upstream_headers["Upload-Length"] = upload_length

        try:
            client = _get_storage_client()
            response = await client.put(
                upload_url,
                content=_bounded_request_stream(request, limit),
                headers=upstream_headers,
                timeout=PART_RELAY_TIMEOUT,
            )
        except HTTPException:
            raise
        except (httpx.HTTPError, ValueError):
            _log.warning("rustdrop part-upload relay failed for drop %s", drop_id)
            _reset_storage_client()
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Storage unreachable")

        if response.status_code == 409:
            # Offset mismatch - the storage VM is the source of truth on what it
            # actually has; the client re-syncs (HEAD) and retries. Not
            # fatal, no drop-level state change.
            raise HTTPException(
                status_code=409,
                detail="offset mismatch",
                headers={"Upload-Offset": response.headers.get("upload-offset", "")},
            )
        if response.status_code == 410:
            await _mark_drop_failed(open_database_handler, drop_id)
            raise HTTPException(status_code=410, detail="Upload session no longer exists")
        if response.status_code >= 400:
            _log.warning(
                "rustdrop part-upload rejected by storage for drop %s: %s",
                drop_id, response.status_code,
            )
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Storage rejected the upload")

        new_offset = int(response.headers.get("upload-offset", offset))
        complete = response.headers.get("x-upload-complete") == "true"
        response_headers = {
            "Upload-Offset": str(new_offset),
            "X-Upload-Complete": "true" if complete else "false",
        }

        if complete:
            content_sha256 = response.headers.get("x-content-sha256")
            with open_database_handler() as connection:
                with connection.cursor() as cursor:
                    ttl_hours = _get_ttl_hours(cursor)
                    cursor.execute(
                        """
                        UPDATE filedrop_drops
                        SET status = 'complete',
                            bytes_uploaded = %s,
                            content_sha256 = %s,
                            expires_at = now() + %s::interval,
                            updated_at = now()
                        WHERE id = %s
                        """,
                        (new_offset, content_sha256, f"{ttl_hours} hours", drop_id),
                    )
                    connection.commit()
            response_headers["X-Content-SHA256"] = content_sha256 or ""
        else:
            # Real forward progress on this drop, even though it isn't done
            # yet - without this, the TTL sweep's stuck-upload backstop had
            # no way to tell "actively, successfully receiving parts" from
            # "genuinely abandoned," since intermediate parts never touched
            # the row at all before. See the sweep query below, which now
            # keys off this instead of created_at.
            def _touch():
                with open_database_handler() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "UPDATE filedrop_drops SET updated_at = now() WHERE id = %s",
                            (drop_id,),
                        )
                        connection.commit()
            await _run_db(_touch)

        return Response(headers=response_headers)

    @app.head(f"{FILEDROP_PATH}/drops/{{drop_id}}/upload")
    async def head_upload_drop(
        drop_id: uuid.UUID,
        device: dict[str, Any] = Depends(require_device_handler),
    ):
        # "How many bytes do you actually have for this drop" - called once
        # at the start of any resume rather than trusting possibly-stale
        # client-side bookkeeping. A drop that's never had a byte uploaded
        # yet (the storage VM 404s) is indistinguishable from "0 bytes received",
        # not an error.
        self_id = device["device_id"]

        def _lookup():
            with open_database_handler() as connection:
                with connection.cursor() as cursor:
                    return _fetch_drop(cursor, drop_id)

        drop = await _run_db(_lookup)
        if drop["sender_device_id"] != self_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Drop not found")

        storage_key = str(drop["storage_key"])
        head_url = f"{_storage_base_url()}/blobs/{storage_key}"
        try:
            client = _get_storage_client()
            response = await client.head(
                head_url, headers=_storage_auth_header(), timeout=PART_RELAY_TIMEOUT
            )
        except httpx.HTTPError:
            _reset_storage_client()
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Storage unreachable")

        if response.status_code == 404:
            return Response(headers={"Upload-Offset": "0", "X-Upload-Complete": "false"})
        if response.status_code >= 400:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Storage returned an error")

        offset = response.headers.get("upload-offset", "0")
        complete = response.headers.get("x-upload-complete", "false")
        return Response(headers={"Upload-Offset": offset, "X-Upload-Complete": complete})

    @app.get(f"{FILEDROP_PATH}/drops/{{drop_id}}/download")
    async def download_drop(
        drop_id: uuid.UUID,
        device: dict[str, Any] = Depends(require_device_handler),
        range: str | None = Header(default=None),
    ):
        self_id = device["device_id"]

        def _lookup():
            with open_database_handler() as connection:
                with connection.cursor() as cursor:
                    return _fetch_drop(cursor, drop_id)

        drop = await _run_db(_lookup)
        if drop["recipient_device_id"] != self_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Drop not found")
        if drop["status"] not in ("uploading", "complete"):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Drop is not downloadable (status={drop['status']})",
            )

        storage_key = str(drop["storage_key"])
        download_url = f"{_storage_base_url()}/blobs/{storage_key}"

        # A download starting from byte 0 (no Range, or an explicit
        # bytes=0-... request) gets a fresh TTL window from this moment,
        # rather than the one set back when the upload finished - a
        # completed drop's TTL is sized for typical hold time, not for
        # covering a legitimately slow multi-hour download on top of it.
        # Deliberately a single reset at the start of a download, not on
        # every resumed part-range request after that: renewing on every
        # request would let a drop be kept alive forever via repeated tiny
        # range requests, which defeats the point of a TTL at all. A
        # download that's paused/resumed across more than one full TTL
        # window from when it first started can still expire mid-transfer -
        # an intentional tradeoff, matching the "eventually give up"
        # philosophy the stall-detection logic already uses elsewhere.
        is_download_start = range is None or range.strip().lower().startswith("bytes=0-")
        if is_download_start and drop["status"] == "complete":
            def _renew_ttl():
                with open_database_handler() as connection:
                    with connection.cursor() as cursor:
                        ttl_hours = _get_ttl_hours(cursor)
                        cursor.execute(
                            """
                            UPDATE filedrop_drops
                            SET expires_at = now() + %s::interval, updated_at = now()
                            WHERE id = %s AND status = 'complete'
                            """,
                            (f"{ttl_hours} hours", drop_id),
                        )
                        connection.commit()
            await _run_db(_renew_ttl)

        # A resuming client (e.g. after losing its connection mid-download)
        # sends Range: bytes=<already-received>- (or a closed bytes=N-M for
        # the bounded-part resumable download path) ; forwarded straight
        # through to the storage VM, which does the actual seek/tail-follow-
        # from-offset. RDS itself never buffers or interprets the range beyond
        # passing it along and relaying the storage VM's 200/206/416 back
        # untouched.
        upstream_headers = _storage_auth_header()
        if range:
            upstream_headers["Range"] = range

        # client.send(..., stream=True) rather than the client.stream()
        # context manager: the response has to outlive this function's own
        # scope so its status/headers can be inspected before deciding what
        # to hand FastAPI, then its body streamed lazily after returning.
        # client itself is the shared, process-lifetime one (see
        # _get_storage_client) - only the per-request upstream_response
        # gets closed below, never the client.
        client = _get_storage_client()
        try:
            upstream_request = client.build_request(
                "GET", download_url, headers=upstream_headers, timeout=None
            )
            upstream_response = await client.send(upstream_request, stream=True)
        except httpx.HTTPError:
            _log.exception("rustdrop download proxy failed for drop %s", drop_id)
            _reset_storage_client()
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Storage unreachable")

        if upstream_response.status_code not in (200, 206):
            await upstream_response.aclose()
            if upstream_response.status_code == 416:
                raise HTTPException(
                    status_code=416,
                    detail="Range not satisfiable",
                    headers=dict(upstream_response.headers),
                )
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Storage returned an error")

        async def proxy_stream() -> AsyncIterator[bytes]:
            try:
                async for chunk in upstream_response.aiter_bytes():
                    yield chunk
            finally:
                await upstream_response.aclose()

        response_headers = {"Content-Disposition": f'attachment; filename="{drop["filename"]}"'}
        for header_name in ("content-range", "accept-ranges", "x-content-sha256"):
            if header_name in upstream_response.headers:
                response_headers[header_name] = upstream_response.headers[header_name]

        return StreamingResponse(
            proxy_stream(),
            status_code=upstream_response.status_code,
            media_type="application/octet-stream",
            headers=response_headers,
        )

    @app.post(f"{FILEDROP_PATH}/drops/{{drop_id}}/complete")
    def complete_drop(
        drop_id: uuid.UUID,
        device: dict[str, Any] = Depends(require_device_handler),
    ):
        # Called by the recipient only after it has fully downloaded AND
        # hash-verified a drop (main.js's accept-drop handler) - marks it
        # 'delivered' so list_drops stops returning it to either side.
        # Idempotent: a drop already 'delivered' (e.g. a retried IPC call)
        # is returned as-is rather than erroring.
        self_id = device["device_id"]
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                drop = _fetch_drop(cursor, drop_id)
                if drop["recipient_device_id"] != self_id:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Drop not found")
                if drop["status"] == "delivered":
                    return _serialize_drop(drop)
                if drop["status"] != "complete":
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=f"Drop cannot be marked delivered (status={drop['status']})",
                    )
                cursor.execute(
                    "UPDATE filedrop_drops SET status = 'delivered', updated_at = now() WHERE id = %s RETURNING *",
                    (drop_id,),
                )
                updated = dict(cursor.fetchone())
                # Durable record of this completed transfer - see
                # filedrop_transfer_events' own doc comment for why this
                # can't just be a live COUNT/SUM against filedrop_drops
                # (that table's rows get deleted by the TTL sweep).
                cursor.execute(
                    """
                    INSERT INTO filedrop_transfer_events
                        (drop_id, sender_device_id, recipient_device_id, bytes)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (
                        updated["id"],
                        updated["sender_device_id"],
                        updated["recipient_device_id"],
                        updated["bytes_uploaded"],
                    ),
                )
                connection.commit()
        return _serialize_drop(updated)

    @app.post(f"{FILEDROP_PATH}/drops/{{drop_id}}/decline")
    async def decline_drop(
        drop_id: uuid.UUID,
        device: dict[str, Any] = Depends(require_device_handler),
    ):
        # Declined = immediate delete from the server (doc section 09, item
        # settled from build order #6 request) - not left for the hourly
        # sweep.
        self_id = device["device_id"]
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                drop = _fetch_drop(cursor, drop_id)
                if drop["recipient_device_id"] != self_id:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND, detail="Drop not found"
                    )
                cursor.execute("DELETE FROM filedrop_drops WHERE id = %s", (drop_id,))
                connection.commit()
        await _delete_blob(str(drop["storage_key"]))
        return {"declined": True}

    # Brad-only (2026-09-21 Config page - consolidates every RustDrop tuning
    # knob onto one Brad-gated admin tab, same require_admin_cookie_brad_only
    # gate as the Mail tab). Not under FILEDROP_PATH since this isn't a
    # device-facing operation, same /ops/api/... namespace device_logs.py
    # uses for its own admin routes. Cookie-based auth, not the header-based
    # require_owner: the dashboard is a browser fetch() call with no
    # Authorization header, only the HttpOnly session cookie - see
    # require_admin_cookie_owner's own doc comment in main.py for why a
    # plain Depends(require_owner) here would 401 every real dashboard call
    # despite a fully valid session.
    @app.get("/ops/api/filedrop/settings")
    def get_filedrop_settings(
        operator: dict[str, Any] = Depends(require_admin_cookie_brad_only_handler),
    ):
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                return {
                    "ttl_hours": _get_ttl_hours(cursor),
                    "sweep_interval_seconds": _get_int_setting(
                        cursor, SWEEP_INTERVAL_SETTING_KEY, DROP_SWEEP_INTERVAL_SECONDS_FALLBACK
                    ),
                    "stuck_upload_backstop_days": _get_int_setting(
                        cursor, STUCK_UPLOAD_BACKSTOP_SETTING_KEY, DROP_STUCK_UPLOAD_MAX_AGE_DAYS_FALLBACK
                    ),
                    "max_drop_size_bytes": _get_int_setting(
                        cursor, MAX_DROP_SIZE_SETTING_KEY, MAX_DROP_SIZE_BYTES_FALLBACK
                    ),
                    "part_size_bytes": min(_get_int_setting(
                        cursor, PART_SIZE_SETTING_KEY, PART_SIZE_BYTES_FALLBACK
                    ), PART_SIZE_BYTES_MAX),
                    "min_throughput_bps": _get_int_setting(
                        cursor, MIN_THROUGHPUT_SETTING_KEY, MIN_THROUGHPUT_BPS_FALLBACK
                    ),
                    "stall_giveup_minutes": _get_int_setting(
                        cursor, STALL_GIVEUP_SETTING_KEY, STALL_GIVEUP_MINUTES_FALLBACK
                    ),
                }

    @app.post("/ops/api/filedrop/settings")
    def set_filedrop_settings(
        payload: RustdropSettingsRequest,
        operator: dict[str, Any] = Depends(require_admin_cookie_brad_only_handler),
    ):
        updates: list[tuple[str, str]] = []
        if payload.ttl_hours is not None:
            updates.append((TTL_SETTING_KEY, str(payload.ttl_hours)))
        if payload.sweep_interval_seconds is not None:
            updates.append((SWEEP_INTERVAL_SETTING_KEY, str(payload.sweep_interval_seconds)))
        if payload.stuck_upload_backstop_days is not None:
            updates.append((STUCK_UPLOAD_BACKSTOP_SETTING_KEY, str(payload.stuck_upload_backstop_days)))
        if payload.max_drop_size_bytes is not None:
            updates.append((MAX_DROP_SIZE_SETTING_KEY, str(payload.max_drop_size_bytes)))
        if payload.part_size_bytes is not None:
            updates.append((PART_SIZE_SETTING_KEY, str(payload.part_size_bytes)))
        if payload.min_throughput_bps is not None:
            updates.append((MIN_THROUGHPUT_SETTING_KEY, str(payload.min_throughput_bps)))
        if payload.stall_giveup_minutes is not None:
            updates.append((STALL_GIVEUP_SETTING_KEY, str(payload.stall_giveup_minutes)))

        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                for key, value in updates:
                    cursor.execute(
                        """
                        INSERT INTO directory_settings (setting_key, setting_value, updated_by)
                        VALUES (%s, %s::jsonb, %s)
                        ON CONFLICT (setting_key)
                        DO UPDATE SET setting_value = EXCLUDED.setting_value, updated_by = EXCLUDED.updated_by
                        """,
                        (key, value, operator["account_id"]),
                    )
                connection.commit()
        return get_filedrop_settings(operator=operator)


async def _mark_drop_failed(open_database_handler: Callable[..., Any], drop_id: uuid.UUID) -> None:
    try:
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE filedrop_drops SET status = 'failed', updated_at = now() WHERE id = %s",
                    (drop_id,),
                )
                connection.commit()
    except Exception:
        _log.exception("failed to mark drop %s as failed", drop_id)
