from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import secrets
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import quote

import jwt
import pyotp
import segno
from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

ACCESS_COOKIE = "__Secure-rd-admin-access"
ACTIVITY_COOKIE = "__Secure-rd-admin-activity"
ADMIN_PATH = "/ops"
RESET_MINUTES = 30
RELAY_LEASE_SECONDS = 600
RELAY_RENEW_AFTER_SECONDS = 240
REENROLLMENT_AUTH_MINUTES = 30
ACTIVITY_RETENTION_DAYS = 180
ACTIVITY_PRUNE_EVERY_SECONDS = 3600
ACTIVITY_PRUNE_BATCH = 5000
LOG = logging.getLogger("uvicorn.error")


class OperatorAccessResetCreateRequest(BaseModel):
    reset_mode: str = Field(
        pattern=r"^(password_only|totp_only|password_totp)$"
    )
    reason: str = Field(min_length=1, max_length=1024)
    owner_password: str = Field(min_length=1, max_length=256)
    owner_totp_code: str = Field(pattern=r"^\d{6}$")


class RustdwebAccessResetCreateRequest(BaseModel):
    # No password, code or reason: the Owner/Manager's signed-in console session is enough (Brad, 2026-10-29).
    reset_mode: str = Field(
        pattern=r"^(password_only|totp_only|password_totp)$"
    )
    reason: str = Field(default="RustDWeb access reset from the console", min_length=1, max_length=1024)


class OperatorSelfAccessResetCreateRequest(BaseModel):
    reset_mode: str = Field(
        pattern=r"^(password_only|totp_only|password_totp)$"
    )
    reason: str = Field(default="Manager self-service access change", min_length=1, max_length=1024)
    current_password: str = Field(min_length=1, max_length=256)
    current_totp_code: str = Field(pattern=r"^\d{6}$")


class OperatorAccessResetTokenRequest(BaseModel):
    reset_token: str = Field(min_length=32, max_length=512)


class OperatorAccessResetAcceptRequest(BaseModel):
    reset_token: str = Field(min_length=32, max_length=512)
    password: str | None = Field(default=None, max_length=256)
    totp_code: str = Field(pattern=r"^\d{6}$")


class DeviceSessionHeartbeatRequest(BaseModel):
    session_id: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )
    session_type: str = Field(
        pattern=r"^(remote_desktop|file_transfer)$"
    )
    state: str = Field(default="active", pattern=r"^(active|ended)$")
    peer_rustdesk_id: str | None = Field(default=None, max_length=64)


class ConnectionTiming(BaseModel):
    """How an initiating RDC connected (build 28+): drives the relay fallback delay stats on the
    Config page. `late` = the relay won but the direct attempt, kept alive briefly to measure,
    succeeded afterwards (the delay was too short for that pair)."""
    route: str | None = Field(default=None, pattern=r"^(relay|direct_tcp|direct_udp|lan|ipv6|webrtc)$")
    connect_ms: int | None = Field(default=None, ge=0, le=600000)
    direct_result: str | None = Field(
        default=None, pattern=r"^(success|failed|not_attempted|late)$"
    )
    direct_ms: int | None = Field(default=None, ge=0, le=600000)
    relay_ms: int | None = Field(default=None, ge=0, le=600000)
    late_direct_ms: int | None = Field(default=None, ge=0, le=600000)
    relay_delay_ms: int | None = Field(default=None, ge=0, le=60000)
    nat_type: str | None = Field(default=None, max_length=16)
    peer_nat_type: str | None = Field(default=None, max_length=16)
    # Build 38+: why a relayed connection didn't go direct (punch timeout, peer chose relay, ...).
    direct_reason: str | None = Field(default=None, max_length=160)
    # "ended" events: how the session felt (RDC's round-trip "Delay"), for judging relay vs direct.
    duration_s: int | None = Field(default=None, ge=0, le=31_536_000)
    avg_delay_ms: int | None = Field(default=None, ge=0, le=600000)
    max_delay_ms: int | None = Field(default=None, ge=0, le=600000)


class DeviceConnectionEventRequest(BaseModel):
    connection_id: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )
    event: str = Field(
        pattern=r"^(initiated|established|rejected|denied|ended)$"
    )
    session_type: str = Field(
        default="remote_desktop",
        pattern=r"^(remote_desktop|file_transfer)$",
    )
    direction: str = Field(pattern=r"^(initiator|receiver)$")
    peer_rustdesk_id: str = Field(min_length=1, max_length=64)
    reason: str | None = Field(default=None, max_length=1024)
    timing: ConnectionTiming | None = None


class DeviceReenrollmentAuthorizationRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=1024)
    expires_in_minutes: int = Field(default=REENROLLMENT_AUTH_MINUTES, ge=5, le=120)


class _SlidingWindowLimiter:
    # Every rule window is 60 s; anything idle for this long holds no information.
    _PRUNE_IDLE_SECONDS = 300
    _PRUNE_EVERY_SECONDS = 60

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._last_prune = time.monotonic()

    def allow(self, key: tuple[str, str], limit: int, window: int) -> bool:
        now = time.monotonic()
        cutoff = now - window
        with self._lock:
            if now - self._last_prune > self._PRUNE_EVERY_SECONDS:
                # Without this, one entry per (path, address) ever seen stays forever: rotating
                # IPv6 addresses grew the map without bound.
                idle = now - self._PRUNE_IDLE_SECONDS
                for stale in [k for k, b in self._events.items() if not b or b[-1] <= idle]:
                    del self._events[stale]
                self._last_prune = now
            bucket = self._events[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                return False
            bucket.append(now)
            return True


class _BodySizeLimit:
    """Caps request bodies before anything buffers or parses them (JSON bodies were read in full,
    unauthenticated, with no limit). Paths that stream and bound their own bodies are exempt."""

    def __init__(self, app: Any, *, default_limit: int, path_limits: dict[str, int], exempt: Callable[[str], bool]) -> None:
        self.app = app
        self.default_limit = default_limit
        self.path_limits = path_limits
        self.exempt = exempt

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or self.exempt(scope.get("path", "")):
            return await self.app(scope, receive, send)
        limit = self.path_limits.get(scope.get("path", ""), self.default_limit)
        declared = None
        for name, value in scope.get("headers") or []:
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = limit + 1
                break
        if declared is not None and declared > limit:
            await send({"type": "http.response.start", "status": 413,
                        "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": b'{"detail":"Request body too large"}'})
            return
        received = 0

        async def bounded_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    # A body without a usable Content-Length ran past the cap: stop reading it.
                    return {"type": "http.disconnect"}
            return message

        return await self.app(scope, bounded_receive, send)


def _b32_hmac_secret(key: str, token: str) -> str:
    digest = hmac.new(
        key.encode("utf-8"),
        ("operator-access-reset:" + token).encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.b32encode(digest[:20]).decode("ascii").rstrip("=")


def _token_hash(token_secret: str, token: str) -> bytes:
    return hmac.new(
        token_secret.encode("utf-8"),
        token.encode("utf-8"),
        hashlib.sha256,
    ).digest()


def _safe_client_ip(raw: str | None) -> str:
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Source IP address is unavailable",
        )
    value = raw.strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Source IP address is invalid",
        ) from error


# Display-only mirror of the nft rules rustdesk-relay-guard-sync installs for
# each mode, so the diagnostics report what the firewall actually does -
# editing these lists changes nothing on the firewall. TCP/UDP 21116 and TCP
# 21117 are accepted unconditionally since 2026-08-27 (the RustDesk protocol
# itself authenticates register_pk and relay sessions; a source-IP allowlist
# only broke carrier-grade-NAT devices) - only 21115/21118/21119 need a relay
# lease, and 21120 is dropped for everything off-loopback. Any mode other
# than "staged" is reported as enforced (the synchronizer's fail-safe; it
# leaves the applied table alone on an unrecognized mode value). "closed"
# means dropped off-loopback.
# guarded_tcp_ports/guarded_udp_ports are also part of the relay-lease wire
# response the client deserializes (RelayLeaseResponse) - always keep both
# keys present, as lists.
def _relay_guard_ports(mode: str) -> dict[str, list[int]]:
    if mode == "staged":
        return {
            "guarded_tcp_ports": [],
            "guarded_udp_ports": [],
            "open_tcp_ports": [21115, 21116, 21117],
            "open_udp_ports": [21116],
            "closed_tcp_ports": [21118, 21119, 21120],
        }
    return {
        "guarded_tcp_ports": [21115, 21118, 21119],
        "guarded_udp_ports": [],
        "open_tcp_ports": [21116, 21117],
        "open_udp_ports": [21116],
        "closed_tcp_ports": [21120],
    }


def _recovery_html() -> str:
    return r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>RustDesk Directory access recovery</title>
  <style>
    :root { color-scheme: dark; font-family: Inter,Segoe UI,Arial,sans-serif; }
    * { box-sizing: border-box; }
    body { margin:0; min-height:100vh; background:#08111f; color:#e8eef7; display:grid; place-items:center; padding:28px; }
    .card { width:min(680px,100%); background:#101b2b; border:1px solid #263a55; border-radius:18px; padding:30px; box-shadow:0 24px 70px rgba(0,0,0,.36); }
    h1 { margin:0 0 8px; font-size:28px; }
    h2 { margin:26px 0 10px; font-size:18px; }
    p { color:#aebdd1; line-height:1.55; }
    .meta { display:grid; grid-template-columns:1fr 1fr; gap:10px; margin:18px 0; }
    .pill { border:1px solid #2b4260; background:#0b1625; border-radius:12px; padding:12px; }
    .label { color:#7f94ad; font-size:12px; text-transform:uppercase; letter-spacing:.06em; }
    .value { margin-top:4px; font-weight:650; overflow-wrap:anywhere; }
    label { display:block; margin:15px 0 6px; color:#c9d5e4; font-size:13px; }
    input { width:100%; padding:12px 13px; border-radius:10px; border:1px solid #38516f; background:#081321; color:#fff; font-size:15px; }
    button { margin-top:18px; border:0; border-radius:10px; padding:12px 17px; font-weight:700; cursor:pointer; background:#3487f5; color:#fff; }
    button:disabled { opacity:.55; cursor:wait; }
    .qr-wrap { display:grid; place-items:center; margin:20px 0; }
    .qr-card { background:white; border-radius:16px; padding:18px; }
    .qr-card img { display:block; width:min(330px,72vw); height:auto; }
    .secret { background:#081321; border:1px solid #2d4563; border-radius:10px; padding:12px; font-family:ui-monospace,SFMono-Regular,Consolas,monospace; overflow-wrap:anywhere; }
    .hidden { display:none !important; }
    .error { color:#ff9b9b; min-height:22px; margin-top:12px; }
    .ok { border:1px solid #1f6d4c; background:#0b2b20; color:#b9f3d6; border-radius:12px; padding:14px; margin-top:18px; }
    .username-callout { margin:12px 0 2px; padding:11px 16px 12px; border:1px solid rgba(77,163,255,.5); border-left:4px solid #4da3ff; border-radius:10px; background:rgba(8,17,31,.62); }
    .username-callout .label { color:#9fb0c6; }
    .username-callout-value { margin-top:3px; color:#fff; font-size:24px; font-weight:800; font-family:ui-monospace,SFMono-Regular,Consolas,monospace; user-select:all; overflow-wrap:anywhere; }
    .warning { border:1px solid #755f25; background:#2b2410; color:#f4dda0; border-radius:12px; padding:14px; margin:16px 0; }
    @media(max-width:560px){ .meta{grid-template-columns:1fr;} .card{padding:22px;} }
  </style>
</head>
<body>
  <main class="card">
    <h1>RustDesk Directory access recovery</h1>
    <p>This one-time access-change link was created by you or a Directory Owner. It expires after 30 minutes and cannot be reused.</p>
    <div id="error" class="error"></div>
    <section id="setup" class="hidden">
      <div class="meta">
        <div class="pill"><div class="label">Person</div><div id="person" class="value"></div></div>
        <div class="pill"><div class="label">Username</div><div id="username" class="value"></div></div>
        <div class="pill"><div class="label">Recovery</div><div id="mode" class="value"></div></div>
        <div class="pill"><div class="label">Expires</div><div id="expires" class="value"></div></div>
      </div>
      <div id="newTotp" class="hidden">
        <div class="warning">Your previous authenticator registration will be replaced. Scan this QR code before submitting the form.</div>
        <div class="qr-wrap"><div class="qr-card"><img id="qr" alt="Authenticator QR code"></div></div>
        <label>Authenticator secret (manual fallback)</label>
        <div id="secret" class="secret"></div>
      </div>
      <div id="existingTotp" class="warning hidden">Use your existing RustDesk Directory authenticator entry for the 6-digit code below.</div>
      <form id="form">
        <div id="passwordFields">
          <label for="password">New password</label>
          <input id="password" type="password" autocomplete="new-password" minlength="12">
          <label for="confirm">Confirm new password</label>
          <input id="confirm" type="password" autocomplete="new-password" minlength="12">
        </div>
        <label for="totp" id="totpLabel">Current 6-digit authenticator code</label>
        <input id="totp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required>
        <button id="submit" type="submit">Update access</button>
      </form>
    </section>
    <section id="success" class="hidden ok">Access has been reset successfully. You can now close this page and sign in with the new password.
      <div class="username-callout"><div class="label">Your username</div><div id="successUser" class="username-callout-value"></div></div>
    </section>
  </main>
<script>
const token = new URLSearchParams(location.search).get("token") || "";
const errorBox = document.getElementById("error");
async function api(path, body){
  const r = await fetch(path,{method:"POST",cache:"no-store",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  let data={}; try{data=await r.json();}catch{}
  if(!r.ok) throw new Error(data.detail || `Request failed (${r.status})`);
  return data;
}
async function load(){
  try{
    const data=await api("/v1/operator-access-resets/setup",{reset_token:token});
    document.getElementById("person").textContent=data.display_name || data.username;
    document.getElementById("username").textContent=data.username;
    const labels={password_only:"Password only",totp_only:"Authenticator only",password_totp:"Password + authenticator"};
    document.getElementById("mode").textContent=labels[data.reset_mode] || data.reset_mode;
    document.getElementById("expires").textContent=new Date(data.expires_at).toLocaleString();
    if(data.reset_mode === "password_totp" || data.reset_mode === "totp_only"){
      document.getElementById("newTotp").classList.remove("hidden");
      document.getElementById("qr").src=data.totp_qr_data_uri;
      document.getElementById("secret").textContent=data.totp_secret;
      document.getElementById("totpLabel").textContent="New 6-digit authenticator code";
    } else {
      document.getElementById("existingTotp").classList.remove("hidden");
    }
    if(data.reset_mode === "totp_only"){
      document.getElementById("passwordFields").classList.add("hidden");
    }
    document.getElementById("setup").classList.remove("hidden");
  }catch(e){ errorBox.textContent=e.message; }
}
document.getElementById("form").addEventListener("submit",async e=>{
  e.preventDefault(); errorBox.textContent="";
  const p=document.getElementById("password").value;
  const c=document.getElementById("confirm").value;
  const code=document.getElementById("totp").value.trim();
  const mode=document.getElementById("mode").textContent;
  const needsPassword=mode !== "Authenticator only";
  if(needsPassword && p.length<12){errorBox.textContent="Password must contain at least 12 characters.";return;}
  if(needsPassword && p!==c){errorBox.textContent="Passwords do not match.";return;}
  if(!/^\d{6}$/.test(code)){errorBox.textContent="Enter the 6-digit authenticator code.";return;}
  const b=document.getElementById("submit"); b.disabled=true; b.textContent="Updating…";
  try{
    await api("/v1/operator-access-resets/accept",{reset_token:token,password:needsPassword?p:null,totp_code:code});
    document.getElementById("setup").classList.add("hidden");
    document.getElementById("successUser").textContent=document.getElementById("username").textContent;
    document.getElementById("success").classList.remove("hidden");
  }catch(e){errorBox.textContent=e.message;}finally{b.disabled=false;b.textContent="Update access";}
});
void load();
</script>
</body>
</html>'''


def _recovery_script_csp() -> str:
    """The recovery page's one inline <script> by SHA-256, so no injected script can run there."""
    html = _recovery_html()
    start = html.index("<script>") + len("<script>")
    script = html[start:html.index("</script>", start)]
    return "'sha256-" + base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii") + "'"


RECOVERY_SCRIPT_CSP = _recovery_script_csp()


# Filedrop rate limits, live-editable via directory_settings (Config page,
# RustDrop group) rather than hardcoded like the rules below - Brad's
# explicit direction, matching how part_size_bytes/ttl_hours/etc already
# work. Re-read on a short periodic timer (not per-request - this
# middleware runs on every single call to RDS, so a DB round-trip per
# request here would be a real cost the sweep-interval-style periodic
# re-read pattern elsewhere in this codebase already avoids).
_FILEDROP_RATE_LIMIT_REFRESH_SECONDS = 30
_FILEDROP_RATE_LIMIT_SETTING_KEYS = {
    "/v1/filedrop/register": "rustdrop.rate_limit_register_per_min",
    "/v1/filedrop/devices": "rustdrop.rate_limit_devices_per_min",
    "/v1/filedrop/drops": "rustdrop.rate_limit_drops_per_min",
    "/v1/filedrop/config": "rustdrop.rate_limit_config_per_min",
}
_FILEDROP_RATE_LIMIT_FALLBACKS = {
    "/v1/filedrop/register": 10,
    "/v1/filedrop/devices": 60,
    "/v1/filedrop/drops": 60,
    "/v1/filedrop/config": 30,
}
_FILEDROP_PART_SIZE_SETTING_KEY = "rustdrop.part_size_bytes"
_FILEDROP_PART_SIZE_FALLBACK = 8 * 1024 * 1024  # matches rustdrop.py's own fallback
# Assumed throughput ceiling for a single RustDrop transfer (default
# 500 Mbit/s - adjust to match your own uplink). When the filedrop hostname
# resolves to the public address for every client, even transfers between
# two internal endpoints go through the WAN link, so it is the practical
# bound regardless of where either endpoint sits. 3x safety margin covers
# protocol overhead, the client's own resync retries, and multiple
# concurrent transfers from one device, without meaningfully loosening the
# bound against genuine abuse.
_FILEDROP_WAN_THROUGHPUT_BYTES_PER_SEC = 500_000_000 // 8
_FILEDROP_PART_RATE_LIMIT_SAFETY_MARGIN = 3


def _compute_part_rate_limit_per_min(part_size_bytes: int) -> int:
    per_transfer = math.ceil(
        _FILEDROP_WAN_THROUGHPUT_BYTES_PER_SEC * 60 / max(part_size_bytes, 1)
    )
    return per_transfer * _FILEDROP_PART_RATE_LIMIT_SAFETY_MARGIN


def prune_device_activity(
    open_database_handler: Callable[..., Any],
    *,
    retention_days: int = ACTIVITY_RETENTION_DAYS,
    batch: int = ACTIVITY_PRUNE_BATCH,
    pause_seconds: float = 0.2,
) -> int:
    """Deletes device_activity_events older than the retention, `batch` rows per statement, each
    committed on its own: the first run after a long gap never holds one long transaction, and the
    pause between batches keeps a big backlog from becoming one burst of disk writes on the host."""
    deleted = 0
    with open_database_handler() as connection:
        while True:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    DELETE FROM device_activity_events
                    WHERE id IN (
                        SELECT id FROM device_activity_events
                        WHERE occurred_at < now() - make_interval(days => %s)
                        LIMIT %s
                    )
                    """,
                    (retention_days, batch),
                )
                count = cursor.rowcount
            connection.commit()
            deleted += count
            if count < batch:
                return deleted
            time.sleep(pause_seconds)


def register_security_extension(
    *,
    app: Any,
    open_database_handler: Callable[..., Any],
    require_operator_handler: Callable[..., dict[str, Any]],
    require_owner_handler: Callable[..., dict[str, Any]],
    require_device_handler: Callable[..., dict[str, Any]],
    verify_owner_reauthentication_handler: Callable[..., Any],
    client_ip_handler: Callable[..., str | None],
    is_protected_account_handler: Callable[[dict[str, Any]], bool],
    token_secret: str,
    totp_key: str,
) -> None:
    limiter = _SlidingWindowLimiter()
    app.add_middleware(
        _BodySizeLimit,
        default_limit=2 * 1024 * 1024,
        # A full 4 MiB client log grows in JSON (escaped Windows paths); 6 MiB refused some every time.
        path_limits={"/v1/device/log-upload": 12 * 1024 * 1024},
        # Sealed envelopes (sealed.py _read_bounded) and RustDrop part uploads (rustdrop.py) stream
        # with their own caps.
        exempt=lambda path: path == "/v1/sealed" or (
            path.startswith("/v1/filedrop/drops/") and path.endswith("/upload")
        ),
    )
    _filedrop_limits: dict[str, int] = dict(_FILEDROP_RATE_LIMIT_FALLBACKS)
    _filedrop_part_rate_limit = _compute_part_rate_limit_per_min(_FILEDROP_PART_SIZE_FALLBACK)
    _filedrop_refresh_started = False

    def _read_filedrop_rate_settings() -> tuple[dict[str, int], int]:
        limits = dict(_FILEDROP_RATE_LIMIT_FALLBACKS)
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                for path, key in _FILEDROP_RATE_LIMIT_SETTING_KEYS.items():
                    cursor.execute(
                        "SELECT setting_value FROM directory_settings WHERE setting_key = %s",
                        (key,),
                    )
                    row = cursor.fetchone()
                    if row is not None:
                        limits[path] = int(row["setting_value"])
                cursor.execute(
                    "SELECT setting_value FROM directory_settings WHERE setting_key = %s",
                    (_FILEDROP_PART_SIZE_SETTING_KEY,),
                )
                row = cursor.fetchone()
                part_size = int(row["setting_value"]) if row else _FILEDROP_PART_SIZE_FALLBACK
        return limits, part_size

    async def _refresh_filedrop_rate_limits_forever() -> None:
        nonlocal _filedrop_limits, _filedrop_part_rate_limit
        while True:
            try:
                limits, part_size = await asyncio.to_thread(_read_filedrop_rate_settings)
                _filedrop_limits = limits
                _filedrop_part_rate_limit = _compute_part_rate_limit_per_min(part_size)
            except Exception:
                pass  # keep serving the last-known-good cached values
            await asyncio.sleep(_FILEDROP_RATE_LIMIT_REFRESH_SECONDS)

    def _ensure_filedrop_rate_refresh_started() -> None:
        nonlocal _filedrop_refresh_started
        if not _filedrop_refresh_started:
            _filedrop_refresh_started = True
            asyncio.create_task(_refresh_filedrop_rate_limits_forever())

    # The 180-day device_activity_events retention, hourly in the background (it ran inside a
    # heartbeat's transaction, so the first prune after a deploy held that heartbeat's locks).
    _activity_prune_started = False

    async def _prune_activity_forever() -> None:
        while True:
            try:
                deleted = await asyncio.to_thread(prune_device_activity, open_database_handler)
                if deleted:
                    LOG.info("device activity: pruned %d events older than %d days", deleted, ACTIVITY_RETENTION_DAYS)
            except Exception:
                LOG.exception("device activity prune failed")
            await asyncio.sleep(ACTIVITY_PRUNE_EVERY_SECONDS)

    def _ensure_activity_prune_started() -> None:
        nonlocal _activity_prune_started
        if not _activity_prune_started:
            _activity_prune_started = True
            asyncio.create_task(_prune_activity_forever())

    @app.middleware("http")
    async def rustdesk_security_rate_limit(request: Request, call_next):
        _ensure_filedrop_rate_refresh_started()
        _ensure_activity_prune_started()
        path = request.url.path
        rules = {
            "/v1/auth/login": (30, 60),
            "/v1/enrollment/devices": (12, 60),
            "/v1/enrollment/check": (12, 60),
            "/v1/enrollment/status": (60, 60),
            "/v1/operator-access-resets/setup": (30, 60),
            "/v1/operator-access-resets/accept": (20, 60),
            f"{ADMIN_PATH}/api/operator/self/access-reset": (10, 60),
            "/v1/device/relay-lease": (60, 60),
            "/v1/device/session-heartbeat": (300, 60),
            "/v1/device/connection-event": (300, 60),
            "/v1/sealed": (1200, 60),
            "/v1/updates/latest": (30, 60),
            # The sign-in routes people and phones actually use (the /v1 ones above are API-only).
            f"{ADMIN_PATH}/api/login": (10, 60),
            f"{ADMIN_PATH}/api/invite/setup": (10, 60),
            f"{ADMIN_PATH}/api/invite/accept": (10, 60),
            f"{ADMIN_PATH}/api/mobile/login": (10, 60),
            f"{ADMIN_PATH}/api/mobile/pair": (10, 60),
            f"{ADMIN_PATH}/api/mobile/key-login": (30, 60),
            f"{ADMIN_PATH}/api/mobile/session/refresh": (60, 60),
            # Every RustDWeb sign-in arrives from the gateway's address, so this is only a
            # gateway-wide backstop; rustdweb.py limits each username + viewer address itself.
            "/v1/device/rustdweb/login": (60, 60),
        }
        rule = rules.get(path)
        limit_key = path
        if rule is None and path in _filedrop_limits:
            rule = (_filedrop_limits[path], 60)
        if rule is None and path.startswith("/v1/filedrop/drops/") and (
            path.endswith("/upload") or path.endswith("/download")
        ):
            # One limiter entry per route shape, not per drop id: a raw path key let anyone
            # mint a new entry with every made-up id.
            limit_key = "/v1/filedrop/drops/*/" + path.rsplit("/", 1)[1]
            # The per-part upload/download/head routes carry a UUID path
            # segment, so they can never match a literal dict key above -
            # this is the only way to cover them at all. Limit is dynamic,
            # not hardcoded: it scales with the live part_size_bytes Config
            # page setting (see _compute_part_rate_limit_per_min), so
            # changing part size there doesn't silently make this limit
            # wrong until someone remembers to also update a constant here.
            rule = (_filedrop_part_rate_limit, 60)
        if rule is not None:
            raw_ip = client_ip_handler(request) or "unknown"
            if not limiter.allow((limit_key, raw_ip), rule[0], rule[1]):
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={"detail": "Too many requests; try again shortly"},
                    headers={"Retry-After": "60"},
                )
        response = await call_next(request)
        if path.startswith("/v1/") or path.startswith(ADMIN_PATH):
            response.headers.setdefault("Cache-Control", "no-store")
            response.headers.setdefault("X-Content-Type-Options", "nosniff")
            response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    def admin_operator(request: Request) -> dict[str, Any]:
        access_token = request.cookies.get(ACCESS_COOKIE)
        activity_token = request.cookies.get(ACTIVITY_COOKIE)
        if not access_token or not activity_token:
            raise HTTPException(status_code=401, detail="Sign in required")
        try:
            access_claims = jwt.decode(
                access_token,
                token_secret,
                algorithms=["HS256"],
                options={"verify_exp": False},
            )
            activity_claims = jwt.decode(
                activity_token,
                token_secret,
                algorithms=["HS256"],
            )
            if activity_claims.get("type") != "admin_activity":
                raise ValueError("activity type")
            if str(activity_claims.get("sub")) != str(access_claims.get("sub")):
                raise ValueError("activity account")
            if str(activity_claims.get("sid")) != str(access_claims.get("sid")):
                raise ValueError("activity session")
        except (jwt.PyJWTError, KeyError, TypeError, ValueError) as error:
            raise HTTPException(status_code=401, detail="Admin session expired") from error
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=access_token,
        )
        return require_operator_handler(credentials)

    def admin_owner(request: Request) -> dict[str, Any]:
        operator = admin_operator(request)
        if operator.get("role") != "owner":
            raise HTTPException(status_code=403, detail="Owner access is required")
        return operator

    def write_audit(
        cursor,
        event_type: str,
        actor_id: uuid.UUID | None,
        target_id: uuid.UUID | None,
        source_ip: str | None,
        details: dict[str, Any],
        target_type: str | None = None,
    ) -> None:
        cursor.execute(
            """
            INSERT INTO audit_events (
                actor_account_id, event_type, target_type,
                target_id, source_ip, details
            ) VALUES (%s,%s,%s,%s,%s,%s::jsonb)
            """,
            (
                actor_id,
                event_type,
                target_type or ("operator_account" if target_id else None),
                target_id,
                source_ip,
                json.dumps(details),
            ),
        )

    def recovery_url(request: Request, token: str) -> str:
        proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "https").split(",")[0].strip()
        host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or "localhost").split(",")[0].strip()
        return f"{proto}://{host}{ADMIN_PATH}/recover?token={quote(token)}"

    def create_reset(account_id: uuid.UUID, payload: OperatorAccessResetCreateRequest | RustdwebAccessResetCreateRequest,
                     request: Request, operator: dict[str, Any],
                     *, skip_reauth: bool = False, target_role: str | None = None) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=RESET_MINUTES)
        token = "rdrst_" + secrets.token_urlsafe(48)
        token_digest = _token_hash(token_secret, token)
        source_ip = client_ip_handler(request)
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, username, display_name, role, is_active
                    FROM operator_accounts
                    WHERE id = %s
                      AND deleted_at IS NULL
                    FOR UPDATE
                    """,
                    (account_id,),
                )
                target = cursor.fetchone()
                if target is None:
                    raise HTTPException(status_code=404, detail="Operator account was not found")
                if target_role is not None and target["role"] != target_role:
                    raise HTTPException(status_code=409, detail="Only RustDWeb users (Viewer accounts) are reset here")
                if target["id"] == operator["account_id"]:
                    raise HTTPException(
                        status_code=409,
                        detail="Use Manager self-service to change your own access",
                    )
                # Nobody resets Brad's access through RDS; only the root-only emergency
                # recovery script on the host can.
                if is_protected_account_handler(target):
                    write_audit(
                        cursor,
                        "operator.protected_access_change_blocked",
                        operator["account_id"],
                        account_id,
                        source_ip,
                        {
                            "username": target["username"],
                            "attempted_action": f"access_reset:{payload.reset_mode}",
                            "protection": "Brad's accounts have no web recovery",
                        },
                    )
                    connection.commit()
                    raise HTTPException(status_code=409, detail="This account has no web recovery")

                if not skip_reauth:
                    verify_owner_reauthentication_handler(
                        cursor,
                        operator["account_id"],
                        payload.owner_password,
                        payload.owner_totp_code,
                    )

                cursor.execute(
                    """
                    UPDATE operator_access_resets
                    SET revoked_at = %s
                    WHERE account_id = %s
                      AND used_at IS NULL
                      AND revoked_at IS NULL
                    """,
                    (now, account_id),
                )

                # Owner recovery revokes all active sessions immediately.
                # Password reset modes also invalidate the old password now;
                # authenticator-only recovery preserves the existing password.
                if payload.reset_mode in {"password_only", "password_totp"}:
                    emergency_unknown_password = secrets.token_urlsafe(64)
                    cursor.execute(
                        """
                        UPDATE operator_accounts
                        SET
                            password_hash = crypt(%s, gen_salt('bf', 12)),
                            must_change_password = TRUE,
                            failed_login_count = 0,
                            locked_until = NULL
                        WHERE id = %s
                        """,
                        (emergency_unknown_password, account_id),
                    )
                if payload.reset_mode in {"totp_only", "password_totp"}:
                    cursor.execute(
                        """
                        UPDATE operator_accounts
                        SET
                            totp_secret_ciphertext = NULL,
                            totp_enabled = FALSE,
                            totp_confirmed_at = NULL,
                            failed_login_count = 0,
                            locked_until = NULL
                        WHERE id = %s
                        """,
                        (account_id,),
                    )
                cursor.execute(
                    """
                    UPDATE operator_sessions
                    SET
                        revoked_at = %s,
                        revoked_by = %s,
                        revocation_reason = 'owner_access_reset'
                    WHERE account_id = %s
                      AND revoked_at IS NULL
                    """,
                    (now, operator["account_id"], account_id),
                )
                revoked_sessions = cursor.rowcount

                reset_id = uuid.uuid4()
                cursor.execute(
                    """
                    INSERT INTO operator_access_resets (
                        id, account_id, token_hash, reset_mode,
                        requested_by, reason, source_ip,
                        created_at, expires_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        reset_id,
                        account_id,
                        token_digest,
                        payload.reset_mode,
                        operator["account_id"],
                        payload.reason.strip(),
                        source_ip,
                        now,
                        expires_at,
                    ),
                )
                write_audit(
                    cursor,
                    "operator.access_reset_created",
                    operator["account_id"],
                    account_id,
                    source_ip,
                    {
                        "username": target["username"],
                        "reset_mode": payload.reset_mode,
                        "reason": payload.reason.strip(),
                        "expires_at": expires_at.isoformat(),
                        "revoked_session_count": revoked_sessions,
                    },
                )
                connection.commit()
                return {
                    "reset_id": reset_id,
                    "account_id": account_id,
                    "username": target["username"],
                    "display_name": target["display_name"],
                    "reset_mode": payload.reset_mode,
                    "expires_at": expires_at,
                    "reset_url": recovery_url(request, token),
                    "revoked_session_count": revoked_sessions,
                    "shown_once": True,
                }

    def create_self_reset(
        payload: OperatorSelfAccessResetCreateRequest,
        request: Request,
        operator: dict[str, Any],
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=RESET_MINUTES)
        token = "rdrst_" + secrets.token_urlsafe(48)
        token_digest = _token_hash(token_secret, token)
        source_ip = client_ip_handler(request)
        account_id = operator["account_id"]
        if is_protected_account_handler(operator):
            raise HTTPException(
                status_code=409,
                detail="This account has no web recovery; access changes are made on the host",
            )
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        id, username, display_name, is_active,
                        crypt(%s, password_hash) = password_hash AS password_ok,
                        CASE
                            WHEN totp_secret_ciphertext IS NULL THEN NULL
                            ELSE pgp_sym_decrypt(totp_secret_ciphertext, %s)::text
                        END AS totp_secret
                    FROM operator_accounts
                    WHERE id = %s
                      AND deleted_at IS NULL
                    FOR UPDATE
                    """,
                    (payload.current_password, totp_key, account_id),
                )
                target = cursor.fetchone()
                totp_ok = bool(
                    target
                    and target["totp_secret"]
                    and pyotp.TOTP(target["totp_secret"]).verify(
                        payload.current_totp_code, valid_window=1
                    )
                )
                if (
                    target is None
                    or not target["is_active"]
                    or not target["password_ok"]
                    or not totp_ok
                ):
                    raise HTTPException(
                        status_code=401,
                        detail="Current password or authenticator code is invalid",
                    )

                cursor.execute(
                    """
                    UPDATE operator_access_resets
                    SET revoked_at = %s
                    WHERE account_id = %s
                      AND used_at IS NULL
                      AND revoked_at IS NULL
                    """,
                    (now, account_id),
                )
                reset_id = uuid.uuid4()
                cursor.execute(
                    """
                    INSERT INTO operator_access_resets (
                        id, account_id, token_hash, reset_mode,
                        requested_by, reason, source_ip,
                        created_at, expires_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        reset_id, account_id, token_digest, payload.reset_mode,
                        account_id, payload.reason.strip(), source_ip, now, expires_at,
                    ),
                )
                write_audit(
                    cursor,
                    "operator.self_access_reset_created",
                    account_id,
                    account_id,
                    source_ip,
                    {
                        "username": target["username"],
                        "reset_mode": payload.reset_mode,
                        "reason": payload.reason.strip(),
                        "expires_at": expires_at.isoformat(),
                    },
                )
                connection.commit()
                return {
                    "reset_id": reset_id,
                    "account_id": account_id,
                    "username": target["username"],
                    "display_name": target["display_name"],
                    "reset_mode": payload.reset_mode,
                    "expires_at": expires_at,
                    "reset_url": recovery_url(request, token),
                    "revoked_session_count": 0,
                    "shown_once": True,
                    "self_service": True,
                }

    @app.post(f"{ADMIN_PATH}/api/operator/self/access-reset")
    def admin_create_self_access_reset(
        payload: OperatorSelfAccessResetCreateRequest,
        request: Request,
        operator: dict[str, Any] = Depends(admin_operator),
    ):
        return create_self_reset(payload, request, operator)

    def get_reset(token: str, *, lock: bool = False):
        now = datetime.now(timezone.utc)
        connection = open_database_handler()
        cursor = connection.cursor()
        cursor.execute(
            f"""
            SELECT
                r.id, r.account_id, r.reset_mode, r.created_at,
                r.expires_at, r.used_at, r.revoked_at,
                a.username, a.display_name, a.is_active, a.role,
                a.totp_enabled,
                CASE
                    WHEN a.totp_secret_ciphertext IS NULL THEN NULL
                    ELSE pgp_sym_decrypt(a.totp_secret_ciphertext, %s)::text
                END AS existing_totp_secret
            FROM operator_access_resets r
            JOIN operator_accounts a
              ON a.id = r.account_id
             AND a.deleted_at IS NULL
            WHERE r.token_hash = %s
            {"FOR UPDATE OF r, a" if lock else ""}
            """,
            (totp_key, _token_hash(token_secret, token)),
        )
        row = cursor.fetchone()
        if row is None:
            cursor.close(); connection.close()
            raise HTTPException(status_code=404, detail="Recovery link is invalid")
        # Brad's protected accounts have no web recovery at all (his decision, 2026-10-17): a lost
        # authenticator is fixed on the host, never by a link, so any link for it is dead.
        if is_protected_account_handler({"id": row["account_id"], "username": row["username"]}):
            cursor.close(); connection.close()
            raise HTTPException(status_code=410, detail="Recovery link has already been used or revoked")
        if row["used_at"] is not None or row["revoked_at"] is not None:
            cursor.close(); connection.close()
            raise HTTPException(status_code=410, detail="Recovery link has already been used or revoked")
        if row["expires_at"] <= now:
            cursor.close(); connection.close()
            raise HTTPException(status_code=410, detail="Recovery link has expired")
        return connection, cursor, row

    @app.post("/v1/operators/{account_id}/access-reset")
    def create_operator_access_reset(
        account_id: uuid.UUID,
        payload: OperatorAccessResetCreateRequest,
        request: Request,
        operator: dict[str, Any] = Depends(require_owner_handler),
    ):
        return create_reset(account_id, payload, request, operator)

    @app.post(f"{ADMIN_PATH}/api/rustdweb/users/{{account_id}}/access-reset")
    def admin_create_rustdweb_access_reset(
        account_id: uuid.UUID,
        payload: RustdwebAccessResetCreateRequest,
        request: Request,
        operator: dict[str, Any] = Depends(admin_operator),
    ):
        if operator.get("role") not in ("owner", "manager"):
            raise HTTPException(status_code=403, detail="Owner or Manager access is required")
        return create_reset(account_id, payload, request, operator,
                            skip_reauth=True, target_role="viewer")

    @app.post(f"{ADMIN_PATH}/api/operators/{{account_id}}/access-reset")
    def admin_create_operator_access_reset(
        account_id: uuid.UUID,
        payload: OperatorAccessResetCreateRequest,
        request: Request,
        operator: dict[str, Any] = Depends(admin_owner),
    ):
        return create_reset(account_id, payload, request, operator)

    @app.post("/v1/operator-access-resets/setup")
    def operator_access_reset_setup(payload: OperatorAccessResetTokenRequest):
        connection, cursor, row = get_reset(payload.reset_token)
        try:
            result: dict[str, Any] = {
                "username": row["username"],
                "display_name": row["display_name"],
                "reset_mode": row["reset_mode"],
                "expires_at": row["expires_at"],
            }
            if row["reset_mode"] in {"password_totp", "totp_only"}:
                secret = _b32_hmac_secret(totp_key, payload.reset_token)
                is_rustdweb = row["role"] == "viewer"
                uri = pyotp.TOTP(secret).provisioning_uri(
                    name=row["username"] if is_rustdweb else "Management",
                    issuer_name="RUSTDWEB" if is_rustdweb else "RUST",
                )
                qr = segno.make(uri, error="m", micro=False)
                result["totp_secret"] = secret
                result["totp_provisioning_uri"] = uri
                result["totp_qr_data_uri"] = qr.svg_data_uri(
                    scale=7,
                    border=4,
                    xmldecl=False,
                )
            return result
        finally:
            cursor.close(); connection.close()

    @app.post("/v1/operator-access-resets/accept")
    def operator_access_reset_accept(payload: OperatorAccessResetAcceptRequest, request: Request):
        connection, cursor, row = get_reset(payload.reset_token, lock=True)
        now = datetime.now(timezone.utc)
        source_ip = client_ip_handler(request)
        try:
            password_required = row["reset_mode"] in {
                "password_only", "password_totp"
            }
            if password_required and (
                payload.password is None or len(payload.password) < 12
            ):
                raise HTTPException(
                    status_code=422,
                    detail="A new password of at least 12 characters is required",
                )

            if row["reset_mode"] in {"password_totp", "totp_only"}:
                new_secret = _b32_hmac_secret(totp_key, payload.reset_token)
                totp_ok = pyotp.TOTP(new_secret).verify(
                    payload.totp_code, valid_window=1
                )
            else:
                new_secret = None
                existing = row["existing_totp_secret"]
                totp_ok = bool(existing) and pyotp.TOTP(existing).verify(
                    payload.totp_code, valid_window=1
                )
            if not totp_ok:
                raise HTTPException(status_code=401, detail="Authenticator code is invalid")

            if row["reset_mode"] == "password_totp":
                cursor.execute(
                    """
                    UPDATE operator_accounts
                    SET
                        password_hash = crypt(%s, gen_salt('bf', 12)),
                        totp_secret_ciphertext = pgp_sym_encrypt(%s, %s),
                        totp_enabled = TRUE,
                        totp_confirmed_at = %s,
                        password_changed_at = %s,
                        must_change_password = FALSE,
                        failed_login_count = 0,
                        locked_until = NULL
                    WHERE id = %s
                    """,
                    (payload.password, new_secret, totp_key, now, now, row["account_id"]),
                )
            elif row["reset_mode"] == "totp_only":
                cursor.execute(
                    """
                    UPDATE operator_accounts
                    SET
                        totp_secret_ciphertext = pgp_sym_encrypt(%s, %s),
                        totp_enabled = TRUE,
                        totp_confirmed_at = %s,
                        failed_login_count = 0,
                        locked_until = NULL
                    WHERE id = %s
                    """,
                    (new_secret, totp_key, now, row["account_id"]),
                )
            else:
                cursor.execute(
                    """
                    UPDATE operator_accounts
                    SET
                        password_hash = crypt(%s, gen_salt('bf', 12)),
                        password_changed_at = %s,
                        must_change_password = FALSE,
                        failed_login_count = 0,
                        locked_until = NULL
                    WHERE id = %s
                    """,
                    (payload.password, now, row["account_id"]),
                )

            cursor.execute(
                """
                UPDATE operator_access_resets
                SET used_at = %s, used_ip = %s
                WHERE id = %s
                """,
                (now, source_ip, row["id"]),
            )
            cursor.execute(
                """
                UPDATE operator_sessions
                SET
                    revoked_at = COALESCE(revoked_at, %s),
                    revoked_by = COALESCE(revoked_by, %s),
                    revocation_reason = COALESCE(revocation_reason, 'access_reset_completed')
                WHERE account_id = %s
                """,
                (now, row["account_id"], row["account_id"]),
            )
            write_audit(
                cursor,
                "operator.access_reset_completed",
                None,
                row["account_id"],
                source_ip,
                {
                    "username": row["username"],
                    "reset_mode": row["reset_mode"],
                    "reset_id": str(row["id"]),
                },
            )
            connection.commit()
            return {
                "status": "ok",
                "account_id": row["account_id"],
                "username": row["username"],
                "reset_mode": row["reset_mode"],
                "completed_at": now,
            }
        except Exception:
            connection.rollback()
            raise
        finally:
            cursor.close(); connection.close()

    @app.get(f"{ADMIN_PATH}/recover", response_class=HTMLResponse, include_in_schema=False)
    def operator_access_recovery_page():
        return HTMLResponse(
            _recovery_html(),
            headers={
                "Cache-Control": "no-store",
                "Content-Security-Policy": f"default-src 'self'; img-src 'self' data:; style-src 'unsafe-inline'; script-src {RECOVERY_SCRIPT_CSP}; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
            },
        )

    def relay_guard_status() -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT setting_value FROM security_settings WHERE setting_key='relay_guard_mode'")
                mode_row = cursor.fetchone()
                mode = mode_row["setting_value"] if mode_row else "enforced"
                cursor.execute(
                    """
                    SELECT
                        COUNT(*) AS active_leases,
                        COUNT(DISTINCT source_ip) AS allowed_ips,
                        MIN(l.expires_at) AS next_expiration,
                        MAX(l.expires_at) AS latest_expiration
                    FROM relay_access_leases l
                    JOIN managed_devices d ON d.id = l.device_id
                    JOIN device_credentials c
                      ON c.device_id = d.id
                     AND c.credential_serial = l.credential_serial
                    WHERE l.revoked_at IS NULL
                      AND l.expires_at > %s
                      AND d.status = 'approved'
                      AND c.revoked_at IS NULL
                      AND (c.expires_at IS NULL OR c.expires_at > %s)
                    """,
                    (now, now),
                )
                counts = cursor.fetchone()
                return {
                    "mode": mode,
                    "active_leases": counts["active_leases"],
                    "allowed_ips": counts["allowed_ips"],
                    "next_expiration": counts["next_expiration"],
                    "latest_expiration": counts["latest_expiration"],
                    "lease_seconds": RELAY_LEASE_SECONDS,
                    "renew_after_seconds": RELAY_RENEW_AFTER_SECONDS,
                    **_relay_guard_ports(mode),
                }

    # Relay enforcement is a permanent production policy.  the admin dashboard and
    # public APIs expose read-only diagnostics only.  Emergency staged mode is
    # deliberately a root-level recovery operation performed directly on the
    # server, not a web/API action.
    @app.get("/v1/security/relay-guard")
    def get_relay_guard(operator: dict[str, Any] = Depends(require_operator_handler)):
        del operator
        return relay_guard_status()

    @app.get(f"{ADMIN_PATH}/api/security/relay-guard")
    def admin_get_relay_guard(operator: dict[str, Any] = Depends(admin_operator)):
        del operator
        return relay_guard_status()

    def authorize_device_reenrollment(
        device_id: uuid.UUID,
        payload: DeviceReenrollmentAuthorizationRequest,
        request: Request,
        operator: dict[str, Any],
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=payload.expires_in_minutes)
        source_ip = client_ip_handler(request)

        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, rustdesk_id, hostname, friendly_name, status
                    FROM managed_devices
                    WHERE id = %s
                    FOR UPDATE
                    """,
                    (device_id,),
                )
                device = cursor.fetchone()
                if device is None:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Managed device not found",
                    )
                # "revoked" is genuinely terminal (Brad's explicit design -
                # not reversible without a fresh install); "blocked" is
                # meant to be reversible via this exact re-enrollment flow
                # (main.py's block_device/change_device_status comments and
                # the admin dashboard's own "Authorize re-enrollment" button
                # both already say so) - it was just never actually let
                # through this guard. Fixed 2026-09-23.
                if device["status"] == "revoked":
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=(
                            "Revoked clients are terminal and cannot be "
                            "reauthorized or re-enrolled"
                        ),
                    )
                if device["status"] not in {"pending", "denied", "blocked"}:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=(
                            "Enrollment recovery authorization is only available "
                            "for pending, denied, or blocked devices"
                        ),
                    )

                requires_prior_poll_token = device["status"] != "pending"

                # A device's enrollment_poll_token_hash is set once at its
                # original enrollment and never rotated during normal
                # approved operation - a device blocked after being stable
                # far longer than ENROLLMENT_POLL_DAYS (90 days, main.py)
                # would otherwise have an already-expired poll window with
                # no way back in, even though its original token (which the
                # client still has cached locally) is still the right one.
                # Extend the expiry only - never touch the hash itself, or
                # the client's already-cached token would stop matching.
                if requires_prior_poll_token:
                    cursor.execute(
                        """
                        UPDATE managed_devices
                        SET enrollment_poll_expires_at = %s
                        WHERE id = %s
                          AND enrollment_poll_token_hash IS NOT NULL
                        """,
                        (now + timedelta(days=90), device_id),
                    )

                cursor.execute(
                    """
                    UPDATE device_reenrollment_authorizations
                    SET revoked_at = %s
                    WHERE device_id = %s
                      AND consumed_at IS NULL
                      AND revoked_at IS NULL
                    """,
                    (now, device_id),
                )

                authorization_id = uuid.uuid4()
                cursor.execute(
                    """
                    INSERT INTO device_reenrollment_authorizations (
                        id, device_id, requested_by, reason, source_ip,
                        created_at, expires_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        authorization_id,
                        device_id,
                        operator["account_id"],
                        payload.reason.strip(),
                        source_ip,
                        now,
                        expires_at,
                    ),
                )
                write_audit(
                    cursor,
                    "device.reenrollment_authorized",
                    operator["account_id"],
                    device_id,
                    source_ip,
                    {
                        "rustdesk_id": device["rustdesk_id"],
                        "previous_status": device["status"],
                        "reason": payload.reason.strip(),
                        "expires_at": expires_at.isoformat(),
                        "requires_prior_poll_token": requires_prior_poll_token,
                        "authorized_by_existing_owner_session": True,
                    },
                    target_type="managed_device",
                )
                connection.commit()

        return {
            "status": "authorized",
            "authorization_id": authorization_id,
            "device_id": device_id,
            "rustdesk_id": device["rustdesk_id"],
            "device_status": device["status"],
            "expires_at": expires_at,
            "requires_prior_poll_token": requires_prior_poll_token,
            "instructions": (
                (
                    "The same Pending device may submit POST "
                    "/v1/enrollment/devices with its original identity. "
                    "Its prior poll token is not required."
                )
                if not requires_prior_poll_token
                else (
                    "The same device may submit POST /v1/enrollment/devices "
                    "with its original identity and reenrollment_poll_token."
                )
            ),
        }

    @app.post("/v1/devices/{device_id}/reenrollment-authorization")
    def create_device_reenrollment_authorization(
        device_id: uuid.UUID,
        payload: DeviceReenrollmentAuthorizationRequest,
        request: Request,
        operator: dict[str, Any] = Depends(require_owner_handler),
    ):
        return authorize_device_reenrollment(
            device_id, payload, request, operator
        )

    @app.post(f"{ADMIN_PATH}/api/devices/{{device_id}}/reenrollment-authorization")
    def admin_create_device_reenrollment_authorization(
        device_id: uuid.UUID,
        payload: DeviceReenrollmentAuthorizationRequest,
        request: Request,
        operator: dict[str, Any] = Depends(admin_owner),
    ):
        return authorize_device_reenrollment(
            device_id, payload, request, operator
        )

    # Telemetry a device writes is bounded per device, not only per address (one compromised
    # device could otherwise grow these tables without limit and fake fleet-wide "in session").
    MAX_OPEN_SESSIONS_PER_DEVICE = 8

    def _device_rate_ok(device: dict[str, Any], route: str, limit: int, window: int = 60) -> None:
        if not limiter.allow((route, f"device:{device['device_id']}"), limit, window):
            raise HTTPException(status_code=429, detail="Too many requests; try again shortly")

    @app.post("/v1/device/session-heartbeat")
    def device_session_heartbeat(
        payload: DeviceSessionHeartbeatRequest,
        request: Request,
        device: dict[str, Any] = Depends(require_device_handler),
    ):
        _device_rate_ok(device, "/v1/device/session-heartbeat", 120)
        now = datetime.now(timezone.utc)
        source_ip = _safe_client_ip(client_ip_handler(request))
        peer_rustdesk_id = (
            payload.peer_rustdesk_id.strip()
            if payload.peer_rustdesk_id and payload.peer_rustdesk_id.strip()
            else None
        )
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, ended_at
                    FROM device_active_sessions
                    WHERE reporting_device_id = %s
                      AND session_key = %s
                    FOR UPDATE
                    """,
                    (device["device_id"], payload.session_id),
                )
                existing = cursor.fetchone()

                peer_device_id = None
                if peer_rustdesk_id:
                    cursor.execute(
                        """
                        SELECT id
                        FROM managed_devices
                        WHERE rustdesk_id = %s
                          AND status = 'approved'
                        LIMIT 1
                        """,
                        (peer_rustdesk_id,),
                    )
                    peer = cursor.fetchone()
                    if peer is not None:
                        peer_device_id = peer["id"]
                    else:
                        # Only approved devices can be in a session with a managed device; any
                        # other id is not shown fleet-wide as a session partner.
                        peer_rustdesk_id = None

                if payload.state == "active" and (existing is None or existing["ended_at"] is not None):
                    cursor.execute(
                        """
                        SELECT count(*) AS open_sessions
                        FROM device_active_sessions
                        WHERE reporting_device_id = %s
                          AND ended_at IS NULL
                          AND last_heartbeat_at > %s - interval '2 minutes'
                        """,
                        (device["device_id"], now),
                    )
                    if cursor.fetchone()["open_sessions"] >= MAX_OPEN_SESSIONS_PER_DEVICE:
                        raise HTTPException(status_code=429, detail="Too many open sessions for this device")

                if payload.state == "active":
                    cursor.execute(
                        """
                        INSERT INTO device_active_sessions (
                            reporting_device_id, session_key, session_type,
                            peer_rustdesk_id, source_ip, started_at,
                            last_heartbeat_at, ended_at
                        )
                        VALUES (%s,%s,%s,%s,%s::inet,%s,%s,NULL)
                        ON CONFLICT (reporting_device_id, session_key)
                        DO UPDATE SET
                            session_type = EXCLUDED.session_type,
                            peer_rustdesk_id = EXCLUDED.peer_rustdesk_id,
                            source_ip = EXCLUDED.source_ip,
                            last_heartbeat_at = EXCLUDED.last_heartbeat_at,
                            ended_at = NULL
                        """,
                        (
                            device["device_id"],
                            payload.session_id,
                            payload.session_type,
                            peer_rustdesk_id,
                            source_ip,
                            now,
                            now,
                        ),
                    )
                    if existing is None or existing["ended_at"] is not None:
                        cursor.execute(
                            """
                            INSERT INTO device_activity_events (
                                device_id, event_type, peer_device_id,
                                peer_rustdesk_id, direction, session_key,
                                session_type, source_ip, details, occurred_at
                            )
                            VALUES (
                                %s, 'connection.established', %s, %s,
                                'receiver', %s, %s, %s::inet,
                                %s::jsonb, %s
                            )
                            ON CONFLICT DO NOTHING
                            """,
                            (
                                device["device_id"],
                                peer_device_id,
                                peer_rustdesk_id,
                                payload.session_id,
                                payload.session_type,
                                source_ip,
                                json.dumps({
                                    "source": "session-heartbeat",
                                    "authoritative_direction": "receiver",
                                }),
                                now,
                            ),
                        )
                else:
                    cursor.execute(
                        """
                        UPDATE device_active_sessions
                        SET last_heartbeat_at = %s, ended_at = %s
                        WHERE reporting_device_id = %s
                          AND session_key = %s
                          AND ended_at IS NULL
                        """,
                        (
                            now,
                            now,
                            device["device_id"],
                            payload.session_id,
                        ),
                    )
                    if cursor.rowcount:
                        cursor.execute(
                            """
                            INSERT INTO device_activity_events (
                                device_id, event_type, peer_device_id,
                                peer_rustdesk_id, direction, session_key,
                                session_type, source_ip, details, occurred_at
                            )
                            VALUES (
                                %s, 'connection.ended', %s, %s,
                                'receiver', %s, %s, %s::inet,
                                %s::jsonb, %s
                            )
                            ON CONFLICT DO NOTHING
                            """,
                            (
                                device["device_id"],
                                peer_device_id,
                                peer_rustdesk_id,
                                payload.session_id,
                                payload.session_type,
                                source_ip,
                                json.dumps({
                                    "source": "session-heartbeat",
                                    "authoritative_direction": "receiver",
                                }),
                                now,
                            ),
                        )

                cursor.execute(
                    """
                    DELETE FROM device_active_sessions
                    WHERE COALESCE(ended_at, last_heartbeat_at)
                          < %s - interval '7 days'
                    """,
                    (now,),
                )
                connection.commit()

        return {
            "status": payload.state,
            "session_id": payload.session_id,
            "session_type": payload.session_type,
            "server_time": now,
            "heartbeat_after_seconds": 15,
            "expires_without_heartbeat_seconds": 45,
        }

    @app.post("/v1/device/connection-event")
    def device_connection_event(
        payload: DeviceConnectionEventRequest,
        request: Request,
        device: dict[str, Any] = Depends(require_device_handler),
    ):
        _device_rate_ok(device, "/v1/device/connection-event", 120)
        now = datetime.now(timezone.utc)
        source_ip = _safe_client_ip(client_ip_handler(request))
        peer_rustdesk_id: str | None = payload.peer_rustdesk_id.strip()

        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, status
                    FROM managed_devices
                    WHERE rustdesk_id = %s
                      AND status = 'approved'
                    LIMIT 1
                    """,
                    (peer_rustdesk_id,),
                )
                peer = cursor.fetchone()
                peer_device_id = peer["id"] if peer else None
                if peer is None:
                    # As in session-heartbeat: only an approved device is kept as the peer, so a
                    # device can't write arbitrary ids into the fleet's connection history.
                    peer_rustdesk_id = None

                cursor.execute(
                    """
                    INSERT INTO device_activity_events (
                        device_id, event_type, peer_device_id,
                        peer_rustdesk_id, direction, session_key,
                        session_type, source_ip, details, occurred_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s::inet,
                        %s::jsonb, %s
                    )
                    ON CONFLICT DO NOTHING
                    """,
                    (
                        device["device_id"],
                        "connection." + payload.event,
                        peer_device_id,
                        peer_rustdesk_id,
                        payload.direction,
                        payload.connection_id,
                        payload.session_type,
                        source_ip,
                        json.dumps({
                            "source": "managed-client",
                            "reason": payload.reason,
                            "peer_managed": peer is not None,
                            "peer_status": peer["status"] if peer else None,
                            "timing": payload.timing.model_dump(exclude_none=True)
                            if payload.timing
                            else None,
                        }),
                        now,
                    ),
                )
                connection.commit()

        return {
            "status": "recorded",
            "event": payload.event,
            "connection_id": payload.connection_id,
            "server_time": now,
        }


    @app.post("/v1/device/relay-lease")
    def device_relay_lease(
        request: Request,
        device: dict[str, Any] = Depends(require_device_handler),
    ):
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=RELAY_LEASE_SECONDS)
        source_ip = _safe_client_ip(client_ip_handler(request))
        lease_id = uuid.uuid4()
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE relay_access_leases
                    SET revoked_at = %s
                    WHERE device_id = %s
                      AND revoked_at IS NULL
                    """,
                    (now, device["device_id"]),
                )
                cursor.execute(
                    """
                    INSERT INTO relay_access_leases (
                        id, device_id, credential_serial, source_ip,
                        issued_at, expires_at, last_renewed_at
                    ) VALUES (%s,%s,%s,%s::inet,%s,%s,%s)
                    """,
                    (
                        lease_id,
                        device["device_id"],
                        device["credential_serial"],
                        source_ip,
                        now,
                        expires_at,
                        now,
                    ),
                )
                cursor.execute("SELECT setting_value FROM security_settings WHERE setting_key='relay_guard_mode'")
                mode_row = cursor.fetchone()
                mode = mode_row["setting_value"] if mode_row else "enforced"
                connection.commit()
        return {
            "status": "authorized",
            "lease_id": lease_id,
            "device_id": device["device_id"],
            "credential_serial": device["credential_serial"],
            "source_ip": source_ip,
            "issued_at": now,
            "expires_at": expires_at,
            "renew_after_seconds": RELAY_RENEW_AFTER_SECONDS,
            "firewall_sync_after_seconds": 3,
            "guard_mode": mode,
            "rustdesk_server": "rendezvous.example.com:21116",
            **_relay_guard_ports(mode),
        }
