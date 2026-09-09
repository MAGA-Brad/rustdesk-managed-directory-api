from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
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

# Public rendezvous server (hbbs) address handed to clients in relay-lease
# responses, host:port. Set this to your own hbbs deployment.
RUSTDESK_SERVER_ADDRESS = os.getenv("RUSTDESK_SERVER_ADDRESS", "rendezvous.example.com:21116")


class OperatorAccessResetCreateRequest(BaseModel):
    reset_mode: str = Field(
        pattern=r"^(password_only|totp_only|password_totp)$"
    )
    reason: str = Field(min_length=1, max_length=1024)
    owner_password: str = Field(min_length=1, max_length=256)
    owner_totp_code: str = Field(pattern=r"^\d{6}$")


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


class DeviceReenrollmentAuthorizationRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=1024)
    expires_in_minutes: int = Field(default=REENROLLMENT_AUTH_MINUTES, ge=5, le=120)


class _SlidingWindowLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def allow(self, key: tuple[str, str], limit: int, window: int) -> bool:
        now = time.monotonic()
        cutoff = now - window
        with self._lock:
            bucket = self._events[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                return False
            bucket.append(now)
            return True


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
    <section id="success" class="hidden ok">Access has been reset successfully. You can now close this page and sign in with the new password.</section>
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
    document.getElementById("success").classList.remove("hidden");
  }catch(e){errorBox.textContent=e.message;}finally{b.disabled=false;b.textContent="Update access";}
});
void load();
</script>
</body>
</html>'''


def register_security_extension(
    *,
    app: Any,
    open_database_handler: Callable[..., Any],
    require_operator_handler: Callable[..., dict[str, Any]],
    require_owner_handler: Callable[..., dict[str, Any]],
    require_device_handler: Callable[..., dict[str, Any]],
    verify_owner_reauthentication_handler: Callable[..., Any],
    client_ip_handler: Callable[..., str | None],
    token_secret: str,
    totp_key: str,
) -> None:
    limiter = _SlidingWindowLimiter()

    @app.middleware("http")
    async def rustdesk_security_rate_limit(request: Request, call_next):
        path = request.url.path
        rules = {
            "/v1/auth/login": (30, 60),
            "/v1/enrollment/devices": (12, 60),
            "/v1/enrollment/status": (60, 60),
            "/v1/operator-access-resets/setup": (30, 60),
            "/v1/operator-access-resets/accept": (20, 60),
            f"{ADMIN_PATH}/api/operator/self/access-reset": (10, 60),
            "/v1/device/relay-lease": (60, 60),
            "/v1/device/session-heartbeat": (300, 60),
        }
        rule = rules.get(path)
        if rule is not None:
            raw_ip = client_ip_handler(request) or "unknown"
            if not limiter.allow((path, raw_ip), rule[0], rule[1]):
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
        host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or "ops.example.com").split(",")[0].strip()
        return f"{proto}://{host}{ADMIN_PATH}/recover?token={quote(token)}"

    def create_reset(account_id: uuid.UUID, payload: OperatorAccessResetCreateRequest, request: Request, operator: dict[str, Any]) -> dict[str, Any]:
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
                if target["id"] == operator["account_id"]:
                    raise HTTPException(
                        status_code=409,
                        detail="Use Manager self-service to change your own access",
                    )

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
                a.username, a.display_name, a.is_active,
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
                uri = pyotp.TOTP(secret).provisioning_uri(
                    name="Management",
                    issuer_name="RUST",
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
                "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
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
                    "guarded_tcp_ports": [21115, 21116, 21117, 21118, 21119],
                    "guarded_udp_ports": [21116],
                    "closed_tcp_ports": [],
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
                if device["status"] in {"blocked", "revoked"}:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=(
                            "Blocked clients are terminal and cannot be "
                            "reauthorized or re-enrolled"
                        ),
                    )
                if device["status"] not in {"pending", "denied"}:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=(
                            "Enrollment recovery authorization is only available "
                            "for pending or denied devices"
                        ),
                    )

                requires_prior_poll_token = device["status"] != "pending"

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

    @app.post("/v1/device/session-heartbeat")
    def device_session_heartbeat(
        payload: DeviceSessionHeartbeatRequest,
        request: Request,
        device: dict[str, Any] = Depends(require_device_handler),
    ):
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
                        LIMIT 1
                        """,
                        (peer_rustdesk_id,),
                    )
                    peer = cursor.fetchone()
                    if peer is not None:
                        peer_device_id = peer["id"]

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
        now = datetime.now(timezone.utc)
        source_ip = _safe_client_ip(client_ip_handler(request))
        peer_rustdesk_id = payload.peer_rustdesk_id.strip()

        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, status
                    FROM managed_devices
                    WHERE rustdesk_id = %s
                    LIMIT 1
                    """,
                    (peer_rustdesk_id,),
                )
                peer = cursor.fetchone()
                peer_device_id = peer["id"] if peer else None

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
            "rustdesk_server": RUSTDESK_SERVER_ADDRESS,
            "guarded_tcp_ports": [21115, 21116, 21117, 21118, 21119],
            "guarded_udp_ports": [21116],
        }
