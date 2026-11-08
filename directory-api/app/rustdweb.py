"""RustDWeb: browser access to RDC Clients through the RustDWeb gateway.

RDS stays the identity authority. The gateway is an enrolled, approved RDC Client named by the setting
rustdweb.gateway_device_id; it calls the /v1/device/rustdweb/* routes below with its own device
credential on behalf of a person who signed in at rustdweb.<domain>. Only Viewer accounts (the "RustDWeb
users") sign in there, with their RDS account and TOTP, and they sign in only there. Owners and Managers
never sign in at RustDWeb; they invite and manage RustDWeb users from the ops console (/ops/api/rustdweb/*).

Sign-in failures: rustdweb.lockout_failures failed sign-ins lock the account for rustdweb.lockout_minutes
(the same locked_until the ops console honours) and block the client IP for as long, except addresses that
are never blocked (private, loopback, Cloudflare, and the rustdweb.never_block list).
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Callable

import pyotp
from fastapi import Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from security_extension import _SlidingWindowLimiter

ADMIN_PATH = "/ops"
# RustDWeb users (the RustDWeb Users tab) only. Ops accounts never sign in here, so their
# password and code never pass through the internet-facing gateway (Brad, 2026-10-17).
ROLES = ("viewer",)

# (default, minimum, maximum)
INT_SETTINGS: dict[str, tuple[int, int, int]] = {
    "max_session_minutes": (480, 15, 1440),
    "idle_disconnect_minutes": (30, 5, 480),
    "max_sessions_per_user": (2, 1, 10),
    "signin_hours": (12, 1, 72),
    "page_idle_minutes": (30, 5, 480),
    "lockout_failures": (2, 1, 10),
    "lockout_minutes": (30, 5, 1440),
}
KEY = "rustdweb.{}".format

# Cloudflare's published ranges (https://www.cloudflare.com/ips): a request can carry one of these only as
# the edge itself, never as a real client, so it is never blocked.
# A remote session still counts as open only while its RustDWeb sign-in is live and it is younger than the
# maximum session length, so a gateway that died without reporting "ended" can't hold a user's slots forever.
OPEN_CONNECTION_SQL = """c.ended_at IS NULL AND c.started_at > now() - make_interval(mins => %(max_minutes)s)
    AND EXISTS (SELECT 1 FROM operator_sessions os WHERE os.id = c.session_id
                AND os.revoked_at IS NULL AND os.expires_at > now())"""

CLOUDFLARE_RANGES = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32",
)]

GENERIC_FAILURE = "Invalid username, password, or authenticator code"
# Sign-in attempts a minute per username + viewer address. Every sign-in reaches RDS from the gateway,
# so the per-address rule in security_extension can only be a gateway-wide backstop: keyed by the
# gateway alone, bad sign-ins from rotating addresses used up everyone's sign-ins.
LOGIN_ATTEMPTS_PER_MINUTE = 10


class RustdwebLoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    totp_code: str = Field(pattern=r"^\d{6}$")
    client_ip: str | None = Field(default=None, max_length=64)
    user_agent: str | None = Field(default=None, max_length=512)


class RustdwebSessionRequest(BaseModel):
    session_token: str = Field(min_length=16, max_length=256)
    activity: bool = False


class RustdwebConnectionEvent(BaseModel):
    session_token: str = Field(min_length=16, max_length=256)
    connection_id: uuid.UUID
    event: str = Field(pattern=r"^(started|authorized|ended)$")
    target_rustdesk_id: str | None = Field(default=None, max_length=32)
    method: str | None = Field(default=None, pattern=r"^(password_totp|accepted|pending)$")
    end_reason: str | None = Field(default=None, max_length=64)
    client_ip: str | None = Field(default=None, max_length=64)


class RustdwebInviteRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    display_name: str = Field(min_length=1, max_length=128)
    expires_in_hours: int = Field(default=72, ge=1, le=720)


class RustdwebReasonRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=1024)


class RustdwebSettingsRequest(BaseModel):
    enabled: bool | None = None
    max_session_minutes: int | None = Field(default=None, ge=15, le=1440)
    idle_disconnect_minutes: int | None = Field(default=None, ge=5, le=480)
    max_sessions_per_user: int | None = Field(default=None, ge=1, le=10)
    signin_hours: int | None = Field(default=None, ge=1, le=72)
    page_idle_minutes: int | None = Field(default=None, ge=5, le=480)
    lockout_failures: int | None = Field(default=None, ge=1, le=10)
    lockout_minutes: int | None = Field(default=None, ge=5, le=1440)
    never_block: str | None = Field(default=None, max_length=2000)
    gateway_device_id: str | None = Field(default=None, max_length=64)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def read_settings(cursor) -> dict[str, Any]:
    cursor.execute("SELECT setting_key, setting_value FROM directory_settings WHERE setting_key LIKE 'rustdweb.%'")
    raw = {row["setting_key"][len("rustdweb."):]: row["setting_value"] for row in cursor.fetchall()}
    out: dict[str, Any] = {}
    for name, (default, low, high) in INT_SETTINGS.items():
        try:
            out[name] = min(max(int(raw.get(name, default)), low), high)
        except (TypeError, ValueError):
            out[name] = default
    out["enabled"] = raw.get("enabled", True) is not False
    out["never_block"] = raw.get("never_block") if isinstance(raw.get("never_block"), str) else ""
    out["gateway_device_id"] = raw.get("gateway_device_id") if isinstance(raw.get("gateway_device_id"), str) else ""
    return out


def parse_never_block(text: str) -> list[ipaddress._BaseNetwork]:
    nets = []
    for part in text.replace(",", " ").split():
        try:
            nets.append(ipaddress.ip_network(part.strip(), strict=False))
        except ValueError:
            continue
    return nets


def parse_ip(value: str | None):
    if not value:
        return None
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def login_rate_key(username: str, ip) -> str:
    """What the sign-in limit counts by: the username and the viewer's address the gateway forwards,
    an IPv6 address by its /64 (one subscriber usually holds it whole; the gateway counts the same)."""
    if ip is not None and ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip is None:
        where = "-"
    elif ip.version == 6:
        where = str(ipaddress.ip_network(f"{ip}/64", strict=False))
    else:
        where = str(ip)
    return f"{username.lower()}|{where}"


def ip_never_blocked(ip, never_block: str) -> bool:
    if ip is None:
        return True
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
        return True
    if any(ip in net for net in CLOUDFLARE_RANGES):
        return True
    return any(ip.version == net.version and ip in net for net in parse_never_block(never_block))


def register_rustdweb_routes(
    *,
    app: Any,
    require_device_handler: Callable[..., dict[str, Any]],
    require_admin_cookie_brad_only_handler: Callable[..., dict[str, Any]],
    open_database_handler: Callable[..., Any],
    write_audit_handler: Callable[..., Any],
    token_hash_handler: Callable[[str], bytes],
    client_ip_handler: Callable[[Request], str | None],
    totp_key: str,
    invitation_request_model: Any,
    account_action_request_model: Any,
    invitation_revoke_request_model: Any,
    create_invitation_handler: Callable[..., dict[str, Any]],
    revoke_invitation_handler: Callable[..., dict[str, Any]],
    disable_operator_handler: Callable[..., dict[str, Any]],
    enable_operator_handler: Callable[..., dict[str, Any]],
    delete_operator_handler: Callable[..., dict[str, Any]],
    unlock_operator_handler: Callable[..., dict[str, Any]],
) -> None:
    def audit(cursor, event_type, *, actor=None, target_type=None, target_id=None, source_ip=None, details=None):
        write_audit_handler(cursor, event_type, actor_account_id=actor, target_type=target_type,
                            target_id=target_id, source_ip=source_ip, details=details or {})

    login_limiter = _SlidingWindowLimiter()

    # ---------------------------------------------------------------- gateway (device credential) side

    def require_gateway(device: dict[str, Any] = Depends(require_device_handler)) -> dict[str, Any]:
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                settings = read_settings(cursor)
        if not settings["gateway_device_id"] or settings["gateway_device_id"] != str(device["device_id"]):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This device is not the RustDWeb gateway")
        # "Turned off" is decided per route: sign-in is refused, a live session check answers 401 so
        # the gateway ends the session, and sign-out / "ended" reports still go through.
        device["rustdweb_settings"] = settings
        return device

    def refuse_when_off(gateway: dict[str, Any], code: int) -> None:
        if not gateway["rustdweb_settings"]["enabled"]:
            raise HTTPException(status_code=code, detail="RustDWeb is turned off")

    def matched_totp_step(secret: str, code: str, now: datetime) -> int | None:
        totp = pyotp.TOTP(secret)
        base = int(now.timestamp()) // totp.interval
        for step in (base, base - 1, base + 1):
            if hmac.compare_digest(totp.generate_otp(step), code):
                return step
        return None

    def record_ip_failure(cursor, ip, settings, now) -> bool:
        """Count a failure for the client IP; True when this failure blocks it."""
        if ip_never_blocked(ip, settings["never_block"]):
            return False
        window = timedelta(minutes=settings["lockout_minutes"])
        cursor.execute("SELECT * FROM rustdweb_ip_blocks WHERE ip = %s FOR UPDATE", (str(ip),))
        row = cursor.fetchone()
        failures = 1
        if row and row["last_failure_at"] and row["last_failure_at"] > now - window:
            failures = row["failures"] + 1
        blocked = failures >= settings["lockout_failures"]
        cursor.execute(
            """
            INSERT INTO rustdweb_ip_blocks (ip, failures, first_failure_at, last_failure_at, blocked_until, blocked_count, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (ip) DO UPDATE SET
                failures = EXCLUDED.failures,
                first_failure_at = COALESCE(CASE WHEN EXCLUDED.failures = 1 THEN EXCLUDED.first_failure_at END,
                                            rustdweb_ip_blocks.first_failure_at),
                last_failure_at = EXCLUDED.last_failure_at,
                blocked_until = COALESCE(EXCLUDED.blocked_until, rustdweb_ip_blocks.blocked_until),
                blocked_count = rustdweb_ip_blocks.blocked_count + EXCLUDED.blocked_count,
                updated_at = EXCLUDED.updated_at
            """,
            (str(ip), 0 if blocked else failures, now, now, now + window if blocked else None, 1 if blocked else 0, now),
        )
        return blocked

    @app.post("/v1/device/rustdweb/login", include_in_schema=False)
    def rustdweb_login(payload: RustdwebLoginRequest, gateway: dict[str, Any] = Depends(require_gateway)):
        refuse_when_off(gateway, status.HTTP_503_SERVICE_UNAVAILABLE)
        settings = gateway["rustdweb_settings"]
        now = _now()
        ip = parse_ip(payload.client_ip)
        ip_text = str(ip) if ip else None
        username = payload.username.strip()
        # Checked before anything touches the database (no audit row either, as for the per-address rule).
        if not login_limiter.allow(("/v1/device/rustdweb/login", login_rate_key(username, ip)), LOGIN_ATTEMPTS_PER_MINUTE, 60):
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                                detail="Too many sign-in attempts. Try again in a minute.",
                                headers={"Retry-After": "60"})
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                if ip is not None:
                    cursor.execute("SELECT blocked_until FROM rustdweb_ip_blocks WHERE ip = %s", (ip_text,))
                    row = cursor.fetchone()
                    if row and row["blocked_until"] and row["blocked_until"] > now:
                        audit(cursor, "rustdweb.login_refused", source_ip=ip_text,
                              details={"username": username, "reason": "ip_blocked", "blocked_until": row["blocked_until"].isoformat()})
                        connection.commit()
                        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                                            detail="Too many failed sign-ins from this address. Try again later.")
                cursor.execute(
                    """
                    SELECT id, username, display_name, role, is_active, deleted_at, must_change_password, totp_enabled,
                           locked_until, rustdweb_failed_count, rustdweb_totp_last_step,
                           crypt(%s, password_hash) = password_hash AS password_ok,
                           CASE WHEN totp_secret_ciphertext IS NULL THEN NULL
                                ELSE pgp_sym_decrypt(totp_secret_ciphertext, %s)::text END AS totp_secret
                    FROM operator_accounts
                    WHERE LOWER(username) = LOWER(%s)
                    FOR UPDATE
                    """,
                    (payload.password, totp_key, username),
                )
                account = cursor.fetchone()
                reason, step = None, None
                if account is None:
                    reason = "invalid_credentials"
                elif account["deleted_at"] is not None or not account["is_active"]:
                    reason = "account_unavailable"
                elif account["locked_until"] is not None and account["locked_until"] > now:
                    reason = "account_locked"
                elif account["role"] not in ROLES:
                    reason = "role_not_allowed"
                elif not account["totp_enabled"] or account["totp_secret"] is None:
                    reason = "totp_enrollment_required"
                else:
                    step = matched_totp_step(account["totp_secret"], payload.totp_code, now)
                    if not account["password_ok"] or step is None:
                        reason = "invalid_credentials"
                    elif account["rustdweb_totp_last_step"] is not None and step <= account["rustdweb_totp_last_step"]:
                        reason = "totp_replayed"
                    elif account["must_change_password"]:
                        reason = "password_change_required"

                if reason is not None:
                    details: dict[str, Any] = {"username": username, "reason": reason}
                    # Only RustDWeb accounts count failures here: trying an ops username at RustDWeb must
                    # not be a way to lock that ops account out of the console.
                    if account is not None and account["role"] in ROLES and reason in (
                            "invalid_credentials", "totp_replayed", "totp_enrollment_required", "password_change_required"):
                        failures = account["rustdweb_failed_count"] + 1
                        locked_until = None
                        if failures >= settings["lockout_failures"]:
                            locked_until = now + timedelta(minutes=settings["lockout_minutes"])
                            failures = 0
                        cursor.execute(
                            "UPDATE operator_accounts SET rustdweb_failed_count = %s, locked_until = COALESCE(%s, locked_until) WHERE id = %s",
                            (failures, locked_until, account["id"]),
                        )
                        if locked_until is not None:
                            details["account_locked_until"] = locked_until.isoformat()
                            audit(cursor, "rustdweb.account_locked", target_type="operator_account", target_id=account["id"],
                                  source_ip=ip_text, details={"username": account["username"], "locked_until": locked_until.isoformat()})
                    if ip is not None and record_ip_failure(cursor, ip, settings, now):
                        details["ip_blocked_minutes"] = settings["lockout_minutes"]
                        audit(cursor, "rustdweb.ip_blocked", source_ip=ip_text,
                              details={"username": username, "minutes": settings["lockout_minutes"]})
                    audit(cursor, "rustdweb.login_failed",
                          target_type="operator_account" if account else None, target_id=account["id"] if account else None,
                          source_ip=ip_text, details=details)
                    connection.commit()
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=GENERIC_FAILURE)

                cursor.execute(
                    "UPDATE operator_accounts SET rustdweb_failed_count = 0, rustdweb_totp_last_step = %s WHERE id = %s",
                    (step, account["id"]),
                )
                if ip is not None:
                    cursor.execute("UPDATE rustdweb_ip_blocks SET failures = 0, updated_at = %s WHERE ip = %s", (now, ip_text))
                session_id = uuid.uuid4()
                token = "rdw_" + secrets.token_urlsafe(32)
                expires_at = now + timedelta(hours=settings["signin_hours"])
                cursor.execute(
                    """
                    INSERT INTO operator_sessions (id, account_id, access_token_hash, refresh_token_hash, mfa_verified_at,
                                                   source_ip, user_agent, created_at, expires_at, last_seen_at, scope)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'rustdweb')
                    """,
                    (session_id, account["id"], token_hash_handler(token),
                     token_hash_handler("rdw_unused_" + secrets.token_urlsafe(32)), now, ip_text,
                     (payload.user_agent or "")[:512] or None, now, expires_at, now),
                )
                audit(cursor, "rustdweb.login_succeeded", actor=account["id"], target_type="operator_account",
                      target_id=account["id"], source_ip=ip_text,
                      details={"username": account["username"], "role": account["role"], "session_id": str(session_id)})
                connection.commit()
        return {
            "session_token": token,
            "session_id": session_id,
            "expires_at": expires_at,
            "account": {"id": account["id"], "username": account["username"],
                        "display_name": account["display_name"], "role": account["role"]},
            "limits": {k: settings[k] for k in ("max_session_minutes", "idle_disconnect_minutes", "max_sessions_per_user", "page_idle_minutes")},
        }

    def load_session(cursor, token: str, *, for_update: bool = True) -> dict[str, Any] | None:
        cursor.execute(
            f"""
            SELECT s.id AS session_id, s.account_id, s.expires_at, s.last_seen_at, s.revoked_at, s.source_ip,
                   a.username, a.display_name, a.role, a.is_active, a.deleted_at
            FROM operator_sessions s JOIN operator_accounts a ON a.id = s.account_id
            WHERE s.access_token_hash = %s AND s.scope = 'rustdweb'
            {"FOR UPDATE OF s" if for_update else ""}
            """,
            (token_hash_handler(token),),
        )
        return cursor.fetchone()

    def active_session(cursor, token: str, settings: dict[str, Any], now: datetime) -> dict[str, Any]:
        row = load_session(cursor, token)
        if (row is None or row["revoked_at"] is not None or row["expires_at"] <= now
                or not row["is_active"] or row["deleted_at"] is not None or row["role"] not in ROLES):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="RustDWeb session is not valid")
        idle_limit = timedelta(minutes=settings["page_idle_minutes"])
        if row["last_seen_at"] is not None and row["last_seen_at"] < now - idle_limit:
            cursor.execute(
                "UPDATE operator_sessions SET revoked_at = %s, revoked_by = %s, revocation_reason = 'rustdweb_page_idle' WHERE id = %s",
                (now, row["account_id"], row["session_id"]),
            )
            return {"expired": True, **row}
        return row

    @app.post("/v1/device/rustdweb/session", include_in_schema=False)
    def rustdweb_session(payload: RustdwebSessionRequest, gateway: dict[str, Any] = Depends(require_gateway)):
        refuse_when_off(gateway, status.HTTP_401_UNAUTHORIZED)
        settings = gateway["rustdweb_settings"]
        now = _now()
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                row = active_session(cursor, payload.session_token, settings, now)
                if row.get("expired"):
                    connection.commit()
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="RustDWeb session ended after inactivity")
                if payload.activity:
                    cursor.execute("UPDATE operator_sessions SET last_seen_at = %s WHERE id = %s", (now, row["session_id"]))
                connection.commit()
        return {
            "session_id": row["session_id"],
            "expires_at": row["expires_at"],
            "account": {"id": row["account_id"], "username": row["username"], "display_name": row["display_name"], "role": row["role"]},
            "limits": {k: settings[k] for k in ("max_session_minutes", "idle_disconnect_minutes", "max_sessions_per_user", "page_idle_minutes")},
        }

    @app.post("/v1/device/rustdweb/logout", include_in_schema=False)
    def rustdweb_logout(payload: RustdwebSessionRequest, gateway: dict[str, Any] = Depends(require_gateway)):
        now = _now()
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                row = load_session(cursor, payload.session_token)
                if row is not None and row["revoked_at"] is None:
                    cursor.execute(
                        "UPDATE operator_sessions SET revoked_at = %s, revoked_by = %s, revocation_reason = 'rustdweb_logout' WHERE id = %s",
                        (now, row["account_id"], row["session_id"]),
                    )
                    audit(cursor, "rustdweb.logout", actor=row["account_id"], target_type="operator_account",
                          target_id=row["account_id"], details={"session_id": str(row["session_id"])})
                connection.commit()
        return {"status": "signed_out"}

    @app.post("/v1/device/rustdweb/connection-event", include_in_schema=False)
    def rustdweb_connection_event(payload: RustdwebConnectionEvent, gateway: dict[str, Any] = Depends(require_gateway)):
        if payload.event != "ended":
            refuse_when_off(gateway, status.HTTP_503_SERVICE_UNAVAILABLE)
        settings = gateway["rustdweb_settings"]
        now = _now()
        ip = parse_ip(payload.client_ip)
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                if payload.event == "ended":
                    # Recorded even after the session was ended or expired: that is usually why it ended.
                    row = load_session(cursor, payload.session_token, for_update=False)
                    if row is None:
                        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown RustDWeb session")
                    cursor.execute(
                        """
                        UPDATE rustdweb_connections SET ended_at = %s, end_reason = %s
                        WHERE id = %s AND account_id = %s AND ended_at IS NULL
                        RETURNING started_at, target_rustdesk_id, method
                        """,
                        (now, (payload.end_reason or "ended")[:64], payload.connection_id, row["account_id"]),
                    )
                    ended = cursor.fetchone()
                    if ended:
                        audit(cursor, "rustdweb.connection_ended", actor=row["account_id"], target_type="rustdweb_connection",
                              target_id=payload.connection_id,
                              details={"target_rustdesk_id": ended["target_rustdesk_id"], "method": ended["method"],
                                       "seconds": int((now - ended["started_at"]).total_seconds()),
                                       "end_reason": payload.end_reason or "ended"})
                    connection.commit()
                    return {"status": "recorded"}

                row = active_session(cursor, payload.session_token, settings, now)
                if row.get("expired"):
                    connection.commit()
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="RustDWeb session ended after inactivity")

                if payload.event == "authorized":
                    cursor.execute(
                        "UPDATE rustdweb_connections SET method = %s WHERE id = %s AND account_id = %s AND ended_at IS NULL",
                        (payload.method or "accepted", payload.connection_id, row["account_id"]),
                    )
                    connection.commit()
                    return {"status": "recorded"}

                if not payload.target_rustdesk_id:
                    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="target_rustdesk_id is required")
                cursor.execute(
                    "SELECT id, friendly_name, hostname FROM managed_devices WHERE rustdesk_id = %s AND status = 'approved'",
                    (payload.target_rustdesk_id,),
                )
                target = cursor.fetchone()
                if target is None:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="That Client is not an approved RDC Client")
                cursor.execute(
                    f"SELECT count(*) AS n FROM rustdweb_connections c WHERE c.account_id = %(account)s AND {OPEN_CONNECTION_SQL}",
                    {"account": row["account_id"], "max_minutes": settings["max_session_minutes"]},
                )
                if cursor.fetchone()["n"] >= settings["max_sessions_per_user"]:
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                        detail=f"You already have {settings['max_sessions_per_user']} remote session(s) open")
                cursor.execute(
                    """
                    INSERT INTO rustdweb_connections (id, session_id, account_id, target_device_id, target_rustdesk_id,
                                                      target_name, method, client_ip, started_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (payload.connection_id, row["session_id"], row["account_id"], target["id"], payload.target_rustdesk_id,
                     target["friendly_name"] or target["hostname"], payload.method or "pending",
                     str(ip) if ip else None, now),
                )
                cursor.execute("UPDATE operator_sessions SET last_seen_at = %s WHERE id = %s", (now, row["session_id"]))
                audit(cursor, "rustdweb.connection_started", actor=row["account_id"], target_type="rustdweb_connection",
                      target_id=payload.connection_id, source_ip=str(ip) if ip else None,
                      details={"target_rustdesk_id": payload.target_rustdesk_id,
                               "target_name": target["friendly_name"] or target["hostname"]})
                connection.commit()
        return {"status": "allowed", "limits": {k: settings[k] for k in ("max_session_minutes", "idle_disconnect_minutes")}}

    @app.get("/v1/device/rustdweb/settings", include_in_schema=False)
    def rustdweb_gateway_settings(gateway: dict[str, Any] = Depends(require_gateway)):
        s = gateway["rustdweb_settings"]
        return {k: s[k] for k in ("enabled", *INT_SETTINGS)}

    # ---------------------------------------------------------------- ops console side

    def require_manager(request: Request) -> dict[str, Any]:
        # The ops console's own Owner-or-Manager cookie check (admin_ui.require_admin_device_manager).
        return app.state.admin_require_owner_or_manager(request)

    def viewer_or_404(cursor, account_id: uuid.UUID) -> dict[str, Any]:
        cursor.execute(
            "SELECT id, username, role FROM operator_accounts WHERE id = %s AND deleted_at IS NULL",
            (account_id,),
        )
        target = cursor.fetchone()
        if target is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="RustDWeb user was not found")
        if target["role"] != "viewer":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail="Only RustDWeb users (Viewer accounts) are managed here")
        return target

    @app.get(f"{ADMIN_PATH}/api/rustdweb/users", include_in_schema=False)
    def admin_rustdweb_users(operator: dict[str, Any] = Depends(require_manager)):
        now = _now()
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                settings = read_settings(cursor)
                cursor.execute(
                    f"""
                    SELECT a.id, a.username, a.display_name, a.email, a.is_active, a.totp_enabled,
                           a.locked_until, a.rustdweb_failed_count, a.created_at,
                           (SELECT max(s.created_at) FROM operator_sessions s WHERE s.account_id = a.id AND s.scope = 'rustdweb') AS last_signin_at,
                           (SELECT count(*) FROM operator_sessions s WHERE s.account_id = a.id AND s.scope = 'rustdweb'
                               AND s.revoked_at IS NULL AND s.expires_at > now()) AS live_signins,
                           (SELECT count(*) FROM rustdweb_connections c WHERE c.account_id = a.id AND {OPEN_CONNECTION_SQL}) AS open_connections
                    FROM operator_accounts a
                    WHERE a.role = 'viewer' AND a.deleted_at IS NULL
                    ORDER BY lower(a.display_name)
                    """,
                    {"max_minutes": settings["max_session_minutes"]},
                )
                users = cursor.fetchall()
                cursor.execute(
                    """
                    SELECT i.id, i.proposed_username, i.proposed_display_name, i.created_at, i.expires_at,
                           o.display_name AS created_by_name
                    FROM operator_invitations i LEFT JOIN operator_accounts o ON o.id = i.created_by
                    WHERE i.requested_role = 'viewer' AND i.status = 'pending' AND i.expires_at > now()
                    ORDER BY i.created_at DESC
                    """
                )
                invitations = cursor.fetchall()
                cursor.execute(
                    "SELECT ip, blocked_until, blocked_count FROM rustdweb_ip_blocks WHERE blocked_until > now() ORDER BY blocked_until DESC"
                )
                blocks = cursor.fetchall()
        for u in users:
            u["locked"] = bool(u["locked_until"] and u["locked_until"] > now)
        return {
            "users": users,
            "invitations": invitations,
            "ip_blocks": [{**b, "ip": str(b["ip"])} for b in blocks],
            "lockout": {"failures": settings["lockout_failures"], "minutes": settings["lockout_minutes"]},
            "enabled": settings["enabled"],
        }

    @app.post(f"{ADMIN_PATH}/api/rustdweb/invitations", include_in_schema=False)
    def admin_rustdweb_invite(payload: RustdwebInviteRequest, request: Request,
                              operator: dict[str, Any] = Depends(require_manager)):
        invite = invitation_request_model(username=payload.username, display_name=payload.display_name,
                                          role="viewer", expires_in_hours=payload.expires_in_hours)
        return create_invitation_handler(payload=invite, request=request, operator=operator)

    @app.post(f"{ADMIN_PATH}/api/rustdweb/invitations/{{invitation_id}}/revoke", include_in_schema=False)
    def admin_rustdweb_revoke_invite(invitation_id: uuid.UUID, payload: RustdwebReasonRequest, request: Request,
                                     operator: dict[str, Any] = Depends(require_manager)):
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT requested_role FROM operator_invitations WHERE id = %s", (invitation_id,))
                row = cursor.fetchone()
        if row is None or row["requested_role"] != "viewer":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="RustDWeb invitation was not found")
        return revoke_invitation_handler(invitation_id=invitation_id,
                                         payload=invitation_revoke_request_model(reason=payload.reason),
                                         request=request, operator=operator)

    @app.post(f"{ADMIN_PATH}/api/rustdweb/users/{{account_id}}/{{action}}", include_in_schema=False)
    def admin_rustdweb_user_action(account_id: uuid.UUID, action: str, payload: RustdwebReasonRequest, request: Request,
                                   operator: dict[str, Any] = Depends(require_manager)):
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                target = viewer_or_404(cursor, account_id)
        reason_payload = account_action_request_model(reason=payload.reason)
        handlers = {
            "disable": disable_operator_handler,
            "enable": enable_operator_handler,
            "delete": delete_operator_handler,
            "unlock": unlock_operator_handler,
        }
        if action in handlers:
            result = handlers[action](account_id=account_id, payload=reason_payload, request=request, operator=operator)
            if action == "unlock":
                with open_database_handler() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute("UPDATE operator_accounts SET rustdweb_failed_count = 0 WHERE id = %s", (account_id,))
                        connection.commit()
            return result
        if action == "end-sessions":
            now = _now()
            with open_database_handler() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        UPDATE operator_sessions SET revoked_at = %s, revoked_by = %s, revocation_reason = 'rustdweb_ended_by_operator'
                        WHERE account_id = %s AND scope = 'rustdweb' AND revoked_at IS NULL
                        """,
                        (now, operator["account_id"], account_id),
                    )
                    ended = cursor.rowcount
                    audit(cursor, "rustdweb.sessions_ended", actor=operator["account_id"], target_type="operator_account",
                          target_id=account_id, source_ip=client_ip_handler(request),
                          details={"username": target["username"], "sessions": ended, "reason": payload.reason.strip()})
                    connection.commit()
            return {"status": "ended", "sessions": ended}
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown action")

    @app.get(f"{ADMIN_PATH}/api/rustdweb/users/{{account_id}}/history", include_in_schema=False)
    def admin_rustdweb_user_history(account_id: uuid.UUID, operator: dict[str, Any] = Depends(require_manager)):
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                target = viewer_or_404(cursor, account_id)
                cursor.execute(
                    """
                    SELECT id, target_rustdesk_id, target_name, method, client_ip, started_at, ended_at, end_reason
                    FROM rustdweb_connections WHERE account_id = %s ORDER BY started_at DESC LIMIT 100
                    """,
                    (account_id,),
                )
                connections = cursor.fetchall()
                cursor.execute(
                    """
                    SELECT event_type, source_ip, details, created_at FROM audit_events
                    WHERE event_type LIKE 'rustdweb.%%' AND target_type = 'operator_account' AND target_id = %s
                    ORDER BY created_at DESC LIMIT 50
                    """,
                    (account_id,),
                )
                events = cursor.fetchall()
        return {
            "user": {"id": target["id"], "username": target["username"]},
            "connections": [{**c, "client_ip": str(c["client_ip"]) if c["client_ip"] else None} for c in connections],
            "events": [{**e, "source_ip": str(e["source_ip"]) if e["source_ip"] else None} for e in events],
        }

    @app.post(f"{ADMIN_PATH}/api/rustdweb/ip-blocks/{{ip}}/clear", include_in_schema=False)
    def admin_rustdweb_clear_ip(ip: str, payload: RustdwebReasonRequest, request: Request,
                                operator: dict[str, Any] = Depends(require_manager)):
        parsed = parse_ip(ip)
        if parsed is None:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Not an IP address")
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute("UPDATE rustdweb_ip_blocks SET blocked_until = NULL, failures = 0, updated_at = now() WHERE ip = %s",
                               (str(parsed),))
                audit(cursor, "rustdweb.ip_unblocked", actor=operator["account_id"], source_ip=client_ip_handler(request),
                      details={"ip": str(parsed), "reason": payload.reason.strip()})
                connection.commit()
        return {"status": "cleared", "ip": str(parsed)}

    @app.get(f"{ADMIN_PATH}/api/rustdweb/settings", include_in_schema=False)
    def admin_rustdweb_settings(operator: dict[str, Any] = Depends(require_admin_cookie_brad_only_handler)):
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                return read_settings(cursor)

    @app.post(f"{ADMIN_PATH}/api/rustdweb/settings", include_in_schema=False)
    def admin_rustdweb_save_settings(payload: RustdwebSettingsRequest, request: Request,
                                     operator: dict[str, Any] = Depends(require_admin_cookie_brad_only_handler)):
        updates: list[tuple[str, str]] = []
        for name in INT_SETTINGS:
            value = getattr(payload, name)
            if value is not None:
                updates.append((KEY(name), str(int(value))))
        if payload.enabled is not None:
            updates.append((KEY("enabled"), "true" if payload.enabled else "false"))
        if payload.never_block is not None:
            entries = [p for p in payload.never_block.replace(",", " ").split() if p]
            bad = [p for p in entries if not parse_never_block(p)]
            if bad:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                    detail=f"Not an IP address or network: {', '.join(bad[:3])}")
            updates.append((KEY("never_block"), json.dumps(" ".join(entries))))
        if payload.gateway_device_id is not None:
            value = payload.gateway_device_id.strip()
            if value:
                try:
                    value = str(uuid.UUID(value))
                except ValueError:
                    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Gateway device id must be a device UUID")
            updates.append((KEY("gateway_device_id"), json.dumps(value)))
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                before = read_settings(cursor)
                for key, value in updates:
                    cursor.execute(
                        """
                        INSERT INTO directory_settings (setting_key, setting_value, updated_by)
                        VALUES (%s, %s::jsonb, %s)
                        ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value,
                            updated_by = EXCLUDED.updated_by, updated_at = now()
                        """,
                        (key, value, operator["account_id"]),
                    )
                after = read_settings(cursor)
                ended = 0
                if (before["enabled"] and not after["enabled"]) or before["gateway_device_id"] != after["gateway_device_id"]:
                    # Turning RustDWeb off or moving it to another gateway ends every sign-in now, so live
                    # sessions stop at the gateway's next check instead of running to their limits.
                    cursor.execute(
                        """
                        UPDATE operator_sessions
                        SET revoked_at = now(), revoked_by = %s, revocation_reason = 'rustdweb_turned_off'
                        WHERE scope = 'rustdweb' AND revoked_at IS NULL
                        """,
                        (operator["account_id"],),
                    )
                    ended = cursor.rowcount
                audit(cursor, "rustdweb.settings_changed", actor=operator["account_id"], source_ip=client_ip_handler(request),
                      details={"changed": [k for k, _ in updates], "sessions_ended": ended})
                connection.commit()
                return after
