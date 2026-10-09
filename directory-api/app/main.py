import time
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
import logging
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import ssl
import uuid
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

import jwt
import psycopg
import pyotp
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from psycopg.rows import dict_row

app = FastAPI(
    title="RustDesk Directory API",
    version="0.9.0",
)

TOKEN_SECRET = os.environ["TOKEN_SIGNING_SECRET"]
DEVICE_SECRET = os.environ["DEVICE_CREDENTIAL_SECRET"]
TOTP_KEY = os.environ["TOTP_ENCRYPTION_SECRET"]

# Mobile companion app (client-manager Android app) config. All optional at
# startup - the mobile-app routes still work without them (push just no-ops)
# so the container doesn't crash-loop before this is fully provisioned.
HEALTH_WATCHER_SHARED_SECRET = os.environ.get("HEALTH_WATCHER_SHARED_SECRET") or None
FIREBASE_PROJECT_ID = os.environ.get("FIREBASE_PROJECT_ID") or None
_firebase_service_account_file = os.environ.get("FIREBASE_SERVICE_ACCOUNT_FILE") or None
FIREBASE_SERVICE_ACCOUNT: dict[str, Any] | None = None
if _firebase_service_account_file:
    try:
        FIREBASE_SERVICE_ACCOUNT = json.loads(
            Path(_firebase_service_account_file).read_text(encoding="utf-8")
        )
    except (OSError, ValueError):
        FIREBASE_SERVICE_ACCOUNT = None

# Outbound mail (first step toward mail-server integration). Optional at startup
# for the same crash-loop-avoidance reason as the mobile-app secrets above -
# the smtp-config endpoints simply refuse to work (503) until this is set.
SMTP_ENCRYPTION_SECRET = os.environ.get("SMTP_ENCRYPTION_SECRET") or None

# Managed peer authentication: RDS signs short-lived device certificates that RDC clients and hbbs
# verify with the matching public key built into them, so only approved devices can connect to
# each other on any route. Optional at startup like the secrets above - without it the peer-cert
# endpoints answer 503 and clients keep running in their configured mode.
PEER_AUTH_MODE_KEY = "peer_auth.mode"
PEER_AUTH_MODES = ("off", "log", "enforce")
PEER_CERT_LIFETIME_HOURS_KEY = "peer_auth.cert_lifetime_hours"
PEER_CERT_RENEW_AFTER_HOURS_KEY = "peer_auth.cert_renew_after_hours"
# How long an RDC controller tries a direct connection before also starting the relay (both race;
# the first to connect wins). Sent to clients with the directory; Config page -> Remote Connections.
RELAY_FALLBACK_DELAY_MS_KEY = "connection.relay_fallback_delay_ms"
RELAY_FALLBACK_DELAY_MS_FALLBACK = 1500
# sec5: hbbs's signed key exchange on device connections (off/optional/required). The host's
# approved-ids sync timer copies it into hbbs's rendezvous_settings file, and brings hbbs's latest
# 5-minute counts (rendezvous_stats) back into RENDEZVOUS_ENCRYPTION_STATS_KEY.
RENDEZVOUS_ENCRYPTION_KEY = "relay.rendezvous_encryption"
RENDEZVOUS_ENCRYPTION_MODES = ("off", "optional", "required")
# Managed clients from this build on require hbbs's key exchange: with it off they cannot connect.
RENDEZVOUS_ENCRYPTION_REQUIRED_BUILD = 30
RENDEZVOUS_ENCRYPTION_STATS_KEY = "relay.rendezvous_encryption_stats"
# sec5: whether hbbs forwards WebRTC offers - off, test (only to the ids in RELAY_WEBRTC_TEST_IDS_KEY,
# devices set up with our STUN server by hand) or on. Synced to hbbs the same way.
RELAY_WEBRTC_KEY = "relay.webrtc"
RELAY_WEBRTC_MODES = ("off", "test", "on")
RELAY_WEBRTC_TEST_IDS_KEY = "relay.webrtc_test_ids"
# Device passports: hbbs's passport check on device connections - off, log (count only), test (refuse only
# where a device in RELAY_PASSPORT_TEST_IDS_KEY is involved), enforce. The host's approved-ids timer
# copies it into hbbs's rendezvous_settings with the identity-key list, and brings hbbs's latest
# 5-minute counts back into RELAY_PASSPORT_STATS_KEY.
RELAY_PASSPORT_KEY = "relay.passport_check"
RELAY_PASSPORT_MODES = ("off", "log", "test", "enforce")
RELAY_PASSPORT_TEST_IDS_KEY = "relay.passport_test_ids"
RELAY_PASSPORT_STATS_KEY = "relay.passport_stats"
# Clients from this build on prove their passport to hbbs; older ones can't connect under Enforce.
PASSPORT_CHECK_READY_BUILD = 34
PEER_AUTH_READY_BUILD = 28
PEER_AUTH_ACTIVE_DAYS = 14


def _load_peer_ca_key():
    value = os.environ.get("PEER_CA_PRIVATE_KEY") or None
    if value is None:
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(value, validate=True))
    except (binascii.Error, ValueError) as error:
        print(f"PEER_CA_PRIVATE_KEY is invalid; peer certificates are disabled: {error}")
        return None


PEER_CA_KEY = _load_peer_ca_key()

ACCESS_TOKEN_MINUTES = 15
SESSION_DAYS = 30
# Brad's explicit ask: the mobile companion app should never force a
# re-login. A very long, rolling window (extended again on every refresh
# below) achieves that in practice without literally never expiring - the
# access token itself still only lives 15 minutes either way, re-issued
# transparently by the app's own automatic-refresh-on-401 logic.
MOBILE_SESSION_DAYS = 3650

# Web/API (non-mobile) sessions also end after this much inactivity,
# matching the dashboard's 8-hour idle sign-out (admin_ui.py
# IDLE_DEFAULT_SECONDS). The dashboard enforces that with a browser-side
# timer and an activity cookie, so a browser that is simply closed never
# reports the sign-out and its row stayed "active" for the full
# SESSION_DAYS. Mobile (manager app) sessions are exempt by design.
OPERATOR_IDLE_TIMEOUT = timedelta(hours=8)

# Config-page-editable overrides for the three constants above - each falls
# back to the hardcoded value above when no directory_settings row exists
# yet. Fetched fresh per token/session issuance (matches this file's own
# client_settings(cursor) precedent below) rather than cached - this is a
# single-process deployment and issuance isn't a hot-enough path to need
# in-memory caching, so a DB round-trip per issuance is fine.
SECURITY_ACCESS_TOKEN_MINUTES_KEY = "security.access_token_minutes"
SECURITY_SESSION_DAYS_KEY = "security.session_days"
SECURITY_MOBILE_SESSION_DAYS_KEY = "security.mobile_session_days"
# Ops dashboard sign-out after inactivity (Config page, Brad-only). Always on and bounded, so it
# can't be switched off; OPERATOR_IDLE_TIMEOUT above is the value when no row exists.
SECURITY_OPS_IDLE_MINUTES_KEY = "security.ops_idle_minutes"
OPS_IDLE_MINUTES_MIN = 15
OPS_IDLE_MINUTES_MAX = 24 * 60


def operator_idle_timeout(cursor) -> timedelta:
    minutes = _get_int_directory_setting(
        cursor, SECURITY_OPS_IDLE_MINUTES_KEY, int(OPERATOR_IDLE_TIMEOUT.total_seconds() // 60)
    )
    return timedelta(minutes=min(max(minutes, OPS_IDLE_MINUTES_MIN), OPS_IDLE_MINUTES_MAX))


MAX_LOGIN_FAILURES = 5
LOCKOUT_MINUTES = 15
# Device enrollment has no per-account lockout to hang a failure count on
# (there's no account until enrollment succeeds) - rate-limit by source IP
# against device_enrollment_events instead, which already records every
# attempt. Generous enough to tolerate a few real typos during a live
# install, tight enough to bound brute-forcing the single shared
# enrollment password.
ENROLLMENT_RATE_LIMIT_WINDOW_MINUTES = 15
ENROLLMENT_MAX_FAILURES_PER_WINDOW = 10
ENROLLMENT_POLL_DAYS = 90
PRESENCE_TIMEOUT_SECONDS = 45
# Clients heartbeat every connection.heartbeat_seconds (Config page; sent back in every heartbeat
# reply). A device counts as offline after three missed heartbeats, never sooner than the original
# 45 s. Read through a short cache: this is consulted on every heartbeat and listing.
HEARTBEAT_SECONDS_KEY = "connection.heartbeat_seconds"
HEARTBEAT_SECONDS_DEFAULT = 15
HEARTBEAT_SECONDS_MIN = 10
HEARTBEAT_SECONDS_MAX = 120
_heartbeat_seconds_cache = {"value": HEARTBEAT_SECONDS_DEFAULT, "at": 0.0}


def heartbeat_seconds() -> int:
    if time.monotonic() - _heartbeat_seconds_cache["at"] > 10:
        try:
            with open_database() as connection:
                with connection.cursor() as cursor:
                    _heartbeat_seconds_cache["value"] = _get_int_directory_setting(
                        cursor, HEARTBEAT_SECONDS_KEY, HEARTBEAT_SECONDS_DEFAULT
                    )
        except Exception:
            pass
        _heartbeat_seconds_cache["at"] = time.monotonic()
    return min(max(int(_heartbeat_seconds_cache["value"]), HEARTBEAT_SECONDS_MIN), HEARTBEAT_SECONDS_MAX)


def presence_timeout_seconds() -> int:
    return max(PRESENCE_TIMEOUT_SECONDS, 3 * heartbeat_seconds())

UPDATE_ROOT = Path("/srv/rustdesk-updates")
UPDATE_RELEASES = UPDATE_ROOT / "releases"
UPDATE_MANIFESTS = UPDATE_ROOT / "manifests"


def _notify_device_pending(device: dict[str, Any]) -> None:
    # Set by register_mobile_routes() near the bottom of this module, once
    # it's imported - always populated by the time any request is served.
    # Best-effort only: this must never affect the enrollment response.
    notify = getattr(app.state, "notify_pending_device", None)
    if notify is None:
        return
    try:
        notify(device)
    except Exception:
        pass

def safe_update_file(base: Path, name: str) -> Path:
    target = (base / name).resolve()
    if not target.is_relative_to(base.resolve()) or not target.is_file():
        raise HTTPException(status_code=404, detail="Update file not found")
    return target

bearer_scheme = HTTPBearer(auto_error=False)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    totp_code: str | None = Field(
        default=None,
        pattern=r"^\d{6}$",
    )


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=32, max_length=512)


class EnrollmentSecretCreateRequest(BaseModel):
    label: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=12, max_length=256)
    max_uses: int | None = Field(default=None, gt=0)
    expires_at: datetime | None = None


class EnrollmentSecretRevokeRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=1024)


class DeviceEnrollmentRequest(BaseModel):
    enrollment_password: str = Field(min_length=1, max_length=256)
    rustdesk_id: str = Field(min_length=1, max_length=64)
    hostname: str = Field(min_length=1, max_length=255)
    friendly_name: str | None = Field(default=None, max_length=128)
    contact_email: str | None = Field(default=None, max_length=320)
    device_public_key: str = Field(min_length=16, max_length=8192)
    client_version: str | None = Field(default=None, max_length=64)

    reenrollment_poll_token: str | None = Field(
        default=None,
        min_length=32,
        max_length=512,
    )


class DeviceEnrollmentStatusRequest(BaseModel):
    device_id: uuid.UUID
    poll_token: str = Field(min_length=32, max_length=512)


class DeviceReenrollmentRequestRequest(BaseModel):
    device_id: uuid.UUID
    poll_token: str = Field(min_length=32, max_length=512)


class DeviceReenrollmentCompleteRequest(BaseModel):
    device_id: uuid.UUID
    poll_token: str = Field(min_length=32, max_length=512)
    rustdesk_id: str = Field(min_length=1, max_length=64)
    hostname: str = Field(min_length=1, max_length=255)
    friendly_name: str | None = Field(default=None, max_length=128)
    contact_email: str | None = Field(default=None, max_length=320)
    device_public_key: str = Field(min_length=16, max_length=8192)
    client_version: str | None = Field(default=None, max_length=64)


class DeviceApprovalRequest(BaseModel):
    friendly_name: str | None = Field(default=None, max_length=128)
    reason: str | None = Field(default=None, max_length=1024)


class DeviceStatusChangeRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=1024)


class DeviceHeartbeatRequest(BaseModel):
    hostname: str | None = Field(default=None, max_length=255)
    friendly_name: str | None = Field(default=None, max_length=255)
    client_version: str | None = Field(default=None, max_length=64)
    # 0 (or absent, for a client older than the build that added this field)
    # means "unmanaged/dev build or too old to report at all" - both are
    # treated identically for the future minimum-version gate. Recorded on
    # every heartbeat (not just the hourly debug-log upload) so fleet-wide
    # build adoption can be verified before any enforcement is turned on.
    managed_build_number: int = 0
    # Build 29+: which release line this device follows, so the reply's versions.build is the
    # latest build it could install.
    arch: str | None = Field(default=None, max_length=32)
    update_channel: str | None = Field(default=None, max_length=32)


class DeviceContactEmailUpdateRequest(BaseModel):
    contact_email: str | None = Field(default=None, max_length=320)


def open_database():
    return psycopg.connect(
        host=os.getenv("DATABASE_HOST", "database"),
        port=int(os.getenv("DATABASE_PORT", "5432")),
        dbname=os.getenv("DATABASE_NAME", "rustdesk_directory"),
        user=os.getenv("DATABASE_USER", "rustdesk_directory"),
        password=os.environ["DATABASE_PASSWORD"],
        connect_timeout=5,
        row_factory=dict_row,
    )


def token_hash(token: str) -> bytes:
    return hmac.new(
        TOKEN_SECRET.encode(),
        token.encode(),
        hashlib.sha256,
    ).digest()


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _get_int_directory_setting(cursor, key: str, fallback: int) -> int:
    cursor.execute(
        "SELECT setting_value FROM directory_settings WHERE setting_key = %s",
        (key,),
    )
    row = cursor.fetchone()
    if row is None:
        return fallback
    try:
        return int(row["setting_value"])
    except (TypeError, ValueError):
        return fallback


def _get_float_directory_setting(cursor, key: str, fallback: float) -> float:
    cursor.execute(
        "SELECT setting_value FROM directory_settings WHERE setting_key = %s",
        (key,),
    )
    row = cursor.fetchone()
    if row is None:
        return fallback
    try:
        return float(row["setting_value"])
    except (TypeError, ValueError):
        return fallback


# Editable from the Config page (Power / Energy Cost group) - fetched fresh
# by the host power-watcher script on every one of its 5-second runs via
# GET /ops/api/internal/power-rate, so a rate change here takes effect on
# the watcher's very next cycle with no redeploy.
POWER_RATE_PER_KWH_KEY = "power.rate_per_kwh"
POWER_RATE_PER_KWH_FALLBACK = 0.15


def issue_access_token(
    cursor,
    account_id: uuid.UUID,
    session_id: uuid.UUID,
    role: str,
    now: datetime,
    scope: str = "full",
) -> tuple[str, datetime]:
    minutes = _get_int_directory_setting(
        cursor, SECURITY_ACCESS_TOKEN_MINUTES_KEY, ACCESS_TOKEN_MINUTES
    )
    expires_at = now + timedelta(minutes=minutes)

    access_token = jwt.encode(
        {
            "sub": str(account_id),
            "sid": str(session_id),
            "role": role,
            "scope": scope,
            "type": "access",
            "iat": now,
            "exp": expires_at,
            "jti": str(uuid.uuid4()),
        },
        TOKEN_SECRET,
        algorithm="HS256",
    )

    return access_token, expires_at


def unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_operator(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    ),
) -> dict[str, Any]:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorized()

    access_token = credentials.credentials

    try:
        claims = jwt.decode(
            access_token,
            TOKEN_SECRET,
            algorithms=["HS256"],
            options={
                "require": [
                    "sub",
                    "sid",
                    "type",
                    "iat",
                    "exp",
                ]
            },
        )

        if claims.get("type") != "access":
            raise unauthorized()

        account_id = uuid.UUID(claims["sub"])
        session_id = uuid.UUID(claims["sid"])
    except (jwt.PyJWTError, KeyError, TypeError, ValueError):
        raise unauthorized()

    now = datetime.now(timezone.utc)

    with open_database() as connection:
        with connection.cursor() as cursor:
            # mfa_verified_at IS NOT NULL: only a session issued after a
            # successful authenticator check counts (refresh() checks the
            # same) - backstops _perform_login's mandatory-TOTP rule so a
            # session row without one can never authenticate.
            cursor.execute(
                """
                SELECT
                    os.id AS session_id,
                    os.account_id,
                    os.mfa_verified_at,
                    os.expires_at AS session_expires_at,
                    os.scope,
                    oa.username,
                    oa.display_name,
                    oa.role,
                    oa.must_change_password,
                    oa.totp_enabled
                FROM operator_sessions os
                JOIN operator_accounts oa
                  ON oa.id = os.account_id
                WHERE os.id = %s
                  AND os.account_id = %s
                  AND os.access_token_hash = %s
                  AND os.revoked_at IS NULL
                  AND os.expires_at > %s
                  AND os.mfa_verified_at IS NOT NULL
                  AND (
                        os.scope = 'mobile'
                        OR COALESCE(os.last_seen_at, os.created_at) > %s
                      )
                  AND oa.is_active = TRUE
                """,
                (
                    session_id,
                    account_id,
                    token_hash(access_token),
                    now,
                    now - operator_idle_timeout(cursor),
                ),
            )

            operator = cursor.fetchone()

            if operator is None:
                raise unauthorized()

            cursor.execute(
                """
                UPDATE operator_sessions
                SET last_seen_at = %s
                WHERE id = %s
                """,
                (now, session_id),
            )

            connection.commit()

            return operator


def poll_token_hash(token: str) -> bytes:
    return hmac.new(
        DEVICE_SECRET.encode(),
        ("enrollment-poll:" + token).encode(),
        hashlib.sha256,
    ).digest()


def decode_device_public_key(value: str) -> bytes:
    compact = "".join(value.split())

    try:
        decoded = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="device_public_key must be valid base64",
        ) from error

    if len(decoded) < 32 or len(decoded) > 4096:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Decoded device public key length is invalid",
        )

    return decoded



CONTACT_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


def normalize_contact_email(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        return None
    if len(normalized) > 320:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Email address must be 320 characters or fewer",
        )
    if normalized.count("@") != 1:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Email address format is invalid",
        )
    local_part, domain = normalized.rsplit("@", 1)
    if len(local_part) > 64 or len(domain) > 255 or not CONTACT_EMAIL_RE.fullmatch(normalized):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Email address format is invalid",
        )
    return normalized

def write_audit(
    cursor,
    event_type: str,
    *,
    actor_account_id: uuid.UUID | None = None,
    target_type: str | None = None,
    target_id: uuid.UUID | None = None,
    source_ip: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    cursor.execute(
        """
        INSERT INTO audit_events (
            actor_account_id,
            event_type,
            target_type,
            target_id,
            source_ip,
            details
        )
        VALUES (
            %s,
            %s,
            %s,
            %s,
            %s,
            %s::jsonb
        )
        """,
        (
            actor_account_id,
            event_type,
            target_type,
            target_id,
            source_ip,
            json.dumps(details or {}),
        ),
    )


def write_device_activity(
    cursor,
    event_type: str,
    *,
    device_id: uuid.UUID,
    occurred_at: datetime,
    source_ip: str | None = None,
    peer_device_id: uuid.UUID | None = None,
    peer_rustdesk_id: str | None = None,
    direction: str | None = None,
    session_key: str | None = None,
    session_type: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    cursor.execute(
        """
        INSERT INTO device_activity_events (
            device_id, event_type, peer_device_id, peer_rustdesk_id,
            direction, session_key, session_type, source_ip,
            details, occurred_at
        )
        VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s
        )
        ON CONFLICT DO NOTHING
        """,
        (
            device_id,
            event_type,
            peer_device_id,
            peer_rustdesk_id,
            direction,
            session_key,
            session_type,
            source_ip,
            json.dumps(details or {}),
            occurred_at,
        ),
    )


def write_enrollment_event(
    cursor,
    *,
    device_id: uuid.UUID | None,
    enrollment_secret_id: uuid.UUID | None,
    rustdesk_id: str,
    hostname: str,
    device_public_key_sha256: str,
    source_ip: str | None,
    client_version: str | None,
    result: str,
    details: dict[str, Any] | None = None,
) -> None:
    cursor.execute(
        """
        INSERT INTO device_enrollment_events (
            device_id,
            enrollment_secret_id,
            rustdesk_id,
            hostname,
            device_public_key_sha256,
            source_ip,
            client_version,
            result,
            details
        )
        VALUES (
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s::jsonb
        )
        """,
        (
            device_id,
            enrollment_secret_id,
            rustdesk_id,
            hostname,
            device_public_key_sha256,
            source_ip,
            client_version,
            result,
            json.dumps(details or {}),
        ),
    )


def _enforce_owner(operator: dict[str, Any]) -> dict[str, Any]:
    # Every current owner-gated route (enrollment secrets, device
    # contact-email edits, operator-account/invitation/role-change
    # management) is out of scope for the mobile companion app by design -
    # baking the scope check in here means any future owner-only route is
    # automatically covered too, without relying on remembering to annotate
    # each one individually.
    if (
        operator["role"] != "owner"
        or operator["must_change_password"]
        or operator["scope"] != "full"
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Owner authorization is required",
        )

    return operator


def _enforce_brad_only(operator: dict[str, Any]) -> dict[str, Any]:
    # Multiple accounts can hold the "owner" role, but mail-server
    # credentials are the first piece of the mail-server
    # integration path and are scoped to Brad's own protected account
    # specifically - reuses the same identity check that already guards his
    # account's lifecycle/role protections, rather than a parallel one.
    if not is_protected_brad_account(operator):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action is restricted to Brad's account",
        )

    return operator


def require_owner(
    operator: dict[str, Any] = Depends(require_operator),
) -> dict[str, Any]:
    return _enforce_owner(operator)


def require_brad_only(
    operator: dict[str, Any] = Depends(require_owner),
) -> dict[str, Any]:
    return _enforce_brad_only(operator)


# The admin dashboard authenticates via an HttpOnly cookie (see
# admin_ui.py's require_admin_operator, which reads ACCESS_COOKIE and calls
# require_operator directly rather than through FastAPI's header-based
# Depends chain) - browser fetch() calls never set an Authorization header.
# Routes registered directly in main.py (rather than through
# register_admin_routes) need this same cookie-based extraction, or every
# dashboard-originated call 401s with "Invalid or expired authentication"
# despite a fully valid session - exactly what happened when this was first
# missed for the smtp-config and dashboard-summary routes below.
ADMIN_ACCESS_COOKIE = "__Secure-rd-admin-access"


def require_admin_cookie_operator(request: Request) -> dict[str, Any]:
    access_token = request.cookies.get(ADMIN_ACCESS_COOKIE)
    if not access_token:
        raise unauthorized()

    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials=access_token,
    )
    return require_operator(credentials)


def require_admin_cookie_owner(
    operator: dict[str, Any] = Depends(require_admin_cookie_operator),
) -> dict[str, Any]:
    return _enforce_owner(operator)


def require_admin_cookie_brad_only(
    operator: dict[str, Any] = Depends(require_admin_cookie_owner),
) -> dict[str, Any]:
    return _enforce_brad_only(operator)


def require_device_manager(
    operator: dict[str, Any] = Depends(require_operator),
) -> dict[str, Any]:
    if (
        operator["role"] not in {"owner", "manager"}
        or operator["must_change_password"]
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Owner or Manager authorization is required",
        )

    return operator


def require_full_scope_operator(
    operator: dict[str, Any] = Depends(require_operator),
) -> dict[str, Any]:
    # Operator-account management (invitations, role changes, disable/enable/
    # delete/unlock, session revocation) must never be reachable by a token
    # issued to the mobile companion app, regardless of the account's role -
    # this is a structural guarantee against a lost/compromised phone, not
    # just something the app's own UI chooses not to expose. Checked against
    # the session row (re-derived every request, same as role above), not the
    # JWT claim alone.
    if operator["scope"] != "full":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action is not available to this session",
        )

    return operator


def sign_device_credential(
    *,
    device_id: uuid.UUID,
    rustdesk_id: str,
    device_public_key: bytes,
    credential_serial: uuid.UUID,
    instance_id: uuid.UUID,
    issued_at: datetime,
    expires_at: datetime | None,
) -> str:
    claims: dict[str, Any] = {
        "sub": str(device_id),
        "serial": str(credential_serial),
        "rustdesk_id": rustdesk_id,
        "pkh": hashlib.sha256(device_public_key).hexdigest(),
        "instance_id": str(instance_id),
        "type": "device_credential",
        "iat": issued_at,
    }

    if expires_at is not None:
        claims["exp"] = expires_at

    return jwt.encode(
        claims,
        DEVICE_SECRET,
        algorithm="HS256",
    )


def require_device(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    ),
) -> dict[str, Any]:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorized()

    return validate_device_credential(credentials.credentials)


def validate_device_credential(credential: str) -> dict[str, Any]:
    # Core of require_device(), factored out so callers that can't use a
    # plain FastAPI Depends() - the chat websocket route, specifically,
    # where an HTTPException raised from a dependency doesn't close the
    # socket as predictably as it rejects a normal HTTP request - can run
    # the same JWT + DB validation manually and control the accept/close
    # sequence themselves.
    try:
        claims = jwt.decode(
            credential,
            DEVICE_SECRET,
            algorithms=["HS256"],
            options={
                "require": [
                    "sub",
                    "serial",
                    "rustdesk_id",
                    "pkh",
                    "instance_id",
                    "type",
                    "iat",
                ]
            },
        )

        if claims.get("type") != "device_credential":
            raise unauthorized()

        device_id = uuid.UUID(claims["sub"])
        credential_serial = uuid.UUID(claims["serial"])
        instance_id = uuid.UUID(claims["instance_id"])
    except (jwt.PyJWTError, KeyError, TypeError, ValueError):
        raise unauthorized()

    now = datetime.now(timezone.utc)

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    d.id AS device_id,
                    d.rustdesk_id,
                    d.hostname,
                    d.friendly_name,
                    d.contact_email,
                    d.device_public_key,
                    d.status,
                    c.credential_serial,
                    c.issued_at,
                    c.expires_at,
                    di.instance_id
                FROM managed_devices d
                JOIN device_credentials c
                  ON c.device_id = d.id
                JOIN directory_instance di
                  ON di.singleton = TRUE
                WHERE d.id = %s
                  AND d.rustdesk_id = %s
                  AND d.status = 'approved'
                  AND c.credential_serial = %s
                  AND c.revoked_at IS NULL
                  AND (
                        c.expires_at IS NULL
                        OR c.expires_at > %s
                  )
                  AND di.instance_id = %s
                """,
                (
                    device_id,
                    claims["rustdesk_id"],
                    credential_serial,
                    now,
                    instance_id,
                ),
            )

            device = cursor.fetchone()

            if device is None:
                raise unauthorized()

            if not hmac.compare_digest(
                hashlib.sha256(
                    device["device_public_key"]
                ).hexdigest(),
                claims["pkh"],
            ):
                raise unauthorized()

            return device


def client_settings(cursor) -> dict[str, Any]:
    cursor.execute(
        """
        SELECT setting_key, setting_value
        FROM directory_settings
        WHERE setting_key LIKE 'client.%'
        ORDER BY setting_key
        """
    )

    return {
        row["setting_key"]: row["setting_value"]
        for row in cursor.fetchall()
    }


def ensure_friendly_name_available(
    cursor,
    friendly_name: str | None,
    *,
    exclude_device_id: uuid.UUID | None = None,
) -> None:
    if friendly_name is None or not friendly_name.strip():
        return

    normalized = friendly_name.strip()
    if exclude_device_id is None:
        cursor.execute(
            """
            SELECT id, rustdesk_id, hostname, friendly_name, status
            FROM managed_devices
            WHERE LOWER(BTRIM(friendly_name)) = LOWER(BTRIM(%s))
              AND status IN ('pending', 'approved', 'blocked')
            LIMIT 1
            """,
            (normalized,),
        )
    else:
        cursor.execute(
            """
            SELECT id, rustdesk_id, hostname, friendly_name, status
            FROM managed_devices
            WHERE LOWER(BTRIM(friendly_name)) = LOWER(BTRIM(%s))
              AND status IN ('pending', 'approved', 'blocked')
              AND id <> %s
            LIMIT 1
            """,
            (normalized, exclude_device_id),
        )

    conflict = cursor.fetchone()
    if conflict is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Friendly name '{normalized}' is already reserved by "
                "another managed client"
            ),
        )


def get_device_for_update(cursor, device_id: uuid.UUID):
    cursor.execute(
        """
        SELECT
            id,
            rustdesk_id,
            hostname,
            friendly_name,
            device_public_key,
            status,
            status_reason,
            last_ip,
            last_seen_at,
            created_at,
            updated_at
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

    return device


def active_device_credential(cursor, device_id: uuid.UUID):
    cursor.execute(
        """
        SELECT
            id,
            credential_serial,
            issued_at,
            expires_at
        FROM device_credentials
        WHERE device_id = %s
          AND revoked_at IS NULL
          AND (
                expires_at IS NULL
                OR expires_at > NOW()
          )
        ORDER BY issued_at DESC
        LIMIT 1
        """,
        (device_id,),
    )

    return cursor.fetchone()


def device_response(device: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": device["id"],
        "rustdesk_id": device["rustdesk_id"],
        "hostname": device["hostname"],
        "friendly_name": device["friendly_name"],
        "status": device["status"],
        "status_reason": device.get("status_reason"),
        "status_changed_at": device.get("status_changed_at"),
        "last_ip": device.get("last_ip"),
        "last_seen_at": device.get("last_seen_at"),
        "created_at": device.get("created_at"),
        "has_active_credential": device.get(
            "has_active_credential"
        ),
    }


@app.get("/health")
def health():
    try:
        with open_database() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail="Database unavailable",
        ) from error

    return {
        "status": "ok",
        "database": "ok",
    }


# Pre-shared-secret ingestion for the hypervisor host-metrics watcher (SSD
# wear, ZFS pool health, per-drive SMART status, host CPU/memory/disk/
# update state) - same trust model and same secret as mobile_api.py's
# internal_health_event (X-Health-Watcher-Secret, constant-time compare),
# since this is the same class of caller: a trusted host-level script, not
# an operator account. Stores the latest snapshot per hostname; admin_ui.py
# reads it back through admin_system_health() to render the Server Health
# box's drive/host detail. Alerting for wear>=50% and per-drive SMART
# failures is a SEPARATE concern handled by that same watcher script
# posting directly to /ops/api/mobile/internal/health-event - this
# endpoint only stores the display snapshot.
@app.post("/ops/api/internal/host-metrics", include_in_schema=False)
def internal_host_metrics(payload: dict[str, Any], request: Request):
    if not HEALTH_WATCHER_SHARED_SECRET or not hmac.compare_digest(
        request.headers.get("X-Health-Watcher-Secret") or "",
        HEALTH_WATCHER_SHARED_SECRET,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid health-watcher credential",
        )

    hostname = str(payload.get("hostname", "")).strip()
    metrics = payload.get("metrics")
    if not hostname or not isinstance(metrics, dict):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="hostname and metrics are required",
        )

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO host_metrics (hostname, payload, updated_at)
                VALUES (%s, %s::jsonb, now())
                ON CONFLICT (hostname) DO UPDATE
                SET payload = EXCLUDED.payload,
                    updated_at = EXCLUDED.updated_at
                """,
                (hostname, json.dumps(metrics)),
            )
            connection.commit()

    return {"status": "recorded"}


# Same trusted-host-script auth as internal_host_metrics above (constant-time
# compare against the shared secret) - lets the host power-watcher script
# pick up a live electricity-rate change from the Config page without a
# redeploy, polled fresh on every one of its 5-second runs (a plain settings
# read is cheap; this mirrors the same "always read live, never cache"
# philosophy already used throughout rustdrop.py's own settings).
@app.get("/ops/api/internal/power-rate", include_in_schema=False)
def internal_power_rate(request: Request):
    if not HEALTH_WATCHER_SHARED_SECRET or not hmac.compare_digest(
        request.headers.get("X-Health-Watcher-Secret") or "",
        HEALTH_WATCHER_SHARED_SECRET,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid health-watcher credential",
        )
    with open_database() as connection:
        with connection.cursor() as cursor:
            rate = _get_float_directory_setting(
                cursor, POWER_RATE_PER_KWH_KEY, POWER_RATE_PER_KWH_FALLBACK
            )
    return {"rate_per_kwh": rate}


def _perform_login(
    payload,
    request: Request,
    scope: str = "full",
) -> dict[str, Any]:
    # scope is deliberately NOT a parameter of the @app.post route below - it
    # must only ever be set by a trusted in-process caller (the mobile-login
    # route in mobile_api.py passes scope="mobile"), never by anything an
    # HTTP client could control, since a token's scope is what structurally
    # keeps a mobile session away from operator-account-management routes.
    now = datetime.now(timezone.utc)
    source_ip = client_ip(request)
    username = payload.username.strip()

    connection = open_database()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    username,
                    display_name,
                    role,
                    is_active,
                    must_change_password,
                    totp_enabled,
                    failed_login_count,
                    locked_until,
                    crypt(%s, password_hash) = password_hash AS password_ok,
                    CASE
                        WHEN totp_secret_ciphertext IS NULL THEN NULL
                        ELSE pgp_sym_decrypt(
                            totp_secret_ciphertext,
                            %s
                        )::text
                    END AS totp_secret
                FROM operator_accounts
                WHERE LOWER(username) = LOWER(%s)
                FOR UPDATE
                """,
                (
                    payload.password,
                    TOTP_KEY,
                    username,
                ),
            )

            account = cursor.fetchone()

            if account is None:
                cursor.execute(
                    """
                    INSERT INTO audit_events (
                        event_type,
                        source_ip,
                        details
                    )
                    VALUES (
                        'operator.login_failed',
                        %s,
                        jsonb_build_object(
                            'username', %s::text,
                            'reason', 'invalid_credentials'
                        )
                    )
                    """,
                    (source_ip, username),
                )
                connection.commit()
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid username, password, or authenticator code",
                )

            locked_until = account["locked_until"]

            if (
                not account["is_active"]
                or (
                    locked_until is not None
                    and locked_until > now
                )
            ):
                cursor.execute(
                    """
                    INSERT INTO audit_events (
                        actor_account_id,
                        event_type,
                        target_type,
                        target_id,
                        source_ip,
                        details
                    )
                    VALUES (
                        %s,
                        'operator.login_failed',
                        'operator_account',
                        %s,
                        %s,
                        jsonb_build_object(
                            'username', %s::text,
                            'reason', 'account_unavailable'
                        )
                    )
                    """,
                    (
                        account["id"],
                        account["id"],
                        source_ip,
                        account["username"],
                    ),
                )
                connection.commit()
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid username, password, or authenticator code",
                )

            # An authenticator code is mandatory for every session - there is
            # no password-only sign-in. Every account-creation path
            # (invitation accept; the Creator-Owner bootstrap, enforced by the
            # migration 013 trigger) enrolls TOTP, so totp_enabled is only
            # ever FALSE after an Owner access reset cleared the
            # authenticator (security_extension.py create_reset).
            # That account must finish the reset's one-time /ops/recover link,
            # which enrolls the new authenticator, before any session is
            # issued. This used to treat FALSE as "no code needed", so a
            # totp_only reset left the old password alone enough to sign in.
            totp_enrollment_required = (
                not account["totp_enabled"]
                or account["totp_secret"] is None
            )
            totp_valid = False

            if not totp_enrollment_required and payload.totp_code:
                totp_valid = pyotp.TOTP(
                    account["totp_secret"]
                ).verify(
                    payload.totp_code,
                    valid_window=1,
                )

            credentials_valid = (
                account["password_ok"]
                and totp_valid
            )

            if not credentials_valid:
                failed_count = account["failed_login_count"] + 1
                new_locked_until = None
                # Same generic 401 to the client either way (a distinct
                # response would confirm the password); the audit reason lets
                # an Owner see why a mid-recovery account cannot sign in.
                failure_reason = (
                    "totp_enrollment_required"
                    if account["password_ok"] and totp_enrollment_required
                    else "invalid_credentials"
                )

                if failed_count >= MAX_LOGIN_FAILURES:
                    new_locked_until = now + timedelta(
                        minutes=LOCKOUT_MINUTES
                    )

                cursor.execute(
                    """
                    UPDATE operator_accounts
                    SET
                        failed_login_count = %s,
                        locked_until = %s
                    WHERE id = %s
                    """,
                    (
                        failed_count,
                        new_locked_until,
                        account["id"],
                    ),
                )

                cursor.execute(
                    """
                    INSERT INTO audit_events (
                        actor_account_id,
                        event_type,
                        target_type,
                        target_id,
                        source_ip,
                        details
                    )
                    VALUES (
                        %s,
                        'operator.login_failed',
                        'operator_account',
                        %s,
                        %s,
                        jsonb_build_object(
                            'username', %s::text,
                            'reason', %s::text,
                            'failed_login_count', %s::integer,
                            'locked_until', %s::timestamptz
                        )
                    )
                    """,
                    (
                        account["id"],
                        account["id"],
                        source_ip,
                        account["username"],
                        failure_reason,
                        failed_count,
                        new_locked_until,
                    ),
                )

                connection.commit()

                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid username, password, or authenticator code",
                )

            session_id = uuid.uuid4()
            session_days = _get_int_directory_setting(
                cursor, SECURITY_SESSION_DAYS_KEY, SESSION_DAYS
            )
            mobile_session_days = _get_int_directory_setting(
                cursor, SECURITY_MOBILE_SESSION_DAYS_KEY, MOBILE_SESSION_DAYS
            )
            session_expires_at = now + timedelta(
                days=mobile_session_days if scope == "mobile" else session_days
            )

            access_token, access_expires_at = issue_access_token(
                cursor,
                account["id"],
                session_id,
                account["role"],
                now,
                scope=scope,
            )

            refresh_token = (
                "rdr_"
                + secrets.token_urlsafe(48)
            )

            cursor.execute(
                """
                INSERT INTO operator_sessions (
                    id,
                    account_id,
                    access_token_hash,
                    refresh_token_hash,
                    mfa_verified_at,
                    source_ip,
                    user_agent,
                    created_at,
                    expires_at,
                    last_seen_at,
                    scope
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s
                )
                """,
                (
                    session_id,
                    account["id"],
                    token_hash(access_token),
                    token_hash(refresh_token),
                    now if account["totp_enabled"] else None,
                    source_ip,
                    request.headers.get("user-agent"),
                    now,
                    session_expires_at,
                    now,
                    scope,
                ),
            )

            cursor.execute(
                """
                UPDATE operator_accounts
                SET
                    failed_login_count = 0,
                    locked_until = NULL,
                    last_login_at = %s,
                    last_login_ip = %s
                WHERE id = %s
                """,
                (
                    now,
                    source_ip,
                    account["id"],
                ),
            )

            cursor.execute(
                """
                INSERT INTO audit_events (
                    actor_account_id,
                    event_type,
                    target_type,
                    target_id,
                    source_ip,
                    details
                )
                VALUES (
                    %s,
                    'operator.login_succeeded',
                    'operator_account',
                    %s,
                    %s,
                    jsonb_build_object(
                        'username', %s::text,
                        'role', %s::text,
                        'session_id', %s::text
                    )
                )
                """,
                (
                    account["id"],
                    account["id"],
                    source_ip,
                    account["username"],
                    account["role"],
                    str(session_id),
                ),
            )

            connection.commit()

            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "access_expires_at": access_expires_at,
                "session_expires_at": session_expires_at,
                "operator": {
                    "id": account["id"],
                    "username": account["username"],
                    "display_name": account["display_name"],
                    "role": account["role"],
                    "must_change_password": account[
                        "must_change_password"
                    ],
                },
            }

    finally:
        connection.close()


@app.post("/v1/auth/login")
def login(payload: LoginRequest, request: Request):
    return _perform_login(payload, request)


@app.post("/v1/auth/refresh")
def refresh(payload: RefreshRequest, request: Request):
    now = datetime.now(timezone.utc)
    source_ip = client_ip(request)

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    os.id AS session_id,
                    os.account_id,
                    os.expires_at AS session_expires_at,
                    os.scope,
                    oa.username,
                    oa.display_name,
                    oa.role,
                    oa.must_change_password
                FROM operator_sessions os
                JOIN operator_accounts oa
                  ON oa.id = os.account_id
                WHERE os.refresh_token_hash = %s
                  AND os.revoked_at IS NULL
                  AND os.expires_at > %s
                  AND os.mfa_verified_at IS NOT NULL
                  AND (
                        os.scope = 'mobile'
                        OR COALESCE(os.last_seen_at, os.created_at) > %s
                      )
                  AND oa.is_active = TRUE
                FOR UPDATE OF os
                """,
                (
                    token_hash(payload.refresh_token),
                    now,
                    now - operator_idle_timeout(cursor),
                ),
            )

            session = cursor.fetchone()

            if session is None:
                raise unauthorized()

            # Must carry the session's existing scope forward - refreshing a
            # mobile session must never silently upgrade it to full scope.
            access_token, access_expires_at = issue_access_token(
                cursor,
                session["account_id"],
                session["session_id"],
                session["role"],
                now,
                scope=session["scope"],
            )

            refresh_token = (
                "rdr_"
                + secrets.token_urlsafe(48)
            )

            # Rolling window for mobile sessions only (see MOBILE_SESSION_DAYS
            # above) - a web/full-scope session's expires_at is untouched
            # here, preserving its existing fixed-30-day-from-login behavior.
            new_session_expires_at = (
                now + timedelta(
                    days=_get_int_directory_setting(
                        cursor, SECURITY_MOBILE_SESSION_DAYS_KEY, MOBILE_SESSION_DAYS
                    )
                )
                if session["scope"] == "mobile"
                else session["session_expires_at"]
            )

            cursor.execute(
                """
                UPDATE operator_sessions
                SET
                    access_token_hash = %s,
                    refresh_token_hash = %s,
                    source_ip = %s,
                    user_agent = %s,
                    last_seen_at = %s,
                    expires_at = %s
                WHERE id = %s
                """,
                (
                    token_hash(access_token),
                    token_hash(refresh_token),
                    source_ip,
                    request.headers.get("user-agent"),
                    now,
                    new_session_expires_at,
                    session["session_id"],
                ),
            )

            cursor.execute(
                """
                INSERT INTO audit_events (
                    actor_account_id,
                    event_type,
                    target_type,
                    target_id,
                    source_ip,
                    details
                )
                VALUES (
                    %s,
                    'operator.session_refreshed',
                    'operator_account',
                    %s,
                    %s,
                    jsonb_build_object(
                        'session_id', %s::text
                    )
                )
                """,
                (
                    session["account_id"],
                    session["account_id"],
                    source_ip,
                    str(session["session_id"]),
                ),
            )

            connection.commit()

            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "access_expires_at": access_expires_at,
                "session_expires_at": new_session_expires_at,
                "operator": {
                    "id": session["account_id"],
                    "username": session["username"],
                    "display_name": session["display_name"],
                    "role": session["role"],
                    "must_change_password": session[
                        "must_change_password"
                    ],
                },
            }


@app.get("/v1/auth/me")
def current_operator(
    operator: dict[str, Any] = Depends(require_operator),
):
    return {
        "id": operator["account_id"],
        "username": operator["username"],
        "display_name": operator["display_name"],
        "role": operator["role"],
        "must_change_password": operator[
            "must_change_password"
        ],
        "totp_enabled": operator["totp_enabled"],
        "mfa_verified": (
            operator["mfa_verified_at"] is not None
        ),
        "session_id": operator["session_id"],
        "session_expires_at": operator[
            "session_expires_at"
        ],
    }


@app.post("/v1/auth/logout")
def logout(
    request: Request,
    operator: dict[str, Any] = Depends(require_operator),
):
    now = datetime.now(timezone.utc)
    source_ip = client_ip(request)

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE operator_sessions
                SET
                    revoked_at = %s,
                    revoked_by = %s,
                    revocation_reason = 'operator_logout'
                WHERE id = %s
                  AND revoked_at IS NULL
                """,
                (
                    now,
                    operator["account_id"],
                    operator["session_id"],
                ),
            )

            cursor.execute(
                """
                INSERT INTO audit_events (
                    actor_account_id,
                    event_type,
                    target_type,
                    target_id,
                    source_ip,
                    details
                )
                VALUES (
                    %s,
                    'operator.logout',
                    'operator_account',
                    %s,
                    %s,
                    jsonb_build_object(
                        'session_id', %s::text
                    )
                )
                """,
                (
                    operator["account_id"],
                    operator["account_id"],
                    source_ip,
                    str(operator["session_id"]),
                ),
            )

            connection.commit()

    return {"status": "logged_out"}

@app.post("/v1/enrollment-secrets")
def create_enrollment_secret(
    payload: EnrollmentSecretCreateRequest,
    request: Request,
    operator: dict[str, Any] = Depends(require_owner),
):
    now = datetime.now(timezone.utc)
    expires_at = payload.expires_at

    if expires_at is not None:
        if expires_at.tzinfo is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="expires_at must include a timezone",
            )

        expires_at = expires_at.astimezone(timezone.utc)

        if expires_at <= now:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="expires_at must be in the future",
            )

    label = payload.label.strip()

    if not label:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="label cannot be blank",
        )

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO enrollment_secrets (
                    label,
                    password_hash,
                    max_uses,
                    created_by,
                    expires_at
                )
                VALUES (
                    %s,
                    crypt(%s, gen_salt('bf', 12)),
                    %s,
                    %s,
                    %s
                )
                RETURNING
                    id,
                    label,
                    is_active,
                    max_uses,
                    use_count,
                    created_at,
                    expires_at
                """,
                (
                    label,
                    payload.password,
                    payload.max_uses,
                    operator["account_id"],
                    expires_at,
                ),
            )

            enrollment_secret = cursor.fetchone()

            write_audit(
                cursor,
                "enrollment_secret.created",
                actor_account_id=operator["account_id"],
                target_type="enrollment_secret",
                target_id=enrollment_secret["id"],
                source_ip=client_ip(request),
                details={
                    "label": enrollment_secret["label"],
                    "max_uses": enrollment_secret["max_uses"],
                    "expires_at": (
                        enrollment_secret["expires_at"].isoformat()
                        if enrollment_secret["expires_at"]
                        else None
                    ),
                },
            )

            connection.commit()

            return enrollment_secret


@app.get("/v1/enrollment-secrets")
def list_enrollment_secrets(
    operator: dict[str, Any] = Depends(require_owner),
):
    del operator
    now = datetime.now(timezone.utc)

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    label,
                    is_active,
                    max_uses,
                    use_count,
                    created_by,
                    created_at,
                    expires_at,
                    revoked_at,
                    revoked_by,
                    revocation_reason
                FROM enrollment_secrets
                ORDER BY created_at DESC
                """
            )

            items = cursor.fetchall()

    for item in items:
        item["usable"] = (
            item["is_active"]
            and item["revoked_at"] is None
            and (
                item["expires_at"] is None
                or item["expires_at"] > now
            )
            and (
                item["max_uses"] is None
                or item["use_count"] < item["max_uses"]
            )
        )

    return {"items": items}


@app.post("/v1/enrollment-secrets/{secret_id}/revoke")
def revoke_enrollment_secret(
    secret_id: uuid.UUID,
    payload: EnrollmentSecretRevokeRequest,
    request: Request,
    operator: dict[str, Any] = Depends(require_owner),
):
    now = datetime.now(timezone.utc)

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    label,
                    is_active,
                    revoked_at,
                    revoked_by,
                    revocation_reason
                FROM enrollment_secrets
                WHERE id = %s
                FOR UPDATE
                """,
                (secret_id,),
            )

            enrollment_secret = cursor.fetchone()

            if enrollment_secret is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Enrollment secret not found",
                )

            if enrollment_secret["revoked_at"] is None:
                cursor.execute(
                    """
                    UPDATE enrollment_secrets
                    SET
                        is_active = FALSE,
                        revoked_at = %s,
                        revoked_by = %s,
                        revocation_reason = %s
                    WHERE id = %s
                    RETURNING
                        id,
                        label,
                        is_active,
                        revoked_at,
                        revoked_by,
                        revocation_reason
                    """,
                    (
                        now,
                        operator["account_id"],
                        payload.reason.strip(),
                        secret_id,
                    ),
                )

                enrollment_secret = cursor.fetchone()

                write_audit(
                    cursor,
                    "enrollment_secret.revoked",
                    actor_account_id=operator["account_id"],
                    target_type="enrollment_secret",
                    target_id=secret_id,
                    source_ip=client_ip(request),
                    details={
                        "label": enrollment_secret["label"],
                        "reason": payload.reason.strip(),
                    },
                )

                connection.commit()

            return enrollment_secret


@app.post("/v1/enrollment/devices")
def enroll_device(
    payload: DeviceEnrollmentRequest,
    request: Request,
):
    now = datetime.now(timezone.utc)
    source_ip = client_ip(request)
    rustdesk_id = payload.rustdesk_id.strip()
    hostname = payload.hostname.strip()
    friendly_name = (
        payload.friendly_name.strip()
        if payload.friendly_name
        and payload.friendly_name.strip()
        else None
    )
    contact_email = normalize_contact_email(payload.contact_email)

    if not rustdesk_id or not hostname:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="rustdesk_id and hostname cannot be blank",
        )

    device_public_key = decode_device_public_key(
        payload.device_public_key
    )
    public_key_sha256 = hashlib.sha256(
        device_public_key
    ).hexdigest()

    connection = open_database()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT count(*) AS recent_failures
                FROM device_enrollment_events
                WHERE source_ip = %s
                  AND result = 'rejected_bad_secret'
                  AND created_at > now() - %s::interval
                """,
                (source_ip, f"{ENROLLMENT_RATE_LIMIT_WINDOW_MINUTES} minutes"),
            )
            recent_failures = cursor.fetchone()["recent_failures"]
            if recent_failures >= ENROLLMENT_MAX_FAILURES_PER_WINDOW:
                write_enrollment_event(
                    cursor,
                    device_id=None,
                    enrollment_secret_id=None,
                    rustdesk_id=rustdesk_id,
                    hostname=hostname,
                    device_public_key_sha256=public_key_sha256,
                    source_ip=source_ip,
                    client_version=payload.client_version,
                    result="rejected_bad_secret",
                    details={"reason": "rate_limited", "recent_failures": recent_failures},
                )
                connection.commit()
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many failed enrollment attempts from this address - try again later",
                )

            cursor.execute(
                """
                SELECT
                    id,
                    label,
                    is_active,
                    max_uses,
                    use_count,
                    expires_at,
                    revoked_at,
                    crypt(%s, password_hash) = password_hash
                        AS password_ok
                FROM enrollment_secrets
                WHERE crypt(%s, password_hash) = password_hash
                ORDER BY created_at DESC
                LIMIT 1
                FOR UPDATE
                """,
                (
                    payload.enrollment_password,
                    payload.enrollment_password,
                ),
            )

            enrollment_secret = cursor.fetchone()

            if enrollment_secret is None:
                write_enrollment_event(
                    cursor,
                    device_id=None,
                    enrollment_secret_id=None,
                    rustdesk_id=rustdesk_id,
                    hostname=hostname,
                    device_public_key_sha256=public_key_sha256,
                    source_ip=source_ip,
                    client_version=payload.client_version,
                    result="rejected_bad_secret",
                    details={"reason": "invalid_enrollment_password"},
                )
                connection.commit()

                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid enrollment password",
                )

            rejection_result = None
            rejection_detail = None

            if (
                not enrollment_secret["is_active"]
                or enrollment_secret["revoked_at"] is not None
            ):
                rejection_result = "rejected_revoked"
                rejection_detail = "Enrollment password is revoked"
            elif (
                enrollment_secret["expires_at"] is not None
                and enrollment_secret["expires_at"] <= now
            ):
                rejection_result = "rejected_expired"
                rejection_detail = "Enrollment password is expired"
            elif (
                enrollment_secret["max_uses"] is not None
                and enrollment_secret["use_count"]
                >= enrollment_secret["max_uses"]
            ):
                rejection_result = "rejected_limit"
                rejection_detail = (
                    "Enrollment password usage limit is reached"
                )

            if rejection_result is not None:
                write_enrollment_event(
                    cursor,
                    device_id=None,
                    enrollment_secret_id=enrollment_secret["id"],
                    rustdesk_id=rustdesk_id,
                    hostname=hostname,
                    device_public_key_sha256=public_key_sha256,
                    source_ip=source_ip,
                    client_version=payload.client_version,
                    result=rejection_result,
                    details={"reason": rejection_result},
                )
                connection.commit()

                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=rejection_detail,
                )

            # Friendly names are human-facing labels only, never security
            # identities.  Pending, Approved, and Blocked devices reserve the
            # name case-insensitively.  Revoked/Denied records release it.
            # If this is an existing identity, the check below is repeated with
            # that device excluded before any re-enrollment update.

            cursor.execute(
                """
                SELECT
                    id,
                    rustdesk_id,
                    hostname,
                    friendly_name,
                    device_public_key,
                    status
                FROM managed_devices
                WHERE rustdesk_id = %s
                   OR device_public_key = %s
                FOR UPDATE
                """,
                (rustdesk_id, device_public_key),
            )

            duplicates = cursor.fetchall()

            if duplicates:
                exact_device = next(
                    (
                        item
                        for item in duplicates
                        if item["rustdesk_id"] == rustdesk_id
                        and item["device_public_key"]
                        == device_public_key
                    ),
                    None,
                )

                # An Owner-authorized Pending recovery may replace a
                # regenerated/lost device public key for the SAME RustDesk ID.
                # Authorization is still checked below before anything changes.
                pending_identity_device = next(
                    (
                        item
                        for item in duplicates
                        if item["rustdesk_id"] == rustdesk_id
                        and item["status"] == "pending"
                    ),
                    None,
                )

                if (
                    exact_device is None
                    and pending_identity_device is not None
                ):
                    exact_device = pending_identity_device

                # A newly presented key may not already belong to another
                # managed device.
                conflicting_devices = [
                    item
                    for item in duplicates
                    if exact_device is None
                    or item["id"] != exact_device["id"]
                ]

                if exact_device is None or conflicting_devices:
                    write_enrollment_event(
                        cursor,
                        device_id=(
                            exact_device["id"]
                            if exact_device
                            else None
                        ),
                        enrollment_secret_id=enrollment_secret["id"],
                        rustdesk_id=rustdesk_id,
                        hostname=hostname,
                        device_public_key_sha256=public_key_sha256,
                        source_ip=source_ip,
                        client_version=payload.client_version,
                        result="duplicate",
                        details={
                            "exact_match": exact_device is not None,
                            "conflicting_device_ids": [
                                str(item["id"])
                                for item in duplicates
                            ],
                            "reason": "identity_conflict",
                        },
                    )
                    connection.commit()
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=(
                            "RustDesk ID or device public key "
                            "already belongs to another device"
                        ),
                    )

                # "revoked" is deliberately absent: revoke is terminal (no
                # path may create a re-enrollment authorization for it, and
                # revoking invalidates any outstanding one), so a revoked
                # identity is refused below even if a stale authorization row
                # somehow survived. Only a fresh install with a new identity
                # can come back, as a new record.
                recoverable_statuses = {
                    "pending",
                    "denied",
                    "blocked",
                }
                if exact_device["status"] in recoverable_statuses:
                    continuity_token = payload.reenrollment_poll_token
                    authorization = None

                    if exact_device["status"] == "pending":
                        cursor.execute(
                            """
                            SELECT
                                a.id,
                                a.requested_by,
                                a.reason,
                                a.created_at,
                                a.expires_at
                            FROM device_reenrollment_authorizations a
                            JOIN operator_accounts o
                              ON o.id = a.requested_by
                            WHERE a.device_id = %s
                              AND a.consumed_at IS NULL
                              AND a.revoked_at IS NULL
                              AND a.expires_at > %s
                              AND o.is_active = TRUE
                              AND o.role = 'owner'
                            ORDER BY a.created_at DESC
                            LIMIT 1
                            FOR UPDATE OF a
                            """,
                            (
                                exact_device["id"],
                                now,
                            ),
                        )
                        authorization = cursor.fetchone()

                    elif continuity_token:
                        cursor.execute(
                            """
                            SELECT
                                a.id,
                                a.requested_by,
                                a.reason,
                                a.created_at,
                                a.expires_at
                            FROM device_reenrollment_authorizations a
                            JOIN operator_accounts o
                              ON o.id = a.requested_by
                            JOIN managed_devices m
                              ON m.id = a.device_id
                            WHERE a.device_id = %s
                              AND a.consumed_at IS NULL
                              AND a.revoked_at IS NULL
                              AND a.expires_at > %s
                              AND o.is_active = TRUE
                              AND o.role = 'owner'
                              AND m.enrollment_poll_token_hash = %s
                            ORDER BY a.created_at DESC
                            LIMIT 1
                            FOR UPDATE OF a
                            """,
                            (
                                exact_device["id"],
                                now,
                                poll_token_hash(continuity_token),
                            ),
                        )
                        authorization = cursor.fetchone()

                    if authorization is None:
                        write_enrollment_event(
                            cursor,
                            device_id=exact_device["id"],
                            enrollment_secret_id=enrollment_secret["id"],
                            rustdesk_id=rustdesk_id,
                            hostname=hostname,
                            device_public_key_sha256=public_key_sha256,
                            source_ip=source_ip,
                            client_version=payload.client_version,
                            result="duplicate",
                            details={
                                "exact_match": True,
                                "previous_status": exact_device["status"],
                                "reason": (
                                    "pending_recovery_authorization_required"
                                    if exact_device["status"] == "pending"
                                    else "reenrollment_authorization_required"
                                ),
                                "continuity_token_supplied": bool(continuity_token),
                            },
                        )
                        connection.commit()
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail=(
                                (
                                    "Owner Pending enrollment recovery "
                                    "authorization is required"
                                )
                                if exact_device["status"] == "pending"
                                else (
                                    "Owner re-enrollment authorization and the "
                                    "device's prior poll token are required"
                                )
                            ),
                        )

                    ensure_friendly_name_available(
                        cursor,
                        friendly_name or exact_device["friendly_name"],
                        exclude_device_id=exact_device["id"],
                    )

                    new_poll_token = "rde_" + secrets.token_urlsafe(48)
                    new_poll_expires_at = now + timedelta(
                        days=ENROLLMENT_POLL_DAYS
                    )
                    reenrollment_reason = (
                        (
                            "Owner-authorized Pending enrollment recovery: "
                            if exact_device["status"] == "pending"
                            else "Owner-authorized re-enrollment: "
                        )
                        + authorization["reason"]
                    )

                    # Make every old device credential and relay lease unusable
                    # before returning the device to Pending Approval.
                    cursor.execute(
                        """
                        UPDATE device_credentials
                        SET
                            revoked_at = COALESCE(revoked_at, %s),
                            revoked_by = COALESCE(revoked_by, %s),
                            revocation_reason = COALESCE(
                                revocation_reason,
                                'Superseded by Owner-authorized re-enrollment'
                            )
                        WHERE device_id = %s
                          AND revoked_at IS NULL
                        """,
                        (
                            now,
                            authorization["requested_by"],
                            exact_device["id"],
                        ),
                    )
                    cursor.execute(
                        """
                        UPDATE relay_access_leases
                        SET revoked_at = COALESCE(revoked_at, %s)
                        WHERE device_id = %s
                          AND revoked_at IS NULL
                        """,
                        (now, exact_device["id"]),
                    )

                    cursor.execute(
                        """
                        UPDATE managed_devices
                        SET
                            hostname = %s,
                            friendly_name = COALESCE(%s, friendly_name),
                            contact_email = COALESCE(%s, contact_email),
                            device_public_key = %s,
                            status = 'pending',
                            status_reason = %s,
                            status_changed_by = %s,
                            last_ip = %s,
                            last_seen_at = %s,
                            enrollment_poll_token_hash = %s,
                            enrollment_poll_expires_at = %s
                        WHERE id = %s
                        RETURNING
                            id,
                            rustdesk_id,
                            hostname,
                            friendly_name,
                            contact_email,
                            status,
                            created_at
                        """,
                        (
                            hostname,
                            friendly_name,
                            contact_email,
                            device_public_key,
                            reenrollment_reason,
                            authorization["requested_by"],
                            source_ip,
                            now,
                            poll_token_hash(new_poll_token),
                            new_poll_expires_at,
                            exact_device["id"],
                        ),
                    )
                    device = cursor.fetchone()

                    cursor.execute(
                        """
                        UPDATE device_reenrollment_authorizations
                        SET consumed_at = %s, consumed_ip = %s
                        WHERE id = %s
                        """,
                        (now, source_ip, authorization["id"]),
                    )
                    cursor.execute(
                        """
                        UPDATE device_reenrollment_requests
                        SET fulfilled_at = %s
                        WHERE device_id = %s
                          AND fulfilled_at IS NULL
                          AND cancelled_at IS NULL
                        """,
                        (now, exact_device["id"]),
                    )
                    cursor.execute(
                        """
                        UPDATE enrollment_secrets
                        SET use_count = use_count + 1
                        WHERE id = %s
                        """,
                        (enrollment_secret["id"],),
                    )

                    write_enrollment_event(
                        cursor,
                        device_id=device["id"],
                        enrollment_secret_id=enrollment_secret["id"],
                        rustdesk_id=rustdesk_id,
                        hostname=hostname,
                        device_public_key_sha256=public_key_sha256,
                        source_ip=source_ip,
                        client_version=payload.client_version,
                        result="accepted_pending",
                        details={
                            "friendly_name": device["friendly_name"],
                            "poll_expires_at": new_poll_expires_at.isoformat(),
                            "reenrollment": True,
                            "previous_status": exact_device["status"],
                            "authorization_id": str(authorization["id"]),
                        },
                    )
                    write_audit(
                        cursor,
                        "device.reenrollment_pending",
                        actor_account_id=authorization["requested_by"],
                        target_type="managed_device",
                        target_id=device["id"],
                        source_ip=source_ip,
                        details={
                            "rustdesk_id": rustdesk_id,
                            "previous_status": exact_device["status"],
                            "authorization_id": str(authorization["id"]),
                            "reenrollment_reason": authorization["reason"],
                        },
                    )
                    connection.commit()
                    _notify_device_pending(device)
                    return {
                        "result": "accepted_pending",
                        "device": device,
                        "poll_token": new_poll_token,
                        "poll_expires_at": new_poll_expires_at,
                        "poll_after_seconds": 10,
                    }

                if exact_device["status"] == "revoked":
                    write_enrollment_event(
                        cursor,
                        device_id=exact_device["id"],
                        enrollment_secret_id=enrollment_secret["id"],
                        rustdesk_id=rustdesk_id,
                        hostname=hostname,
                        device_public_key_sha256=public_key_sha256,
                        source_ip=source_ip,
                        client_version=payload.client_version,
                        result="duplicate",
                        details={
                            "exact_match": True,
                            "previous_status": exact_device["status"],
                            "reason": "revoked_terminal",
                            "continuity_token_supplied": bool(
                                payload.reenrollment_poll_token
                            ),
                        },
                    )
                    connection.commit()
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=(
                            "Revoked clients are terminal and cannot be "
                            "re-enrolled; a fresh install is required"
                        ),
                    )

                write_enrollment_event(
                    cursor,
                    device_id=exact_device["id"],
                    enrollment_secret_id=enrollment_secret["id"],
                    rustdesk_id=rustdesk_id,
                    hostname=hostname,
                    device_public_key_sha256=public_key_sha256,
                    source_ip=source_ip,
                    client_version=payload.client_version,
                    result="duplicate",
                    details={
                        "exact_match": True,
                        "previous_status": exact_device["status"],
                        "reason": "already_enrolled",
                    },
                )
                connection.commit()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "This device is already enrolled; "
                        "use its original poll token"
                    ),
                )

            ensure_friendly_name_available(
                cursor,
                friendly_name,
            )

            poll_token = "rde_" + secrets.token_urlsafe(48)
            poll_expires_at = now + timedelta(
                days=ENROLLMENT_POLL_DAYS
            )

            cursor.execute(
                """
                INSERT INTO managed_devices (
                    rustdesk_id,
                    hostname,
                    friendly_name,
                    contact_email,
                    device_public_key,
                    status,
                    last_ip,
                    last_seen_at,
                    enrollment_poll_token_hash,
                    enrollment_poll_expires_at
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    'pending',
                    %s,
                    %s,
                    %s,
                    %s
                )
                RETURNING
                    id,
                    rustdesk_id,
                    hostname,
                    friendly_name,
                    contact_email,
                    status,
                    created_at
                """,
                (
                    rustdesk_id,
                    hostname,
                    friendly_name,
                    contact_email,
                    device_public_key,
                    source_ip,
                    now,
                    poll_token_hash(poll_token),
                    poll_expires_at,
                ),
            )

            device = cursor.fetchone()

            cursor.execute(
                """
                UPDATE enrollment_secrets
                SET use_count = use_count + 1
                WHERE id = %s
                """,
                (enrollment_secret["id"],),
            )

            write_enrollment_event(
                cursor,
                device_id=device["id"],
                enrollment_secret_id=enrollment_secret["id"],
                rustdesk_id=rustdesk_id,
                hostname=hostname,
                device_public_key_sha256=public_key_sha256,
                source_ip=source_ip,
                client_version=payload.client_version,
                result="accepted_pending",
                details={
                    "friendly_name": friendly_name,
                    "poll_expires_at": poll_expires_at.isoformat(),
                },
            )

            write_audit(
                cursor,
                "device.enrollment_pending",
                target_type="managed_device",
                target_id=device["id"],
                source_ip=source_ip,
                details={
                    "rustdesk_id": rustdesk_id,
                    "hostname": hostname,
                    "enrollment_secret_id": str(
                        enrollment_secret["id"]
                    ),
                },
            )

            connection.commit()
            _notify_device_pending(device)
            _send_alert_email(
                subject="New device enrolled",
                body=(
                    "A new device has enrolled and is awaiting approval.\n\n"
                    f"Hostname: {device['hostname']}\n"
                    f"Friendly name: {device['friendly_name'] or '(none given)'}\n"
                    f"Source IP: {source_ip}\n"
                ),
            )

            return {
                "result": "accepted_pending",
                "device": device,
                "poll_token": poll_token,
                "poll_expires_at": poll_expires_at,
                "poll_after_seconds": 10,
            }
    finally:
        connection.close()


def _active_reenrollment_state(
    cursor,
    *,
    device_id: uuid.UUID,
    now: datetime,
) -> dict[str, Any]:
    cursor.execute(
        """
        SELECT id, requested_at, expires_at
        FROM device_reenrollment_requests
        WHERE device_id = %s
          AND fulfilled_at IS NULL
          AND cancelled_at IS NULL
          AND expires_at > %s
        ORDER BY requested_at DESC
        LIMIT 1
        """,
        (device_id, now),
    )
    request_row = cursor.fetchone()

    cursor.execute(
        """
        SELECT a.id, a.requested_by, a.reason, a.created_at, a.expires_at
        FROM device_reenrollment_authorizations a
        JOIN operator_accounts o
          ON o.id = a.requested_by
        WHERE a.device_id = %s
          AND a.consumed_at IS NULL
          AND a.revoked_at IS NULL
          AND a.expires_at > %s
          AND o.is_active = TRUE
          AND o.role = 'owner'
        ORDER BY a.created_at DESC
        LIMIT 1
        """,
        (device_id, now),
    )
    authorization = cursor.fetchone()

    return {
        "requested": request_row is not None,
        "request_id": request_row["id"] if request_row else None,
        "request_expires_at": request_row["expires_at"] if request_row else None,
        "authorized": authorization is not None,
        "authorization_id": authorization["id"] if authorization else None,
        "authorization_expires_at": authorization["expires_at"] if authorization else None,
    }


@app.post("/v1/enrollment/reenrollment-request")
def request_device_reenrollment(
    payload: DeviceReenrollmentRequestRequest,
    request: Request,
):
    now = datetime.now(timezone.utc)
    source_ip = client_ip(request)

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, rustdesk_id, status, enrollment_poll_expires_at
                FROM managed_devices
                WHERE id = %s
                  AND enrollment_poll_token_hash = %s
                  AND enrollment_poll_expires_at > %s
                  AND status IN ('denied', 'blocked')
                FOR UPDATE
                """,
                (
                    payload.device_id,
                    poll_token_hash(payload.poll_token),
                    now,
                ),
            )
            device = cursor.fetchone()
            if device is None:
                raise unauthorized()

            sliding_poll_expires_at = now + timedelta(days=ENROLLMENT_POLL_DAYS)
            cursor.execute(
                """
                UPDATE managed_devices
                SET last_ip = %s,
                    last_seen_at = %s,
                    enrollment_poll_expires_at = %s
                WHERE id = %s
                """,
                (source_ip, now, sliding_poll_expires_at, device["id"]),
            )

            # Close an expired request so the partial unique index permits a
            # fresh request without accumulating active duplicates.
            cursor.execute(
                """
                UPDATE device_reenrollment_requests
                SET cancelled_at = %s
                WHERE device_id = %s
                  AND fulfilled_at IS NULL
                  AND cancelled_at IS NULL
                  AND expires_at <= %s
                """,
                (now, device["id"], now),
            )

            state = _active_reenrollment_state(
                cursor, device_id=device["id"], now=now
            )

            if not state["requested"]:
                request_id = uuid.uuid4()
                request_expires_at = now + timedelta(hours=24)
                cursor.execute(
                    """
                    INSERT INTO device_reenrollment_requests (
                        id, device_id, requested_at, source_ip, expires_at
                    ) VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        request_id,
                        device["id"],
                        now,
                        source_ip,
                        request_expires_at,
                    ),
                )
                write_audit(
                    cursor,
                    "device.reenrollment_requested",
                    target_type="managed_device",
                    target_id=device["id"],
                    source_ip=source_ip,
                    details={
                        "rustdesk_id": device["rustdesk_id"],
                        "device_status": device["status"],
                        "request_id": str(request_id),
                        "expires_at": request_expires_at.isoformat(),
                    },
                )
                state["requested"] = True
                state["request_id"] = request_id
                state["request_expires_at"] = request_expires_at

            connection.commit()
            return {
                "status": "requested",
                "device_id": device["id"],
                "device_status": device["status"],
                "poll_expires_at": sliding_poll_expires_at,
                "reenrollment_requested": state["requested"],
                "reenrollment_request_id": state["request_id"],
                "reenrollment_request_expires_at": state["request_expires_at"],
                "reenrollment_authorized": state["authorized"],
                "reenrollment_authorization_expires_at": state[
                    "authorization_expires_at"
                ],
            }


@app.post("/v1/enrollment/reenroll")
def complete_device_reenrollment(
    payload: DeviceReenrollmentCompleteRequest,
    request: Request,
):
    now = datetime.now(timezone.utc)
    source_ip = client_ip(request)
    rustdesk_id = payload.rustdesk_id.strip()
    hostname = payload.hostname.strip()
    friendly_name = (
        payload.friendly_name.strip()
        if payload.friendly_name and payload.friendly_name.strip()
        else None
    )
    contact_email = normalize_contact_email(payload.contact_email)
    device_public_key = decode_device_public_key(payload.device_public_key)
    public_key_sha256 = hashlib.sha256(device_public_key).hexdigest()

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, rustdesk_id, hostname, friendly_name,
                       device_public_key, status
                FROM managed_devices
                WHERE id = %s
                  AND enrollment_poll_token_hash = %s
                  AND enrollment_poll_expires_at > %s
                  AND status IN ('denied', 'blocked')
                FOR UPDATE
                """,
                (
                    payload.device_id,
                    poll_token_hash(payload.poll_token),
                    now,
                ),
            )
            device = cursor.fetchone()
            if device is None:
                raise unauthorized()
            if device["rustdesk_id"] != rustdesk_id:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Re-enrollment RustDesk ID does not match managed device",
                )

            cursor.execute(
                """
                SELECT id
                FROM managed_devices
                WHERE device_public_key = %s
                  AND id <> %s
                LIMIT 1
                """,
                (device_public_key, device["id"]),
            )
            if cursor.fetchone() is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Device public key belongs to another managed device",
                )

            state = _active_reenrollment_state(
                cursor, device_id=device["id"], now=now
            )
            if not state["authorized"]:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Owner re-enrollment authorization is required",
                )

            cursor.execute(
                """
                SELECT a.id, a.requested_by, a.reason, a.expires_at
                FROM device_reenrollment_authorizations a
                JOIN operator_accounts o
                  ON o.id = a.requested_by
                WHERE a.id = %s
                  AND a.device_id = %s
                  AND a.consumed_at IS NULL
                  AND a.revoked_at IS NULL
                  AND a.expires_at > %s
                  AND o.is_active = TRUE
                  AND o.role = 'owner'
                FOR UPDATE OF a
                """,
                (state["authorization_id"], device["id"], now),
            )
            authorization = cursor.fetchone()
            if authorization is None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Owner re-enrollment authorization is no longer valid",
                )

            ensure_friendly_name_available(
                cursor,
                friendly_name or device["friendly_name"],
                exclude_device_id=device["id"],
            )

            new_poll_token = "rde_" + secrets.token_urlsafe(48)
            new_poll_expires_at = now + timedelta(days=ENROLLMENT_POLL_DAYS)
            previous_status = device["status"]
            reenrollment_reason = (
                "Owner-authorized managed re-enrollment: "
                + authorization["reason"]
            )

            cursor.execute(
                """
                UPDATE device_credentials
                SET revoked_at = COALESCE(revoked_at, %s),
                    revoked_by = COALESCE(revoked_by, %s),
                    revocation_reason = COALESCE(
                        revocation_reason,
                        'Superseded by Owner-authorized re-enrollment'
                    )
                WHERE device_id = %s
                  AND revoked_at IS NULL
                """,
                (now, authorization["requested_by"], device["id"]),
            )
            cursor.execute(
                """
                UPDATE relay_access_leases
                SET revoked_at = COALESCE(revoked_at, %s)
                WHERE device_id = %s
                  AND revoked_at IS NULL
                """,
                (now, device["id"]),
            )
            cursor.execute(
                """
                UPDATE managed_devices
                SET hostname = %s,
                    friendly_name = COALESCE(%s, friendly_name),
                    contact_email = COALESCE(%s, contact_email),
                    device_public_key = %s,
                    status = 'pending',
                    status_reason = %s,
                    status_changed_by = %s,
                    last_ip = %s,
                    last_seen_at = %s,
                    enrollment_poll_token_hash = %s,
                    enrollment_poll_expires_at = %s
                WHERE id = %s
                RETURNING id, rustdesk_id, hostname, friendly_name, contact_email, status, created_at
                """,
                (
                    hostname,
                    friendly_name,
                    contact_email,
                    device_public_key,
                    reenrollment_reason,
                    authorization["requested_by"],
                    source_ip,
                    now,
                    poll_token_hash(new_poll_token),
                    new_poll_expires_at,
                    device["id"],
                ),
            )
            updated = cursor.fetchone()

            cursor.execute(
                """
                UPDATE device_reenrollment_authorizations
                SET consumed_at = %s, consumed_ip = %s
                WHERE id = %s
                """,
                (now, source_ip, authorization["id"]),
            )
            cursor.execute(
                """
                UPDATE device_reenrollment_requests
                SET fulfilled_at = %s
                WHERE device_id = %s
                  AND fulfilled_at IS NULL
                  AND cancelled_at IS NULL
                """,
                (now, device["id"]),
            )

            write_enrollment_event(
                cursor,
                device_id=device["id"],
                enrollment_secret_id=None,
                rustdesk_id=rustdesk_id,
                hostname=hostname,
                device_public_key_sha256=public_key_sha256,
                source_ip=source_ip,
                client_version=payload.client_version,
                result="accepted_pending",
                details={
                    "reenrollment": True,
                    "continuity_endpoint": True,
                    "previous_status": previous_status,
                    "authorization_id": str(authorization["id"]),
                    "poll_expires_at": new_poll_expires_at.isoformat(),
                },
            )
            write_audit(
                cursor,
                "device.reenrollment_pending",
                actor_account_id=authorization["requested_by"],
                target_type="managed_device",
                target_id=device["id"],
                source_ip=source_ip,
                details={
                    "rustdesk_id": rustdesk_id,
                    "previous_status": previous_status,
                    "authorization_id": str(authorization["id"]),
                    "continuity_endpoint": True,
                },
            )
            connection.commit()
            _notify_device_pending(updated)
            return {
                "result": "accepted_pending",
                "device": updated,
                "poll_token": new_poll_token,
                "poll_expires_at": new_poll_expires_at,
                "poll_after_seconds": 10,
            }


@app.post("/v1/enrollment/status")
def enrollment_status(
    payload: DeviceEnrollmentStatusRequest,
    request: Request,
):
    now = datetime.now(timezone.utc)

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    d.id,
                    d.rustdesk_id,
                    d.hostname,
                    d.friendly_name,
                    d.device_public_key,
                    d.status,
                    d.status_reason,
                    d.status_changed_at,
                    d.enrollment_poll_expires_at,
                    c.credential_serial,
                    c.issued_at AS credential_issued_at,
                    c.expires_at AS credential_expires_at,
                    di.instance_id
                FROM managed_devices d
                LEFT JOIN device_credentials c
                  ON c.device_id = d.id
                 AND c.revoked_at IS NULL
                 AND (
                        c.expires_at IS NULL
                        OR c.expires_at > %s
                 )
                JOIN directory_instance di
                  ON di.singleton = TRUE
                WHERE d.id = %s
                  AND d.enrollment_poll_token_hash = %s
                  AND d.enrollment_poll_expires_at > %s
                """,
                (
                    now,
                    payload.device_id,
                    poll_token_hash(payload.poll_token),
                    now,
                ),
            )

            device = cursor.fetchone()

            if device is None:
                raise unauthorized()

            sliding_poll_expires_at = (
                now + timedelta(days=ENROLLMENT_POLL_DAYS)
                if device["status"] in {
                    "pending", "denied", "blocked", "revoked"
                }
                else device["enrollment_poll_expires_at"]
            )

            # An approved device's presence comes from its heartbeat only.
            # The one approved client that still polls here is a device whose
            # key changed and so can no longer heartbeat - touching
            # last_seen_at for it would show a broken device as online. For
            # approved records sliding_poll_expires_at is the stored value,
            # so skipping the UPDATE changes nothing else.
            if device["status"] != "approved":
                cursor.execute(
                    """
                    UPDATE managed_devices
                    SET
                        last_ip = %s,
                        last_seen_at = %s,
                        enrollment_poll_expires_at = %s
                    WHERE id = %s
                    """,
                    (
                        client_ip(request),
                        now,
                        sliding_poll_expires_at,
                        device["id"],
                    ),
                )

            terminal_status = device["status"] in {
                "denied", "blocked", "revoked"
            }
            # Same fix as authorize_device_reenrollment/
            # request_device_reenrollment/complete_device_reenrollment
            # (2026-09-23) - this was the 4th and final place this exact
            # "only denied" restriction was missed after "blocked" was added
            # as a feature. Without it, the periodic status poll a blocked
            # client calls every ~10-15s always hardcoded
            # reenrollment_authorized/requested to false, so the client
            # never learned an operator had authorized it even though the
            # DB row existed - confirmed live against a blocked managed client.
            recovery_eligible = device["status"] in {"denied", "blocked"}
            reenrollment = (
                _active_reenrollment_state(
                    cursor, device_id=device["id"], now=now
                )
                if recovery_eligible
                else {
                    "requested": False,
                    "request_id": None,
                    "request_expires_at": None,
                    "authorized": False,
                    "authorization_id": None,
                    "authorization_expires_at": None,
                }
            )

            response: dict[str, Any] = {
                "device_id": device["id"],
                "rustdesk_id": device["rustdesk_id"],
                "status": device["status"],
                "status_reason": device["status_reason"],
                "status_changed_at": device[
                    "status_changed_at"
                ],
                "poll_expires_at": sliding_poll_expires_at,
                "poll_after_seconds": 15 if terminal_status else 10,
                "reenrollment_requested": reenrollment["requested"],
                "reenrollment_request_id": reenrollment["request_id"],
                "reenrollment_request_expires_at": reenrollment[
                    "request_expires_at"
                ],
                "reenrollment_authorized": reenrollment["authorized"],
                "reenrollment_authorization_expires_at": reenrollment[
                    "authorization_expires_at"
                ],
            }

            if (
                device["status"] == "approved"
                and device["credential_serial"] is not None
            ):
                response["credential"] = sign_device_credential(
                    device_id=device["id"],
                    rustdesk_id=device["rustdesk_id"],
                    device_public_key=device["device_public_key"],
                    credential_serial=device[
                        "credential_serial"
                    ],
                    instance_id=device["instance_id"],
                    issued_at=device["credential_issued_at"],
                    expires_at=device[
                        "credential_expires_at"
                    ],
                )
                response["credential_serial"] = device[
                    "credential_serial"
                ]

            connection.commit()

            return response


def device_lifetime_stats(cursor, *, device_id: uuid.UUID) -> dict[str, int]:
    """Lifetime counts for Client Management's MSG/Conn column.

    Messages: from chat_message_send_events (count-only, no body - see its
    own table comment). Connections: from device_activity_events, the same
    table the dashboard's 24h/7-day connection stats already read from.
    """
    cursor.execute(
        "SELECT COUNT(*) AS count FROM chat_message_send_events WHERE sender_device_id = %s",
        (device_id,),
    )
    messages = cursor.fetchone()["count"]

    cursor.execute(
        """
        SELECT COUNT(*) AS count FROM device_activity_events
        WHERE device_id = %s AND event_type = 'connection.established'
        """,
        (device_id,),
    )
    connections = cursor.fetchone()["count"]

    return {"lifetime_messages_sent": messages, "lifetime_connections": connections}


def latest_manifest_build_numbers() -> dict[str, int]:
    """Best-effort {arch: build_number} for the stable channel, read directly
    from the manifest JSON on disk (no release-file hash check - this is for
    Client Management's status display only, not for serving the update
    itself; see load_update_manifest() for the verified version used by
    managed_update_latest()). Lets device_latest_debug_log_info() tell a
    device is out of date even when its most recent debug-log upload
    predates the newest publish, since that upload's own self-reported
    pending_managed_update field only reflects what the client itself knew
    about at upload time and goes stale the moment a newer build ships.
    """
    build_numbers: dict[str, int] = {}
    for arch in ("x86_64", "aarch64"):
        for name in (f"stable-{arch}.json", "stable.json"):
            try:
                manifest = json.loads((UPDATE_MANIFESTS / name).read_text(encoding="utf-8"))
                build_numbers[arch] = int(manifest["build_number"])
            except (OSError, ValueError, KeyError, TypeError):
                continue
            break
    # RDC for Android: its own manifest only (no pre-arch fallback - that one is x86_64).
    try:
        manifest = json.loads((UPDATE_MANIFESTS / "stable-android-aarch64.json").read_text(encoding="utf-8"))
        build_numbers["android-aarch64"] = int(manifest["build_number"])
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return build_numbers


def _normalize_reported_gpus(value: Any) -> list[dict[str, Any]] | None:
    """Client-reported GPU list (hardware_info.gpus, build 27+), kept to the
    fields the dashboard shows and capped in size - it is device-supplied.
    None means the client predates GPU reporting; [] means it found none.
    """
    if not isinstance(value, list):
        return None
    gpus: list[dict[str, Any]] = []
    for item in value[:8]:
        if not isinstance(item, dict):
            continue
        memory = item.get("memory_bytes")
        kind = str(item.get("kind") or "unknown")
        gpus.append({
            "name": str(item.get("name") or "")[:120],
            "vendor": str(item.get("vendor") or "")[:40],
            "kind": kind if kind in {"dedicated", "integrated", "virtual", "unknown"} else "unknown",
            "memory_bytes": memory if isinstance(memory, int) and memory > 0 else None,
            "driver_version": str(item.get("driver_version") or "")[:40] or None,
        })
    return gpus


def _normalize_reported_security(value: Any) -> dict[str, Any] | None:
    """Client-reported security posture (hardware_info.security, build 33+), kept to the fields the
    dashboard shows and capped in size - it is device-supplied. None means the client predates it.
    """
    if not isinstance(value, dict):
        return None

    def text(item: Any) -> str | None:
        if isinstance(item, bool) or not isinstance(item, (str, int, float)):
            return None
        return str(item)[:80] or None

    def flag(item: Any) -> bool | None:
        return item if isinstance(item, bool) else None

    def number(item: Any) -> int | None:
        return item if isinstance(item, int) and not isinstance(item, bool) else None

    def seconds(item: Any) -> float | None:
        if isinstance(item, bool) or not isinstance(item, (int, float)) or item != item:
            return None
        return round(float(item), 3)

    def section(name: str, fields: dict[str, Any]) -> dict[str, Any] | None:
        item = value.get(name)
        if not isinstance(item, dict):
            return None
        return {key: kind(item.get(key)) for key, kind in fields.items()}

    # RDC for Android's device report (RdcPlatform.kt) in place of the Windows inventory.
    android = section("android", {
        "manufacturer": text, "model": text, "release": text, "sdk": number, "security_patch": text,
        "screen_lock": flag, "encryption": text, "developer_options": flag, "usb_debugging": flag,
        "wireless_debugging": flag, "auto_time": flag, "verified_boot": text, "bootloader_locked": flag,
        "strongbox": flag, "secret_key_storage": text, "install_unknown_apps": flag, "installer": text,
        "version_code": number,
    })
    if android is not None:
        network = value["android"].get("network")
        android["network"] = (
            {
                key: kind(network.get(key))
                for key, kind in {
                    "type": text, "vpn": flag, "validated": flag, "private_dns": flag, "private_dns_server": text,
                }.items()
            }
            if isinstance(network, dict) else None
        )
    profiles = value.get("firewall_profiles")
    products = value.get("antivirus_products")
    return {
        "android": android,
        "tpm": section("tpm", {
            "present": flag, "spec_version": text, "manufacturer": text, "manufacturer_version": text,
            "kind": text, "enabled": flag, "activated": flag, "error": text,
        }),
        "secure_boot": text(value.get("secure_boot")),
        "firmware_type": text(value.get("firmware_type")),
        "bitlocker": section("bitlocker", {"protection": text, "fully_encrypted": flag}),
        "windows": section("windows", {"display_version": text, "edition": text, "build": text}),
        "defender": section("defender", {
            "antivirus_enabled": flag, "realtime": flag, "signature_age_days": number, "mode": text,
        }),
        "antivirus_products": [p for p in map(text, products[:8]) if p] if isinstance(products, list) else None,
        "firewall_profiles": (
            {str(k)[:20]: flag(v) for k, v in list(profiles.items())[:6]} if isinstance(profiles, dict) else None
        ),
        "rustdesk_firewall_rules": section("rustdesk_firewall_rules", {
            "total": number, "allow_in": number, "allow_out": number, "block": number,
        }),
        "time": section("time", {
            "ntp_server": text, "type": text, "source": text, "last_sync": text,
            "offset_seconds": seconds, "offset_server": text,
        }),
        "virtual_machine": flag(value.get("virtual_machine")),
        "identity_key_protection": text(value.get("identity_key_protection")),
        "passport": section("passport", {"serial": text, "exp": number, "prot": text}),
        "peer_cert_expires": number(value.get("peer_cert_expires")),
        "connection_path": section("connection_path", {"path": text, "tcp_lost_seconds_ago": number}),
        "error": text(value.get("error")),
    }


def _reported_android_text(info: dict[str, Any], key: str) -> str | None:
    """A device-supplied field of RDC for Android's report (hardware_info.security.android)."""
    security = info.get("security")
    android = security.get("android") if isinstance(security, dict) else None
    value = android.get(key) if isinstance(android, dict) else None
    return value[:80] if isinstance(value, str) and value else None


def device_latest_debug_log_info(
    cursor, *, device_id: uuid.UUID, latest_build_numbers: dict[str, int] | None = None
) -> dict[str, Any]:
    """Most recent debug-log snapshot for Client Management's Build #/Update
    columns and the Details popup's device-specs boxes - see device_logs.py's
    hardware_info payload for the full field set this reads from.
    """
    cursor.execute(
        """
        SELECT hardware_info, uploaded_at
        FROM device_debug_logs
        WHERE device_id = %s
        ORDER BY uploaded_at DESC
        LIMIT 1
        """,
        (device_id,),
    )
    row = cursor.fetchone()
    info = (row["hardware_info"] if row else None) or {}
    log_build_number = info.get("managed_build_number")
    # Every heartbeat reports the running build; the debug log's copy is only as fresh as the
    # last upload, which can be days old (one device showed UPDATE for a build it had already
    # installed). Prefer the heartbeat, and drop a pending-update flag from an older log.
    cursor.execute(
        """
        SELECT reported_build_number, passport_serial, passport_expires_at, key_protection,
               identity_public_key, platform
        FROM managed_devices WHERE id = %s
        """,
        (device_id,),
    )
    reported = cursor.fetchone()
    reported_build_number = reported["reported_build_number"] if reported else None
    build_number = reported_build_number or log_build_number
    pending_update = (
        info.get("pending_managed_update") if build_number == log_build_number else None
    )
    platform = reported["platform"] if reported else "windows"
    latest_known_build = (
        None if platform == "android"
        else (latest_build_numbers or {}).get(info.get("architecture") or "x86_64")
    )
    if platform == "android":
        # RDC for Android releases are numbered build * 100 + revision, reported by the app itself.
        installed_release = info.get("android_release")
        latest_android = (latest_build_numbers or {}).get("android-aarch64")
        if not isinstance(installed_release, int) or isinstance(installed_release, bool) or latest_android is None:
            update_status = "unknown"
        else:
            update_status = "update_available" if installed_release < latest_android else "up_to_date"
    elif build_number is None:
        update_status = "unknown"
    elif latest_known_build is not None and build_number < latest_known_build:
        update_status = "update_available"
    else:
        update_status = "up_to_date"
    return {
        "debug_log_uploaded_at": row["uploaded_at"].isoformat() if row else None,
        "debug_log_build_number": build_number,
        "debug_log_pending_update": pending_update,
        "debug_log_latest_known_build": latest_known_build,
        "debug_log_update_status": update_status,
        "debug_log_os": info.get("os"),
        "debug_log_cpu": info.get("cpu"),
        "debug_log_gpus": _normalize_reported_gpus(info.get("gpus")),
        "debug_log_memory": info.get("memory"),
        "debug_log_manufacturer": info.get("manufacturer") or _reported_android_text(info, "manufacturer"),
        "debug_log_model": info.get("model") or _reported_android_text(info, "model"),
        "debug_log_architecture": info.get("architecture"),
        "debug_log_uptime_seconds": info.get("uptime_seconds"),
        "debug_log_system_drive_total_bytes": info.get("system_drive_total_bytes"),
        "debug_log_system_drive_available_bytes": info.get("system_drive_available_bytes"),
        "debug_log_client_reported_time": info.get("client_reported_time"),
        "debug_log_security": _normalize_reported_security(info.get("security")),
        # The CA's record (live, not from the log): the device's current passport and key.
        "passport_serial": reported["passport_serial"] if reported else None,
        "passport_expires_at": (
            reported["passport_expires_at"].isoformat()
            if reported and reported["passport_expires_at"] else None
        ),
        "platform": platform,
        "identity_key_protection": reported["key_protection"] if reported else None,
        "identity_key_fingerprint": (
            _sec8_fingerprint(reported["identity_public_key"])
            if reported and reported["identity_public_key"] else None
        ),
    }


def device_active_connections(
    cursor,
    *,
    device_id: uuid.UUID,
    rustdesk_id: str,
    now: datetime,
) -> list[dict[str, Any]]:
    cutoff = now - timedelta(seconds=presence_timeout_seconds())
    cursor.execute(
        """
        SELECT *
        FROM (
            SELECT
                s.session_key,
                s.session_type,
                s.peer_rustdesk_id,
                COALESCE(peer.friendly_name, peer.hostname) AS peer_display_name,
                peer.id AS peer_device_id,
                'receiver'::text AS direction,
                s.started_at,
                s.last_heartbeat_at,
                (
                    SELECT e.details -> 'timing' ->> 'route'
                    FROM device_activity_events e
                    WHERE (
                        e.session_key = s.session_key
                        -- the initiator keys a session rdc-<session id>-<n>; the receiver
                        -- keys it <peer id>:<session id>:<conn id>
                        OR e.session_key LIKE
                            'rdc-' || split_part(s.session_key, ':', 2) || '-%%'
                    )
                      AND e.event_type = 'connection.established'
                      AND e.details -> 'timing' ? 'route'
                    ORDER BY e.occurred_at DESC
                    LIMIT 1
                ) AS route
            FROM device_active_sessions s
            LEFT JOIN managed_devices peer
              ON peer.rustdesk_id = s.peer_rustdesk_id
            WHERE s.reporting_device_id = %s
              AND s.ended_at IS NULL
              AND s.last_heartbeat_at >= %s

            UNION ALL

            SELECT
                s.session_key,
                s.session_type,
                reporting.rustdesk_id AS peer_rustdesk_id,
                COALESCE(reporting.friendly_name, reporting.hostname)
                    AS peer_display_name,
                reporting.id AS peer_device_id,
                'initiator'::text AS direction,
                s.started_at,
                s.last_heartbeat_at,
                (
                    SELECT e.details -> 'timing' ->> 'route'
                    FROM device_activity_events e
                    WHERE (
                        e.session_key = s.session_key
                        -- the initiator keys a session rdc-<session id>-<n>; the receiver
                        -- keys it <peer id>:<session id>:<conn id>
                        OR e.session_key LIKE
                            'rdc-' || split_part(s.session_key, ':', 2) || '-%%'
                    )
                      AND e.event_type = 'connection.established'
                      AND e.details -> 'timing' ? 'route'
                    ORDER BY e.occurred_at DESC
                    LIMIT 1
                ) AS route
            FROM device_active_sessions s
            JOIN managed_devices reporting
              ON reporting.id = s.reporting_device_id
            WHERE s.peer_rustdesk_id = %s
              AND s.reporting_device_id <> %s
              AND s.ended_at IS NULL
              AND s.last_heartbeat_at >= %s
        ) active
        ORDER BY active.last_heartbeat_at DESC, active.session_key
        """,
        (device_id, cutoff, rustdesk_id, device_id, cutoff),
    )
    return [dict(row) for row in cursor.fetchall()]


@app.get("/v1/devices")
def list_devices(
    device_status: str | None = None,
    operator: dict[str, Any] = Depends(require_operator),
):
    del operator

    if device_status is not None and device_status not in {
        "pending",
        "approved",
        "denied",
        "blocked",
        "revoked",
    }:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid device_status",
        )

    with open_database() as connection:
        with connection.cursor() as cursor:
            if device_status is None:
                cursor.execute(
                    """
                    SELECT v.*, d.contact_email
                    FROM admin_device_overview AS v
                    JOIN managed_devices AS d ON d.id = v.id
                    ORDER BY v.created_at DESC
                    """
                )
            else:
                cursor.execute(
                    """
                    SELECT v.*, d.contact_email
                    FROM admin_device_overview AS v
                    JOIN managed_devices AS d ON d.id = v.id
                    WHERE v.status = %s
                    ORDER BY v.created_at DESC
                    """,
                    (device_status,),
                )

            items = [dict(row) for row in cursor.fetchall()]
            now = datetime.now(timezone.utc)
            latest_build_numbers = latest_manifest_build_numbers()
            for item in items:
                item["active_connections"] = device_active_connections(
                    cursor,
                    device_id=item["id"],
                    rustdesk_id=item["rustdesk_id"],
                    now=now,
                )
                item.update(device_lifetime_stats(cursor, device_id=item["id"]))
                item.update(
                    device_latest_debug_log_info(
                        cursor, device_id=item["id"], latest_build_numbers=latest_build_numbers
                    )
                )

            return {"items": items}


@app.get("/v1/devices/{device_id}")
def get_device(
    device_id: uuid.UUID,
    operator: dict[str, Any] = Depends(require_operator),
):
    del operator

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT v.*, d.contact_email
                FROM admin_device_overview AS v
                JOIN managed_devices AS d ON d.id = v.id
                WHERE v.id = %s
                """,
                (device_id,),
            )

            device = cursor.fetchone()

            if device is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Managed device not found",
                )

            device.update(
                device_latest_debug_log_info(
                    cursor, device_id=device_id, latest_build_numbers=latest_manifest_build_numbers()
                )
            )

            cursor.execute(
                """
                SELECT
                    from_status,
                    to_status,
                    changed_by,
                    reason,
                    changed_at
                FROM device_status_history
                WHERE device_id = %s
                ORDER BY changed_at DESC
                """,
                (device_id,),
            )

            status_history = cursor.fetchall()
            now = datetime.now(timezone.utc)
            active_connections = device_active_connections(
                cursor,
                device_id=device["id"],
                rustdesk_id=device["rustdesk_id"],
                now=now,
            )

            cursor.execute(
                """
                SELECT
                    e.id,
                    e.event_type,
                    e.peer_device_id,
                    e.peer_rustdesk_id,
                    COALESCE(peer.friendly_name, peer.hostname)
                        AS peer_display_name,
                    e.direction,
                    e.session_key,
                    e.session_type,
                    e.source_ip,
                    e.details,
                    e.occurred_at
                FROM device_activity_events e
                LEFT JOIN managed_devices peer
                  ON peer.id = e.peer_device_id
                WHERE e.device_id = %s
                  AND e.event_type LIKE 'connection.%%'
                ORDER BY e.occurred_at DESC
                LIMIT 150
                """,
                (device_id,),
            )
            session_history = cursor.fetchall()

            return {
                "device": device,
                "status_history": status_history,
                "active_connections": active_connections,
                "session_history": session_history,
                "session_history_note": (
                    "History contains managed-client-reported connection "
                    "events. Accepted v1.12 clients primarily provide "
                    "receiving-side established/ended telemetry; v1.13 "
                    "will add complete initiator/request telemetry."
                ),
            }


def _update_device_contact_email(
    *,
    device_id: uuid.UUID,
    contact_email: str | None,
    request: Request,
    actor_account_id: uuid.UUID | None,
    actor_type: str,
) -> dict[str, Any]:
    normalized = normalize_contact_email(contact_email)
    now = datetime.now(timezone.utc)
    source_ip = client_ip(request)

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, rustdesk_id, contact_email
                FROM managed_devices
                WHERE id = %s
                FOR UPDATE
                """,
                (device_id,),
            )
            device_row = cursor.fetchone()
            if device_row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Managed device not found",
                )

            previous = device_row["contact_email"]
            if previous != normalized:
                cursor.execute(
                    """
                    UPDATE managed_devices
                    SET contact_email = %s,
                        updated_at = %s
                    WHERE id = %s
                    """,
                    (normalized, now, device_id),
                )
                if cursor.rowcount != 1:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=(
                            "Managed-device email update did not affect "
                            "exactly one row"
                        ),
                    )
                write_audit(
                    cursor,
                    "device.contact_email_changed",
                    actor_account_id=actor_account_id,
                    target_type="managed_device",
                    target_id=device_id,
                    source_ip=source_ip,
                    details={
                        "old_contact_email": previous,
                        "new_contact_email": normalized,
                        "changed_by": actor_type,
                    },
                )
            connection.commit()

    return {
        "status": "updated",
        "device_id": device_id,
        "rustdesk_id": device_row["rustdesk_id"],
        "contact_email": normalized,
        "changed_at": now,
    }


@app.put("/v1/devices/{device_id}/contact-email")
def update_device_contact_email(
    device_id: uuid.UUID,
    payload: DeviceContactEmailUpdateRequest,
    request: Request,
    operator: dict[str, Any] = Depends(require_owner),
):
    # Keep the explicit role check because the admin dashboard calls this handler
    # directly after its own authenticated proxy authorization.
    if operator.get("role") != "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Owner authorization is required",
        )
    return _update_device_contact_email(
        device_id=device_id,
        contact_email=payload.contact_email,
        request=request,
        actor_account_id=operator["account_id"],
        actor_type="owner",
    )


@app.post("/v1/devices/{device_id}/approve")
def approve_device(
    device_id: uuid.UUID,
    payload: DeviceApprovalRequest,
    request: Request,
    operator: dict[str, Any] = Depends(
        require_device_manager
    ),
):
    now = datetime.now(timezone.utc)

    with open_database() as connection:
        with connection.cursor() as cursor:
            device = get_device_for_update(cursor, device_id)
            previous_status = device["status"]

            if previous_status in {"blocked", "revoked"}:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "Blocked or revoked devices cannot be "
                        "approved directly"
                    ),
                )

            friendly_name = (
                payload.friendly_name.strip()
                if payload.friendly_name
                and payload.friendly_name.strip()
                else device["friendly_name"]
            )

            ensure_friendly_name_available(
                cursor,
                friendly_name,
                exclude_device_id=device_id,
            )

            if previous_status != "approved":
                cursor.execute(
                    """
                    UPDATE managed_devices
                    SET
                        status = 'approved',
                        status_reason = %s,
                        status_changed_by = %s,
                        friendly_name = %s
                    WHERE id = %s
                    """,
                    (
                        (
                            payload.reason.strip()
                            if payload.reason
                            and payload.reason.strip()
                            else "Approved by operator"
                        ),
                        operator["account_id"],
                        friendly_name,
                        device_id,
                    ),
                )
            elif friendly_name != device["friendly_name"]:
                cursor.execute(
                    """
                    UPDATE managed_devices
                    SET friendly_name = %s
                    WHERE id = %s
                    """,
                    (friendly_name, device_id),
                )

            credential = active_device_credential(
                cursor,
                device_id,
            )

            if credential is None:
                cursor.execute(
                    """
                    INSERT INTO device_credentials (
                        device_id,
                        issued_by
                    )
                    VALUES (%s, %s)
                    RETURNING
                        id,
                        credential_serial,
                        issued_at,
                        expires_at
                    """,
                    (
                        device_id,
                        operator["account_id"],
                    ),
                )

                credential = cursor.fetchone()

            cursor.execute(
                """
                SELECT instance_id
                FROM directory_instance
                WHERE singleton = TRUE
                """
            )
            instance = cursor.fetchone()

            signed_credential = sign_device_credential(
                device_id=device_id,
                rustdesk_id=device["rustdesk_id"],
                device_public_key=device["device_public_key"],
                credential_serial=credential[
                    "credential_serial"
                ],
                instance_id=instance["instance_id"],
                issued_at=credential["issued_at"],
                expires_at=credential["expires_at"],
            )

            # sec8: queue the device's first passport for the CA VM. A savepoint keeps any problem here
            # from failing the approval itself.
            if previous_status != "approved":
                try:
                    with connection.transaction():
                        if _sec8_mode(cursor) != "off":
                            device_payload = _sec8_device_payload(cursor, device_id)
                            if device_payload is not None:
                                sec8_enqueue(cursor, "issue", device_id, {
                                    "device": device_payload,
                                    "approver": sec8_approver(operator),
                                    "lifetime_days": _sec8_lifetime_days(cursor),
                                    "reason": "approve",
                                })
                except Exception as error:
                    print(f"sec8: could not queue passport for {device_id}: {error}", flush=True)

            write_audit(
                cursor,
                "device.approved",
                actor_account_id=operator["account_id"],
                target_type="managed_device",
                target_id=device_id,
                source_ip=client_ip(request),
                details={
                    "previous_status": previous_status,
                    "friendly_name": friendly_name,
                    "credential_serial": str(
                        credential["credential_serial"]
                    ),
                },
            )

            connection.commit()

            return {
                "device_id": device_id,
                "status": "approved",
                "friendly_name": friendly_name,
                "credential_serial": credential[
                    "credential_serial"
                ],
                "credential": signed_credential,
            }


def change_device_status(
    *,
    device_id: uuid.UUID,
    new_status: str,
    reason: str,
    request: Request,
    operator: dict[str, Any],
) -> dict[str, Any]:
    with open_database() as connection:
        with connection.cursor() as cursor:
            device = get_device_for_update(cursor, device_id)
            previous_status = device["status"]
            now = datetime.now(timezone.utc)

            if new_status == "denied":
                if previous_status == "denied":
                    return {
                        "device_id": device_id,
                        "status": "denied",
                    }

                if previous_status != "pending":
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=(
                            "Only pending devices may be denied"
                        ),
                    )

            if new_status == "revoked":
                if previous_status == "revoked":
                    return {
                        "device_id": device_id,
                        "status": "revoked",
                    }

                if previous_status != "approved":
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=(
                            "Only approved devices may be revoked"
                        ),
                    )

            if new_status == "blocked":
                if previous_status == "blocked":
                    return {
                        "device_id": device_id,
                        "status": "blocked",
                    }

                # Block is reversible (Owner-authorized re-enrollment accepts
                # blocked), so it must never be reachable from "revoked" - that
                # would turn a terminal revoke back into a recoverable state.
                # Only approved (dashboard + mobile) and pending (mobile app's
                # pending-row Block) are ever offered; denied is already
                # recoverable on its own and blocking it would re-reserve its
                # released friendly name without the availability check.
                if previous_status == "revoked":
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=(
                            "Revoked devices are terminal and cannot be "
                            "blocked"
                        ),
                    )

                if previous_status not in {"approved", "pending"}:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=(
                            "Only approved or pending devices may be blocked"
                        ),
                    )

            terminal_cleanup: dict[str, int] = {}
            # revoked is at least as final as blocked (Brad's explicit
            # design: block is reversible via re-approval, revoke is not
            # without a fresh install) - it must get the same relay-lease/
            # re-enrollment cleanup, not just the credential revocation the
            # guard_managed_device_status trigger already does generically
            # for any move off "approved".
            if new_status in ("blocked", "revoked"):
                cursor.execute(
                    """
                    UPDATE device_credentials
                    SET revoked_at = COALESCE(revoked_at, %s),
                        revoked_by = COALESCE(revoked_by, %s),
                        revocation_reason = COALESCE(
                            revocation_reason,
                            'Managed client permanently blocked'
                        )
                    WHERE device_id = %s
                      AND revoked_at IS NULL
                    """,
                    (now, operator["account_id"], device_id),
                )
                terminal_cleanup["credentials_revoked"] = cursor.rowcount
                terminal_cleanup["edge_certs_revoked"] = revoke_device_edge_certs(cursor, device_id)

                cursor.execute(
                    """
                    UPDATE relay_access_leases
                    SET revoked_at = COALESCE(revoked_at, %s)
                    WHERE device_id = %s
                      AND revoked_at IS NULL
                    """,
                    (now, device_id),
                )
                terminal_cleanup["relay_leases_revoked"] = cursor.rowcount

                cursor.execute(
                    """
                    UPDATE device_reenrollment_authorizations
                    SET revoked_at = COALESCE(revoked_at, %s)
                    WHERE device_id = %s
                      AND consumed_at IS NULL
                      AND revoked_at IS NULL
                    """,
                    (now, device_id),
                )
                terminal_cleanup["reenrollment_authorizations_revoked"] = cursor.rowcount

                cursor.execute(
                    """
                    UPDATE device_reenrollment_requests
                    SET cancelled_at = COALESCE(cancelled_at, %s)
                    WHERE device_id = %s
                      AND fulfilled_at IS NULL
                      AND cancelled_at IS NULL
                    """,
                    (now, device_id),
                )
                terminal_cleanup["reenrollment_requests_cancelled"] = cursor.rowcount

            cursor.execute(
                """
                UPDATE managed_devices
                SET
                    status = %s,
                    status_reason = %s,
                    status_changed_by = %s
                WHERE id = %s
                RETURNING
                    id,
                    rustdesk_id,
                    hostname,
                    friendly_name,
                    status,
                    status_reason,
                    status_changed_at,
                    last_ip,
                    last_seen_at,
                    created_at
                """,
                (
                    new_status,
                    reason.strip(),
                    operator["account_id"],
                    device_id,
                ),
            )

            updated_device = cursor.fetchone()

            # sec8: the CA VM stops renewing for blocked/revoked devices. Always queued (revoking is the safe
            # direction), in a savepoint so it can never fail the status change.
            if new_status in ("blocked", "revoked"):
                try:
                    with connection.transaction():
                        sec8_enqueue(cursor, "revoke", device_id, {
                            "rid": device["rustdesk_id"],
                            "did": str(device_id),
                            "reason": new_status,
                        })
                except Exception as error:
                    print(f"sec8: could not queue revoke for {device_id}: {error}", flush=True)

            write_audit(
                cursor,
                f"device.{new_status}",
                actor_account_id=operator["account_id"],
                target_type="managed_device",
                target_id=device_id,
                source_ip=client_ip(request),
                details={
                    "previous_status": previous_status,
                    "reason": reason.strip(),
                    **terminal_cleanup,
                },
            )

            connection.commit()

            return updated_device


@app.post("/v1/devices/{device_id}/deny")
def deny_device(
    device_id: uuid.UUID,
    payload: DeviceStatusChangeRequest,
    request: Request,
    operator: dict[str, Any] = Depends(
        require_device_manager
    ),
):
    return change_device_status(
        device_id=device_id,
        new_status="denied",
        reason=payload.reason,
        request=request,
        operator=operator,
    )


@app.post("/v1/devices/{device_id}/block")
def block_device(
    device_id: uuid.UUID,
    payload: DeviceStatusChangeRequest,
    request: Request,
    operator: dict[str, Any] = Depends(
        require_device_manager
    ),
):
    return change_device_status(
        device_id=device_id,
        new_status="blocked",
        reason=payload.reason,
        request=request,
        operator=operator,
    )


@app.post("/v1/devices/{device_id}/revoke")
def revoke_device(
    device_id: uuid.UUID,
    payload: DeviceStatusChangeRequest,
    request: Request,
    operator: dict[str, Any] = Depends(
        require_device_manager
    ),
):
    # Previously a shim that normalized every "revoke" call to the
    # "blocked" status - "revoked" is a genuinely distinct, terminal status
    # (already valid per the managed_devices_status_check constraint, and
    # already fully handled client-side via DirectoryState::Revoked's own
    # status text) that was simply never being reached. change_device_status
    # itself already enforces revoked's own precondition (only reachable
    # from "approved", never from "blocked" - block is meant to be
    # reversible via re-approval, revoke is meant to not be without a fresh
    # install).
    return change_device_status(
        device_id=device_id,
        new_status="revoked",
        reason=payload.reason.strip(),
        request=request,
        operator=operator,
    )


@app.get("/v1/device/me")
def current_device(
    device: dict[str, Any] = Depends(require_device),
):
    return {
        "id": device["device_id"],
        "rustdesk_id": device["rustdesk_id"],
        "hostname": device["hostname"],
        "friendly_name": device["friendly_name"],
        "contact_email": device["contact_email"],
        "status": device["status"],
        "credential_serial": device[
            "credential_serial"
        ],
        "credential_issued_at": device["issued_at"],
        "credential_expires_at": device["expires_at"],
        "instance_id": device["instance_id"],
    }


@app.put("/v1/device/contact-email")
def update_current_device_contact_email(
    payload: DeviceContactEmailUpdateRequest,
    request: Request,
    device: dict[str, Any] = Depends(require_device),
):
    return _update_device_contact_email(
        device_id=device["device_id"],
        contact_email=payload.contact_email,
        request=request,
        actor_account_id=None,
        actor_type="managed_device",
    )


@app.post("/v1/device/heartbeat")
def device_heartbeat(
    payload: DeviceHeartbeatRequest,
    request: Request,
    device: dict[str, Any] = Depends(require_device),
):
    now = datetime.now(timezone.utc)
    source_ip = client_ip(request)
    sliding_poll_expires_at = now + timedelta(
        days=ENROLLMENT_POLL_DAYS
    )

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT last_seen_at, debug_log_requested_at
                FROM managed_devices
                WHERE id = %s
                FOR UPDATE
                """,
                (device["device_id"],),
            )
            presence = cursor.fetchone()
            note_edge_verification(cursor, device["device_id"], request.headers, now)
            previous_last_seen = (
                presence["last_seen_at"] if presence else None
            )
            debug_log_requested = bool(
                presence and presence["debug_log_requested_at"] is not None
            )

            if previous_last_seen is None:
                write_device_activity(
                    cursor,
                    "client.active",
                    device_id=device["device_id"],
                    occurred_at=now,
                    source_ip=source_ip,
                    details={"reason": "first managed heartbeat"},
                )
            elif (
                now - previous_last_seen
                > timedelta(seconds=presence_timeout_seconds())
            ):
                inactive_at = previous_last_seen + timedelta(
                    seconds=presence_timeout_seconds()
                )
                write_device_activity(
                    cursor,
                    "client.inactive",
                    device_id=device["device_id"],
                    occurred_at=inactive_at,
                    source_ip=source_ip,
                    details={
                        "reason": "heartbeat timeout",
                        "timeout_seconds": presence_timeout_seconds(),
                    },
                )
                write_device_activity(
                    cursor,
                    "client.active",
                    device_id=device["device_id"],
                    occurred_at=now,
                    source_ip=source_ip,
                    details={"reason": "managed heartbeat resumed"},
                )

            update_fields = {
                "last_ip": source_ip,
                "last_seen_at": now,
                "enrollment_poll_expires_at": sliding_poll_expires_at,
                "reported_build_number": payload.managed_build_number,
                "platform": "android" if (payload.arch or "").startswith("android") else "windows",
            }

            if payload.hostname is not None and payload.hostname.strip():
                update_fields["hostname"] = payload.hostname.strip()

            if (
                payload.friendly_name is not None
                and payload.friendly_name.strip()
                and payload.friendly_name.strip() != device["friendly_name"]
            ):
                # Client-initiated rename: keep the same uniqueness rule used at
                # enrollment so a self-service rename cannot collide with another
                # managed device's reserved name. A collision must not fail the
                # whole heartbeat (presence/last_seen tracking has to keep
                # working) - just skip the rename and let the client retry.
                try:
                    ensure_friendly_name_available(
                        cursor,
                        payload.friendly_name,
                        exclude_device_id=device["device_id"],
                    )
                    update_fields["friendly_name"] = payload.friendly_name.strip()
                except HTTPException:
                    pass

            set_clause = ", ".join(f"{key} = %s" for key in update_fields)
            cursor.execute(
                f"""
                UPDATE managed_devices
                SET {set_clause}
                WHERE id = %s
                """,
                (*update_fields.values(), device["device_id"]),
            )

            connection.commit()

            return {
                "status": "ok",
                "server_time": now,
                "device_status": "approved",
                "client_version": payload.client_version,
                "debug_log_requested": debug_log_requested,
                "heartbeat_seconds": heartbeat_seconds(),
                "versions": device_sync_versions(
                    device["device_id"], payload.arch, payload.update_channel
                ),
            }


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _peer_ca_public_key_b64() -> str:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    raw = PEER_CA_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def _get_peer_auth_mode(cursor) -> str:
    cursor.execute(
        "SELECT setting_value FROM directory_settings WHERE setting_key = %s",
        (PEER_AUTH_MODE_KEY,),
    )
    row = cursor.fetchone()
    mode = str(row["setting_value"]).strip().strip('"').lower() if row else "log"
    return mode if mode in PEER_AUTH_MODES else "log"


def _get_rendezvous_encryption(cursor) -> tuple[str, dict[str, Any] | None]:
    """The hbbs key exchange mode (default optional) and hbbs's latest 5-minute counts, if any."""
    cursor.execute(
        "SELECT setting_key, setting_value FROM directory_settings WHERE setting_key IN (%s, %s)",
        (RENDEZVOUS_ENCRYPTION_KEY, RENDEZVOUS_ENCRYPTION_STATS_KEY),
    )
    rows = {row["setting_key"]: row["setting_value"] for row in cursor.fetchall()}
    mode = str(rows.get(RENDEZVOUS_ENCRYPTION_KEY, "optional")).strip().strip('"').lower()
    stats = rows.get(RENDEZVOUS_ENCRYPTION_STATS_KEY)
    return (
        mode if mode in RENDEZVOUS_ENCRYPTION_MODES else "optional",
        stats if isinstance(stats, dict) else None,
    )


def _devices_requiring_rendezvous_encryption(cursor) -> int:
    """Approved devices (seen recently or not) whose build can't connect while hbbs's key exchange is off."""
    cursor.execute(
        """
        SELECT COUNT(*) AS n FROM managed_devices
        WHERE status = 'approved' AND COALESCE(reported_build_number, 0) >= %s
        """,
        (RENDEZVOUS_ENCRYPTION_REQUIRED_BUILD,),
    )
    return int(cursor.fetchone()["n"] or 0)


def _get_relay_webrtc(cursor) -> tuple[str, str]:
    """hbbs's WebRTC signaling switch (default off) and the test device ids."""
    cursor.execute(
        "SELECT setting_key, setting_value FROM directory_settings WHERE setting_key IN (%s, %s)",
        (RELAY_WEBRTC_KEY, RELAY_WEBRTC_TEST_IDS_KEY),
    )
    rows = {row["setting_key"]: row["setting_value"] for row in cursor.fetchall()}
    mode = str(rows.get(RELAY_WEBRTC_KEY, "off")).strip().strip('"').lower()
    ids = rows.get(RELAY_WEBRTC_TEST_IDS_KEY)
    return (mode if mode in RELAY_WEBRTC_MODES else "off", ids if isinstance(ids, str) else "")


def _get_relay_passport(cursor) -> tuple[str, str, dict[str, Any] | None]:
    """hbbs's passport check (default off), its test device ids and hbbs's latest counts."""
    cursor.execute(
        "SELECT setting_key, setting_value FROM directory_settings WHERE setting_key IN (%s, %s, %s)",
        (RELAY_PASSPORT_KEY, RELAY_PASSPORT_TEST_IDS_KEY, RELAY_PASSPORT_STATS_KEY),
    )
    rows = {row["setting_key"]: row["setting_value"] for row in cursor.fetchall()}
    mode = str(rows.get(RELAY_PASSPORT_KEY, "off")).strip().strip('"').lower()
    ids = rows.get(RELAY_PASSPORT_TEST_IDS_KEY)
    stats = rows.get(RELAY_PASSPORT_STATS_KEY)
    return (
        mode if mode in RELAY_PASSPORT_MODES else "off",
        ids if isinstance(ids, str) else "",
        stats if isinstance(stats, dict) else None,
    )


def _devices_not_ready_for_passport_check(cursor) -> int:
    """Approved devices seen in the last 30 days whose build can't prove a passport to hbbs."""
    cursor.execute(
        """
        SELECT COUNT(*) AS n FROM managed_devices
        WHERE status = 'approved' AND last_seen_at >= now() - interval '30 days'
          AND COALESCE(reported_build_number, 0) < %s
        """,
        (PASSPORT_CHECK_READY_BUILD,),
    )
    return int(cursor.fetchone()["n"] or 0)


@app.get("/v1/peer-auth/ca")
def peer_auth_ca():
    if PEER_CA_KEY is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Peer certificates are not configured",
        )
    return {"alg": "ed25519", "public_key": _peer_ca_public_key_b64()}


@app.post("/v1/device/peer-cert")
def issue_peer_cert(
    device: dict[str, Any] = Depends(require_device),
):
    """A short-lived certificate binding this approved device's RustDesk id to its identity key.
    require_device already limits callers to approved devices with a valid credential."""
    if PEER_CA_KEY is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Peer certificates are not configured",
        )

    now = datetime.now(timezone.utc)
    serial = uuid.uuid4()

    with open_database() as connection:
        with connection.cursor() as cursor:
            lifetime_hours = _get_int_directory_setting(
                cursor, PEER_CERT_LIFETIME_HOURS_KEY, 96
            )
            renew_after_hours = _get_int_directory_setting(
                cursor, PEER_CERT_RENEW_AFTER_HOURS_KEY, 24
            )
            lifetime_hours = min(max(lifetime_hours, 1), 24 * 30)
            renew_after_hours = min(max(renew_after_hours, 1), lifetime_hours)
            expires_at = now + timedelta(hours=lifetime_hours)

            payload = json.dumps(
                {
                    "v": 1,
                    "rid": device["rustdesk_id"],
                    "pk": base64.b64encode(bytes(device["device_public_key"])).decode("ascii"),
                    "did": str(device["device_id"]),
                    "iat": int(now.timestamp()),
                    "nbf": int(now.timestamp()),
                    "exp": int(expires_at.timestamp()),
                    "sn": str(serial),
                },
                separators=(",", ":"),
            ).encode("utf-8")
            signature = PEER_CA_KEY.sign(payload)

            cursor.execute(
                """
                UPDATE managed_devices
                SET peer_cert_serial = %s,
                    peer_cert_expires_at = %s
                WHERE id = %s
                """,
                (serial, expires_at, device["device_id"]),
            )
            connection.commit()

    return {
        "cert": f"{_b64url(payload)}.{_b64url(signature)}",
        "expires_at": expires_at,
        "renew_after_seconds": renew_after_hours * 3600,
    }


# ---- sec8 device passports. The CA VM signs; RDS only queues jobs for it
# (ca_jobs, served by the separate ca_link container) and stores what comes back. Nothing is enforced yet.
SEC8_PASSPORT_MODE_KEY = "sec8.passport_mode"  # "off" | "log"
SEC8_LIFETIME_DAYS_KEY = "sec8.passport_lifetime_days"
SEC8_GRACE_DAYS_KEY = "sec8.passport_grace_days"
SEC8_LIFETIME_DAYS_DEFAULT, SEC8_LIFETIME_DAYS_MIN, SEC8_LIFETIME_DAYS_MAX = 1, 1, 7
SEC8_GRACE_DAYS_DEFAULT, SEC8_GRACE_DAYS_MIN, SEC8_GRACE_DAYS_MAX = 7, 0, 30


def _sec8_mode(cursor) -> str:
    cursor.execute(
        "SELECT setting_value FROM directory_settings WHERE setting_key = %s",
        (SEC8_PASSPORT_MODE_KEY,),
    )
    row = cursor.fetchone()
    value = row["setting_value"] if row else "off"
    return value if value in ("off", "log") else "off"


def _sec8_lifetime_days(cursor) -> int:
    value = _get_int_directory_setting(cursor, SEC8_LIFETIME_DAYS_KEY, SEC8_LIFETIME_DAYS_DEFAULT)
    return min(max(value, SEC8_LIFETIME_DAYS_MIN), SEC8_LIFETIME_DAYS_MAX)


def _sec8_grace_days(cursor) -> int:
    value = _get_int_directory_setting(cursor, SEC8_GRACE_DAYS_KEY, SEC8_GRACE_DAYS_DEFAULT)
    return min(max(value, SEC8_GRACE_DAYS_MIN), SEC8_GRACE_DAYS_MAX)


def _sec8_fingerprint(public_key_b64url: str) -> str | None:
    """First 16 bytes of SHA-256 of the raw key, hex - the fingerprint the CA mails."""
    try:
        raw = base64.urlsafe_b64decode(public_key_b64url + "=" * (-len(public_key_b64url) % 4))
    except (binascii.Error, ValueError):
        return None
    return hashlib.sha256(raw).hexdigest()[:32]


def _sec8_device_payload(cursor, device_id) -> dict[str, Any] | None:
    cursor.execute(
        """
        SELECT id, rustdesk_id, friendly_name, hostname, device_public_key,
               identity_public_key, identity_key_alg, key_protection
        FROM managed_devices WHERE id = %s
        """,
        (device_id,),
    )
    d = cursor.fetchone()
    if not d or not d["device_public_key"]:
        return None
    rdk = _b64url(bytes(d["device_public_key"]))
    return {
        "rid": d["rustdesk_id"],
        "did": str(d["id"]),
        "name": d["friendly_name"] or d["hostname"] or "",
        "idk": d["identity_public_key"] or rdk,
        "idk_alg": d["identity_key_alg"] or "ed25519",
        "rdk": rdk,
        "prot": d["key_protection"] or "legacy",
    }


def sec8_enqueue(cursor, kind: str, device_id, payload: dict[str, Any]) -> None:
    cursor.execute(
        "INSERT INTO ca_jobs (kind, device_id, payload) VALUES (%s, %s, %s::jsonb)",
        (kind, device_id, json.dumps(payload)),
    )


def sec8_approver(operator: dict[str, Any], source: str | None = None) -> dict[str, str]:
    return {
        "name": operator.get("display_name") or operator.get("username") or "",
        "role": operator.get("role") or "",
        "source": source or ("mobile app" if operator.get("scope") == "mobile" else "dashboard"),
    }


class Sec8SignedRequest(BaseModel):
    request: str = Field(min_length=10, max_length=4096, pattern=r"^[A-Za-z0-9_.-]+$")


SEC8_KEYUPDATE_DOMAIN = b"rdcp1-keyupdate\0"
SEC8_REQUEST_MAX_AGE = 600


def _sec8_unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sec8_verify_key_update(request_text: str, on_file_idk: str, rid: str, did: str) -> dict[str, str]:
    """RDS's own check of a key update, so the identity key it lists for hbbs (the two-box rule) never
    comes from the CA's word alone: signed by the key RDS has on file and by the new key, for this
    device, and recent. Returns the new key and its protection."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    def refuse(reason: str):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Key update refused: {reason}")

    parts = request_text.split(".")
    if len(parts) != 3:
        refuse("malformed")
    try:
        body_bytes = _sec8_unb64(parts[0])
        old_sig, new_sig = _sec8_unb64(parts[1]), _sec8_unb64(parts[2])
        body = json.loads(body_bytes)
    except (binascii.Error, ValueError):
        refuse("malformed")
    if not isinstance(body, dict) or body.get("typ") != "rdc-keyupdate" or body.get("v") != 1:
        refuse("not a key update")
    if body.get("rid") != rid or body.get("did") != did:
        refuse("not for this device")
    if body.get("old_key") != on_file_idk:
        refuse("not signed by the key on file")
    if body.get("new_alg") != "ed25519" or not isinstance(body.get("new_key"), str):
        refuse("unsupported key")
    ts = body.get("ts")
    if not isinstance(ts, int) or abs(int(time.time()) - ts) > SEC8_REQUEST_MAX_AGE:
        refuse("too old or from the future")
    message = SEC8_KEYUPDATE_DOMAIN + body_bytes
    try:
        old_key = _sec8_unb64(body["old_key"])
        new_key = _sec8_unb64(body["new_key"])
        if len(old_key) != 32 or len(new_key) != 32:
            refuse("unsupported key")
        Ed25519PublicKey.from_public_bytes(old_key).verify(old_sig, message)
        Ed25519PublicKey.from_public_bytes(new_key).verify(new_sig, message)
    except (InvalidSignature, ValueError, binascii.Error):
        refuse("signature does not verify")
    prot = body.get("prot") if isinstance(body.get("prot"), str) else "unknown"
    return {"idk": body["new_key"], "prot": prot[:16]}


@app.get("/v1/device/passport")
def get_device_passport(
    device: dict[str, Any] = Depends(require_device),
):
    """The device's newest passport (or null) and which identity key the CA has on file for it, so the
    client knows whether to send a key update (signed by that key) or a renewal."""
    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT serial, passport, nbf, expires_at FROM device_passports
                WHERE device_id = %s
                ORDER BY expires_at DESC LIMIT 1
                """,
                (device["device_id"],),
            )
            row = cursor.fetchone()
            on_file = _sec8_device_payload(cursor, device["device_id"])
            mode = _sec8_mode(cursor)
            lifetime_days = _sec8_lifetime_days(cursor)
            grace_days = _sec8_grace_days(cursor)
    return {
        "mode": mode,
        "passport": row["passport"] if row else None,
        "serial": row["serial"] if row else None,
        "expires_at": row["expires_at"] if row else None,
        "idk_on_file": on_file["idk"] if on_file else None,
        "prot_on_file": on_file["prot"] if on_file else None,
        "renew_after_seconds": lifetime_days * 86400 // 2,
        "grace_days": grace_days,
    }


def _sec8_queue_device_request(device: dict[str, Any], kind: str, request_text: str) -> dict[str, str]:
    with open_database() as connection:
        with connection.cursor() as cursor:
            if _sec8_mode(cursor) == "off":
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Passports are not enabled",
                )
            on_file = _sec8_device_payload(cursor, device["device_id"])
            if not on_file:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="No device key on file")
            # The key the CA's result must carry: for a key update the new key, checked here first.
            if kind == "keyupdate":
                expected = sec8_verify_key_update(
                    request_text, on_file["idk"], device["rustdesk_id"], str(device["device_id"])
                )
            else:
                expected = {"idk": on_file["idk"], "prot": on_file["prot"]}
            cursor.execute(
                """
                SELECT count(*) AS n FROM ca_jobs
                WHERE device_id = %s AND kind IN ('renew', 'keyupdate') AND done_at IS NULL
                """,
                (device["device_id"],),
            )
            if cursor.fetchone()["n"] >= 2:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="A request for this device is already waiting",
                )
            sec8_enqueue(cursor, kind, device["device_id"], {
                "rid": device["rustdesk_id"],
                "did": str(device["device_id"]),
                "request": request_text,
                "lifetime_days": _sec8_lifetime_days(cursor),
                "expected_idk": expected["idk"],
                "expected_prot": expected["prot"],
            })
        connection.commit()
    return {"status": "queued"}


@app.post("/v1/device/passport/renew", status_code=status.HTTP_202_ACCEPTED)
def renew_device_passport(
    payload: Sec8SignedRequest,
    device: dict[str, Any] = Depends(require_device),
):
    """Renewal request signed with the device's identity key; the CA VM checks the signature itself."""
    return _sec8_queue_device_request(device, "renew", payload.request)


@app.post("/v1/device/identity-key", status_code=status.HTTP_202_ACCEPTED)
def update_device_identity_key(
    payload: Sec8SignedRequest,
    device: dict[str, Any] = Depends(require_device),
):
    """Move to a new identity key, signed by the key on file and by the new key; checked by the CA VM."""
    return _sec8_queue_device_request(device, "keyupdate", payload.request)


@app.get("/ops/api/ca-status")
def get_ca_status(
    operator: dict[str, Any] = Depends(require_admin_cookie_brad_only),
):
    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT status, updated_at FROM ca_status WHERE id = 1")
            ca = cursor.fetchone()
            cursor.execute(
                """
                SELECT
                    count(*) FILTER (WHERE done_at IS NULL) AS pending,
                    count(*) FILTER (WHERE done_at > now() - interval '24 hours' AND ok) AS ok_24h,
                    count(*) FILTER (WHERE done_at > now() - interval '24 hours' AND NOT ok) AS refused_24h
                FROM ca_jobs
                """
            )
            queue = cursor.fetchone()
            cursor.execute(
                """
                SELECT
                    count(*) FILTER (WHERE status = 'approved') AS approved,
                    count(*) FILTER (WHERE status = 'approved' AND passport_expires_at > now()) AS with_passport
                FROM managed_devices
                """
            )
            devices = cursor.fetchone()
            cursor.execute(
                """
                SELECT j.id, j.kind, j.ok, j.error, j.created_at, j.done_at,
                       COALESCE(m.friendly_name, m.hostname) AS device, m.rustdesk_id
                FROM ca_jobs j LEFT JOIN managed_devices m ON m.id = j.device_id
                ORDER BY j.id DESC LIMIT 15
                """
            )
            recent = cursor.fetchall()
            mode = _sec8_mode(cursor)
    return {
        "mode": mode,
        "ca": ca["status"] if ca else None,
        "ca_seen_at": ca["updated_at"] if ca else None,
        "pending_jobs": int(queue["pending"] or 0),
        "ok_24h": int(queue["ok_24h"] or 0),
        "refused_24h": int(queue["refused_24h"] or 0),
        "approved_devices": int(devices["approved"] or 0),
        "devices_with_passport": int(devices["with_passport"] or 0),
        "recent_jobs": recent,
    }


@app.post("/ops/api/ca/issue-all")
def ca_issue_all(
    operator: dict[str, Any] = Depends(require_admin_cookie_brad_only),
):
    """Queue a passport for every approved device without a valid one (after the bootstrap import, or
    after passports were off for a while). Devices the CA already knows with the same key get no mail."""
    queued = 0
    with open_database() as connection:
        with connection.cursor() as cursor:
            if _sec8_mode(cursor) == "off":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Turn passports on (Log) first",
                )
            cursor.execute(
                """
                SELECT d.id FROM managed_devices d
                WHERE d.status = 'approved'
                  AND (d.passport_expires_at IS NULL OR d.passport_expires_at <= now())
                  AND NOT EXISTS (
                      SELECT 1 FROM ca_jobs j
                      WHERE j.device_id = d.id AND j.kind = 'issue' AND j.done_at IS NULL
                  )
                """
            )
            lifetime_days = _sec8_lifetime_days(cursor)
            for row in cursor.fetchall():
                device_payload = _sec8_device_payload(cursor, row["id"])
                if device_payload is None:
                    continue
                sec8_enqueue(cursor, "issue", row["id"], {
                    "device": device_payload,
                    "approver": sec8_approver(operator, "dashboard (issue all)"),
                    "lifetime_days": lifetime_days,
                    "reason": "bootstrap",
                })
                queued += 1
        connection.commit()
    return {"queued": queued}


@app.get("/v1/directory")
def approved_directory(
    request: Request,
    device: dict[str, Any] = Depends(require_device),
):
    now = datetime.now(timezone.utc)

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT instance_id
                FROM directory_instance
                WHERE singleton = TRUE
                """
            )
            instance = cursor.fetchone()

            cursor.execute(
                """
                SELECT
                    id,
                    rustdesk_id,
                    display_name,
                    hostname,
                    last_seen_at,
                    (
                        SELECT encode(m.device_public_key, 'base64')
                        FROM managed_devices m
                        WHERE m.id = approved_device_directory.id
                    ) AS device_public_key,
                    (
                        SELECT m.platform
                        FROM managed_devices m
                        WHERE m.id = approved_device_directory.id
                    ) AS platform
                FROM approved_device_directory
                WHERE id <> %s
                ORDER BY LOWER(display_name), rustdesk_id
                """,
                (device["device_id"],),
            )
            devices = [dict(row) for row in cursor.fetchall()]
            online_cutoff = now - timedelta(seconds=presence_timeout_seconds())
            for item in devices:
                last_seen = item.get("last_seen_at")
                item["online"] = bool(
                    last_seen is not None
                    and last_seen >= online_cutoff
                )

            # Batched (not per-device) lookup of who each approved device is
            # currently in an active session with, so RDC's own peer list can
            # show an "in session" indicator - mirrors device_active_connections()
            # used by the /ops admin dashboard, but as a single query covering
            # every device at once rather than one query per device, since this
            # endpoint is polled by every client on every refresh.
            session_cutoff = now - timedelta(seconds=presence_timeout_seconds())
            cursor.execute(
                """
                SELECT reporting_device_id AS device_id, peer_name FROM (
                    SELECT
                        s.reporting_device_id,
                        COALESCE(peer.friendly_name, peer.hostname, 'Unknown peer') AS peer_name
                    FROM device_active_sessions s
                    LEFT JOIN managed_devices peer
                      ON peer.rustdesk_id = s.peer_rustdesk_id
                    WHERE s.ended_at IS NULL
                      AND s.last_heartbeat_at >= %s

                    UNION ALL

                    SELECT
                        peer.id AS reporting_device_id,
                        COALESCE(reporting.friendly_name, reporting.hostname, 'Unknown peer') AS peer_name
                    FROM device_active_sessions s
                    JOIN managed_devices reporting
                      ON reporting.id = s.reporting_device_id
                    JOIN managed_devices peer
                      ON peer.rustdesk_id = s.peer_rustdesk_id
                    WHERE s.ended_at IS NULL
                      AND s.last_heartbeat_at >= %s
                ) combined
                """,
                (session_cutoff, session_cutoff),
            )
            active_peer_by_device = {}
            for row in cursor.fetchall():
                active_peer_by_device.setdefault(row["device_id"], row["peer_name"])
            for item in devices:
                item["active_session_peer"] = active_peer_by_device.get(item["id"])

            cursor.execute(
                """
                SELECT
                    (
                        SELECT COUNT(*)
                        FROM managed_devices d
                        WHERE d.status = 'approved'
                          AND d.last_seen_at IS NOT NULL
                          AND d.last_seen_at >= %s
                    ) AS online_clients,
                    (
                        SELECT COUNT(*)
                        FROM device_active_sessions s
                        JOIN managed_devices d
                          ON d.id = s.reporting_device_id
                        WHERE s.ended_at IS NULL
                          AND s.last_heartbeat_at >= %s
                          AND d.status = 'approved'
                    ) AS active_sessions
                """,
                (online_cutoff, online_cutoff),
            )
            stats_row = cursor.fetchone()
            server_stats = {
                "online_clients": int(stats_row["online_clients"] or 0),
                "active_sessions": int(stats_row["active_sessions"] or 0),
            }

            # Only client.directory_refresh_seconds is ever read back out of
            # this - the rest of the client.* settings table has no reader
            # on either end (no admin UI writes it, no client reads it), so
            # it stops here rather than round-tripping to every client too.
            settings = client_settings(cursor)
            refresh_seconds = settings.get(
                "client.directory_refresh_seconds",
                300,
            )

            peer_auth_mode = _get_peer_auth_mode(cursor)
            relay_fallback_delay_ms = _get_int_directory_setting(
                cursor, RELAY_FALLBACK_DELAY_MS_KEY, RELAY_FALLBACK_DELAY_MS_FALLBACK
            )
            # Build 30+: whether this device may start WebRTC connections - the same decision
            # hbbs makes about forwarding offers to it.
            webrtc_mode, webrtc_test_ids = _get_relay_webrtc(cursor)
            device_webrtc = webrtc_mode == "on" or (
                webrtc_mode == "test"
                and str(device.get("rustdesk_id") or "")
                in {i.strip() for i in webrtc_test_ids.split(",") if i.strip()}
            )

            payload = {
                "instance_id": instance["instance_id"],
                "generated_at": now,
                "refresh_seconds": refresh_seconds,
                "devices": devices,
                "server_stats": server_stats,
                # RDC's controlled side applies this to the controller's peer certificate:
                # off | log | enforce (see /v1/device/peer-cert).
                "peer_auth": {"mode": peer_auth_mode},
                "connection": {
                    "relay_fallback_delay_ms": relay_fallback_delay_ms,
                    "webrtc": device_webrtc,
                },
                # The requesting device's own row is excluded from `devices`
                # above (`WHERE id <> %s` - the peer list only ever shows
                # other machines), so this is the only way a client can
                # learn its own active-session state. active_peer_by_device
                # is keyed by device id and built from a query with no such
                # exclusion, so it may already hold this device's own id.
                "self_active_session_peer": active_peer_by_device.get(
                    device["device_id"]
                ),
            }
            # Clients fetch this when told it changed (or on their slow backstop) and send back the
            # version they hold; an unchanged view costs a bare 304 instead of the full list.
            etag = directory_etag(payload)
            if request.headers.get("if-none-match") == etag:
                return Response(status_code=304, headers={"ETag": etag})
            return JSONResponse(content=jsonable_encoder(payload), headers={"ETag": etag})


def load_update_manifest(channel: str, arch: str) -> dict[str, Any]:
    require_arch_field = True
    try:
        path = safe_update_file(UPDATE_MANIFESTS, f"{channel}-{arch}.json")
    except HTTPException as error:
        if error.status_code != status.HTTP_404_NOT_FOUND or arch != "x86_64":
            raise
        # Pre-arch-aware manifests (published before this server understood
        # architectures) only ever exist under the plain channel name and only
        # ever described x86_64 builds. Fall back so already-deployed x64
        # clients keep working until the channel is republished with --arch.
        path = safe_update_file(UPDATE_MANIFESTS, f"{channel}.json")
        require_arch_field = False

    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Managed update manifest is unavailable",
        ) from error

    if not isinstance(manifest, dict):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Managed update manifest is invalid",
        )

    required = {
        "channel",
        "build_number",
        "version",
        "file_name",
        "size",
        "sha256",
        "signature",
        "published_at",
    }
    if require_arch_field:
        required = required | {"arch"}
    if not required.issubset(manifest):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Managed update manifest is incomplete",
        )

    if manifest.get("channel") != channel:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Managed update manifest channel mismatch",
        )

    if require_arch_field and manifest.get("arch") != arch:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Managed update manifest architecture mismatch",
        )

    file_name = str(manifest.get("file_name", ""))
    # RDC for Android updates with APKs on its own arch key; every other arch is a Windows installer.
    suffix = ".apk" if arch == "android-aarch64" else ".exe"
    if Path(file_name).name != file_name or not file_name.lower().endswith(suffix):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Managed update manifest filename is invalid",
        )

    release = safe_update_file(UPDATE_RELEASES, file_name)
    if release.stat().st_size != int(manifest.get("size", -1)):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Managed update release size does not match manifest",
        )

    expected_sha256 = str(manifest.get("sha256", "")).lower()
    if (
        len(expected_sha256) != 64
        or any(ch not in "0123456789abcdef" for ch in expected_sha256)
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Managed update manifest SHA256 is invalid",
        )
    digest = hashlib.sha256()
    with release.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    if not hmac.compare_digest(digest.hexdigest(), expected_sha256):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Managed update release hash does not match manifest",
        )

    return manifest


@app.get("/v1/updates/latest")
def managed_update_latest(
    channel: str = Query(default="stable", pattern=r"^(stable|pilot)$"),
    arch: str = Query(default="x86_64", pattern=r"^(x86_64|aarch64|android-aarch64)$"),
    device: dict[str, Any] = Depends(require_device),
):
    del device
    try:
        manifest = load_update_manifest(channel, arch)
    except HTTPException as error:
        if error.status_code == status.HTTP_404_NOT_FOUND:
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        raise

    return {
        **manifest,
        "download_path": f"/v1/updates/releases/{manifest['file_name']}",
    }


@app.get("/v1/updates/releases/{file_name}")
def managed_update_release(
    file_name: str,
    device: dict[str, Any] = Depends(require_device),
):
    del device
    release = safe_update_file(UPDATE_RELEASES, file_name)
    return FileResponse(
        release,
        media_type=(
            "application/vnd.android.package-archive"
            if file_name.lower().endswith(".apk")
            else "application/vnd.microsoft.portable-executable"
        ),
        filename=file_name,
        headers={
            "Cache-Control": "private, no-store, max-age=0",
            "X-Content-Type-Options": "nosniff",
        },
    )


class OperatorInvitationCreateRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    display_name: str = Field(min_length=1, max_length=128)
    role: str = Field(pattern=r"^(manager|viewer)$")
    expires_in_hours: int = Field(default=72, ge=1, le=720)


class OperatorInvitationTokenRequest(BaseModel):
    invitation_token: str = Field(min_length=32, max_length=512)


class OperatorInvitationAcceptRequest(BaseModel):
    invitation_token: str = Field(min_length=32, max_length=512)
    password: str = Field(min_length=12, max_length=256)
    totp_code: str = Field(pattern=r"^\d{6}$")


class OperatorInvitationRevokeRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=1024)


class OperatorAccountActionRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=1024)


class OperatorEmailUpdateRequest(BaseModel):
    email: str | None = Field(default=None, max_length=320)


# Placeholder: replace with your deployment's protected primary-owner
# operator_accounts.id (keep it in sync with the same UUID in migration 023).
# The nil UUID never matches a real account, so until it is set the
# protection relies on the username check below alone.
PROTECTED_BRAD_ACCOUNT_ID = uuid.UUID(
    "00000000-0000-0000-0000-000000000000"
)
PROTECTED_BRAD_USERNAME = "brad"


def is_protected_brad_account(account: dict[str, Any]) -> bool:
    return (
        account.get("id") == PROTECTED_BRAD_ACCOUNT_ID
        or str(account.get("username", "")).strip().lower()
        == PROTECTED_BRAD_USERNAME
    )


def invitation_token_hash(token: str) -> bytes:
    return hmac.new(
        TOKEN_SECRET.encode(),
        ("operator-invitation:" + token).encode(),
        hashlib.sha256,
    ).digest()


def invitation_totp_secret(token: str) -> str:
    digest = hmac.new(
        TOTP_KEY.encode(),
        ("operator-invitation-totp:" + token).encode(),
        hashlib.sha256,
    ).digest()

    return base64.b32encode(digest).decode().rstrip("=")


def operator_account_response(
    cursor,
    account_id: uuid.UUID,
) -> dict[str, Any]:
    cursor.execute(
        """
        SELECT
            oa.id,
            oa.username,
            oa.display_name,
            oa.email,
            oa.role,
            oa.is_active,
            oa.must_change_password,
            oa.totp_enabled,
            oa.failed_login_count,
            oa.locked_until,
            oa.last_login_at,
            oa.last_login_ip,
            oa.password_changed_at,
            oa.totp_confirmed_at,
            oa.created_at,
            oa.updated_at,
            creator.username AS created_by_username,
            (
                SELECT COUNT(*)
                FROM operator_sessions os
                WHERE os.account_id = oa.id
                  AND os.revoked_at IS NULL
                  AND os.expires_at > NOW()
            ) AS active_session_count
        FROM operator_accounts oa
        LEFT JOIN operator_accounts creator
          ON creator.id = oa.created_by
        WHERE oa.id = %s
          AND oa.deleted_at IS NULL
        """,
        (account_id,),
    )

    account = cursor.fetchone()

    if account is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Operator account was not found",
        )

    return account


def pending_invitation_for_token(
    cursor,
    invitation_token: str,
    *,
    lock: bool,
) -> dict[str, Any]:
    lock_clause = "FOR UPDATE OF oi" if lock else ""

    cursor.execute(
        f"""
        SELECT
            oi.id,
            oi.proposed_username,
            oi.proposed_display_name,
            oi.requested_role,
            oi.created_by,
            oi.created_at,
            oi.expires_at,
            oi.status,
            creator.username AS created_by_username
        FROM operator_invitations oi
        JOIN operator_accounts creator
          ON creator.id = oi.created_by
        WHERE oi.token_hash = %s
        {lock_clause}
        """,
        (invitation_token_hash(invitation_token),),
    )

    invitation = cursor.fetchone()

    if invitation is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or unavailable invitation",
        )

    return invitation


@app.post("/v1/operator-invitations")
def create_operator_invitation(
    payload: OperatorInvitationCreateRequest,
    request: Request,
    operator: dict[str, Any] = Depends(require_owner),
):
    now = datetime.now(timezone.utc)
    source_ip = client_ip(request)
    username = payload.username.strip()
    display_name = payload.display_name.strip()

    if not username or not display_name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Username and display name cannot be blank",
        )

    raw_token = "rdi_" + secrets.token_urlsafe(48)
    expires_at = now + timedelta(hours=payload.expires_in_hours)

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE operator_invitations
                SET status = 'expired'
                WHERE status = 'pending'
                  AND expires_at <= %s
                """,
                (now,),
            )

            cursor.execute(
                """
                SELECT id
                FROM operator_accounts
                WHERE LOWER(username) = LOWER(%s)
                """,
                (username,),
            )

            if cursor.fetchone() is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="An operator account already uses that username",
                )

            cursor.execute(
                """
                SELECT id
                FROM operator_invitations
                WHERE status = 'pending'
                  AND LOWER(proposed_username) = LOWER(%s)
                """,
                (username,),
            )

            if cursor.fetchone() is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="A pending invitation already uses that username",
                )

            try:
                cursor.execute(
                    """
                    INSERT INTO operator_invitations (
                        proposed_username,
                        proposed_display_name,
                        requested_role,
                        token_hash,
                        created_by,
                        created_at,
                        expires_at
                    )
                    VALUES (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s
                    )
                    RETURNING
                        id,
                        proposed_username,
                        proposed_display_name,
                        requested_role,
                        created_at,
                        expires_at,
                        status
                    """,
                    (
                        username,
                        display_name,
                        payload.role,
                        invitation_token_hash(raw_token),
                        operator["account_id"],
                        now,
                        expires_at,
                    ),
                )
                invitation = cursor.fetchone()
            except psycopg.errors.UniqueViolation as error:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="That invitation conflicts with an existing invitation",
                ) from error

            write_audit(
                cursor,
                "operator.invitation_created",
                actor_account_id=operator["account_id"],
                target_type="operator_invitation",
                target_id=invitation["id"],
                source_ip=source_ip,
                details={
                    "username": username,
                    "display_name": display_name,
                    "role": payload.role,
                    "expires_at": expires_at.isoformat(),
                },
            )

            connection.commit()

            return {
                **invitation,
                "invitation_token": raw_token,
                "setup_endpoint": "/v1/operator-invitations/setup",
                "accept_endpoint": "/v1/operator-invitations/accept",
            }


@app.get("/v1/operator-invitations")
def list_operator_invitations(
    operator: dict[str, Any] = Depends(require_owner),
):
    now = datetime.now(timezone.utc)

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE operator_invitations
                SET status = 'expired'
                WHERE status = 'pending'
                  AND expires_at <= %s
                """,
                (now,),
            )

            cursor.execute(
                """
                SELECT
                    oi.id,
                    oi.proposed_username,
                    oi.proposed_display_name,
                    oi.requested_role,
                    oi.status,
                    oi.created_at,
                    oi.expires_at,
                    oi.accepted_at,
                    oi.revoked_at,
                    creator.username AS created_by_username,
                    accepted.username AS accepted_username,
                    revoker.username AS revoked_by_username
                FROM operator_invitations oi
                JOIN operator_accounts creator
                  ON creator.id = oi.created_by
                LEFT JOIN operator_accounts accepted
                  ON accepted.id = oi.accepted_account_id
                LEFT JOIN operator_accounts revoker
                  ON revoker.id = oi.revoked_by
                ORDER BY oi.created_at DESC
                """
            )
            invitations = cursor.fetchall()
            connection.commit()

            return {
                "generated_at": now,
                "invitations": invitations,
            }


@app.post("/v1/operator-invitations/{invitation_id}/revoke")
def revoke_operator_invitation(
    invitation_id: uuid.UUID,
    payload: OperatorInvitationRevokeRequest,
    request: Request,
    operator: dict[str, Any] = Depends(require_owner),
):
    now = datetime.now(timezone.utc)
    source_ip = client_ip(request)

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    proposed_username,
                    requested_role,
                    status,
                    expires_at
                FROM operator_invitations
                WHERE id = %s
                FOR UPDATE
                """,
                (invitation_id,),
            )
            invitation = cursor.fetchone()

            if invitation is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Operator invitation was not found",
                )

            if (
                invitation["status"] == "pending"
                and invitation["expires_at"] <= now
            ):
                cursor.execute(
                    """
                    UPDATE operator_invitations
                    SET status = 'expired'
                    WHERE id = %s
                    """,
                    (invitation_id,),
                )
                connection.commit()
                raise HTTPException(
                    status_code=status.HTTP_410_GONE,
                    detail="Operator invitation has expired",
                )

            if invitation["status"] != "pending":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Only pending invitations can be revoked",
                )

            cursor.execute(
                """
                UPDATE operator_invitations
                SET
                    status = 'revoked',
                    revoked_at = %s,
                    revoked_by = %s
                WHERE id = %s
                """,
                (
                    now,
                    operator["account_id"],
                    invitation_id,
                ),
            )

            write_audit(
                cursor,
                "operator.invitation_revoked",
                actor_account_id=operator["account_id"],
                target_type="operator_invitation",
                target_id=invitation_id,
                source_ip=source_ip,
                details={
                    "username": invitation["proposed_username"],
                    "role": invitation["requested_role"],
                    "reason": payload.reason.strip(),
                },
            )

            connection.commit()

            return {
                "id": invitation_id,
                "status": "revoked",
                "revoked_at": now,
                "reason": payload.reason.strip(),
            }


@app.post("/v1/operator-invitations/setup")
def setup_operator_invitation(
    payload: OperatorInvitationTokenRequest,
):
    now = datetime.now(timezone.utc)

    with open_database() as connection:
        with connection.cursor() as cursor:
            invitation = pending_invitation_for_token(
                cursor,
                payload.invitation_token,
                lock=True,
            )

            if invitation["status"] != "pending":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Invitation is no longer pending",
                )

            if invitation["expires_at"] <= now:
                cursor.execute(
                    """
                    UPDATE operator_invitations
                    SET status = 'expired'
                    WHERE id = %s
                    """,
                    (invitation["id"],),
                )
                connection.commit()
                raise HTTPException(
                    status_code=status.HTTP_410_GONE,
                    detail="Operator invitation has expired",
                )

            if invitation["requested_role"] not in {
                "manager",
                "viewer",
            }:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="This invitation requires the protected Owner promotion workflow",
                )

            secret = invitation_totp_secret(
                payload.invitation_token
            )
            provisioning_uri = pyotp.TOTP(
                secret
            ).provisioning_uri(
                name="Management",
                issuer_name="RUST",
            )

            return {
                "invitation_id": invitation["id"],
                "username": invitation["proposed_username"],
                "display_name": invitation["proposed_display_name"],
                "role": invitation["requested_role"],
                "expires_at": invitation["expires_at"],
                "totp_secret": secret,
                "totp_provisioning_uri": provisioning_uri,
            }


@app.post("/v1/operator-invitations/accept")
def accept_operator_invitation(
    payload: OperatorInvitationAcceptRequest,
    request: Request,
):
    now = datetime.now(timezone.utc)
    source_ip = client_ip(request)

    with open_database() as connection:
        with connection.cursor() as cursor:
            invitation = pending_invitation_for_token(
                cursor,
                payload.invitation_token,
                lock=True,
            )

            if invitation["status"] != "pending":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Invitation is no longer pending",
                )

            if invitation["expires_at"] <= now:
                cursor.execute(
                    """
                    UPDATE operator_invitations
                    SET status = 'expired'
                    WHERE id = %s
                    """,
                    (invitation["id"],),
                )
                connection.commit()
                raise HTTPException(
                    status_code=status.HTTP_410_GONE,
                    detail="Operator invitation has expired",
                )

            if invitation["requested_role"] not in {
                "manager",
                "viewer",
            }:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="This invitation requires the protected Owner promotion workflow",
                )

            secret = invitation_totp_secret(
                payload.invitation_token
            )
            totp_valid = pyotp.TOTP(secret).verify(
                payload.totp_code,
                valid_window=1,
            )

            if not totp_valid:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authenticator code",
                )

            cursor.execute(
                """
                SELECT id
                FROM operator_accounts
                WHERE LOWER(username) = LOWER(%s)
                """,
                (invitation["proposed_username"],),
            )

            if cursor.fetchone() is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="An operator account already uses that username",
                )

            try:
                cursor.execute(
                    """
                    INSERT INTO operator_accounts (
                        username,
                        display_name,
                        password_hash,
                        totp_secret_ciphertext,
                        totp_enabled,
                        role,
                        is_active,
                        must_change_password,
                        created_by,
                        password_changed_at,
                        totp_confirmed_at
                    )
                    VALUES (
                        %s,
                        %s,
                        crypt(%s, gen_salt('bf', 12)),
                        pgp_sym_encrypt(%s, %s),
                        TRUE,
                        %s,
                        TRUE,
                        FALSE,
                        %s,
                        %s,
                        %s
                    )
                    RETURNING
                        id,
                        username,
                        display_name,
                        role,
                        is_active,
                        must_change_password,
                        totp_enabled,
                        created_at
                    """,
                    (
                        invitation["proposed_username"],
                        invitation["proposed_display_name"],
                        payload.password,
                        secret,
                        TOTP_KEY,
                        invitation["requested_role"],
                        invitation["created_by"],
                        now,
                        now,
                    ),
                )
                account = cursor.fetchone()
            except psycopg.errors.UniqueViolation as error:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="An operator account already uses that username",
                ) from error

            cursor.execute(
                """
                UPDATE operator_invitations
                SET
                    status = 'accepted',
                    accepted_at = %s,
                    accepted_account_id = %s
                WHERE id = %s
                """,
                (
                    now,
                    account["id"],
                    invitation["id"],
                ),
            )

            write_audit(
                cursor,
                "operator.invitation_accepted",
                actor_account_id=account["id"],
                target_type="operator_invitation",
                target_id=invitation["id"],
                source_ip=source_ip,
                details={
                    "username": account["username"],
                    "display_name": account["display_name"],
                    "role": account["role"],
                    "created_by": str(invitation["created_by"]),
                },
            )

            connection.commit()

            return {
                "status": "accepted",
                "account": account,
                "login_endpoint": "/v1/auth/login",
            }


def authorize_operator_self_or_owner(
    operator: dict[str, Any],
    account_id: uuid.UUID,
) -> None:
    if (
        operator["role"] != "owner"
        and operator["account_id"] != account_id
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Owner access or the current Manager account is required",
        )


def revoke_idle_operator_sessions(cursor) -> None:
    # Closes out web/API sessions idle past the ops idle timeout (Config page) so the
    # Client Managers session counts and lists match what can still sign in
    # (require_operator/refresh already refuse them). Run where those counts
    # are shown rather than on a timer - this app has no scheduler hook.
    now = datetime.now(timezone.utc)
    cursor.execute(
        """
        UPDATE operator_sessions
        SET revoked_at = %s,
            revoked_by = account_id,
            revocation_reason = 'admin_idle_timeout'
        WHERE revoked_at IS NULL
          AND expires_at > %s
          AND scope <> 'mobile'
          AND COALESCE(last_seen_at, created_at) <= %s
        """,
        (now, now, now - operator_idle_timeout(cursor)),
    )


def operator_account_details_response(
    cursor,
    account_id: uuid.UUID,
) -> dict[str, Any]:
    revoke_idle_operator_sessions(cursor)
    account = operator_account_response(cursor, account_id)

    cursor.execute(
        """
        SELECT
            id, created_at, expires_at, last_seen_at,
            revoked_at, revocation_reason, source_ip, user_agent
        FROM operator_sessions
        WHERE account_id = %s
        ORDER BY created_at DESC
        LIMIT 50
        """,
        (account_id,),
    )
    sessions = cursor.fetchall()

    cursor.execute(
        """
        SELECT
            ae.id, ae.event_type, ae.target_type, ae.target_id,
            ae.source_ip, ae.details, ae.created_at,
            actor.username AS actor_username
        FROM audit_events ae
        LEFT JOIN operator_accounts actor
          ON actor.id = ae.actor_account_id
        WHERE ae.event_type LIKE 'operator.%%'
          AND (
                ae.actor_account_id = %s
                OR (
                    ae.target_type = 'operator_account'
                    AND ae.target_id = %s
                )
              )
        ORDER BY ae.created_at DESC
        LIMIT 150
        """,
        (account_id, account_id),
    )
    activity = cursor.fetchall()

    return {
        "account": account,
        "sessions": sessions,
        "activity_history": activity,
    }


@app.get("/v1/operators")
def list_operator_accounts(
    operator: dict[str, Any] = Depends(require_owner),
):
    with open_database() as connection:
        with connection.cursor() as cursor:
            revoke_idle_operator_sessions(cursor)
            connection.commit()
            cursor.execute(
                """
                SELECT
                    oa.id,
                    oa.username,
                    oa.display_name,
                    oa.email,
                    oa.role,
                    oa.is_active,
                    oa.must_change_password,
                    oa.totp_enabled,
                    oa.failed_login_count,
                    oa.locked_until,
                    oa.last_login_at,
                    oa.last_login_ip,
                    oa.created_at,
                    creator.username AS created_by_username,
                    (
                        SELECT COUNT(*)
                        FROM operator_sessions os
                        WHERE os.account_id = oa.id
                          AND os.revoked_at IS NULL
                          AND os.expires_at > NOW()
                    ) AS active_session_count
                FROM operator_accounts oa
                LEFT JOIN operator_accounts creator
                  ON creator.id = oa.created_by
                WHERE oa.deleted_at IS NULL
                ORDER BY
                    CASE oa.role
                        WHEN 'owner' THEN 1
                        WHEN 'manager' THEN 2
                        ELSE 3
                    END,
                    LOWER(oa.username)
                """
            )

            return {
                "operators": cursor.fetchall(),
            }


@app.get("/v1/operators/{account_id}")
def get_operator_account(
    account_id: uuid.UUID,
    operator: dict[str, Any] = Depends(require_full_scope_operator),
):
    authorize_operator_self_or_owner(operator, account_id)
    with open_database() as connection:
        with connection.cursor() as cursor:
            return operator_account_details_response(
                cursor,
                account_id,
            )


@app.put("/v1/operators/{account_id}/email")
def update_operator_email(
    account_id: uuid.UUID,
    payload: OperatorEmailUpdateRequest,
    request: Request,
    operator: dict[str, Any] = Depends(require_operator),
):
    authorize_operator_self_or_owner(operator, account_id)
    normalized = normalize_contact_email(payload.email)
    now = datetime.now(timezone.utc)
    source_ip = client_ip(request)

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, username, email
                FROM operator_accounts
                WHERE id = %s
                  AND deleted_at IS NULL
                FOR UPDATE
                """,
                (account_id,),
            )
            target = cursor.fetchone()
            if target is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Operator account was not found",
                )

            previous = target["email"]
            if previous != normalized:
                cursor.execute(
                    """
                    UPDATE operator_accounts
                    SET email = %s, updated_at = %s
                    WHERE id = %s
                    """,
                    (normalized, now, account_id),
                )
                write_audit(
                    cursor,
                    "operator.email_changed",
                    actor_account_id=operator["account_id"],
                    target_type="operator_account",
                    target_id=account_id,
                    source_ip=source_ip,
                    details={
                        "username": target["username"],
                        "old_email": previous,
                        "new_email": normalized,
                        "self_service": operator["account_id"] == account_id,
                    },
                )
            connection.commit()
            return operator_account_details_response(cursor, account_id)


@app.post("/v1/operators/{account_id}/disable")
def disable_operator_account(
    account_id: uuid.UUID,
    payload: OperatorAccountActionRequest,
    request: Request,
    operator: dict[str, Any] = Depends(require_owner),
):
    now = datetime.now(timezone.utc)
    source_ip = client_ip(request)

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, username, role, is_active, deleted_at
                FROM operator_accounts
                WHERE id = %s
                  AND deleted_at IS NULL
                FOR UPDATE
                """,
                (account_id,),
            )
            target = cursor.fetchone()

            if target is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Operator account was not found",
                )

            if is_protected_brad_account(target):
                write_audit(
                    cursor,
                    "operator.protected_lifecycle_change_blocked",
                    actor_account_id=operator["account_id"],
                    target_type="operator_account",
                    target_id=target["id"],
                    source_ip=source_ip,
                    details={
                        "username": target["username"],
                        "attempted_action": "disable",
                        "protection": "Brad account status/lifecycle is immutable",
                    },
                )
                connection.commit()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Brad account status and lifecycle are permanently protected",
                )

            if target["role"] == "owner":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Owner accounts require the protected Owner workflow",
                )

            if target["is_active"]:
                cursor.execute(
                    """
                    UPDATE operator_accounts
                    SET is_active = FALSE
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
                        revocation_reason = 'operator_account_disabled'
                    WHERE account_id = %s
                      AND revoked_at IS NULL
                    """,
                    (
                        now,
                        operator["account_id"],
                        account_id,
                    ),
                )

                write_audit(
                    cursor,
                    "operator.disabled",
                    actor_account_id=operator["account_id"],
                    target_type="operator_account",
                    target_id=account_id,
                    source_ip=source_ip,
                    details={
                        "username": target["username"],
                        "reason": payload.reason.strip(),
                    },
                )

            response = operator_account_response(
                cursor,
                account_id,
            )
            connection.commit()
            return response


@app.post("/v1/operators/{account_id}/enable")
def enable_operator_account(
    account_id: uuid.UUID,
    payload: OperatorAccountActionRequest,
    request: Request,
    operator: dict[str, Any] = Depends(require_owner),
):
    source_ip = client_ip(request)

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, username, role, is_active, deleted_at
                FROM operator_accounts
                WHERE id = %s
                  AND deleted_at IS NULL
                FOR UPDATE
                """,
                (account_id,),
            )
            target = cursor.fetchone()

            if target is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Operator account was not found",
                )

            if is_protected_brad_account(target):
                write_audit(
                    cursor,
                    "operator.protected_lifecycle_change_blocked",
                    actor_account_id=operator["account_id"],
                    target_type="operator_account",
                    target_id=target["id"],
                    source_ip=source_ip,
                    details={
                        "username": target["username"],
                        "attempted_action": "enable",
                        "protection": "Brad account status/lifecycle is immutable",
                    },
                )
                connection.commit()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Brad account status and lifecycle are permanently protected",
                )

            if target["role"] == "owner":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Owner accounts require the protected Owner workflow",
                )

            if not target["is_active"]:
                cursor.execute(
                    """
                    UPDATE operator_accounts
                    SET is_active = TRUE
                    WHERE id = %s
                    """,
                    (account_id,),
                )

                write_audit(
                    cursor,
                    "operator.enabled",
                    actor_account_id=operator["account_id"],
                    target_type="operator_account",
                    target_id=account_id,
                    source_ip=source_ip,
                    details={
                        "username": target["username"],
                        "reason": payload.reason.strip(),
                    },
                )

            response = operator_account_response(
                cursor,
                account_id,
            )
            connection.commit()
            return response


@app.post("/v1/operators/{account_id}/delete")
def delete_operator_account(
    account_id: uuid.UUID,
    payload: OperatorAccountActionRequest,
    request: Request,
    operator: dict[str, Any] = Depends(require_owner),
):
    now = datetime.now(timezone.utc)
    source_ip = client_ip(request)

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id, username, display_name, email, role, is_active,
                    totp_enabled, last_login_at, last_login_ip,
                    created_at, created_by, deleted_at
                FROM operator_accounts
                WHERE id = %s
                  AND deleted_at IS NULL
                FOR UPDATE
                """,
                (account_id,),
            )
            target = cursor.fetchone()

            if target is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Operator account was not found",
                )

            if is_protected_brad_account(target):
                write_audit(
                    cursor,
                    "operator.protected_lifecycle_change_blocked",
                    actor_account_id=operator["account_id"],
                    target_type="operator_account",
                    target_id=target["id"],
                    source_ip=source_ip,
                    details={
                        "username": target["username"],
                        "attempted_action": "delete",
                        "protection": "Brad account status/lifecycle is immutable",
                    },
                )
                connection.commit()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Brad account status and lifecycle are permanently protected",
                )

            if target["role"] == "owner":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Owner accounts cannot be deleted from Client Managers",
                )

            if target["is_active"]:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Disable the account before deleting it",
                )

            cursor.execute(
                """
                UPDATE operator_sessions
                SET
                    revoked_at = COALESCE(revoked_at, %s),
                    revoked_by = COALESCE(revoked_by, %s),
                    revocation_reason = COALESCE(
                        revocation_reason,
                        'operator_account_deleted'
                    )
                WHERE account_id = %s
                  AND revoked_at IS NULL
                """,
                (now, operator["account_id"], account_id),
            )
            revoked_sessions = cursor.rowcount

            cursor.execute(
                """
                UPDATE operator_access_resets
                SET revoked_at = COALESCE(revoked_at, %s)
                WHERE account_id = %s
                  AND used_at IS NULL
                  AND revoked_at IS NULL
                """,
                (now, account_id),
            )
            revoked_resets = cursor.rowcount

            cursor.execute(
                """
                UPDATE operator_role_change_requests
                SET status = 'cancelled'
                WHERE target_account_id = %s
                  AND status = 'pending'
                """,
                (account_id,),
            )
            cancelled_role_changes = cursor.rowcount

            cursor.execute(
                """
                UPDATE operator_invitations
                SET
                    status = 'revoked',
                    revoked_at = %s,
                    revoked_by = %s
                WHERE target_account_id = %s
                  AND status = 'pending'
                """,
                (now, operator["account_id"], account_id),
            )
            revoked_invitations = cursor.rowcount

            deletion_snapshot = {
                "username": target["username"],
                "display_name": target["display_name"],
                "email": target["email"],
                "role": target["role"],
                "is_active": target["is_active"],
                "totp_enabled": target["totp_enabled"],
                "last_login_at": (
                    target["last_login_at"].isoformat()
                    if target["last_login_at"] is not None
                    else None
                ),
                "last_login_ip": (
                    str(target["last_login_ip"])
                    if target["last_login_ip"] is not None
                    else None
                ),
                "created_at": target["created_at"].isoformat(),
                "created_by": (
                    str(target["created_by"])
                    if target["created_by"] is not None
                    else None
                ),
                "reason": payload.reason.strip(),
                "revoked_session_count": revoked_sessions,
                "revoked_reset_count": revoked_resets,
                "cancelled_role_change_count": cancelled_role_changes,
                "revoked_invitation_count": revoked_invitations,
            }

            write_audit(
                cursor,
                "operator.deleted",
                actor_account_id=operator["account_id"],
                target_type="operator_account",
                target_id=account_id,
                source_ip=source_ip,
                details=deletion_snapshot,
            )

            cursor.execute(
                """
                UPDATE operator_accounts
                SET
                    deleted_at = %s,
                    deleted_by = %s,
                    deletion_reason = %s,
                    is_active = FALSE,
                    updated_at = %s
                WHERE id = %s
                """,
                (
                    now,
                    operator["account_id"],
                    payload.reason.strip(),
                    now,
                    account_id,
                ),
            )
            connection.commit()

            return {
                "status": "deleted",
                "account_id": account_id,
                "username": target["username"],
                "audit_preserved": True,
            }


@app.post("/v1/operators/{account_id}/unlock")
def unlock_operator_account(
    account_id: uuid.UUID,
    payload: OperatorAccountActionRequest,
    request: Request,
    operator: dict[str, Any] = Depends(require_owner),
):
    source_ip = client_ip(request)

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, username
                FROM operator_accounts
                WHERE id = %s
                  AND deleted_at IS NULL
                FOR UPDATE
                """,
                (account_id,),
            )
            target = cursor.fetchone()

            if target is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Operator account was not found",
                )

            cursor.execute(
                """
                UPDATE operator_accounts
                SET
                    failed_login_count = 0,
                    locked_until = NULL
                WHERE id = %s
                """,
                (account_id,),
            )

            write_audit(
                cursor,
                "operator.unlocked",
                actor_account_id=operator["account_id"],
                target_type="operator_account",
                target_id=account_id,
                source_ip=source_ip,
                details={
                    "username": target["username"],
                    "reason": payload.reason.strip(),
                },
            )

            response = operator_account_response(
                cursor,
                account_id,
            )
            connection.commit()
            return response


@app.post("/v1/operators/{account_id}/revoke-sessions")
def revoke_operator_sessions(
    account_id: uuid.UUID,
    payload: OperatorAccountActionRequest,
    request: Request,
    operator: dict[str, Any] = Depends(require_owner),
):
    now = datetime.now(timezone.utc)
    source_ip = client_ip(request)

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, username
                FROM operator_accounts
                WHERE id = %s
                  AND deleted_at IS NULL
                """,
                (account_id,),
            )
            target = cursor.fetchone()

            if target is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Operator account was not found",
                )

            cursor.execute(
                """
                UPDATE operator_sessions
                SET
                    revoked_at = %s,
                    revoked_by = %s,
                    revocation_reason = 'owner_revoked_sessions'
                WHERE account_id = %s
                  AND revoked_at IS NULL
                """,
                (
                    now,
                    operator["account_id"],
                    account_id,
                ),
            )
            revoked_sessions = cursor.rowcount

            write_audit(
                cursor,
                "operator.sessions_revoked",
                actor_account_id=operator["account_id"],
                target_type="operator_account",
                target_id=account_id,
                source_ip=source_ip,
                details={
                    "username": target["username"],
                    "reason": payload.reason.strip(),
                    "revoked_session_count": revoked_sessions,
                },
            )

            connection.commit()

            return {
                "account_id": account_id,
                "username": target["username"],
                "revoked_session_count": revoked_sessions,
                "revoked_at": now,
            }


class OperatorRoleChangeCreateRequest(BaseModel):
    requested_role: str = Field(
        pattern=r"^(owner|manager|viewer)$"
    )
    reason: str = Field(min_length=1, max_length=1024)
    expires_in_minutes: int = Field(default=15, ge=5, le=60)
    owner_password: str | None = Field(
        default=None,
        min_length=1,
        max_length=256,
    )
    owner_totp_code: str | None = Field(
        default=None,
        pattern=r"^\d{6}$",
    )


class OperatorRoleChangeActionRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=1024)


def verify_owner_reauthentication(
    cursor,
    owner_account_id: uuid.UUID,
    password: str | None,
    totp_code: str | None,
) -> tuple[datetime, datetime]:
    if password is None or totp_code is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Owner password and authenticator code are required "
                "for this role change"
            ),
        )

    cursor.execute(
        """
        SELECT
            is_active,
            role,
            must_change_password,
            totp_enabled,
            crypt(%s, password_hash) = password_hash AS password_ok,
            CASE
                WHEN totp_secret_ciphertext IS NULL THEN NULL
                ELSE pgp_sym_decrypt(
                    totp_secret_ciphertext,
                    %s
                )::text
            END AS totp_secret
        FROM operator_accounts
        WHERE id = %s
        FOR UPDATE
        """,
        (
            password,
            TOTP_KEY,
            owner_account_id,
        ),
    )
    owner = cursor.fetchone()

    totp_valid = False

    if (
        owner is not None
        and owner["is_active"]
        and owner["role"] == "owner"
        and not owner["must_change_password"]
        and owner["totp_enabled"]
        and owner["totp_secret"] is not None
    ):
        totp_valid = pyotp.TOTP(
            owner["totp_secret"]
        ).verify(
            totp_code,
            valid_window=1,
        )

    if (
        owner is None
        or not owner["password_ok"]
        or not totp_valid
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Owner password or authenticator code is invalid",
        )

    verified_at = datetime.now(timezone.utc)
    return verified_at, verified_at


def operator_role_change_response(
    cursor,
    request_id: uuid.UUID,
) -> dict[str, Any]:
    cursor.execute(
        """
        SELECT
            orcr.id,
            orcr.target_account_id,
            target.username AS target_username,
            target.display_name AS target_display_name,
            target.role AS current_role,
            target.is_active AS target_is_active,
            orcr.requested_role,
            orcr.requested_by,
            requester.username AS requested_by_username,
            orcr.owner_password_verified_at,
            orcr.owner_totp_verified_at,
            orcr.status,
            orcr.reason,
            orcr.created_at,
            orcr.expires_at,
            orcr.completed_at,
            orcr.completed_by,
            completer.username AS completed_by_username
        FROM operator_role_change_requests orcr
        JOIN operator_accounts target
          ON target.id = orcr.target_account_id
        JOIN operator_accounts requester
          ON requester.id = orcr.requested_by
        LEFT JOIN operator_accounts completer
          ON completer.id = orcr.completed_by
        WHERE orcr.id = %s
        """,
        (request_id,),
    )
    role_change = cursor.fetchone()

    if role_change is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Operator role-change request was not found",
        )

    return role_change


@app.post("/v1/operators/{account_id}/role-change-requests")
def create_operator_role_change_request(
    account_id: uuid.UUID,
    payload: OperatorRoleChangeCreateRequest,
    request: Request,
    operator: dict[str, Any] = Depends(require_owner),
):
    now = datetime.now(timezone.utc)
    source_ip = client_ip(request)
    reason = payload.reason.strip()

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE operator_role_change_requests
                SET status = 'expired'
                WHERE status = 'pending'
                  AND expires_at <= %s
                """,
                (now,),
            )

            cursor.execute(
                """
                SELECT
                    id,
                    username,
                    display_name,
                    role,
                    is_active,
                    must_change_password,
                    totp_enabled
                FROM operator_accounts
                WHERE id = %s
                FOR UPDATE
                """,
                (account_id,),
            )
            target = cursor.fetchone()

            if target is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Operator account was not found",
                )

            if is_protected_brad_account(target):
                write_audit(
                    cursor,
                    "operator.protected_role_change_blocked",
                    actor_account_id=operator["account_id"],
                    target_type="operator_account",
                    target_id=target["id"],
                    source_ip=source_ip,
                    details={
                        "username": target["username"],
                        "current_role": target["role"],
                        "requested_role": payload.requested_role,
                        "protection": "Brad account role is permanently fixed as Owner",
                    },
                )
                connection.commit()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Brad account role is permanently protected as Owner",
                )

            if account_id == operator["account_id"]:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Owners cannot change their own role",
                )

            if not target["is_active"]:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Inactive operator accounts cannot receive a role change",
                )

            if target["role"] == payload.requested_role:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="The operator already has the requested role",
                )

            if (
                payload.requested_role == "owner"
                and (
                    not target["totp_enabled"]
                    or target["must_change_password"]
                )
            ):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "The target must have a confirmed authenticator "
                        "and completed password setup before Owner promotion"
                    ),
                )

            sensitive_owner_change = (
                target["role"] == "owner"
                or payload.requested_role == "owner"
            )

            password_verified_at = None
            totp_verified_at = None

            if sensitive_owner_change:
                (
                    password_verified_at,
                    totp_verified_at,
                ) = verify_owner_reauthentication(
                    cursor,
                    operator["account_id"],
                    payload.owner_password,
                    payload.owner_totp_code,
                )

            expires_at = now + timedelta(
                minutes=payload.expires_in_minutes
            )

            try:
                cursor.execute(
                    """
                    INSERT INTO operator_role_change_requests (
                        target_account_id,
                        requested_role,
                        requested_by,
                        owner_password_verified_at,
                        owner_totp_verified_at,
                        reason,
                        created_at,
                        expires_at
                    )
                    VALUES (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s
                    )
                    RETURNING id
                    """,
                    (
                        account_id,
                        payload.requested_role,
                        operator["account_id"],
                        password_verified_at,
                        totp_verified_at,
                        reason,
                        now,
                        expires_at,
                    ),
                )
                request_id = cursor.fetchone()["id"]
            except psycopg.errors.UniqueViolation as error:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "A pending role-change request already exists "
                        "for this operator"
                    ),
                ) from error
            except (
                psycopg.errors.CheckViolation,
                psycopg.errors.RaiseException,
            ) as error:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=str(error).splitlines()[0],
                ) from error

            write_audit(
                cursor,
                "operator.role_change_requested",
                actor_account_id=operator["account_id"],
                target_type="operator_account",
                target_id=account_id,
                source_ip=source_ip,
                details={
                    "target_username": target["username"],
                    "current_role": target["role"],
                    "requested_role": payload.requested_role,
                    "reason": reason,
                    "request_id": str(request_id),
                    "expires_at": expires_at.isoformat(),
                    "owner_reauthentication_required": sensitive_owner_change,
                },
            )

            response = operator_role_change_response(
                cursor,
                request_id,
            )
            connection.commit()
            return response


@app.get("/v1/operator-role-change-requests")
def list_operator_role_change_requests(
    operator: dict[str, Any] = Depends(require_owner),
):
    now = datetime.now(timezone.utc)

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE operator_role_change_requests
                SET status = 'expired'
                WHERE status = 'pending'
                  AND expires_at <= %s
                """,
                (now,),
            )

            cursor.execute(
                """
                SELECT
                    orcr.id,
                    orcr.target_account_id,
                    target.username AS target_username,
                    target.display_name AS target_display_name,
                    target.role AS current_role,
                    target.is_active AS target_is_active,
                    orcr.requested_role,
                    requester.username AS requested_by_username,
                    orcr.owner_password_verified_at,
                    orcr.owner_totp_verified_at,
                    orcr.status,
                    orcr.reason,
                    orcr.created_at,
                    orcr.expires_at,
                    orcr.completed_at,
                    completer.username AS completed_by_username
                FROM operator_role_change_requests orcr
                JOIN operator_accounts target
                  ON target.id = orcr.target_account_id
                JOIN operator_accounts requester
                  ON requester.id = orcr.requested_by
                LEFT JOIN operator_accounts completer
                  ON completer.id = orcr.completed_by
                ORDER BY orcr.created_at DESC
                """
            )
            role_changes = cursor.fetchall()
            connection.commit()

            return {
                "generated_at": now,
                "role_change_requests": role_changes,
            }


@app.post(
    "/v1/operator-role-change-requests/{request_id}/complete"
)
def complete_operator_role_change_request(
    request_id: uuid.UUID,
    payload: OperatorRoleChangeActionRequest,
    request: Request,
    operator: dict[str, Any] = Depends(require_owner),
):
    now = datetime.now(timezone.utc)
    source_ip = client_ip(request)
    completion_reason = payload.reason.strip()

    connection = open_database()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    orcr.id,
                    orcr.target_account_id,
                    orcr.requested_role,
                    orcr.requested_by,
                    orcr.owner_password_verified_at,
                    orcr.owner_totp_verified_at,
                    orcr.status,
                    orcr.reason,
                    orcr.expires_at,
                    target.username AS target_username,
                    target.role AS current_role,
                    target.is_active AS target_is_active,
                    target.totp_enabled AS target_totp_enabled,
                    target.must_change_password AS target_must_change_password
                FROM operator_role_change_requests orcr
                JOIN operator_accounts target
                  ON target.id = orcr.target_account_id
                WHERE orcr.id = %s
                FOR UPDATE OF orcr, target
                """,
                (request_id,),
            )
            role_change = cursor.fetchone()

            if role_change is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Operator role-change request was not found",
                )

            if role_change["status"] != "pending":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Only pending role-change requests can be completed",
                )

            if role_change["expires_at"] <= now:
                cursor.execute(
                    """
                    UPDATE operator_role_change_requests
                    SET status = 'expired'
                    WHERE id = %s
                    """,
                    (request_id,),
                )
                connection.commit()
                raise HTTPException(
                    status_code=status.HTTP_410_GONE,
                    detail="Operator role-change request has expired",
                )

            if (
                role_change["target_account_id"] == PROTECTED_BRAD_ACCOUNT_ID
                or str(role_change["target_username"]).strip().lower()
                == PROTECTED_BRAD_USERNAME
            ):
                write_audit(
                    cursor,
                    "operator.protected_role_change_blocked",
                    actor_account_id=operator["account_id"],
                    target_type="operator_account",
                    target_id=role_change["target_account_id"],
                    source_ip=source_ip,
                    details={
                        "username": role_change["target_username"],
                        "current_role": role_change["current_role"],
                        "requested_role": role_change["requested_role"],
                        "request_id": str(request_id),
                        "protection": "Brad account role is permanently fixed as Owner",
                    },
                )
                connection.commit()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Brad account role is permanently protected as Owner",
                )

            if role_change["target_account_id"] == operator["account_id"]:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Owners cannot complete a change to their own role",
                )

            if not role_change["target_is_active"]:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Inactive operator accounts cannot receive a role change",
                )

            if role_change["current_role"] == role_change["requested_role"]:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="The operator already has the requested role",
                )

            if (
                role_change["requested_role"] == "owner"
                and (
                    role_change["owner_password_verified_at"] is None
                    or role_change["owner_totp_verified_at"] is None
                    or not role_change["target_totp_enabled"]
                    or role_change["target_must_change_password"]
                )
            ):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "Owner promotion prerequisites are no longer satisfied"
                    ),
                )

            cursor.execute(
                """
                UPDATE operator_role_change_requests
                SET
                    status = 'completed',
                    completed_at = %s,
                    completed_by = %s
                WHERE id = %s
                """,
                (
                    now,
                    operator["account_id"],
                    request_id,
                ),
            )

            cursor.execute(
                """
                UPDATE operator_sessions
                SET
                    revoked_at = %s,
                    revoked_by = %s,
                    revocation_reason = 'operator_role_changed'
                WHERE account_id = %s
                  AND revoked_at IS NULL
                """,
                (
                    now,
                    operator["account_id"],
                    role_change["target_account_id"],
                ),
            )
            revoked_session_count = cursor.rowcount

            write_audit(
                cursor,
                "operator.role_change_completed",
                actor_account_id=operator["account_id"],
                target_type="operator_account",
                target_id=role_change["target_account_id"],
                source_ip=source_ip,
                details={
                    "target_username": role_change["target_username"],
                    "old_role": role_change["current_role"],
                    "new_role": role_change["requested_role"],
                    "request_id": str(request_id),
                    "request_reason": role_change["reason"],
                    "completion_reason": completion_reason,
                    "revoked_session_count": revoked_session_count,
                },
            )

            response = {
                "request": operator_role_change_response(
                    cursor,
                    request_id,
                ),
                "operator": operator_account_response(
                    cursor,
                    role_change["target_account_id"],
                ),
                "revoked_session_count": revoked_session_count,
            }
            connection.commit()
            return response

    except (
        psycopg.errors.CheckViolation,
        psycopg.errors.RaiseException,
    ) as error:
        connection.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(error).splitlines()[0],
        ) from error
    finally:
        connection.close()


@app.post(
    "/v1/operator-role-change-requests/{request_id}/cancel"
)
def cancel_operator_role_change_request(
    request_id: uuid.UUID,
    payload: OperatorRoleChangeActionRequest,
    request: Request,
    operator: dict[str, Any] = Depends(require_owner),
):
    now = datetime.now(timezone.utc)
    source_ip = client_ip(request)
    cancellation_reason = payload.reason.strip()

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    orcr.id,
                    orcr.target_account_id,
                    orcr.requested_role,
                    orcr.status,
                    orcr.expires_at,
                    target.username AS target_username,
                    target.role AS current_role
                FROM operator_role_change_requests orcr
                JOIN operator_accounts target
                  ON target.id = orcr.target_account_id
                WHERE orcr.id = %s
                FOR UPDATE OF orcr
                """,
                (request_id,),
            )
            role_change = cursor.fetchone()

            if role_change is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Operator role-change request was not found",
                )

            if role_change["status"] != "pending":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Only pending role-change requests can be cancelled",
                )

            if role_change["expires_at"] <= now:
                cursor.execute(
                    """
                    UPDATE operator_role_change_requests
                    SET status = 'expired'
                    WHERE id = %s
                    """,
                    (request_id,),
                )
                connection.commit()
                raise HTTPException(
                    status_code=status.HTTP_410_GONE,
                    detail="Operator role-change request has expired",
                )

            cursor.execute(
                """
                UPDATE operator_role_change_requests
                SET status = 'cancelled'
                WHERE id = %s
                """,
                (request_id,),
            )

            write_audit(
                cursor,
                "operator.role_change_cancelled",
                actor_account_id=operator["account_id"],
                target_type="operator_account",
                target_id=role_change["target_account_id"],
                source_ip=source_ip,
                details={
                    "target_username": role_change["target_username"],
                    "current_role": role_change["current_role"],
                    "requested_role": role_change["requested_role"],
                    "request_id": str(request_id),
                    "reason": cancellation_reason,
                },
            )

            response = operator_role_change_response(
                cursor,
                request_id,
            )
            connection.commit()
            return response


# --- OUTBOUND MAIL (mail-server integration groundwork) ---
# Brad-only, not owner-only - see require_brad_only.

class SmtpConfigUpdate(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)
    use_tls: bool = True
    username: str | None = None
    # None = leave the stored password untouched. "" = explicitly clear it.
    # Anything else = replace it.
    password: str | None = None
    from_address: str = Field(min_length=3, max_length=255)
    enabled: bool = False


class SmtpTestRequest(BaseModel):
    # All optional - omitted fields fall back to whatever is already saved,
    # so Test Connection works either against in-progress edits or the
    # stored config, without requiring a save first.
    host: str | None = None
    port: int | None = None
    use_tls: bool | None = None
    username: str | None = None
    password: str | None = None
    from_address: str | None = None
    test_recipient: str = Field(min_length=3, max_length=255)


def _smtp_config_response(cursor) -> dict[str, Any]:
    cursor.execute(
        """
        SELECT host, port, use_tls, username, from_address, enabled,
               password_ciphertext IS NOT NULL AS has_password,
               updated_at
        FROM smtp_config
        WHERE id = 1
        """
    )
    row = cursor.fetchone()
    if row is None:
        return {
            "host": None,
            "port": None,
            "use_tls": True,
            "username": None,
            "from_address": None,
            "enabled": False,
            "has_password": False,
            "updated_at": None,
        }
    return dict(row)


@app.get("/ops/api/smtp-config")
def get_smtp_config(
    operator: dict[str, Any] = Depends(require_admin_cookie_brad_only),
):
    with open_database() as connection:
        with connection.cursor() as cursor:
            return _smtp_config_response(cursor)


@app.put("/ops/api/smtp-config")
def update_smtp_config(
    payload: SmtpConfigUpdate,
    request: Request,
    operator: dict[str, Any] = Depends(require_admin_cookie_brad_only),
):
    if payload.password not in (None, "") and not SMTP_ENCRYPTION_SECRET:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SMTP_ENCRYPTION_SECRET is not configured on the server",
        )

    source_ip = client_ip(request)
    now = datetime.now(timezone.utc)

    if payload.password is None:
        password_value_sql = "NULL"
        password_update_sql = "smtp_config.password_ciphertext"
        password_params: tuple[Any, ...] = ()
    elif payload.password == "":
        password_value_sql = "NULL"
        password_update_sql = "NULL"
        password_params = ()
    else:
        password_value_sql = "pgp_sym_encrypt(%s, %s)"
        password_update_sql = "EXCLUDED.password_ciphertext"
        password_params = (payload.password, SMTP_ENCRYPTION_SECRET)

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                INSERT INTO smtp_config (
                    id, host, port, use_tls, username, password_ciphertext,
                    from_address, enabled, updated_at, updated_by_account_id
                )
                VALUES (
                    1, %s, %s, %s, %s, {password_value_sql},
                    %s, %s, %s, %s
                )
                ON CONFLICT (id) DO UPDATE SET
                    host = EXCLUDED.host,
                    port = EXCLUDED.port,
                    use_tls = EXCLUDED.use_tls,
                    username = EXCLUDED.username,
                    password_ciphertext = {password_update_sql},
                    from_address = EXCLUDED.from_address,
                    enabled = EXCLUDED.enabled,
                    updated_at = EXCLUDED.updated_at,
                    updated_by_account_id = EXCLUDED.updated_by_account_id
                """,
                (
                    payload.host,
                    payload.port,
                    payload.use_tls,
                    payload.username,
                    *password_params,
                    payload.from_address,
                    payload.enabled,
                    now,
                    operator["account_id"],
                ),
            )

            write_audit(
                cursor,
                "smtp.config_updated",
                actor_account_id=operator["account_id"],
                # No target_type/target_id: smtp_config is a singleton with
                # no UUID row id, and audit_events_target_pair_check requires
                # target_type and target_id to be both null or both set.
                source_ip=source_ip,
                details={
                    "host": payload.host,
                    "port": payload.port,
                    "enabled": payload.enabled,
                    "password_changed": bool(payload.password),
                    "password_cleared": payload.password == "",
                },
            )
            connection.commit()
            return _smtp_config_response(cursor)


def _send_mail(
    *,
    host: str,
    port: int,
    use_tls: bool,
    username: str | None,
    password: str | None,
    from_address: str,
    to_address: str,
    subject: str,
    body: str,
) -> None:
    message = MIMEText(body)
    message["Subject"] = subject
    message["From"] = from_address
    message["To"] = to_address

    with smtplib.SMTP(host, port, timeout=10) as server:
        if use_tls:
            server.starttls(context=ssl.create_default_context())
        if username and password:
            server.login(username, password)
        server.sendmail(from_address, [to_address], message.as_string())


def _send_smtp_test(
    *,
    host: str,
    port: int,
    use_tls: bool,
    username: str | None,
    password: str | None,
    from_address: str,
    test_recipient: str,
) -> None:
    _send_mail(
        host=host,
        port=port,
        use_tls=use_tls,
        username=username,
        password=password,
        from_address=from_address,
        to_address=test_recipient,
        subject="RustDesk Directory - SMTP test",
        body=(
            "This is a test message from the RustDesk Directory admin console, "
            "confirming outbound SMTP delivery is working."
        ),
    )


def _send_alert_email(*, subject: str, body: str) -> None:
    # Best-effort only, same as push notifications elsewhere in this file -
    # an alert email must never break the caller (enrollment, a health-event
    # report, a backup timer). Always goes to Brad's own account email; this
    # is a Brad-only feature (see the Mail settings page) with one recipient.
    if not SMTP_ENCRYPTION_SECRET:
        return
    try:
        with open_database() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT host, port, use_tls, username, from_address, enabled,
                        CASE
                            WHEN password_ciphertext IS NULL THEN NULL
                            ELSE pgp_sym_decrypt(password_ciphertext, %s)
                        END AS password
                    FROM smtp_config
                    WHERE id = 1
                    """,
                    (SMTP_ENCRYPTION_SECRET,),
                )
                config = cursor.fetchone()
                if (
                    not config
                    or not config["enabled"]
                    or not config["host"]
                    or not config["port"]
                    or not config["from_address"]
                ):
                    return

                cursor.execute(
                    "SELECT email FROM operator_accounts WHERE id = %s",
                    (PROTECTED_BRAD_ACCOUNT_ID,),
                )
                recipient_row = cursor.fetchone()

        recipient = recipient_row["email"] if recipient_row else None
        if not recipient:
            return

        _send_mail(
            host=config["host"],
            port=config["port"],
            use_tls=config["use_tls"],
            username=config["username"],
            password=config["password"],
            from_address=config["from_address"],
            to_address=recipient,
            subject=subject,
            body=body,
        )
        logging.getLogger("uvicorn.error").info("alert email sent: %s", subject)
    except Exception as error:
        logging.getLogger("uvicorn.error").warning(
            "alert email failed: %s: %s", type(error).__name__, error
        )


@app.post("/ops/api/smtp-config/test")
def test_smtp_config(
    payload: SmtpTestRequest,
    operator: dict[str, Any] = Depends(require_admin_cookie_brad_only),
):
    with open_database() as connection:
        with connection.cursor() as cursor:
            if SMTP_ENCRYPTION_SECRET:
                cursor.execute(
                    """
                    SELECT host, port, use_tls, username, from_address,
                        CASE
                            WHEN password_ciphertext IS NULL THEN NULL
                            ELSE pgp_sym_decrypt(password_ciphertext, %s)
                        END AS password
                    FROM smtp_config
                    WHERE id = 1
                    """,
                    (SMTP_ENCRYPTION_SECRET,),
                )
            else:
                cursor.execute(
                    """
                    SELECT host, port, use_tls, username, from_address,
                           NULL AS password
                    FROM smtp_config
                    WHERE id = 1
                    """
                )
            stored = cursor.fetchone() or {}

    host = payload.host or stored.get("host")
    port = payload.port or stored.get("port")
    use_tls = (
        payload.use_tls if payload.use_tls is not None
        else stored.get("use_tls", True)
    )
    username = (
        payload.username if payload.username is not None
        else stored.get("username")
    )
    password = (
        payload.password if payload.password is not None
        else stored.get("password")
    )
    from_address = payload.from_address or stored.get("from_address")

    if not host or not port or not from_address:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Host, port, and a From address are required to test",
        )

    try:
        _send_smtp_test(
            host=host,
            port=port,
            use_tls=use_tls,
            username=username,
            password=password,
            from_address=from_address,
            test_recipient=payload.test_recipient,
        )
        return {
            "success": True,
            "message": f"Test message sent to {payload.test_recipient}.",
        }
    except (smtplib.SMTPException, OSError, TimeoutError) as error:
        return {"success": False, "message": str(error)}


class SecuritySettingsRequest(BaseModel):
    # All optional and independently upserted, matching RustdropSettingsRequest's
    # own convention (rustdrop.py) - only fields actually sent get changed.
    access_token_minutes: int | None = Field(default=None, ge=5, le=120)
    session_days: int | None = Field(default=None, ge=1, le=180)
    mobile_session_days: int | None = Field(default=None, ge=7, le=3650)
    ops_idle_minutes: int | None = Field(
        default=None, ge=OPS_IDLE_MINUTES_MIN, le=OPS_IDLE_MINUTES_MAX
    )


def _security_settings_response(cursor) -> dict[str, Any]:
    return {
        "ops_idle_minutes": int(operator_idle_timeout(cursor).total_seconds() // 60),
        "access_token_minutes": _get_int_directory_setting(
            cursor, SECURITY_ACCESS_TOKEN_MINUTES_KEY, ACCESS_TOKEN_MINUTES
        ),
        "session_days": _get_int_directory_setting(
            cursor, SECURITY_SESSION_DAYS_KEY, SESSION_DAYS
        ),
        "mobile_session_days": _get_int_directory_setting(
            cursor, SECURITY_MOBILE_SESSION_DAYS_KEY, MOBILE_SESSION_DAYS
        ),
    }


@app.get("/ops/api/security-settings")
def get_security_settings(
    operator: dict[str, Any] = Depends(require_admin_cookie_brad_only),
):
    with open_database() as connection:
        with connection.cursor() as cursor:
            return _security_settings_response(cursor)


@app.post("/ops/api/security-settings")
def set_security_settings(
    payload: SecuritySettingsRequest,
    operator: dict[str, Any] = Depends(require_admin_cookie_brad_only),
):
    updates: list[tuple[str, str]] = []
    if payload.access_token_minutes is not None:
        updates.append((SECURITY_ACCESS_TOKEN_MINUTES_KEY, str(payload.access_token_minutes)))
    if payload.session_days is not None:
        updates.append((SECURITY_SESSION_DAYS_KEY, str(payload.session_days)))
    if payload.mobile_session_days is not None:
        updates.append((SECURITY_MOBILE_SESSION_DAYS_KEY, str(payload.mobile_session_days)))
    if payload.ops_idle_minutes is not None:
        updates.append((SECURITY_OPS_IDLE_MINUTES_KEY, str(payload.ops_idle_minutes)))

    with open_database() as connection:
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
    return get_security_settings(operator=operator)


class PowerSettingsRequest(BaseModel):
    rate_per_kwh: float | None = Field(default=None, ge=0.01, le=1.00)


@app.get("/ops/api/power-settings")
def get_power_settings(
    operator: dict[str, Any] = Depends(require_admin_cookie_brad_only),
):
    with open_database() as connection:
        with connection.cursor() as cursor:
            return {
                "rate_per_kwh": _get_float_directory_setting(
                    cursor, POWER_RATE_PER_KWH_KEY, POWER_RATE_PER_KWH_FALLBACK
                ),
            }


@app.post("/ops/api/power-settings")
def set_power_settings(
    payload: PowerSettingsRequest,
    operator: dict[str, Any] = Depends(require_admin_cookie_brad_only),
):
    if payload.rate_per_kwh is not None:
        with open_database() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO directory_settings (setting_key, setting_value, updated_by)
                    VALUES (%s, %s::jsonb, %s)
                    ON CONFLICT (setting_key)
                    DO UPDATE SET setting_value = EXCLUDED.setting_value, updated_by = EXCLUDED.updated_by
                    """,
                    (POWER_RATE_PER_KWH_KEY, str(payload.rate_per_kwh), operator["account_id"]),
                )
                connection.commit()
    return get_power_settings(operator=operator)


class ConnectionSettingsRequest(BaseModel):
    peer_auth_mode: str | None = Field(default=None, pattern="^(off|log|enforce)$")
    cert_lifetime_hours: int | None = Field(default=None, ge=1, le=720)
    cert_renew_after_hours: int | None = Field(default=None, ge=1, le=720)
    relay_fallback_delay_ms: int | None = Field(default=None, ge=0, le=10000)
    heartbeat_seconds: int | None = Field(
        default=None, ge=HEARTBEAT_SECONDS_MIN, le=HEARTBEAT_SECONDS_MAX
    )
    rendezvous_encryption: str | None = Field(default=None, pattern="^(off|optional|required)$")
    webrtc: str | None = Field(default=None, pattern="^(off|test|on)$")
    webrtc_test_ids: str | None = Field(default=None, max_length=500, pattern="^[A-Za-z0-9_, -]*$")
    passport_mode: str | None = Field(default=None, pattern="^(off|log)$")
    passport_lifetime_days: int | None = Field(
        default=None, ge=SEC8_LIFETIME_DAYS_MIN, le=SEC8_LIFETIME_DAYS_MAX
    )
    passport_grace_days: int | None = Field(
        default=None, ge=SEC8_GRACE_DAYS_MIN, le=SEC8_GRACE_DAYS_MAX
    )
    passport_check: str | None = Field(default=None, pattern="^(off|log|test|enforce)$")
    passport_check_test_ids: str | None = Field(
        default=None, max_length=500, pattern="^[A-Za-z0-9_, -]*$"
    )


@app.get("/ops/api/connection-settings")
def get_connection_settings(
    operator: dict[str, Any] = Depends(require_admin_cookie_brad_only),
):
    active_since = datetime.now(timezone.utc) - timedelta(days=PEER_AUTH_ACTIVE_DAYS)
    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    COUNT(*) AS active,
                    COUNT(*) FILTER (WHERE COALESCE(reported_build_number, 0) >= %s) AS ready
                FROM managed_devices
                WHERE status = 'approved' AND last_seen_at >= %s
                """,
                (PEER_AUTH_READY_BUILD, active_since),
            )
            readiness = cursor.fetchone()
            rendezvous_mode, rendezvous_stats = _get_rendezvous_encryption(cursor)
            webrtc_mode, webrtc_test_ids = _get_relay_webrtc(cursor)
            passport_check, passport_check_ids, passport_check_stats = _get_relay_passport(cursor)
            return {
                "passport_check": passport_check,
                "passport_check_test_ids": passport_check_ids,
                "passport_check_stats": passport_check_stats,
                "passport_check_ready_build": PASSPORT_CHECK_READY_BUILD,
                "devices_not_ready_for_passport_check": _devices_not_ready_for_passport_check(cursor),
                "rendezvous_encryption": rendezvous_mode,
                "rendezvous_encryption_stats": rendezvous_stats,
                "rendezvous_encryption_required_build": RENDEZVOUS_ENCRYPTION_REQUIRED_BUILD,
                "devices_requiring_rendezvous_encryption": _devices_requiring_rendezvous_encryption(cursor),
                "webrtc": webrtc_mode,
                "webrtc_test_ids": webrtc_test_ids,
                "peer_auth_mode": _get_peer_auth_mode(cursor),
                "cert_lifetime_hours": _get_int_directory_setting(
                    cursor, PEER_CERT_LIFETIME_HOURS_KEY, 96
                ),
                "cert_renew_after_hours": _get_int_directory_setting(
                    cursor, PEER_CERT_RENEW_AFTER_HOURS_KEY, 24
                ),
                "relay_fallback_delay_ms": _get_int_directory_setting(
                    cursor, RELAY_FALLBACK_DELAY_MS_KEY, RELAY_FALLBACK_DELAY_MS_FALLBACK
                ),
                "heartbeat_seconds": _get_int_directory_setting(
                    cursor, HEARTBEAT_SECONDS_KEY, HEARTBEAT_SECONDS_DEFAULT
                ),
                "presence_timeout_seconds": presence_timeout_seconds(),
                "passport_mode": _sec8_mode(cursor),
                "passport_lifetime_days": _sec8_lifetime_days(cursor),
                "passport_grace_days": _sec8_grace_days(cursor),
                "ca_configured": PEER_CA_KEY is not None,
                "active_devices": int(readiness["active"] or 0),
                "active_devices_ready": int(readiness["ready"] or 0),
                "ready_build": PEER_AUTH_READY_BUILD,
                "active_days": PEER_AUTH_ACTIVE_DAYS,
            }


@app.get("/ops/api/connection-stats")
def get_connection_stats(
    days: int = Query(default=7, ge=1, le=90),
    operator: dict[str, Any] = Depends(require_admin_cookie_brad_only),
):
    """Connection route + timing stats from initiating clients (build 28+), for tuning the relay
    fallback delay. A direct success counts its direct_ms, or late_direct_ms when the relay won
    first but the direct attempt succeeded afterwards."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                WITH t AS (
                    SELECT details -> 'timing' AS t
                    FROM device_activity_events
                    WHERE event_type = 'connection.established'
                      AND occurred_at >= %s
                      AND jsonb_typeof(details -> 'timing') = 'object'
                ), v AS (
                    SELECT
                        t ->> 'route' AS route,
                        t ->> 'direct_result' AS direct_result,
                        CASE
                            WHEN t ->> 'direct_result' = 'success' THEN (t ->> 'direct_ms')::int
                            WHEN t ->> 'direct_result' = 'late' THEN (t ->> 'late_direct_ms')::int
                        END AS direct_ok_ms,
                        (t ->> 'relay_ms')::int AS relay_ms
                    FROM t
                )
                SELECT
                    COUNT(*) AS connections,
                    COUNT(*) FILTER (WHERE route = 'relay') AS via_relay,
                    COUNT(*) FILTER (WHERE route IN ('direct_tcp', 'direct_udp', 'ipv6', 'webrtc')) AS via_direct,
                    COUNT(*) FILTER (WHERE route = 'webrtc') AS via_webrtc,
                    COUNT(*) FILTER (WHERE route = 'lan') AS via_lan,
                    COUNT(*) FILTER (WHERE direct_result IN ('success', 'failed', 'late')) AS direct_tried,
                    COUNT(*) FILTER (WHERE direct_result IN ('success', 'late')) AS direct_ok,
                    COUNT(*) FILTER (WHERE direct_result = 'late') AS late_direct,
                    MIN(direct_ok_ms) AS direct_min,
                    ROUND(AVG(direct_ok_ms)) AS direct_avg,
                    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY direct_ok_ms) AS direct_p95,
                    MAX(direct_ok_ms) AS direct_max,
                    MIN(relay_ms) AS relay_min,
                    ROUND(AVG(relay_ms)) AS relay_avg,
                    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY relay_ms) AS relay_p95,
                    MAX(relay_ms) AS relay_max
                FROM v
                """,
                (since,),
            )
            row = dict(cursor.fetchone())
            # Session round-trip delay ("Delay" in RDC) by route, from "ended" events.
            cursor.execute(
                """
                SELECT
                    details -> 'timing' ->> 'route' AS route,
                    COUNT(*) AS sessions,
                    MIN((details -> 'timing' ->> 'avg_delay_ms')::int) AS min_ms,
                    ROUND(AVG((details -> 'timing' ->> 'avg_delay_ms')::int)) AS avg_ms,
                    PERCENTILE_CONT(0.95) WITHIN GROUP (
                        ORDER BY (details -> 'timing' ->> 'avg_delay_ms')::int
                    ) AS p95_ms,
                    MAX((details -> 'timing' ->> 'max_delay_ms')::int) AS max_ms
                FROM device_activity_events
                WHERE event_type = 'connection.ended'
                  AND occurred_at >= %s
                  AND details -> 'timing' ? 'avg_delay_ms'
                GROUP BY 1
                ORDER BY 1
                """,
                (since,),
            )
            as_int = lambda v: int(v) if v is not None else None
            session_delay = [
                {
                    "route": r["route"],
                    "sessions": int(r["sessions"]),
                    "min_ms": as_int(r["min_ms"]),
                    "avg_ms": as_int(r["avg_ms"]),
                    "p95_ms": as_int(r["p95_ms"]),
                    "max_ms": as_int(r["max_ms"]),
                }
                for r in cursor.fetchall()
            ]
            delay_ms = _get_int_directory_setting(
                cursor, RELAY_FALLBACK_DELAY_MS_KEY, RELAY_FALLBACK_DELAY_MS_FALLBACK
            )
    stats = {
        key: (int(value) if value is not None else None) for key, value in row.items()
    }
    # Only suggest once there is enough direct data to mean something.
    p95 = stats["direct_p95"]
    stats["suggested_delay_ms"] = (
        int(-(-p95 // 100) * 100) if p95 is not None and stats["direct_ok"] >= 10 else None
    )
    stats["current_delay_ms"] = delay_ms
    stats["days"] = days
    stats["session_delay"] = session_delay
    return stats


@app.post("/ops/api/connection-settings")
def set_connection_settings(
    payload: ConnectionSettingsRequest,
    operator: dict[str, Any] = Depends(require_admin_cookie_brad_only),
):
    with open_database() as connection:
        with connection.cursor() as cursor:
            lifetime = payload.cert_lifetime_hours or _get_int_directory_setting(
                cursor, PEER_CERT_LIFETIME_HOURS_KEY, 96
            )
            renew = payload.cert_renew_after_hours or _get_int_directory_setting(
                cursor, PEER_CERT_RENEW_AFTER_HOURS_KEY, 24
            )
            if renew >= lifetime:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Renew-after must be shorter than the certificate lifetime",
                )
            if payload.rendezvous_encryption == "off":
                blocking = _devices_requiring_rendezvous_encryption(cursor)
                if blocking:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=(
                            f"Rendezvous encryption can't be turned off: {blocking} approved device(s) run build "
                            f"{RENDEZVOUS_ENCRYPTION_REQUIRED_BUILD} or newer and can't connect without it"
                        ),
                    )
            if payload.passport_check == "enforce":
                not_ready = _devices_not_ready_for_passport_check(cursor)
                if not_ready:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=(
                            f"Passport check can't be enforced yet: {not_ready} approved device(s) seen in the last "
                            f"30 days run a build before {PASSPORT_CHECK_READY_BUILD} and would be locked out. "
                            "Use 'Test devices only' until they update."
                        ),
                    )
            updates = [
                (RELAY_PASSPORT_KEY, json.dumps(payload.passport_check))
                if payload.passport_check is not None else None,
                (
                    RELAY_PASSPORT_TEST_IDS_KEY,
                    json.dumps(",".join(i for i in (p.strip() for p in payload.passport_check_test_ids.split(",")) if i)),
                )
                if payload.passport_check_test_ids is not None else None,
                (PEER_AUTH_MODE_KEY, json.dumps(payload.peer_auth_mode))
                if payload.peer_auth_mode is not None else None,
                (PEER_CERT_LIFETIME_HOURS_KEY, str(payload.cert_lifetime_hours))
                if payload.cert_lifetime_hours is not None else None,
                (PEER_CERT_RENEW_AFTER_HOURS_KEY, str(payload.cert_renew_after_hours))
                if payload.cert_renew_after_hours is not None else None,
                (RELAY_FALLBACK_DELAY_MS_KEY, str(payload.relay_fallback_delay_ms))
                if payload.relay_fallback_delay_ms is not None else None,
                (HEARTBEAT_SECONDS_KEY, str(payload.heartbeat_seconds))
                if payload.heartbeat_seconds is not None else None,
                (RENDEZVOUS_ENCRYPTION_KEY, json.dumps(payload.rendezvous_encryption))
                if payload.rendezvous_encryption is not None else None,
                (RELAY_WEBRTC_KEY, json.dumps(payload.webrtc))
                if payload.webrtc is not None else None,
                (SEC8_PASSPORT_MODE_KEY, json.dumps(payload.passport_mode))
                if payload.passport_mode is not None else None,
                (SEC8_LIFETIME_DAYS_KEY, str(payload.passport_lifetime_days))
                if payload.passport_lifetime_days is not None else None,
                (SEC8_GRACE_DAYS_KEY, str(payload.passport_grace_days))
                if payload.passport_grace_days is not None else None,
                (
                    RELAY_WEBRTC_TEST_IDS_KEY,
                    json.dumps(",".join(i for i in (p.strip() for p in payload.webrtc_test_ids.split(",")) if i)),
                )
                if payload.webrtc_test_ids is not None else None,
            ]
            for key, value in filter(None, updates):
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
    _heartbeat_seconds_cache["at"] = 0.0
    return get_connection_settings(operator=operator)


CONNECTION_EVENT_TYPES = (
    "connection.established",
    "connection.rejected",
    "connection.denied",
    "connection.ended",
)


@app.get("/ops/api/dashboard-summary")
def get_dashboard_summary(
    operator: dict[str, Any] = Depends(require_admin_cookie_operator),
):
    del operator

    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM managed_devices
                GROUP BY status
                """
            )
            device_status_counts = {
                row["status"]: row["count"] for row in cursor.fetchall()
            }

            cursor.execute(
                """
                SELECT event_type, COUNT(*) AS count
                FROM device_activity_events
                WHERE event_type = ANY(%s)
                  AND occurred_at >= now() - interval '24 hours'
                GROUP BY event_type
                """,
                (list(CONNECTION_EVENT_TYPES),),
            )
            connection_stats_24h = {
                row["event_type"].split(".", 1)[1]: row["count"]
                for row in cursor.fetchall()
            }

            cursor.execute(
                """
                SELECT
                    COUNT(*) FILTER (WHERE occurred_at >= now() - interval '7 days') AS last_7d,
                    COUNT(*) AS lifetime
                FROM device_activity_events
                WHERE event_type = 'connection.established'
                """
            )
            conn_row = cursor.fetchone()

            # Total wall-clock time connections were actually open, not just
            # how many started. Pairs each connection.established event with
            # its matching connection.ended event (same device_id +
            # session_key, the nearest one at or after it - handles the
            # rare case of a reused session_key without mispairing across
            # sessions) and sums the duration. Unpaired established events
            # (session still active, or no ended event was ever recorded -
            # e.g. an app crash) are excluded rather than guessed at.
            cursor.execute(
                """
                WITH paired AS (
                    SELECT
                        est.occurred_at AS started_at,
                        (
                            SELECT MIN(ended.occurred_at)
                            FROM device_activity_events ended
                            WHERE ended.device_id = est.device_id
                              AND ended.session_key = est.session_key
                              AND ended.event_type = 'connection.ended'
                              AND ended.occurred_at >= est.occurred_at
                        ) AS ended_at
                    FROM device_activity_events est
                    WHERE est.event_type = 'connection.established'
                      AND est.session_key IS NOT NULL
                )
                SELECT
                    COALESCE(SUM(EXTRACT(EPOCH FROM (ended_at - started_at)))
                        FILTER (WHERE started_at >= now() - interval '24 hours'), 0) AS seconds_24h,
                    COALESCE(SUM(EXTRACT(EPOCH FROM (ended_at - started_at)))
                        FILTER (WHERE started_at >= now() - interval '7 days'), 0) AS seconds_7d,
                    COALESCE(SUM(EXTRACT(EPOCH FROM (ended_at - started_at))), 0) AS seconds_lifetime
                FROM paired
                """
            )
            conn_time_row = cursor.fetchone()

            cursor.execute(
                """
                SELECT
                    COUNT(*) FILTER (WHERE sent_at >= now() - interval '7 days') AS last_7d,
                    COUNT(*) AS lifetime
                FROM chat_message_send_events
                """
            )
            msg_row = cursor.fetchone()

            cursor.execute(
                """
                SELECT
                    COUNT(*) AS lifetime,
                    COALESCE(SUM(bytes), 0) AS bytes_lifetime
                FROM filedrop_transfer_events
                """
            )
            rustdrop_row = cursor.fetchone()

    return {
        "device_status_counts": device_status_counts,
        "connection_stats_24h": connection_stats_24h,
        "connections_established_7d": conn_row["last_7d"],
        "connections_established_lifetime": conn_row["lifetime"],
        "connection_time_24h_seconds": float(conn_time_row["seconds_24h"]),
        "connection_time_7d_seconds": float(conn_time_row["seconds_7d"]),
        "connection_time_lifetime_seconds": float(conn_time_row["seconds_lifetime"]),
        "messages_sent_7d": msg_row["last_7d"],
        "messages_sent_lifetime": msg_row["lifetime"],
        "rustdrop_files_transferred_lifetime": rustdrop_row["lifetime"],
        "rustdrop_bytes_transferred_lifetime": int(rustdrop_row["bytes_lifetime"]),
    }


# BEGIN RustDesk Directory Security Extension v0.7.0
from security_extension import register_security_extension as _register_security_extension

_register_security_extension(
    app=app,
    open_database_handler=open_database,
    require_operator_handler=require_operator,
    require_owner_handler=require_owner,
    require_device_handler=require_device,
    verify_owner_reauthentication_handler=verify_owner_reauthentication,
    client_ip_handler=client_ip,
    token_secret=TOKEN_SECRET,
    totp_key=TOTP_KEY,
)
# END RustDesk Directory Security Extension v0.7.0

# --- ADMIN WEB DASHBOARD ---
from admin_ui import register_admin_routes

register_admin_routes(
    app=app,
    login_handler=login,
    refresh_handler=refresh,
    logout_handler=logout,
    require_operator_handler=require_operator,
    list_devices_handler=list_devices,
    get_device_handler=get_device,
    approve_device_handler=approve_device,
    deny_device_handler=deny_device,
    block_device_handler=block_device,
    revoke_device_handler=revoke_device,
    update_device_contact_email_handler=update_device_contact_email,
    list_operators_handler=list_operator_accounts,
    get_operator_handler=get_operator_account,
    update_operator_email_handler=update_operator_email,
    disable_operator_handler=disable_operator_account,
    enable_operator_handler=enable_operator_account,
    delete_operator_handler=delete_operator_account,
    unlock_operator_handler=unlock_operator_account,
    revoke_operator_sessions_handler=revoke_operator_sessions,
    create_operator_invitation_handler=create_operator_invitation,
    list_operator_invitations_handler=list_operator_invitations,
    revoke_operator_invitation_handler=revoke_operator_invitation,
    setup_operator_invitation_handler=setup_operator_invitation,
    accept_operator_invitation_handler=accept_operator_invitation,
    create_operator_role_change_handler=create_operator_role_change_request,
    list_operator_role_changes_handler=list_operator_role_change_requests,
    complete_operator_role_change_handler=complete_operator_role_change_request,
    cancel_operator_role_change_handler=cancel_operator_role_change_request,
    health_handler=health,
    token_secret=TOKEN_SECRET,
    open_database_handler=open_database,
    write_audit_handler=write_audit,
    client_ip_handler=client_ip,
)

# --- MOBILE COMPANION APP (client-manager Android app) ---
from mobile_api import register_mobile_routes

record_health_event = register_mobile_routes(
    app=app,
    login_handler=_perform_login,
    refresh_handler=refresh,
    logout_handler=logout,
    require_operator_handler=require_operator,
    require_device_manager_handler=require_device_manager,
    list_devices_handler=list_devices,
    approve_device_handler=approve_device,
    block_device_handler=block_device,
    revoke_device_handler=revoke_device,
    open_database_handler=open_database,
    client_ip_handler=client_ip,
    health_watcher_secret=HEALTH_WATCHER_SHARED_SECRET,
    firebase_service_account=FIREBASE_SERVICE_ACCOUNT,
    firebase_project_id=FIREBASE_PROJECT_ID,
    send_email_handler=_send_alert_email,
)

# --- EDGE CLIENT CERTIFICATES (Cloudflare mTLS for client. and ops.) ---
from edge_certs import note_edge_verification, register_edge_cert_routes, revoke_device_edge_certs

register_edge_cert_routes(
    app=app,
    open_database_handler=open_database,
    require_device_handler=require_device,
    require_operator_bearer_handler=require_operator,
    require_operator_cookie_handler=require_admin_cookie_operator,
    require_owner_cookie_handler=require_admin_cookie_owner,
)

# --- SEALED TRANSPORT (application-layer end-to-end encryption for managed-client API calls) ---
from sealed import register_sealed_routes
from security_extension import ADMIN_PATH as _SEALED_ADMIN_PATH

register_sealed_routes(
    app=app,
    admin_path=_SEALED_ADMIN_PATH,
    open_database_handler=open_database,
    validate_device_credential_handler=validate_device_credential,
    require_owner_cookie_handler=require_admin_cookie_owner,
    send_alert_email_handler=_send_alert_email,
    alert_account_id=PROTECTED_BRAD_ACCOUNT_ID,
)

# --- MANAGED CHAT (out-of-session messaging between managed devices) ---
from managed_chat import register_chat_routes

register_chat_routes(
    app=app,
    require_device_handler=require_device,
    validate_device_credential_handler=validate_device_credential,
    open_database_handler=open_database,
)

app.state.presence_timeout_seconds = presence_timeout_seconds

# --- DEVICE SYNC (versions in every heartbeat + wait-for-change, instead of polling) ---
from device_sync import directory_etag, register_device_sync

device_sync_versions = register_device_sync(
    app=app,
    open_database_handler=open_database,
    require_device_handler=require_device,
    manifests_dir=UPDATE_MANIFESTS,
    presence_timeout_seconds=presence_timeout_seconds,
)

# --- DEVICE DEBUG LOGS (hourly diagnostic log upload for support) ---
from device_logs import register_device_log_routes

register_device_log_routes(
    app=app,
    require_device_handler=require_device,
    require_admin_cookie_brad_only_handler=require_admin_cookie_brad_only,
    open_database_handler=open_database,
)


# --- RUSTDROP (send-and-accept file drop, replacing built-in push/pull) ---
from rustdrop import register_rustdrop_routes

register_rustdrop_routes(
    app=app,
    require_device_handler=require_device,
    require_admin_cookie_brad_only_handler=require_admin_cookie_brad_only,
    open_database_handler=open_database,
    report_health_event_handler=record_health_event,
)
