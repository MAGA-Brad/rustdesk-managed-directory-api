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

# Outbound mail (first step toward Mailcow integration). Optional at startup
# for the same crash-loop-avoidance reason as the mobile-app secrets above -
# the smtp-config endpoints simply refuse to work (503) until this is set.
SMTP_ENCRYPTION_SECRET = os.environ.get("SMTP_ENCRYPTION_SECRET") or None

ACCESS_TOKEN_MINUTES = 15
SESSION_DAYS = 30
# Brad's explicit ask: the mobile companion app should never force a
# re-login. A very long, rolling window (extended again on every refresh
# below) achieves that in practice without literally never expiring - the
# access token itself still only lives 15 minutes either way, re-issued
# transparently by the app's own automatic-refresh-on-401 logic.
MOBILE_SESSION_DAYS = 3650
MAX_LOGIN_FAILURES = 5
LOCKOUT_MINUTES = 15
ENROLLMENT_POLL_DAYS = 90
PRESENCE_TIMEOUT_SECONDS = 45

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


def issue_access_token(
    account_id: uuid.UUID,
    session_id: uuid.UUID,
    role: str,
    now: datetime,
    scope: str = "full",
) -> tuple[str, datetime]:
    expires_at = now + timedelta(minutes=ACCESS_TOKEN_MINUTES)

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
                  AND oa.is_active = TRUE
                """,
                (
                    session_id,
                    account_id,
                    token_hash(access_token),
                    now,
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
    # Multiple accounts hold the "owner" role (brad, michael, bradpixel,
    # brady), but mail-server credentials are the first piece of the Mailcow
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

            totp_valid = not account["totp_enabled"]

            if account["totp_enabled"] and payload.totp_code:
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
                            'reason', 'invalid_credentials',
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
            session_expires_at = now + timedelta(
                days=MOBILE_SESSION_DAYS if scope == "mobile" else SESSION_DAYS
            )

            access_token, access_expires_at = issue_access_token(
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
                  AND oa.is_active = TRUE
                FOR UPDATE OF os
                """,
                (
                    token_hash(payload.refresh_token),
                    now,
                ),
            )

            session = cursor.fetchone()

            if session is None:
                raise unauthorized()

            # Must carry the session's existing scope forward - refreshing a
            # mobile session must never silently upgrade it to full scope.
            access_token, access_expires_at = issue_access_token(
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
                now + timedelta(days=MOBILE_SESSION_DAYS)
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

                recoverable_statuses = {
                    "pending",
                    "denied",
                    "blocked",
                    "revoked",
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
                  AND status = 'denied'
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
                  AND status = 'denied'
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
            recovery_eligible = device["status"] == "denied"
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
                "hostname": device["hostname"],
                "friendly_name": device["friendly_name"],
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
                response["client_settings"] = client_settings(
                    cursor
                )

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


def device_active_connections(
    cursor,
    *,
    device_id: uuid.UUID,
    rustdesk_id: str,
    now: datetime,
) -> list[dict[str, Any]]:
    cutoff = now - timedelta(seconds=PRESENCE_TIMEOUT_SECONDS)
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
                s.last_heartbeat_at
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
                s.last_heartbeat_at
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
            for item in items:
                item["active_connections"] = device_active_connections(
                    cursor,
                    device_id=item["id"],
                    rustdesk_id=item["rustdesk_id"],
                    now=now,
                )
                item.update(device_lifetime_stats(cursor, device_id=item["id"]))

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

            if new_status == "blocked" and previous_status == "blocked":
                return {
                    "device_id": device_id,
                    "status": "blocked",
                }

            terminal_cleanup: dict[str, int] = {}
            if new_status == "blocked":
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
    return change_device_status(
        device_id=device_id,
        new_status="blocked",
        reason=(
            "Legacy revoke request normalized to terminal Blocked: "
            + payload.reason.strip()
        ),
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
                SELECT last_seen_at
                FROM managed_devices
                WHERE id = %s
                FOR UPDATE
                """,
                (device["device_id"],),
            )
            presence = cursor.fetchone()
            previous_last_seen = (
                presence["last_seen_at"] if presence else None
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
                > timedelta(seconds=PRESENCE_TIMEOUT_SECONDS)
            ):
                inactive_at = previous_last_seen + timedelta(
                    seconds=PRESENCE_TIMEOUT_SECONDS
                )
                write_device_activity(
                    cursor,
                    "client.inactive",
                    device_id=device["device_id"],
                    occurred_at=inactive_at,
                    source_ip=source_ip,
                    details={
                        "reason": "heartbeat timeout",
                        "timeout_seconds": PRESENCE_TIMEOUT_SECONDS,
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

            settings = client_settings(cursor)
            connection.commit()

            return {
                "status": "ok",
                "server_time": now,
                "device_status": "approved",
                "client_version": payload.client_version,
                "client_settings": settings,
            }


@app.get("/v1/directory")
def approved_directory(
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
                    last_ip,
                    last_seen_at
                FROM approved_device_directory
                WHERE id <> %s
                ORDER BY LOWER(display_name), rustdesk_id
                """,
                (device["device_id"],),
            )
            devices = [dict(row) for row in cursor.fetchall()]
            online_cutoff = now - timedelta(seconds=PRESENCE_TIMEOUT_SECONDS)
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
            session_cutoff = now - timedelta(seconds=PRESENCE_TIMEOUT_SECONDS)
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
                "online_window_seconds": PRESENCE_TIMEOUT_SECONDS,
                "active_session_timeout_seconds": PRESENCE_TIMEOUT_SECONDS,
            }

            settings = client_settings(cursor)
            refresh_seconds = settings.get(
                "client.directory_refresh_seconds",
                300,
            )

            return {
                "instance_id": instance["instance_id"],
                "generated_at": now,
                "refresh_seconds": refresh_seconds,
                "devices": devices,
                "server_stats": server_stats,
                "client_settings": settings,
            }


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
    if Path(file_name).name != file_name or not file_name.lower().endswith(".exe"):
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
    arch: str = Query(default="x86_64", pattern=r"^(x86_64|aarch64)$"),
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
        media_type="application/vnd.microsoft.portable-executable",
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


PROTECTED_BRAD_ACCOUNT_ID = uuid.UUID(
    "da1c8c16-bf66-4e79-930c-f9b68496aa4a"
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


def operator_account_details_response(
    cursor,
    account_id: uuid.UUID,
) -> dict[str, Any]:
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


# --- OUTBOUND MAIL (Mailcow integration groundwork) ---
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
    except Exception:
        pass


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

            cursor.execute(
                """
                SELECT
                    COUNT(*) FILTER (WHERE sent_at >= now() - interval '7 days') AS last_7d,
                    COUNT(*) AS lifetime
                FROM chat_message_send_events
                """
            )
            msg_row = cursor.fetchone()

    return {
        "device_status_counts": device_status_counts,
        "connection_stats_24h": connection_stats_24h,
        "connections_established_7d": conn_row["last_7d"],
        "connections_established_lifetime": conn_row["lifetime"],
        "messages_sent_7d": msg_row["last_7d"],
        "messages_sent_lifetime": msg_row["lifetime"],
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

register_mobile_routes(
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

# --- MANAGED CHAT (out-of-session messaging between managed devices) ---
from managed_chat import register_chat_routes

register_chat_routes(
    app=app,
    require_device_handler=require_device,
    validate_device_credential_handler=validate_device_credential,
    open_database_handler=open_database,
)

