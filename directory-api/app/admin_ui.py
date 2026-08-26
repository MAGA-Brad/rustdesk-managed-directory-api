from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Callable
from pathlib import Path
import json
import uuid

import jwt
import segno
from fastapi import Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials

ACCESS_COOKIE = "__Secure-rd-admin-access"
REFRESH_COOKIE = "__Secure-rd-admin-refresh"
ACTIVITY_COOKIE = "__Secure-rd-admin-activity"
ADMIN_PATH = "/ops"
ACCESS_MAX_AGE = 15 * 60
REFRESH_MAX_AGE = 30 * 24 * 60 * 60
IDLE_DEFAULT_SECONDS = 8 * 60 * 60


def register_admin_routes(
    *,
    app: Any,
    login_handler: Callable[..., dict[str, Any]],
    refresh_handler: Callable[..., dict[str, Any]],
    logout_handler: Callable[..., dict[str, Any]],
    require_operator_handler: Callable[..., dict[str, Any]],
    list_devices_handler: Callable[..., dict[str, Any]],
    get_device_handler: Callable[..., dict[str, Any]],
    approve_device_handler: Callable[..., dict[str, Any]],
    deny_device_handler: Callable[..., dict[str, Any]],
    block_device_handler: Callable[..., dict[str, Any]],
    revoke_device_handler: Callable[..., dict[str, Any]],
    update_device_contact_email_handler: Callable[..., dict[str, Any]],
    list_operators_handler: Callable[..., dict[str, Any]],
    get_operator_handler: Callable[..., dict[str, Any]],
    update_operator_email_handler: Callable[..., dict[str, Any]],
    disable_operator_handler: Callable[..., dict[str, Any]],
    enable_operator_handler: Callable[..., dict[str, Any]],
    delete_operator_handler: Callable[..., dict[str, Any]],
    unlock_operator_handler: Callable[..., dict[str, Any]],
    revoke_operator_sessions_handler: Callable[..., dict[str, Any]],
    create_operator_invitation_handler: Callable[..., dict[str, Any]],
    list_operator_invitations_handler: Callable[..., dict[str, Any]],
    revoke_operator_invitation_handler: Callable[..., dict[str, Any]],
    setup_operator_invitation_handler: Callable[..., dict[str, Any]],
    accept_operator_invitation_handler: Callable[..., dict[str, Any]],
    create_operator_role_change_handler: Callable[..., dict[str, Any]],
    list_operator_role_changes_handler: Callable[..., dict[str, Any]],
    complete_operator_role_change_handler: Callable[..., dict[str, Any]],
    cancel_operator_role_change_handler: Callable[..., dict[str, Any]],
    health_handler: Callable[..., dict[str, Any]],
    token_secret: str,
    open_database_handler: Callable[..., Any],
    write_audit_handler: Callable[..., Any],
    client_ip_handler: Callable[[Request], str],
) -> None:
    def admin_idle_policy() -> tuple[bool, int]:
        # the admin dashboard inactivity sign-out is a fixed security policy.  It is not
        # configurable from the admin dashboard or any public/admin API.
        return True, IDLE_DEFAULT_SECONDS

    def set_admin_cookies(
        response: Response,
        result: dict[str, Any],
    ) -> None:
        response.set_cookie(
            key=ACCESS_COOKIE,
            value=result["access_token"],
            max_age=ACCESS_MAX_AGE,
            httponly=True,
            secure=True,
            samesite="strict",
            path=ADMIN_PATH,
        )
        response.set_cookie(
            key=REFRESH_COOKIE,
            value=result["refresh_token"],
            max_age=REFRESH_MAX_AGE,
            httponly=True,
            secure=True,
            samesite="strict",
            path=ADMIN_PATH,
        )

    def set_admin_activity_cookie(
        response: Response,
        access_token: str,
    ) -> None:
        try:
            access_claims = jwt.decode(
                access_token,
                token_secret,
                algorithms=["HS256"],
                options={"verify_exp": False},
            )
            account_id = str(access_claims["sub"])
            session_id = str(access_claims["sid"])
        except (
            jwt.PyJWTError,
            KeyError,
            TypeError,
            ValueError,
        ) as error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unable to establish the inactivity timer",
            ) from error

        now = datetime.now(timezone.utc)
        idle_enabled, idle_seconds = admin_idle_policy()
        token_lifetime = idle_seconds if idle_enabled else REFRESH_MAX_AGE
        activity_token = jwt.encode(
            {
                "sub": account_id,
                "sid": session_id,
                "type": "admin_activity",
                "iat": now,
                "exp": now + timedelta(seconds=token_lifetime),
            },
            token_secret,
            algorithm="HS256",
        )

        response.set_cookie(
            key=ACTIVITY_COOKIE,
            value=activity_token,
            max_age=REFRESH_MAX_AGE,
            httponly=True,
            secure=True,
            samesite="strict",
            path=ADMIN_PATH,
        )

    def clear_admin_cookies(response: Response) -> None:
        for cookie_name in (
            ACCESS_COOKIE,
            REFRESH_COOKIE,
            ACTIVITY_COOKIE,
        ):
            response.delete_cookie(
                key=cookie_name,
                path=ADMIN_PATH,
                secure=True,
                httponly=True,
                samesite="strict",
            )

    def decode_admin_activity(
        request: Request,
        *,
        verify_expiration: bool = True,
    ) -> dict[str, Any]:
        activity_token = request.cookies.get(ACTIVITY_COOKIE)
        idle_enabled, idle_seconds = admin_idle_policy()
        idle_hours = max(1, round(idle_seconds / 3600))

        if not activity_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=(
                    f"Signed out after {idle_hours} hours of inactivity"
                ),
            )

        try:
            claims = jwt.decode(
                activity_token,
                token_secret,
                algorithms=["HS256"],
                options={
                    "verify_exp": verify_expiration and idle_enabled,
                    "require": [
                        "sub",
                        "sid",
                        "type",
                        "iat",
                        "exp",
                    ],
                },
            )
        except jwt.ExpiredSignatureError as error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=(
                    f"Signed out after {idle_hours} hours of inactivity"
                ),
            ) from error
        except (
            jwt.PyJWTError,
            KeyError,
            TypeError,
            ValueError,
        ) as error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Admin inactivity state is invalid",
            ) from error

        if claims.get("type") != "admin_activity":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Admin inactivity state is invalid",
            )

        return claims

    def revoke_session_ids(
        account_id: uuid.UUID,
        session_id: uuid.UUID,
        reason: str,
    ) -> None:
        now = datetime.now(timezone.utc)

        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE operator_sessions
                    SET
                        revoked_at = %s,
                        revoked_by = %s,
                        revocation_reason = %s
                    WHERE id = %s
                      AND revoked_at IS NULL
                    """,
                    (
                        now,
                        account_id,
                        reason,
                        session_id,
                    ),
                )
                connection.commit()

    def revoke_session(access_token: str, reason: str) -> None:
        try:
            claims = jwt.decode(
                access_token,
                token_secret,
                algorithms=["HS256"],
                options={"verify_exp": False},
            )
            session_id = uuid.UUID(claims["sid"])
            account_id = uuid.UUID(claims["sub"])
        except (
            jwt.PyJWTError,
            KeyError,
            TypeError,
            ValueError,
        ):
            return

        revoke_session_ids(
            account_id,
            session_id,
            reason,
        )

    def revoke_activity_session(
        request: Request,
        reason: str,
    ) -> None:
        try:
            claims = decode_admin_activity(
                request,
                verify_expiration=False,
            )
            account_id = uuid.UUID(str(claims["sub"]))
            session_id = uuid.UUID(str(claims["sid"]))
        except (
            HTTPException,
            KeyError,
            TypeError,
            ValueError,
        ):
            return

        revoke_session_ids(
            account_id,
            session_id,
            reason,
        )

    def revoke_request_session(
        request: Request,
        reason: str,
    ) -> None:
        access_token = request.cookies.get(ACCESS_COOKIE)

        if access_token:
            revoke_session(access_token, reason)
            return

        revoke_activity_session(request, reason)

    def require_admin_operator(request: Request) -> dict[str, Any]:
        access_token = request.cookies.get(ACCESS_COOKIE)

        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Dashboard authentication is required",
            )

        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=access_token,
        )
        operator = require_operator_handler(credentials)

        if (
            operator["role"] not in {"owner", "manager", "viewer"}
            or operator["must_change_password"]
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Dashboard authorization is required",
            )

        activity_claims = decode_admin_activity(request)

        if (
            str(activity_claims["sub"])
            != str(operator["account_id"])
            or str(activity_claims["sid"])
            != str(operator["session_id"])
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Dashboard inactivity state does not match this session",
            )

        return operator

    def require_admin_owner(request: Request) -> dict[str, Any]:
        operator = require_admin_operator(request)

        if operator["role"] != "owner":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Owner authorization is required",
            )

        return operator

    def no_store_headers() -> dict[str, str]:
        return {
            "Cache-Control": "no-store, max-age=0",
            "Pragma": "no-cache",
            "X-Robots-Tag": "noindex, nofollow, noarchive",
        }

    def set_no_store(response: Response) -> None:
        response.headers.update(no_store_headers())

    @app.get(
        ADMIN_PATH,
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    @app.get(
        f"{ADMIN_PATH}/",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def admin_page() -> HTMLResponse:
        return HTMLResponse(
            ADMIN_HTML,
            headers={
                **no_store_headers(),
                "Content-Security-Policy": (
                    "default-src 'self'; "
                    "style-src 'unsafe-inline'; "
                    "script-src 'unsafe-inline'; "
                    "connect-src 'self'; "
                    "img-src 'self' data:; "
                    "frame-ancestors 'none'; "
                    "base-uri 'none'; "
                    "form-action 'self'"
                ),
            },
        )

    @app.get(
        f"{ADMIN_PATH}/invite",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def admin_invitation_page() -> HTMLResponse:
        return HTMLResponse(
            INVITE_HTML,
            headers={
                **no_store_headers(),
                "Content-Security-Policy": (
                    "default-src 'self'; "
                    "style-src 'unsafe-inline'; "
                    "script-src 'unsafe-inline'; "
                    "connect-src 'self'; "
                    "img-src 'self' data:; "
                    "frame-ancestors 'none'; "
                    "base-uri 'none'; "
                    "form-action 'self'"
                ),
            },
        )

    @app.post(
        f"{ADMIN_PATH}/api/invite/setup",
        include_in_schema=False,
    )
    def admin_invitation_setup(
        payload: dict[str, Any],
        response: Response,
    ):
        invitation_token = str(
            payload.get("invitation_token", "")
        ).strip()

        if not invitation_token:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invitation token is required",
            )

        result = setup_operator_invitation_handler(
            payload=SimpleNamespace(
                invitation_token=invitation_token,
            ),
        )

        provisioning_uri = str(
            result.get("totp_provisioning_uri", "")
        ).strip()
        if not provisioning_uri:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Authenticator provisioning URI was not generated",
            )

        qr_code = segno.make(
            provisioning_uri,
            error="m",
            micro=False,
        )

        result = dict(result)
        result["totp_qr_data_uri"] = qr_code.svg_data_uri(
            scale=7,
            border=4,
            xmldecl=False,
        )

        set_no_store(response)
        return result

    @app.post(
        f"{ADMIN_PATH}/api/invite/accept",
        include_in_schema=False,
    )
    def admin_invitation_accept(
        payload: dict[str, Any],
        request: Request,
        response: Response,
    ):
        invitation_token = str(
            payload.get("invitation_token", "")
        ).strip()
        password = str(payload.get("password", ""))
        totp_code = str(payload.get("totp_code", "")).strip()

        if not invitation_token:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invitation token is required",
            )

        if len(password) < 12:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Password must contain at least 12 characters",
            )

        if len(totp_code) != 6 or not totp_code.isdigit():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Authenticator code must contain six digits",
            )

        result = accept_operator_invitation_handler(
            payload=SimpleNamespace(
                invitation_token=invitation_token,
                password=password,
                totp_code=totp_code,
            ),
            request=request,
        )
        set_no_store(response)
        return result

    @app.post(
        f"{ADMIN_PATH}/api/login",
        include_in_schema=False,
    )
    def admin_login(
        payload: dict[str, Any],
        request: Request,
        response: Response,
    ):
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))
        totp_code = (
            str(payload.get("totp_code", "")).strip() or None
        )

        if not username or not password:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Username and password are required",
            )

        if totp_code is not None and (
            len(totp_code) != 6 or not totp_code.isdigit()
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    "Authenticator code must contain six digits"
                ),
            )

        result = login_handler(
            SimpleNamespace(
                username=username,
                password=password,
                totp_code=totp_code,
            ),
            request,
        )

        if (
            result["operator"]["role"]
            not in {"owner", "manager", "viewer"}
            or result["operator"]["must_change_password"]
        ):
            revoke_session(
                result["access_token"],
                "admin_role_not_allowed",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Dashboard authorization is required",
            )

        set_admin_cookies(response, result)
        set_admin_activity_cookie(
            response,
            result["access_token"],
        )
        set_no_store(response)

        return {
            "status": "authenticated",
            "operator": result["operator"],
            "access_expires_at": result[
                "access_expires_at"
            ],
            "session_expires_at": result[
                "session_expires_at"
            ],
        }

    @app.post(
        f"{ADMIN_PATH}/api/session/refresh",
        include_in_schema=False,
    )
    def admin_refresh(
        request: Request,
        response: Response,
    ):
        try:
            activity_claims = decode_admin_activity(request)
        except HTTPException as error:
            revoke_request_session(
                request,
                "admin_idle_timeout",
            )
            clear_admin_cookies(response)
            set_no_store(response)
            response.status_code = status.HTTP_401_UNAUTHORIZED
            return {"detail": error.detail}

        refresh_token = request.cookies.get(REFRESH_COOKIE)

        if not refresh_token:
            revoke_request_session(
                request,
                "admin_refresh_cookie_missing",
            )
            clear_admin_cookies(response)
            set_no_store(response)
            response.status_code = status.HTTP_401_UNAUTHORIZED
            return {"detail": "Admin session has expired"}

        try:
            result = refresh_handler(
                SimpleNamespace(refresh_token=refresh_token),
                request,
            )
        except HTTPException:
            revoke_request_session(
                request,
                "admin_refresh_failed",
            )
            clear_admin_cookies(response)
            set_no_store(response)
            raise

        if (
            result["operator"]["role"]
            not in {"owner", "manager", "viewer"}
            or result["operator"]["must_change_password"]
        ):
            revoke_session(
                result["access_token"],
                "admin_role_not_allowed",
            )
            clear_admin_cookies(response)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Dashboard authorization is required",
            )

        try:
            refreshed_claims = jwt.decode(
                result["access_token"],
                token_secret,
                algorithms=["HS256"],
                options={"verify_exp": False},
            )
        except jwt.PyJWTError as error:
            revoke_session(
                result["access_token"],
                "admin_refresh_identity_invalid",
            )
            clear_admin_cookies(response)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refreshed session identity is invalid",
            ) from error

        if (
            str(refreshed_claims.get("sub"))
            != str(activity_claims["sub"])
            or str(refreshed_claims.get("sid"))
            != str(activity_claims["sid"])
        ):
            revoke_session(
                result["access_token"],
                "admin_refresh_identity_mismatch",
            )
            clear_admin_cookies(response)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refreshed session does not match",
            )

        set_admin_cookies(response, result)
        set_no_store(response)

        return {
            "status": "refreshed",
            "operator": result["operator"],
            "access_expires_at": result[
                "access_expires_at"
            ],
            "session_expires_at": result[
                "session_expires_at"
            ],
        }

    @app.get(
        f"{ADMIN_PATH}/api/me",
        include_in_schema=False,
    )
    def admin_me(
        response: Response,
        operator: dict[str, Any] = Depends(
            require_admin_operator
        ),
    ):
        set_no_store(response)
        return {
            "id": operator["account_id"],
            "username": operator["username"],
            "display_name": operator["display_name"],
            "role": operator["role"],
            "totp_enabled": operator["totp_enabled"],
            "mfa_verified": (
                operator["mfa_verified_at"] is not None
            ),
            "session_expires_at": operator[
                "session_expires_at"
            ],
        }

    @app.post(
        f"{ADMIN_PATH}/api/activity",
        include_in_schema=False,
    )
    def admin_activity(
        request: Request,
        response: Response,
        operator: dict[str, Any] = Depends(
            require_admin_operator
        ),
    ):
        del operator
        access_token = request.cookies.get(ACCESS_COOKIE)

        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Admin authentication is required",
            )

        set_admin_activity_cookie(response, access_token)
        set_no_store(response)
        idle_enabled, idle_seconds = admin_idle_policy()
        return {
            "status": "active",
            "idle_timeout_enabled": idle_enabled,
            "idle_timeout_seconds": idle_seconds,
        }

    @app.get(
        f"{ADMIN_PATH}/api/health",
        include_in_schema=False,
    )
    def admin_health(
        response: Response,
        operator: dict[str, Any] = Depends(
            require_admin_operator
        ),
    ):
        del operator
        set_no_store(response)
        return health_handler()

    @app.get(
        f"{ADMIN_PATH}/api/summary",
        include_in_schema=False,
    )
    def admin_summary(
        response: Response,
        operator: dict[str, Any] = Depends(
            require_admin_operator
        ),
    ):
        del operator
        set_no_store(response)
        now = datetime.now(timezone.utc)
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        COUNT(*) FILTER (
                            WHERE status IN ('approved', 'pending')
                        ) AS managed,
                        COUNT(*) FILTER (
                            WHERE status = 'approved'
                        ) AS approved,
                        COUNT(*) FILTER (
                            WHERE status = 'pending'
                        ) AS pending,
                        COUNT(*) FILTER (
                            WHERE status = 'approved'
                              AND last_seen_at >= %s - interval '45 seconds'
                        ) AS active_clients,
                        COUNT(*) FILTER (
                            WHERE status = 'approved'
                              AND (
                                  last_seen_at IS NULL
                                  OR last_seen_at < %s - interval '45 seconds'
                              )
                        ) AS inactive_clients
                    FROM managed_devices
                    """,
                    (now, now),
                )
                counts = cursor.fetchone()

                cursor.execute(
                    """
                    SELECT COUNT(DISTINCT l.device_id) AS active_leases
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
                active_leases = cursor.fetchone()["active_leases"]

                cursor.execute(
                    """
                    SELECT COUNT(*) AS active_sessions
                    FROM device_active_sessions s
                    JOIN managed_devices d
                      ON d.id = s.reporting_device_id
                    WHERE s.ended_at IS NULL
                      AND s.last_heartbeat_at >= %s - interval '45 seconds'
                      AND d.status = 'approved'
                    """,
                    (now,),
                )
                active_sessions = cursor.fetchone()["active_sessions"]

        return {
            **counts,
            "active_leases": active_leases,
            "active_sessions": active_sessions,
            "active_client_window_seconds": 45,
            "active_session_timeout_seconds": 45,
            "generated_at": now,
        }

    @app.get(
        f"{ADMIN_PATH}/api/system-health",
        include_in_schema=False,
    )
    def admin_system_health(
        response: Response,
        operator: dict[str, Any] = Depends(
            require_admin_operator
        ),
    ):
        del operator
        set_no_store(response)
        status_path = Path("/run/rustdesk-ops/health.json")
        try:
            data = json.loads(status_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("health document is not an object")
            generated_at = datetime.fromisoformat(
                str(data.get("generated_at", "")).replace("Z", "+00:00")
            )
            if generated_at.tzinfo is None:
                generated_at = generated_at.replace(tzinfo=timezone.utc)
            age_seconds = max(
                0.0,
                (datetime.now(timezone.utc) - generated_at).total_seconds(),
            )
            data["age_seconds"] = age_seconds
            data["stale"] = age_seconds > 45
            return data
        except FileNotFoundError:
            return {
                "status": "unavailable",
                "stale": True,
                "services": {},
                "detail": "Critical service health has not been generated yet",
            }
        except (OSError, ValueError, json.JSONDecodeError):
            return {
                "status": "error",
                "stale": True,
                "services": {},
                "detail": "Critical service health could not be read",
            }

    @app.get(
        f"{ADMIN_PATH}/api/operations",
        include_in_schema=False,
    )
    def admin_operations(
        response: Response,
        operator: dict[str, Any] = Depends(
            require_admin_owner
        ),
    ):
        del operator
        set_no_store(response)
        status_path = Path("/run/rustdesk-ops/status.json")
        try:
            data = json.loads(
                status_path.read_text(encoding="utf-8")
            )
            if not isinstance(data, dict):
                raise ValueError("status document is not an object")
            return data
        except FileNotFoundError:
            return {
                "status": "unavailable",
                "detail": "Host operations status has not been generated yet",
            }
        except (OSError, ValueError, json.JSONDecodeError):
            return {
                "status": "error",
                "detail": "Host operations status could not be read",
            }

    @app.get(
        f"{ADMIN_PATH}/api/devices",
        include_in_schema=False,
    )
    def admin_devices(
        response: Response,
        device_status: str | None = None,
        operator: dict[str, Any] = Depends(
            require_admin_operator
        ),
    ):
        set_no_store(response)
        return list_devices_handler(
            device_status=device_status,
            operator=operator,
        )

    @app.get(
        f"{ADMIN_PATH}/api/devices/{{device_id}}",
        include_in_schema=False,
    )
    def admin_device_detail(
        device_id: uuid.UUID,
        response: Response,
        operator: dict[str, Any] = Depends(
            require_admin_operator
        ),
    ):
        result = get_device_handler(
            device_id=device_id,
            operator=operator,
        )
        set_no_store(response)
        return result

    @app.post(
        f"{ADMIN_PATH}/api/devices/{{device_id}}/{{action}}",
        include_in_schema=False,
    )
    def admin_device_action(
        device_id: uuid.UUID,
        action: str,
        payload: dict[str, Any],
        request: Request,
        response: Response,
        operator: dict[str, Any] = Depends(
            require_admin_operator
        ),
    ):
        reason = str(payload.get("reason", "")).strip()

        if action == "delete":
            if operator["role"] != "owner":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Owner authorization is required",
                )
            if not reason:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="A reason is required",
                )

            now = datetime.now(timezone.utc)
            source_ip = client_ip_handler(request)
            with open_database_handler() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT
                            id, rustdesk_id, hostname, friendly_name,
                            contact_email, status, status_reason, status_changed_at,
                            last_ip, last_seen_at, created_at,
                            encode(digest(device_public_key, 'sha256'), 'hex')
                                AS device_public_key_sha256
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
                            detail="Managed device was not found",
                        )
                    if device["status"] not in {"blocked", "revoked"}:
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail=(
                                "Only blocked or revoked managed-device "
                                "records can be deleted"
                            ),
                        )

                    cursor.execute(
                        """
                        SELECT
                            from_status,
                            to_status,
                            reason,
                            changed_at,
                            changed_by
                        FROM device_status_history
                        WHERE device_id = %s
                        ORDER BY changed_at
                        """,
                        (device_id,),
                    )
                    status_history = [
                        {
                            "from_status": item["from_status"],
                            "to_status": item["to_status"],
                            "reason": item["reason"],
                            "changed_at": (
                                item["changed_at"].isoformat()
                                if item["changed_at"] is not None
                                else None
                            ),
                            "changed_by": (
                                str(item["changed_by"])
                                if item["changed_by"] is not None
                                else None
                            ),
                        }
                        for item in cursor.fetchall()
                    ]

                    dependent_counts: dict[str, int] = {}
                    count_specs = (
                        ("device_credentials", "device_id"),
                        ("relay_access_leases", "device_id"),
                        ("device_reenrollment_requests", "device_id"),
                        ("device_reenrollment_authorizations", "device_id"),
                        ("device_status_history", "device_id"),
                        ("device_activity_events", "device_id"),
                        ("device_active_sessions", "reporting_device_id"),
                    )
                    for table_name, column_name in count_specs:
                        cursor.execute(
                            f"SELECT COUNT(*) AS count FROM {table_name} "
                            f"WHERE {column_name} = %s",
                            (device_id,),
                        )
                        dependent_counts[table_name] = int(
                            cursor.fetchone()["count"]
                        )

                    device_snapshot = {
                        "id": str(device["id"]),
                        "rustdesk_id": device["rustdesk_id"],
                        "hostname": device["hostname"],
                        "friendly_name": device["friendly_name"],
                        "contact_email": device["contact_email"],
                        "final_status": device["status"],
                        "status_reason": device["status_reason"],
                        "status_changed_at": (
                            device["status_changed_at"].isoformat()
                            if device["status_changed_at"] is not None
                            else None
                        ),
                        "last_ip": (
                            str(device["last_ip"])
                            if device["last_ip"] is not None
                            else None
                        ),
                        "last_seen_at": (
                            device["last_seen_at"].isoformat()
                            if device["last_seen_at"] is not None
                            else None
                        ),
                        "created_at": device["created_at"].isoformat(),
                        "device_public_key_sha256": (
                            device["device_public_key_sha256"]
                        ),
                    }

                    write_audit_handler(
                        cursor,
                        "device.deleted",
                        actor_account_id=operator["account_id"],
                        target_type="managed_device_deleted",
                        target_id=device_id,
                        source_ip=source_ip,
                        details={
                            "reason": reason,
                            "deleted_at": now.isoformat(),
                            "device": device_snapshot,
                            "status_history": status_history,
                            "dependent_rows_removed": dependent_counts,
                            "history_note": (
                                "Enrollment events and audit events are "
                                "preserved independently; status history is "
                                "archived in this immutable audit record."
                            ),
                        },
                    )
                    cursor.execute(
                        "DELETE FROM managed_devices WHERE id = %s",
                        (device_id,),
                    )
                    if cursor.rowcount != 1:
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail=(
                                "Managed-device deletion did not affect "
                                "exactly one row"
                            ),
                        )
                    connection.commit()

            result = {
                "status": "deleted",
                "device_id": device_id,
                "rustdesk_id": device["rustdesk_id"],
                "deleted_at": now,
            }
        elif action == "approve":
            friendly_name_value = payload.get("friendly_name")
            friendly_name = (
                str(friendly_name_value).strip()
                if friendly_name_value is not None
                else None
            )
            result = approve_device_handler(
                device_id=device_id,
                payload=SimpleNamespace(
                    friendly_name=friendly_name or None,
                    reason=reason or None,
                ),
                request=request,
                operator=operator,
            )
        else:
            if not reason:
                raise HTTPException(
                    status_code=(
                        status.HTTP_422_UNPROCESSABLE_ENTITY
                    ),
                    detail="A reason is required",
                )

            handlers = {
                "deny": deny_device_handler,
                "block": block_device_handler,
                "revoke": revoke_device_handler,
            }
            handler = handlers.get(action)

            if handler is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Unknown device action",
                )

            result = handler(
                device_id=device_id,
                payload=SimpleNamespace(reason=reason),
                request=request,
                operator=operator,
            )

        set_no_store(response)
        return result

    @app.get(
        f"{ADMIN_PATH}/api/operators",
        include_in_schema=False,
    )
    def admin_operators(
        response: Response,
        operator: dict[str, Any] = Depends(
            require_admin_operator
        ),
    ):
        set_no_store(response)
        if operator["role"] == "owner":
            return list_operators_handler(operator=operator)
        detail = get_operator_handler(
            account_id=operator["account_id"],
            operator=operator,
        )
        return {"operators": [detail["account"]]}

    @app.get(
        f"{ADMIN_PATH}/api/operators/{{account_id}}",
        include_in_schema=False,
    )
    def admin_operator_detail(
        account_id: uuid.UUID,
        response: Response,
        operator: dict[str, Any] = Depends(
            require_admin_operator
        ),
    ):
        result = get_operator_handler(
            account_id=account_id,
            operator=operator,
        )
        set_no_store(response)
        return result

    @app.put(
        f"{ADMIN_PATH}/api/operators/{{account_id}}/email",
        include_in_schema=False,
    )
    def admin_operator_email(
        account_id: uuid.UUID,
        payload: dict[str, Any],
        request: Request,
        response: Response,
        operator: dict[str, Any] = Depends(
            require_admin_operator
        ),
    ):
        raw_email = payload.get("email")
        result = update_operator_email_handler(
            account_id=account_id,
            payload=SimpleNamespace(
                email=(str(raw_email) if raw_email is not None else None)
            ),
            request=request,
            operator=operator,
        )
        set_no_store(response)
        return result

    @app.post(
        f"{ADMIN_PATH}/api/operators/{{account_id}}/role-change",
        include_in_schema=False,
    )
    def admin_create_role_change(
        account_id: uuid.UUID,
        payload: dict[str, Any],
        request: Request,
        response: Response,
        operator: dict[str, Any] = Depends(
            require_admin_owner
        ),
    ):
        requested_role = str(
            payload.get("requested_role", "")
        ).strip()
        reason = str(payload.get("reason", "")).strip()
        owner_password_value = payload.get("owner_password")
        owner_totp_value = payload.get("owner_totp_code")
        owner_password = (
            str(owner_password_value)
            if owner_password_value is not None
            else None
        )
        owner_totp_code = (
            str(owner_totp_value).strip()
            if owner_totp_value is not None
            else None
        )

        if requested_role not in {
            "owner",
            "manager",
            "viewer",
        }:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid requested role",
            )

        if not reason:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="A reason is required",
            )

        result = create_operator_role_change_handler(
            account_id=account_id,
            payload=SimpleNamespace(
                requested_role=requested_role,
                reason=reason,
                expires_in_minutes=15,
                owner_password=owner_password,
                owner_totp_code=owner_totp_code,
            ),
            request=request,
            operator=operator,
        )
        set_no_store(response)
        return result

    @app.post(
        f"{ADMIN_PATH}/api/operators/{{account_id}}/{{action}}",
        include_in_schema=False,
    )
    def admin_operator_action(
        account_id: uuid.UUID,
        action: str,
        payload: dict[str, Any],
        request: Request,
        response: Response,
        operator: dict[str, Any] = Depends(
            require_admin_owner
        ),
    ):
        reason = str(payload.get("reason", "")).strip()

        if not reason:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="A reason is required",
            )

        handlers = {
            "disable": disable_operator_handler,
            "enable": enable_operator_handler,
            "delete": delete_operator_handler,
            "unlock": unlock_operator_handler,
            "revoke-sessions": (
                revoke_operator_sessions_handler
            ),
        }
        handler = handlers.get(action)

        if handler is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Unknown operator action",
            )

        result = handler(
            account_id=account_id,
            payload=SimpleNamespace(reason=reason),
            request=request,
            operator=operator,
        )
        set_no_store(response)
        return result

    @app.get(
        f"{ADMIN_PATH}/api/invitations",
        include_in_schema=False,
    )
    def admin_invitations(
        response: Response,
        operator: dict[str, Any] = Depends(
            require_admin_owner
        ),
    ):
        result = list_operator_invitations_handler(
            operator=operator,
        )
        set_no_store(response)
        return result

    @app.post(
        f"{ADMIN_PATH}/api/invitations",
        include_in_schema=False,
    )
    def admin_create_invitation(
        payload: dict[str, Any],
        request: Request,
        response: Response,
        operator: dict[str, Any] = Depends(
            require_admin_owner
        ),
    ):
        username = str(payload.get("username", "")).strip()
        display_name = str(
            payload.get("display_name", "")
        ).strip()
        role = str(payload.get("role", "")).strip()
        expires_in_hours = int(
            payload.get("expires_in_hours", 72)
        )

        if not username or not display_name:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Username and display name are required",
            )

        if role not in {"manager", "viewer"}:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invitation role must be manager or viewer",
            )

        if not 1 <= expires_in_hours <= 720:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invitation expiration must be 1 to 720 hours",
            )

        result = create_operator_invitation_handler(
            payload=SimpleNamespace(
                username=username,
                display_name=display_name,
                role=role,
                expires_in_hours=expires_in_hours,
            ),
            request=request,
            operator=operator,
        )
        set_no_store(response)
        return result

    @app.post(
        f"{ADMIN_PATH}/api/invitations/{{invitation_id}}/revoke",
        include_in_schema=False,
    )
    def admin_revoke_invitation(
        invitation_id: uuid.UUID,
        payload: dict[str, Any],
        request: Request,
        response: Response,
        operator: dict[str, Any] = Depends(
            require_admin_owner
        ),
    ):
        reason = str(payload.get("reason", "")).strip()

        if not reason:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="A reason is required",
            )

        result = revoke_operator_invitation_handler(
            invitation_id=invitation_id,
            payload=SimpleNamespace(reason=reason),
            request=request,
            operator=operator,
        )
        set_no_store(response)
        return result

    @app.get(
        f"{ADMIN_PATH}/api/role-changes",
        include_in_schema=False,
    )
    def admin_role_changes(
        response: Response,
        operator: dict[str, Any] = Depends(
            require_admin_owner
        ),
    ):
        result = list_operator_role_changes_handler(
            operator=operator,
        )
        set_no_store(response)
        return result

    @app.post(
        f"{ADMIN_PATH}/api/role-changes/{{request_id}}/{{action}}",
        include_in_schema=False,
    )
    def admin_role_change_action(
        request_id: uuid.UUID,
        action: str,
        payload: dict[str, Any],
        request: Request,
        response: Response,
        operator: dict[str, Any] = Depends(
            require_admin_owner
        ),
    ):
        reason = str(payload.get("reason", "")).strip()

        if not reason:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="A reason is required",
            )

        handlers = {
            "complete": complete_operator_role_change_handler,
            "cancel": cancel_operator_role_change_handler,
        }
        handler = handlers.get(action)

        if handler is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Unknown role-change action",
            )

        result = handler(
            request_id=request_id,
            payload=SimpleNamespace(reason=reason),
            request=request,
            operator=operator,
        )
        set_no_store(response)
        return result

    def _activity_items(
        *,
        limit: int,
        event_type: str | None,
    ) -> list[dict[str, Any]]:
        now = datetime.now(timezone.utc)
        normalized_event_type = event_type.strip() if event_type else None
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    WITH stored_activity AS (
                        SELECT
                            dae.id,
                            dae.event_type,
                            NULL::text AS actor_username,
                            COALESCE(d.friendly_name,d.hostname,d.rustdesk_id)
                                AS actor_display_name,
                            CASE
                                WHEN peer.id IS NULL AND dae.peer_rustdesk_id IS NOT NULL
                                    THEN 'rustdesk_peer'::text
                                WHEN peer.id IS NULL THEN NULL
                                ELSE 'managed_device'::text
                            END AS target_type,
                            peer.id AS target_id,
                            COALESCE(
                                peer.friendly_name,
                                peer.hostname,
                                peer.rustdesk_id,
                                dae.peer_rustdesk_id
                            ) AS target_device_name,
                            dae.source_ip::text AS source_ip,
                            dae.details || jsonb_build_object(
                                'peer_rustdesk_id', dae.peer_rustdesk_id,
                                'peer_name', COALESCE(
                                    peer.friendly_name,
                                    peer.hostname,
                                    peer.rustdesk_id
                                ),
                                'direction', dae.direction,
                                'session_type', dae.session_type
                            ) AS details,
                            dae.occurred_at AS created_at
                        FROM device_activity_events dae
                        JOIN managed_devices d ON d.id = dae.device_id
                        LEFT JOIN managed_devices peer
                          ON peer.id = dae.peer_device_id
                    ),
                    current_inactive AS (
                        SELECT
                            gen_random_uuid() AS id,
                            'client.inactive'::text AS event_type,
                            NULL::text AS actor_username,
                            COALESCE(d.friendly_name,d.hostname,d.rustdesk_id)
                                AS actor_display_name,
                            NULL::text AS target_type,
                            NULL::uuid AS target_id,
                            NULL::text AS target_device_name,
                            d.last_ip::text AS source_ip,
                            jsonb_build_object(
                                'reason','heartbeat timeout',
                                'timeout_seconds',45,
                                'synthetic_current_state',true
                            ) AS details,
                            d.last_seen_at + interval '45 seconds' AS created_at
                        FROM managed_devices d
                        WHERE d.status = 'approved'
                          AND d.last_seen_at IS NOT NULL
                          AND d.last_seen_at < %s - interval '45 seconds'
                          AND NOT EXISTS (
                              SELECT 1
                              FROM device_activity_events dae
                              WHERE dae.device_id = d.id
                                AND dae.event_type = 'client.inactive'
                                AND dae.occurred_at = d.last_seen_at + interval '45 seconds'
                          )
                    ),
                    audit_activity AS (
                        SELECT
                            ae.id,
                            ae.event_type,
                            actor.username AS actor_username,
                            actor.display_name AS actor_display_name,
                            ae.target_type,
                            ae.target_id,
                            COALESCE(
                                target.username,
                                target_device.friendly_name,
                                target_device.hostname,
                                target_device.rustdesk_id
                            ) AS target_device_name,
                            ae.source_ip::text AS source_ip,
                            ae.details,
                            ae.created_at
                        FROM audit_events ae
                        LEFT JOIN operator_accounts actor
                          ON actor.id = ae.actor_account_id
                        LEFT JOIN operator_accounts target
                          ON ae.target_type = 'operator_account'
                         AND target.id = ae.target_id
                        LEFT JOIN managed_devices target_device
                          ON ae.target_type = 'managed_device'
                         AND target_device.id = ae.target_id
                        WHERE ae.event_type <> 'operator.session_refreshed'
                    ),
                    combined AS (
                        SELECT * FROM stored_activity
                        UNION ALL
                        SELECT * FROM current_inactive
                        UNION ALL
                        SELECT * FROM audit_activity
                    )
                    SELECT *
                    FROM combined
                    WHERE (%s::text IS NULL OR event_type = %s)
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (now, normalized_event_type, normalized_event_type, limit),
                )
                return cursor.fetchall()

    @app.get(
        f"{ADMIN_PATH}/api/activity-feed",
        include_in_schema=False,
    )
    def admin_activity_feed(
        response: Response,
        limit: int = Query(default=200, ge=1, le=500),
        event_type: str | None = Query(default=None, max_length=64),
        operator: dict[str, Any] = Depends(require_admin_owner),
    ):
        del operator
        set_no_store(response)
        return {
            "items": _activity_items(limit=limit, event_type=event_type),
            "limit": limit,
        }

    @app.get(
        f"{ADMIN_PATH}/api/audit",
        include_in_schema=False,
    )
    def admin_audit_compatibility(
        response: Response,
        limit: int = Query(default=150, ge=1, le=250),
        event_type: str | None = Query(default=None, max_length=64),
        operator: dict[str, Any] = Depends(require_admin_owner),
    ):
        del operator
        set_no_store(response)
        return {
            "items": _activity_items(limit=limit, event_type=event_type),
            "limit": limit,
        }


    @app.post(
        f"{ADMIN_PATH}/api/idle-logout",
        include_in_schema=False,
    )
    def admin_idle_logout(
        request: Request,
        response: Response,
    ):
        revoke_request_session(
            request,
            "admin_idle_timeout",
        )
        clear_admin_cookies(response)
        set_no_store(response)
        return {
            "status": "logged_out",
            "reason": "idle_timeout",
        }

    @app.post(
        f"{ADMIN_PATH}/api/logout",
        include_in_schema=False,
    )
    def admin_logout(
        request: Request,
        response: Response,
        operator: dict[str, Any] = Depends(
            require_admin_operator
        ),
    ):
        result = logout_handler(
            request=request,
            operator=operator,
        )
        clear_admin_cookies(response)
        set_no_store(response)
        return result


ADMIN_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>RustDesk Directory</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #08111f;
      --panel: #111d2e;
      --panel-2: #17263a;
      --line: #263a53;
      --text: #eef5ff;
      --muted: #9fb0c7;
      --accent: #4fa3ff;
      --good: #37c978;
      --warn: #f6b94b;
      --bad: #f06368;
      --shadow: 0 20px 55px rgba(0,0,0,.32);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at 10% 10%, rgba(79,163,255,.14), transparent 26rem),
        linear-gradient(145deg, #07101d, #0b1626 55%, #08111f);
    }
    button, input, select { font: inherit; }
    button { cursor: pointer; }
    button:disabled { cursor: not-allowed; opacity: .45; }
    .hidden { display: none !important; }
    .shell {
      width: min(1480px, calc(100% - 32px));
      margin: 0 auto;
      padding: 28px 0 48px;
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .logo {
      width: 42px;
      height: 42px;
      border-radius: 12px;
      display: grid;
      place-items: center;
      background: linear-gradient(135deg, #4fa3ff, #786cff);
      box-shadow: 0 10px 30px rgba(79,163,255,.25);
      font-weight: 800;
    }
    .brand h1 { margin: 0; font-size: 20px; }
    .brand p {
      margin: 3px 0 0;
      color: var(--muted);
      font-size: 13px;
    }
    .login-wrap {
      min-height: calc(100vh - 76px);
      display: grid;
      place-items: center;
    }
    .login-card, .panel, .stat {
      border: 1px solid var(--line);
      background:
        linear-gradient(
          160deg,
          rgba(23,38,58,.95),
          rgba(13,25,41,.96)
        );
      box-shadow: var(--shadow);
    }
    .login-card {
      width: min(440px, 100%);
      border-radius: 22px;
      padding: 28px;
    }
    .login-card .brand { margin-bottom: 28px; }
    label {
      display: block;
      color: var(--muted);
      font-size: 13px;
      margin: 16px 0 7px;
    }
    input, select {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 11px;
      background: #0a1524;
      color: var(--text);
      padding: 12px 13px;
      outline: none;
    }
    input:focus, select:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(79,163,255,.13);
    }
    .primary, .secondary, .small {
      border: 0;
      border-radius: 11px;
      padding: 11px 15px;
      font-weight: 700;
    }
    .primary {
      width: 100%;
      margin-top: 20px;
      color: white;
      background: linear-gradient(135deg, #278df8, #6467f2);
    }
    .secondary {
      color: var(--text);
      background: var(--panel-2);
      border: 1px solid var(--line);
    }
    .small {
      padding: 7px 10px;
      font-size: 12px;
      color: var(--text);
      background: rgba(23,38,58,.96);
      border: 1px solid var(--line);
      white-space: nowrap;
    }
    .small.danger {
      color: #ffb2b5;
      border-color: rgba(240,99,104,.42);
      background: rgba(240,99,104,.08);
    }
    .small.good {
      color: #9ceabd;
      border-color: rgba(55,201,120,.38);
      background: rgba(55,201,120,.08);
    }
    .error {
      min-height: 22px;
      margin-top: 12px;
      color: #ff9b9f;
      font-size: 13px;
    }
    .topbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 20px;
      margin-bottom: 18px;
    }
    .actions {
      display: flex;
      gap: 9px;
      align-items: center;
      flex-wrap: wrap;
    }
    .operator {
      color: var(--muted);
      font-size: 13px;
      margin-right: 4px;
    }
    .health-strip {
      display: flex;
      align-items: center;
      gap: 6px;
      flex-wrap: nowrap;
    }
    .health-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 6px 8px;
      background: rgba(17,29,46,.9);
      color: var(--muted);
      font-size: 11px;
      font-weight: 700;
      white-space: nowrap;
    }
    .dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--warn);
      box-shadow: 0 0 14px currentColor;
      flex: 0 0 auto;
    }
    .dot.good { background: var(--good); }
    .dot.warn { background: var(--warn); }
    .dot.bad { background: var(--bad); }
    .dot.unknown { background: #77869a; }
    .tabs {
      display: flex;
      gap: 8px;
      margin: 0 0 18px;
      padding: 6px;
      width: fit-content;
      max-width: 100%;
      overflow-x: auto;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: rgba(8,17,31,.55);
    }
    .tab {
      border: 0;
      border-radius: 10px;
      padding: 9px 14px;
      color: var(--muted);
      background: transparent;
      font-weight: 750;
      white-space: nowrap;
    }
    .tab.active {
      color: white;
      background: linear-gradient(135deg, #278df8, #6467f2);
      box-shadow: 0 8px 22px rgba(39,141,248,.2);
    }
    .stats {
      display: grid;
      grid-template-columns: repeat(6, minmax(130px, 1fr));
      gap: 12px;
      margin-bottom: 18px;
    }
    .stat { border-radius: 16px; padding: 16px; }
    .stat .value { font-size: 28px; font-weight: 800; }
    .stat .label {
      margin-top: 4px;
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .08em;
    }
    #clientStats {
      grid-template-columns: repeat(7, minmax(0, 1fr));
      gap: 9px;
    }
    #clientStats .stat {
      min-width: 0;
      padding: 12px 10px;
      text-align: center;
    }
    #clientStats .stat .value {
      font-size: 25px;
    }
    #clientStats .stat .label {
      font-size: 10px;
      letter-spacing: .055em;
      white-space: nowrap;
    }
    .panel {
      border-radius: 18px;
      overflow: hidden;
      margin-bottom: 18px;
    }
    .panel-head {
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: center;
      padding: 16px 18px;
      border-bottom: 1px solid var(--line);
    }
    .panel-head h2 { margin: 0; font-size: 16px; }
    .panel-head p {
      margin: 4px 0 0;
      color: var(--muted);
      font-size: 12px;
    }
    .filters {
      display: flex;
      gap: 10px;
      align-items: center;
    }
    .filters select { width: 190px; padding: 9px 10px; }
    .filters input { width: 250px; padding: 9px 10px; }
    .table-wrap { overflow-x: auto; }
    table {
      width: 100%;
      border-collapse: collapse;
      min-width: 1120px;
    }
    th, td {
      text-align: left;
      padding: 13px 16px;
      border-bottom: 1px solid rgba(38,58,83,.68);
      font-size: 13px;
      vertical-align: top;
    }
    th {
      color: var(--muted);
      font-weight: 700;
      background: rgba(8,17,31,.42);
      position: sticky;
      top: 0;
    }
    tbody tr:hover { background: rgba(79,163,255,.045); }
    .name { font-weight: 700; }
    .sub {
      color: var(--muted);
      font-size: 12px;
      margin-top: 3px;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 5px 8px;
      border-radius: 999px;
      background: rgba(159,176,199,.12);
      border: 1px solid rgba(159,176,199,.2);
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .04em;
      white-space: nowrap;
    }
    .badge.approved, .badge.online, .badge.active,
    .badge.owner {
      color: #7ce6a8;
      border-color: rgba(55,201,120,.3);
      background: rgba(55,201,120,.09);
    }
    .badge.pending, .badge.manager, .badge.locked {
      color: #ffd17a;
      border-color: rgba(246,185,75,.3);
      background: rgba(246,185,75,.09);
    }
    .badge.viewer {
      color: #9fcaff;
      border-color: rgba(79,163,255,.3);
      background: rgba(79,163,255,.09);
    }
    .badge.blocked, .badge.denied, .badge.revoked,
    .badge.offline, .badge.disabled, .badge.failed {
      color: #ff999d;
      border-color: rgba(240,99,104,.3);
      background: rgba(240,99,104,.08);
    }
    .action-row {
      display: flex;
      gap: 7px;
      align-items: center;
      flex-wrap: wrap;
    }
    .details {
      max-width: 520px;
      color: #c7d4e5;
      font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
      font-size: 11px;
      line-height: 1.45;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }
    .empty {
      padding: 40px 18px;
      text-align: center;
      color: var(--muted);
    }
    .footnote {
      color: var(--muted);
      font-size: 12px;
      margin: 12px 2px 0;
    }
    .toast {
      position: fixed;
      right: 18px;
      bottom: 18px;
      z-index: 50;
      max-width: min(430px, calc(100% - 36px));
      border: 1px solid var(--line);
      border-radius: 13px;
      padding: 12px 14px;
      background: #132238;
      color: var(--text);
      box-shadow: var(--shadow);
      font-size: 13px;
    }
    .toast.bad {
      border-color: rgba(240,99,104,.45);
      color: #ffb8bb;
    }
    .row-actions {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 6px;
      min-width: 260px;
    }
    .modal-backdrop {
      position: fixed;
      inset: 0;
      z-index: 1000;
      display: grid;
      place-items: center;
      padding: 20px;
      background: rgba(2,8,16,.78);
      backdrop-filter: blur(5px);
    }
    .modal-card {
      width: min(920px, 100%);
      max-height: calc(100vh - 40px);
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 20px;
      background: linear-gradient(
        160deg,
        rgba(23,38,58,.99),
        rgba(10,21,36,.99)
      );
      box-shadow: 0 30px 90px rgba(0,0,0,.55);
    }
    .modal-head {
      position: sticky;
      top: 0;
      z-index: 2;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 16px;
      padding: 18px 20px;
      border-bottom: 1px solid var(--line);
      background: rgba(12,24,40,.97);
    }
    .modal-head h2 { margin: 0; font-size: 18px; }
    .modal-head p {
      margin: 5px 0 0;
      color: var(--muted);
      font-size: 13px;
    }
    .modal-body { padding: 20px; }
    .detail-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 20px;
    }
    .detail-item {
      min-width: 0;
      border: 1px solid rgba(38,58,83,.75);
      border-radius: 13px;
      padding: 12px;
      background: rgba(8,17,31,.45);
    }
    .detail-label {
      color: var(--muted);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: .07em;
    }
    .detail-value {
      margin-top: 6px;
      overflow-wrap: anywhere;
      font-weight: 700;
      font-size: 13px;
    }
    .modal-section-title {
      margin: 20px 0 10px;
      font-size: 14px;
    }
    .modal-actions {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px;
      margin-top: 16px;
    }
    .history-table { min-width: 680px; }
    body.modal-open { overflow: hidden; }
    @media (max-width: 1050px) {
      .stats { grid-template-columns: repeat(3, 1fr); }
      #clientStats { grid-template-columns: repeat(4, minmax(0, 1fr)); }
      .health-strip { flex-wrap: wrap; }
    }
    @media (max-width: 680px) {
      .shell {
        width: min(100% - 20px, 1480px);
        padding-top: 16px;
      }
      .topbar {
        align-items: flex-start;
        flex-direction: column;
      }
      .stats { grid-template-columns: repeat(2, 1fr); }
      #clientStats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .panel-head {
        align-items: flex-start;
        flex-direction: column;
      }
      .filters {
        width: 100%;
        flex-direction: column;
        align-items: stretch;
      }
      .filters select, .filters input {
        width: 100%;
      }
    }
  
    .owner-only.hidden-by-role { display: none !important; }
    .permissions-panel { margin-top: 24px; }
    .permission-stats { margin-top: 24px; }
    .compact-panel { margin-top: 18px; }
    .control-select {
      min-width: 118px;
      padding: 8px 30px 8px 10px;
      border-radius: 9px;
      font-weight: 700;
    }
    .control-select:disabled {
      cursor: not-allowed;
      opacity: .6;
    }
    .status-control {
      min-width: 102px;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 7px 12px;
      font-weight: 800;
    }
    .status-control.active {
      background: rgba(56, 189, 128, .13);
      color: #8bf0b9;
      border-color: rgba(56, 189, 128, .35);
    }
    .status-control.disabled {
      background: rgba(148, 163, 184, .12);
      color: #c4d0df;
      border-color: rgba(148, 163, 184, .28);
    }
    .approval-yes { color: #8bf0b9; font-weight: 800; }
    .approval-no { color: var(--muted); font-weight: 700; }
    .modal-form {
      display: grid;
      gap: 14px;
    }
    .form-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 14px;
    }
    .form-field {
      display: grid;
      gap: 7px;
    }
    .form-field label {
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
    }
    .form-field input,
    .form-field select,
    .form-field textarea {
      width: 100%;
    }
    .form-field textarea {
      min-height: 92px;
      resize: vertical;
    }
    .form-actions {
      display: flex;
      justify-content: flex-end;
      gap: 10px;
      flex-wrap: wrap;
      margin-top: 4px;
    }
    .generated-link {
      display: grid;
      gap: 10px;
      padding: 14px;
      border: 1px solid rgba(56, 189, 128, .35);
      border-radius: 12px;
      background: rgba(56, 189, 128, .08);
    }
    .generated-link code {
      display: block;
      overflow-wrap: anywhere;
      color: #dff9eb;
      white-space: pre-wrap;
    }
    .warning-box {
      padding: 12px 14px;
      border: 1px solid rgba(245, 158, 11, .38);
      border-radius: 10px;
      background: rgba(245, 158, 11, .09);
      color: #f7d99a;
    }
    #pendingCount.pending-alert {
      color: var(--bad);
    }
    .ops-status-groups {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(255px, 1fr));
      gap: 10px;
      padding: 12px 14px 14px;
    }
    .ops-status-group {
      min-width: 0;
      overflow: hidden;
      border: 1px solid rgba(38,58,83,.82);
      border-radius: 12px;
      background: rgba(8,17,31,.38);
    }
    .ops-status-group h3 {
      margin: 0;
      padding: 9px 11px;
      border-bottom: 1px solid rgba(38,58,83,.68);
      color: #c8d6e8;
      background: rgba(8,17,31,.34);
      font-size: 11px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: .055em;
    }
    .ops-status-row {
      display: grid;
      grid-template-columns: minmax(0, .95fr) minmax(0, 1.25fr);
      align-items: center;
      gap: 12px;
      min-height: 34px;
      padding: 7px 11px;
      border-bottom: 1px solid rgba(38,58,83,.48);
    }
    .ops-status-row:last-child {
      border-bottom: 0;
    }
    .ops-status-label {
      min-width: 0;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.3;
    }
    .ops-status-value {
      min-width: 0;
      color: var(--text);
      font-size: 13px;
      font-weight: 700;
      line-height: 1.3;
      text-align: right;
      overflow-wrap: anywhere;
    }
    .compact-panel .warning-box {
      margin: 0 14px 14px;
      font-size: 12px;
      line-height: 1.45;
    }
    .ops-primary-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 18px;
      align-items: start;
    }
    .ops-primary-grid > .panel {
      min-width: 0;
      margin: 0;
    }
    @media (max-width: 1180px) {
      .ops-primary-grid {
        grid-template-columns: 1fr;
      }
    }
    @media (max-width: 760px) {
      .ops-status-groups {
        grid-template-columns: 1fr;
      }
      .ops-status-row {
        grid-template-columns: minmax(0, 1fr) minmax(0, 1.15fr);
      }
    }
    .permission-note {
      max-width: 420px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.45;
    }
    .invite-shell {
      width: min(680px, calc(100% - 28px));
      margin: 50px auto;
    }
    .invite-card {
      padding: 24px;
      border: 1px solid var(--line);
      border-radius: 18px;
      background: var(--panel);
      box-shadow: 0 24px 70px rgba(0, 0, 0, .35);
    }
    .invite-card h1 { margin: 0 0 8px; }
    .invite-card .intro { color: var(--muted); margin: 0 0 22px; }
    .invite-summary {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
      margin-bottom: 18px;
    }
    .invite-summary > div {
      padding: 12px;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: var(--panel-2);
    }
    .invite-secret {
      overflow-wrap: anywhere;
      user-select: all;
      font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
    }
    @media (max-width: 760px) {
      .form-grid, .invite-summary { grid-template-columns: 1fr; }
    }

  </style>
</head>
<body>
  <main class="shell">
    <section id="loginView" class="login-wrap">
      <form id="loginForm" class="login-card" autocomplete="on">
        <div class="brand">
          <div class="logo">RD</div>
          <div>
            <h1>RustDesk Directory</h1>
            <p>Owner administration</p>
          </div>
        </div>
        <label for="username">Owner username</label>
        <input
          id="username"
          name="username"
          autocomplete="username"
          required
        >
        <label for="password">Password</label>
        <input
          id="password"
          name="password"
          type="password"
          autocomplete="current-password"
          required
        >
        <label for="totp">Authenticator code</label>
        <input
          id="totp"
          name="totp"
          inputmode="numeric"
          pattern="[0-9]{6}"
          maxlength="6"
          autocomplete="one-time-code"
          required
        >
        <button
          id="loginButton"
          class="primary"
          type="submit"
        >Sign in</button>
        <div id="loginError" class="error" role="alert"></div>
      </form>
    </section>

    <section id="dashboardView" class="hidden">
      <header class="topbar">
        <div class="brand">
          <div class="logo">RD</div>
          <div>
            <h1>RustDesk Directory</h1>
            <p>Client, operator, and server health management</p>
          </div>
        </div>
        <div class="actions">
          <span id="criticalHealth" class="health-strip" aria-label="Critical service health">
            <span class="health-pill" data-health="api"><span class="dot unknown"></span><span>API</span></span>
            <span class="health-pill" data-health="database"><span class="dot unknown"></span><span>DB</span></span>
            <span class="health-pill" data-health="https"><span class="dot unknown"></span><span>HTTPS</span></span>
            <span class="health-pill" data-health="id_server"><span class="dot unknown"></span><span>ID Server</span></span>
            <span class="health-pill" data-health="relay"><span class="dot unknown"></span><span>Relay</span></span>
            <span class="health-pill" data-health="relay_guard"><span class="dot unknown"></span><span>Relay Guard</span></span>
          </span>
          <span id="operatorText" class="operator"></span>
          <button
            id="refreshButton"
            class="secondary"
            type="button"
          >Refresh</button>
          <button
            id="logoutButton"
            class="secondary"
            type="button"
          >Sign out</button>
        </div>
      </header>

      <nav class="tabs" aria-label="Administration sections">
        <button
          class="tab active"
          data-tab="clients"
          type="button"
        >Group Management</button>
        <button
          class="tab owner-only"
          data-tab="security"
          type="button"
        >Activity</button>
      </nav>

      <section id="clientsTab" class="tab-view">
        <section class="stats" id="clientStats">
          <article class="stat"><div id="totalCount" class="value">0</div><div class="label">Managed</div></article>
          <article class="stat"><div id="activeClientCount" class="value">0</div><div class="label">Active Clients</div></article>
          <article class="stat"><div id="pendingCount" class="value">0</div><div class="label">Pending</div></article>
          <article class="stat"><div id="activeSessionCount" class="value">0</div><div class="label">Active Sessions</div></article>
        </section>

        <section class="panel">
          <div class="panel-head">
            <div>
              <h2>Client Management</h2>
              <p>Pending approvals and currently approved clients</p>
            </div>
            <div class="filters">
              <select
                id="statusFilter"
                aria-label="Filter managed clients"
              >
                <option value="">All managed</option>
                <option value="approved">Approved</option>
                <option value="pending">Pending</option>
              </select>
              <button
                id="findReenrollmentButton"
                class="secondary owner-only"
                type="button"
              >Authorize re-enrollment</button>
            </div>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Client</th>
                  <th>RustDesk ID</th>
                  <th>Status</th>
                  <th>Presence</th>
                  <th>Last IP</th>
                  <th>Last seen</th>
                  <th>Credential</th>
                  <th>Actions</th>
                  <th>Connected To</th>
                </tr>
              </thead>
              <tbody id="deviceRows"></tbody>
            </table>
            <div id="deviceEmpty" class="empty hidden">
              No clients match this filter.
            </div>
          </div>
        </section>
        <p class="footnote">
          Active Clients are Approved clients whose most recent heartbeat was
          within the last 45 seconds. Pending, Blocked, Revoked, and Denied records
          do not count as active. Active Sessions are fresh desktop or file-transfer
          sessions reported by Approved managed clients.
        </p>

        <section id="ownerPermissionsSection" class="owner-only">

          <div class="ops-primary-grid">
          <section class="panel compact-panel" id="operationsPanel">
            <div class="panel-head">
              <div>
                <h2>Server Health</h2>
                <p>
                  Host services, backups, restore verification,
                  TLS certificate, storage, and pinned RustDesk image.
                </p>
              </div>
              <div class="filters">
                <span id="opsOverallBadge" class="badge">CHECKING</span>
              </div>
            </div>
            <section class="ops-status-groups">
              <section class="ops-status-group">
                <h3>Core Services</h3>
                <div class="ops-status-row"><span class="ops-status-label">Directory API</span><span id="opsApi" class="ops-status-value">-</span></div>
                <div class="ops-status-row"><span class="ops-status-label">Database</span><span id="opsDatabase" class="ops-status-value">-</span></div>
                <div class="ops-status-row"><span class="ops-status-label">Relay Guard</span><span id="opsRelay" class="ops-status-value">-</span></div>
                <div class="ops-status-row"><span class="ops-status-label">RustDesk</span><span id="opsRustDesk" class="ops-status-value">-</span></div>
              </section>
              <section class="ops-status-group">
                <h3>Protection / Recovery</h3>
                <div class="ops-status-row"><span class="ops-status-label">Latest Backup</span><span id="opsBackup" class="ops-status-value">-</span></div>
                <div class="ops-status-row"><span class="ops-status-label">Restore Test</span><span id="opsRestore" class="ops-status-value">-</span></div>
                <div class="ops-status-row"><span class="ops-status-label">Directory HTTPS TLS</span><span id="opsTls" class="ops-status-value">-</span></div>
                <div class="ops-status-row"><span class="ops-status-label">Client API HTTPS</span><span id="opsClientTls" class="ops-status-value">-</span></div>
                <div class="ops-status-row"><span class="ops-status-label">Disk Free</span><span id="opsDisk" class="ops-status-value">-</span></div>
              </section>
            </section>
            <div class="warning-box" id="opsDetail">
              Waiting for host operations status.
            </div>
          </section>

          <section class="panel compact-panel" id="upstreamPanel">
            <div class="panel-head">
              <div>
                <h2>Upstream Update</h2>
                <p>
                  RustDesk upstream change assessment against the current
                  custom client base and patch footprint.
                </p>
              </div>
              <div class="filters">
                <span id="upstreamBadge" class="badge">CHECKING</span>
              </div>
            </div>
            <section class="ops-status-groups">
              <section class="ops-status-group">
                <h3>Upstream</h3>
                <div class="ops-status-row"><span class="ops-status-label">Release</span><span id="upstreamRef" class="ops-status-value">-</span></div>
                <div class="ops-status-row"><span class="ops-status-label">New Commits</span><span id="upstreamCommits" class="ops-status-value">-</span></div>
              </section>
              <section class="ops-status-group">
                <h3>Custom Client</h3>
                <div class="ops-status-row"><span class="ops-status-label">Patch Check</span><span id="upstreamPatchCheck" class="ops-status-value">-</span></div>
                <div class="ops-status-row"><span class="ops-status-label">Upstream Base</span><span id="upstreamBase" class="ops-status-value">-</span></div>
              </section>
            </section>
            <div class="warning-box" id="upstreamDetail">
              Waiting for upstream assessment.
            </div>
          </section>
          </div>

        </section>

        <section class="panel permissions-panel">
            <div class="panel-head">
              <div>
                <h2>Client Managers</h2>
                <p>
                  Each Manager can review their own account, email, sign-in history,
                  password, and authenticator. Owners can also invite Managers, change
                  roles, recover other Manager accounts, and revoke access. Pending
                  invitations and pending role changes remain inline for Owners.
                </p>
              </div>
              <div class="filters">
                <button
                  id="invitePersonButton"
                  class="primary owner-only"
                  type="button"
                >Invite Manager</button>
              </div>
            </div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Person</th>
                    <th>Can approve</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>MFA</th>
                    <th>Sessions</th>
                    <th>Last login</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody id="operatorRows"></tbody>
              </table>
              <div id="operatorEmpty" class="empty hidden">
                No accounts were returned.
              </div>
            </div>
          </section>

        <section class="panel" id="blockedRevokedPanel">
          <div class="panel-head">
            <div>
              <h2>Blocked / Revoked Clients</h2>
              <p>Terminal Blocked and Revoked managed identities retained for audit. These clients cannot be reauthorized or re-enrolled.</p>
            </div>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Client</th>
                  <th>RustDesk ID</th>
                  <th>Status</th>
                  <th>Last IP</th>
                  <th>Last seen</th>
                  <th>Status changed</th>
                  <th>Reason</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody id="blockedRevokedRows"></tbody>
            </table>
            <div id="blockedRevokedEmpty" class="empty hidden">
              No blocked or revoked clients.
            </div>
          </div>
        </section>
      </section>

      <section id="securityTab" class="tab-view hidden owner-only">
        <section class="panel">
          <div class="panel-head">
            <div>
              <h2>Activity</h2>
              <p>
                Managed-client presence, connection, account, enrollment,
                and administrative events
              </p>
            </div>
            <div class="filters">
              <select
                id="eventFilter"
                aria-label="Filter by event type"
              >
                <option value="">All event types</option>
              </select>
              <input
                id="auditSearch"
                type="search"
                placeholder="Search client, peer, actor, IP, or details"
                aria-label="Search activity"
              >
            </div>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Event</th>
                  <th>Actor</th>
                  <th>Target</th>
                  <th>Source IP</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody id="auditRows"></tbody>
            </table>
            <div id="auditEmpty" class="empty hidden">
              No activity events match this filter.
            </div>
          </div>
        </section>
        <p class="footnote">
          Showing the newest 150 events. Audit records cannot be
          updated, deleted, or truncated.
        </p>
      </section>

    </section>
  </main>

  <div
    id="deviceModal"
    class="modal-backdrop hidden"
    role="dialog"
    aria-modal="true"
    aria-labelledby="deviceModalTitle"
  >
    <section class="modal-card">
      <header class="modal-head">
        <div>
          <h2 id="deviceModalTitle">Managed client</h2>
          <p id="deviceModalSubtitle">Loading device details</p>
        </div>
        <button
          id="deviceModalClose"
          class="secondary"
          type="button"
        >Close</button>
      </header>
      <div class="modal-body">
        <div id="deviceDetailGrid" class="detail-grid"></div>
        <div id="deviceModalActions" class="modal-actions"></div>
        <h3 class="modal-section-title">Active sessions</h3>
        <div id="deviceActiveConnections" class="detail-grid"></div>
        <h3 class="modal-section-title">Session history</h3>
        <p id="deviceSessionNote" class="sub"></p>
        <div class="table-wrap">
          <table class="history-table">
            <thead><tr><th>Time</th><th>State</th><th>Direction</th><th>Peer</th><th>Type</th><th>Reason</th></tr></thead>
            <tbody id="deviceSessionRows"></tbody>
          </table>
          <div id="deviceSessionEmpty" class="empty hidden">No reported session history is available.</div>
        </div>
        <h3 class="modal-section-title">Status history</h3>
        <div class="table-wrap">
          <table class="history-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>From</th>
                <th>To</th>
                <th>Reason</th>
                <th>Changed by</th>
              </tr>
            </thead>
            <tbody id="deviceHistoryRows"></tbody>
          </table>
          <div id="deviceHistoryEmpty" class="empty hidden">
            No status history is available.
          </div>
        </div>
      </div>
    </section>
  </div>


  <div id="operatorModal" class="modal-backdrop hidden" role="dialog" aria-modal="true" aria-labelledby="operatorModalTitle">
    <section class="modal-card">
      <header class="modal-head">
        <div><h2 id="operatorModalTitle">Manager Details</h2><p id="operatorModalSubtitle">Loading Manager details</p></div>
        <button id="operatorModalClose" class="secondary" type="button">Close</button>
      </header>
      <div class="modal-body">
        <div id="operatorDetailGrid" class="detail-grid"></div>
        <div id="operatorEmailEditor"></div>
        <div id="operatorModalActions" class="modal-actions"></div>
        <div id="operatorGeneratedReset" class="generated-link hidden">
          <strong>One-time access link created — shown once</strong>
          <code id="operatorGeneratedResetLink"></code>
          <div class="form-actions"><button id="copyOperatorResetLink" class="secondary" type="button">Copy link</button></div>
        </div>
        <h3 class="modal-section-title">Access history</h3>
        <div class="table-wrap">
          <table class="history-table"><thead><tr><th>Time</th><th>Event</th><th>Actor</th><th>Source IP</th><th>Details</th></tr></thead><tbody id="operatorHistoryRows"></tbody></table>
          <div id="operatorHistoryEmpty" class="empty hidden">No Manager access history is available.</div>
        </div>
        <h3 class="modal-section-title">Login sessions</h3>
        <div class="table-wrap">
          <table class="history-table"><thead><tr><th>Created</th><th>Last seen</th><th>Expires</th><th>State</th><th>Source IP</th></tr></thead><tbody id="operatorSessionRows"></tbody></table>
          <div id="operatorSessionEmpty" class="empty hidden">No login sessions are available.</div>
        </div>
      </div>
    </section>
  </div>

  <div
    id="invitePersonModal"
    class="modal-backdrop hidden"
    role="dialog"
    aria-modal="true"
    aria-labelledby="invitePersonTitle"
  >
    <section class="modal-card">
      <header class="modal-head">
        <div>
          <h2 id="invitePersonTitle">Invite New Manager</h2>
          <p>
            Create a new Manager account with its own password
            and authenticator.
          </p>
        </div>
        <button
          id="invitePersonClose"
          class="secondary"
          type="button"
        >Close</button>
      </header>
      <div class="modal-body">
        <form id="invitePersonForm" class="modal-form">
          <div class="form-grid">
            <div class="form-field">
              <label for="inviteDisplayName">Display name</label>
              <input
                id="inviteDisplayName"
                maxlength="128"
                autocomplete="off"
                required
              >
            </div>
            <div class="form-field">
              <label for="inviteUsername">Username</label>
              <input
                id="inviteUsername"
                maxlength="64"
                autocomplete="off"
                required
              >
            </div>
            <div class="form-field">
              <label for="inviteExpiry">Invitation expires</label>
              <select id="inviteExpiry" required>
                <option value="24">24 hours</option>
                <option value="72" selected>3 days</option>
                <option value="168">7 days</option>
                <option value="336">14 days</option>
                <option value="720">30 days</option>
              </select>
            </div>
          </div>
          <div class="warning-box">
            The invitation link contains a secret token. Send it
            only to the intended person. It is displayed once.
          </div>
          <div
            id="inviteGenerated"
            class="generated-link hidden"
          >
            <strong>Invitation created</strong>
            <code id="inviteGeneratedLink"></code>
            <div class="form-actions">
              <button
                id="copyInviteLink"
                class="secondary"
                type="button"
              >Copy link</button>
            </div>
          </div>
          <div id="inviteFormError" class="error"></div>
          <div class="form-actions">
            <button
              id="inviteCancelButton"
              class="secondary"
              type="button"
            >Cancel</button>
            <button
              id="inviteSubmitButton"
              class="primary"
              type="submit"
            >Create invitation</button>
          </div>
        </form>
      </div>
    </section>
  </div>

  <div
    id="roleChangeModal"
    class="modal-backdrop hidden"
    role="dialog"
    aria-modal="true"
    aria-labelledby="roleChangeTitle"
  >
    <section class="modal-card">
      <header class="modal-head">
        <div>
          <h2 id="roleChangeTitle">Change permission</h2>
          <p id="roleChangeSubtitle"></p>
        </div>
        <button
          id="roleChangeClose"
          class="secondary"
          type="button"
        >Close</button>
      </header>
      <div class="modal-body">
        <form id="roleChangeForm" class="modal-form">
          <input id="roleChangeAccountId" type="hidden">
          <input id="roleChangeCurrentRole" type="hidden">
          <div class="form-field">
            <label for="roleChangeRequestedRole">
              New permission
            </label>
            <select id="roleChangeRequestedRole" required>
              <option value="owner">Owner</option>
              <option value="manager">Manager</option>
              <option value="viewer">Viewer</option>
            </select>
          </div>
          <div class="form-field">
            <label for="roleChangeReason">Reason</label>
            <textarea
              id="roleChangeReason"
              maxlength="1024"
              required
            ></textarea>
          </div>
          <div
            id="ownerReauthFields"
            class="form-grid hidden"
          >
            <div class="form-field">
              <label for="ownerReauthPassword">
                Your Owner password
              </label>
              <input
                id="ownerReauthPassword"
                type="password"
                maxlength="256"
                autocomplete="current-password"
              >
            </div>
            <div class="form-field">
              <label for="ownerReauthTotp">
                Your 6-digit authenticator code
              </label>
              <input
                id="ownerReauthTotp"
                inputmode="numeric"
                pattern="[0-9]{6}"
                maxlength="6"
                autocomplete="one-time-code"
              >
            </div>
          </div>
          <div id="roleChangeWarning" class="warning-box hidden">
            Owner promotions and demotions require your password
            and authenticator code. The affected person's active
            sessions will be revoked.
          </div>
          <div id="roleChangeError" class="error"></div>
          <div class="form-actions">
            <button
              id="roleChangeCancelButton"
              class="secondary"
              type="button"
            >Cancel</button>
            <button
              id="roleChangeSubmitButton"
              class="primary"
              type="submit"
            >Apply permission</button>
          </div>
        </form>
      </div>
    </section>
  </div>

  <div id="accessResetModal" class="modal-backdrop hidden" role="dialog" aria-modal="true" aria-labelledby="accessResetTitle">
    <section class="modal-card">
      <header class="modal-head">
        <div><h2 id="accessResetTitle">Reset account access</h2><p id="accessResetSubtitle"></p></div>
        <button id="accessResetClose" class="secondary" type="button">Close</button>
      </header>
      <div class="modal-body">
        <form id="accessResetForm" class="modal-form">
          <input id="accessResetAccountId" type="hidden">
          <div class="form-field">
            <label for="accessResetMode">Recovery type</label>
            <select id="accessResetMode" required>
              <option value="password_only">Reset password only</option>
              <option value="totp_only">Reset authenticator only</option>
              <option value="password_totp">Reset password + authenticator</option>
            </select>
          </div>
          <div class="form-field"><label for="accessResetReason">Reason</label><textarea id="accessResetReason" maxlength="1024" required></textarea></div>
          <div class="form-grid">
            <div class="form-field"><label id="accessResetPasswordLabel" for="accessResetOwnerPassword">Your Owner password</label><input id="accessResetOwnerPassword" type="password" maxlength="256" autocomplete="current-password" required></div>
            <div class="form-field"><label id="accessResetTotpLabel" for="accessResetOwnerTotp">Your 6-digit authenticator code</label><input id="accessResetOwnerTotp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required></div>
          </div>
          <div id="accessResetWarning" class="warning-box">Owner recovery revokes the person's active sessions immediately. Password reset modes also invalidate the old password. The one-time recovery link expires after 30 minutes.</div>
          <div id="accessResetGenerated" class="generated-link hidden"><strong>Recovery link created — shown once</strong><code id="accessResetGeneratedLink"></code><div class="form-actions"><button id="copyAccessResetLink" class="secondary" type="button">Copy link</button></div></div>
          <div id="accessResetError" class="error"></div>
          <div class="form-actions"><button id="accessResetCancel" class="secondary" type="button">Cancel</button><button id="accessResetSubmit" class="primary" type="submit">Create recovery link</button></div>
        </form>
      </div>
    </section>
  </div>

  <div id="reenrollmentModal" class="modal-backdrop hidden" role="dialog" aria-modal="true" aria-labelledby="reenrollmentTitle">
    <section class="modal-card">
      <header class="modal-head">
        <div><h2 id="reenrollmentTitle">Authorize client re-enrollment</h2><p id="reenrollmentSubtitle"></p></div>
        <button id="reenrollmentClose" class="secondary" type="button">Close</button>
      </header>
      <div class="modal-body">
        <form id="reenrollmentForm" class="modal-form">
          <input id="reenrollmentDeviceId" type="hidden">
          <input id="reenrollmentDeviceName" type="hidden">
          <div class="form-field"><label for="reenrollmentReason">Reason</label><textarea id="reenrollmentReason" maxlength="1024" required></textarea></div>
          <div class="warning-box">Your current authenticated Owner session authorizes this action. Authorization lasts 30 minutes and is single-use. For a Pending client with a lost local poll token, recovery requires the exact same RustDesk ID and device public key and does not require the old poll token. Denied, Blocked, and Revoked clients must still prove continuity with their previous DPAPI-protected poll token. Recovery never approves a client automatically.</div>
          <div id="reenrollmentError" class="error"></div>
          <div class="form-actions"><button id="reenrollmentCancel" class="secondary" type="button">Cancel</button><button id="reenrollmentSubmit" class="primary" type="submit">Authorize re-enrollment</button></div>
        </form>
      </div>
    </section>
  </div>

  <div id="toast" class="toast hidden" role="status"></div>

  <script>
    const BASE = "/ops/api";
    const loginView = document.getElementById("loginView");
    const dashboardView = document.getElementById("dashboardView");
    const loginForm = document.getElementById("loginForm");
    const loginButton = document.getElementById("loginButton");
    const loginError = document.getElementById("loginError");
    const statusFilter = document.getElementById("statusFilter");
    const eventFilter = document.getElementById("eventFilter");
    const auditSearch = document.getElementById("auditSearch");
    const deviceRows = document.getElementById("deviceRows");
    const deviceModal = document.getElementById("deviceModal");
    const deviceModalTitle = document.getElementById(
      "deviceModalTitle"
    );
    const deviceModalSubtitle = document.getElementById(
      "deviceModalSubtitle"
    );
    const deviceDetailGrid = document.getElementById(
      "deviceDetailGrid"
    );
    const deviceModalActions = document.getElementById(
      "deviceModalActions"
    );
    const deviceHistoryRows = document.getElementById(
      "deviceHistoryRows"
    );
    const deviceHistoryEmpty = document.getElementById(
      "deviceHistoryEmpty"
    );
    const deviceActiveConnections = document.getElementById(
      "deviceActiveConnections"
    );
    const deviceSessionRows = document.getElementById("deviceSessionRows");
    const deviceSessionEmpty = document.getElementById("deviceSessionEmpty");
    const deviceSessionNote = document.getElementById("deviceSessionNote");
    const blockedRevokedRows = document.getElementById(
      "blockedRevokedRows"
    );
    const blockedRevokedEmpty = document.getElementById(
      "blockedRevokedEmpty"
    );
    const operatorRows = document.getElementById("operatorRows");
    const operatorModal = document.getElementById("operatorModal");
    const operatorDetailGrid = document.getElementById("operatorDetailGrid");
    const operatorEmailEditor = document.getElementById("operatorEmailEditor");
    const operatorModalActions = document.getElementById("operatorModalActions");
    const operatorHistoryRows = document.getElementById("operatorHistoryRows");
    const operatorHistoryEmpty = document.getElementById("operatorHistoryEmpty");
    const operatorSessionRows = document.getElementById("operatorSessionRows");
    const operatorSessionEmpty = document.getElementById("operatorSessionEmpty");
    const invitePersonModal = document.getElementById(
      "invitePersonModal"
    );
    const roleChangeModal = document.getElementById(
      "roleChangeModal"
    );
    const accessResetModal = document.getElementById("accessResetModal");
    const reenrollmentModal = document.getElementById("reenrollmentModal");
    const auditRows = document.getElementById("auditRows");
    const deviceEmpty = document.getElementById("deviceEmpty");
    const operatorEmpty = document.getElementById("operatorEmpty");
    const auditEmpty = document.getElementById("auditEmpty");
    const toast = document.getElementById("toast");

    const ACTIVITY_TOUCH_INTERVAL_MS = 60 * 1000;
    const IDLE_TIMEOUT_MS = 8 * 60 * 60 * 1000;

    let refreshTimer = null;
    let liveIndicatorTimer = null;
    let idleTimer = null;
    let toastTimer = null;
    let refreshPromise = null;
    let idleLogoutInFlight = false;
    let lastHumanActivityAt = Date.now();
    let lastActivitySentAt = 0;
    let activityTouchInFlight = false;
    let currentOperator = null;
    let deviceItems = [];
    let operatorItems = [];
    let invitationItems = [];
    let roleChangeItems = [];
    let operationsState = null;
    let auditItems = [];
    let accessResetSelfService = false;

    function escapeHtml(value) {
      return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
    }

    function showToast(message, bad = false) {
      if (toastTimer) clearTimeout(toastTimer);
      toast.textContent = message;
      toast.className = bad ? "toast bad" : "toast";
      toast.classList.remove("hidden");
      toastTimer = setTimeout(
        () => toast.classList.add("hidden"),
        5000
      );
    }

    function showLogin(message = "") {
      dashboardView.classList.add("hidden");
      loginView.classList.remove("hidden");
      loginError.textContent = message;
      currentOperator = null;

      if (refreshTimer) clearInterval(refreshTimer);
      if (liveIndicatorTimer) clearInterval(liveIndicatorTimer);
      if (idleTimer) clearInterval(idleTimer);

      refreshTimer = null;
      liveIndicatorTimer = null;
      idleTimer = null;
    }

    function startIdleMonitoring() {
      lastHumanActivityAt = Date.now();

      if (!idleTimer) {
        idleTimer = setInterval(checkIdleTimeout, 60000);
      }
    }

    function showDashboard() {
      loginView.classList.add("hidden");
      dashboardView.classList.remove("hidden");
      startIdleMonitoring();

      if (!refreshTimer) {
        refreshTimer = setInterval(loadDashboard, 30000);
      }
      if (!liveIndicatorTimer) {
        liveIndicatorTimer = setInterval(refreshLiveIndicators, 10000);
      }
    }

    async function refreshSession() {
      if (!refreshPromise) {
        refreshPromise = (async () => {
          try {
            const response = await fetch(
              BASE + "/session/refresh",
              {
                method: "POST",
                credentials: "same-origin",
                cache: "no-store"
              }
            );

            let detail = "";

            if (!response.ok) {
              try {
                const body = await response.json();
                detail = body.detail || "";
              } catch {
                // Keep an empty server detail.
              }
            }

            return {
              ok: response.ok,
              status: response.status,
              detail
            };
          } catch {
            return {
              ok: false,
              status: 0,
              detail: "Unable to contact the server."
            };
          }
        })().finally(() => {
          refreshPromise = null;
        });
      }

      return refreshPromise;
    }

    async function request(path, options = {}, retry = true) {
      const response = await fetch(BASE + path, {
        credentials: "same-origin",
        cache: "no-store",
        headers: {
          "Content-Type": "application/json",
          ...(options.headers || {})
        },
        ...options
      });

      if (
        response.status === 401
        && retry
        && path !== "/session/refresh"
        && path !== "/login"
      ) {
        const refreshed = await refreshSession();

        if (refreshed.ok) {
          return request(path, options, false);
        }

        showLogin(
          refreshed.detail
          || "Your session expired. Sign in again."
        );
      }

      return response;
    }

    async function touchServerActivity() {
      if (
        activityTouchInFlight
        || dashboardView.classList.contains("hidden")
      ) {
        return;
      }

      activityTouchInFlight = true;

      try {
        const response = await request(
          "/activity",
          { method: "POST" }
        );

        if (!response.ok && response.status !== 401) {
          showToast(
            "Unable to update the activity timer.",
            true
          );
        }
      } finally {
        activityTouchInFlight = false;
      }
    }

    function recordHumanActivity() {
      if (dashboardView.classList.contains("hidden")) {
        return;
      }

      const now = Date.now();
      lastHumanActivityAt = now;

      if (
        now - lastActivitySentAt
        >= ACTIVITY_TOUCH_INTERVAL_MS
      ) {
        lastActivitySentAt = now;
        void touchServerActivity();
      }
    }

    async function performIdleLogout() {
      if (idleLogoutInFlight) return;

      idleLogoutInFlight = true;

      try {
        const response = await fetch(
          BASE + "/idle-logout",
          {
            method: "POST",
            credentials: "same-origin",
            cache: "no-store"
          }
        );

        if (!response.ok) {
          showToast(
            "The server did not confirm logout. Retrying...",
            true
          );
          setTimeout(performIdleLogout, 5000);
          return;
        }

        showLogin(
          "Signed out after 8 hours of inactivity."
        );
      } catch {
        showToast(
          "Unable to reach the server to complete logout. Retrying...",
          true
        );
        setTimeout(performIdleLogout, 5000);
      } finally {
        idleLogoutInFlight = false;
      }
    }

    function checkIdleTimeout() {
      if (
        dashboardView.classList.contains("hidden")
        || Date.now() - lastHumanActivityAt
          < IDLE_TIMEOUT_MS
      ) {
        return false;
      }

      void performIdleLogout();
      return true;
    }

    async function parseError(response) {
      try {
        const body = await response.json();
        return body.detail || "Request failed";
      } catch {
        return "Request failed";
      }
    }

    function formatDate(value) {
      if (!value) return "Never";
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return String(value);
      return date.toLocaleString();
    }

    function isRecent(value) {
      if (!value) return false;
      const timestamp = new Date(value).getTime();
      return (
        Number.isFinite(timestamp)
        && Date.now() - timestamp <= 45 * 1000
      );
    }

    function isLocked(value) {
      if (!value) return false;
      const timestamp = new Date(value).getTime();
      return Number.isFinite(timestamp) && timestamp > Date.now();
    }

    function countStatus(items, itemStatus) {
      return items.filter(
        item => item.status === itemStatus
      ).length;
    }

    function isOwner() {
      return currentOperator && currentOperator.role === "owner";
    }

    function canApproveDevices() {
      return currentOperator
        && ["owner", "manager"].includes(currentOperator.role);
    }

    function applyRoleVisibility() {
      const owner = isOwner();

      document.querySelectorAll(".owner-only").forEach(element => {
        element.classList.toggle("hidden-by-role", !owner);
      });

      if (!owner) {
        const activeTab = document.querySelector(".tab.active");
        if (activeTab && activeTab.dataset.tab !== "clients") {
          document.querySelector(
            '.tab[data-tab="clients"]'
          ).click();
        }
      }
    }

    function renderDeviceStats(summary, items) {
      const fallbackManaged = items.filter(
        item => ["approved", "pending"].includes(item.status)
      );
      const activeFallback = fallbackManaged.filter(
        item => item.status === "approved" && isRecent(item.last_seen_at)
      ).length;

      document.getElementById("totalCount").textContent =
        summary?.managed ?? fallbackManaged.length;
      document.getElementById("activeClientCount").textContent =
        summary?.active_clients ?? activeFallback;
      const pendingCount =
        summary?.pending ?? countStatus(fallbackManaged, "pending");
      const pendingElement = document.getElementById("pendingCount");
      pendingElement.textContent = pendingCount;
      pendingElement.classList.toggle(
        "pending-alert",
        Number(pendingCount) > 0
      );
      document.getElementById("activeSessionCount").textContent =
        summary?.active_sessions ?? 0;
    }

    function deviceActionButtons(device) {
      const deviceId = escapeHtml(device.id);
      const deviceName = escapeHtml(
        device.friendly_name
        || device.hostname
        || device.rustdesk_id
        || "Managed client"
      );
      const detailsButton =
        `<button class="small device-detail"
          data-id="${deviceId}" type="button">Details</button>`;

      if (!canApproveDevices()) return detailsButton;

      if (device.status === "pending") {
        return [
          `<button class="small good device-action"
            data-id="${deviceId}" data-name="${deviceName}"
            data-action="approve" type="button">Approve</button>`,
          `<button class="small danger device-action"
            data-id="${deviceId}" data-name="${deviceName}"
            data-action="deny" type="button">Deny</button>`,
          detailsButton
        ].join("");
      }

      return detailsButton;
    }


    function connectedToHtml(device) {
      const sessions = Array.isArray(device.active_connections)
        ? device.active_connections
        : [];
      if (!sessions.length) return `<span class="sub">-</span>`;
      return sessions.map(item => {
        const arrow = item.direction === "initiator" ? "→" : "←";
        const peer = item.peer_display_name || item.peer_rustdesk_id || "Unknown peer";
        const rid = item.peer_rustdesk_id && item.peer_display_name
          ? ` (${escapeHtml(item.peer_rustdesk_id)})`
          : "";
        const kind = item.session_type === "file_transfer" ? "File transfer" : "Desktop";
        return `<div class="connected-peer"><strong>${arrow} ${escapeHtml(peer)}${rid}</strong><div class="sub">${escapeHtml(kind)}</div></div>`;
      }).join("");
    }

    function renderDevices() {
      const selected = statusFilter.value;
      const managed = deviceItems.filter(
        item => ["approved", "pending"].includes(item.status)
      );
      const filtered = selected
        ? managed.filter(item => item.status === selected)
        : managed;

      deviceEmpty.classList.toggle(
        "hidden",
        filtered.length !== 0
      );

      deviceRows.innerHTML = filtered.map(device => {
        const name =
          device.friendly_name
          || device.hostname
          || "Unnamed client";
        const host =
          device.hostname && device.hostname !== name
            ? device.hostname
            : "";
        const recent = isRecent(device.last_seen_at);
        const statusName = escapeHtml(
          device.status || "unknown"
        );

        return `
          <tr>
            <td>
              <div class="name">${escapeHtml(name)}</div>
              <div class="sub">${escapeHtml(host)}</div>
            </td>
            <td>${escapeHtml(device.rustdesk_id || "-")}</td>
            <td>
              <span class="badge ${statusName}">
                ${statusName}
              </span>
              ${device.reenrollment_requested ? `
                <div class="sub" style="margin-top:6px">
                  Re-enrollment requested by client
                </div>` : ""}
            </td>
            <td>
              <span class="badge ${recent ? "online" : "offline"}">
                ${recent ? "Active" : "Inactive"}
              </span>
            </td>
            <td>${escapeHtml(device.last_ip || "-")}</td>
            <td>${escapeHtml(formatDate(device.last_seen_at))}</td>
            <td>
              <span class="badge ${
                device.has_active_credential
                  ? "approved"
                  : "offline"
              }">
                ${
                  device.has_active_credential
                    ? "Active"
                    : "None"
                }
              </span>
            </td>
            <td>
              <div class="row-actions">
                ${deviceActionButtons(device)}
              </div>
            </td>
            <td>${connectedToHtml(device)}</td>
          </tr>`;
      }).join("");
    }

    function renderBlockedRevokedDevices() {
      const items = deviceItems.filter(
        item => ["blocked", "revoked"].includes(item.status)
      );
      blockedRevokedEmpty.classList.toggle("hidden", items.length !== 0);
      blockedRevokedRows.innerHTML = items.map(device => {
        const name = device.friendly_name || device.hostname || "Unnamed client";
        const host = device.hostname && device.hostname !== name ? device.hostname : "";
        const id = escapeHtml(device.id);
        const safeName = escapeHtml(name);
        const statusName = String(device.status || "blocked").toLowerCase();
        const action = isOwner()
          ? `<button class="small danger device-action"
               data-id="${id}" data-name="${safeName}"
               data-action="delete" type="button">Delete</button>`
          : `<span class="sub">Owner only</span>`;
        return `
          <tr>
            <td><div class="name">${safeName}</div><div class="sub">${escapeHtml(host)}</div><div class="sub">Device ${id}</div></td>
            <td>${escapeHtml(device.rustdesk_id || "-")}</td>
            <td><span class="badge ${escapeHtml(statusName)}">${escapeHtml(statusName)}</span></td>
            <td>${escapeHtml(device.last_ip || "-")}</td>
            <td>${escapeHtml(formatDate(device.last_seen_at))}</td>
            <td>${escapeHtml(formatDate(device.status_changed_at))}</td>
            <td>${escapeHtml(device.status_reason || "-")}</td>
            <td><div class="row-actions">${action}</div></td>
          </tr>`;
      }).join("");
    }


    function closeDeviceModal() {
      deviceModal.classList.add("hidden");
      document.body.classList.remove("modal-open");
      deviceModalActions.innerHTML = "";
      deviceActiveConnections.innerHTML = "";
      deviceSessionRows.innerHTML = "";
      deviceSessionNote.textContent = "";
    }

    function modalActionButtons(device) {
      const name = escapeHtml(
        device.friendly_name
        || device.hostname
        || device.rustdesk_id
        || "Managed client"
      );
      const id = escapeHtml(device.id);
      const buttons = [];

      if (!canApproveDevices()) {
        return `<span class="sub">Read-only access</span>`;
      }

      if (device.status === "pending") {
        buttons.push(
          `<button class="small good device-action"
            data-id="${id}" data-name="${name}"
            data-action="approve" type="button">Approve client</button>`,
          `<button class="small danger device-action"
            data-id="${id}" data-name="${name}"
            data-action="deny" type="button">Deny enrollment</button>`
        );
        if (isOwner()) {
          buttons.push(
            `<button class="small good device-reenroll"
              data-id="${id}" data-name="${name}"
              type="button">Recover enrollment</button>`
          );
        }
      } else if (device.status === "approved") {
        buttons.push(
          `<button class="small danger device-action"
            data-id="${id}" data-name="${name}"
            data-action="block" type="button">Block client</button>`
        );
      } else if (device.status === "denied") {
        buttons.push(`<span class="badge denied">denied</span>`);
        if (isOwner()) {
          buttons.push(
            `<button class="small good device-reenroll"
              data-id="${id}" data-name="${name}"
              type="button">Authorize re-enrollment</button>`
          );
        }
      } else if (["blocked", "revoked"].includes(device.status)) {
        if (isOwner()) {
          buttons.push(
            `<button class="small danger device-action"
              data-id="${id}" data-name="${name}"
              data-action="delete" type="button">Delete</button>`
          );
        } else {
          buttons.push(`<span class="sub">Owner-only deletion</span>`);
        }
      } else {
        buttons.push(`<span class="sub">No management action is currently available.</span>`);
      }

      return buttons.join("");
    }


    function renderDeviceDetail(result) {
      const device = result.device || {};
      const history = result.status_history || [];
      const activeConnections = result.active_connections || [];
      const sessionHistory = result.session_history || [];
      const name =
        device.friendly_name
        || device.hostname
        || device.rustdesk_id
        || "Managed client";

      deviceModalTitle.textContent = name;
      deviceModalSubtitle.textContent =
        `RustDesk ID ${device.rustdesk_id || "-"}`;

      const details = [
        ["Hostname", device.hostname || "-"],
        ["Friendly name", device.friendly_name || "-"],
        ["Email address", device.contact_email || "-"],
        ["Status", device.status || "unknown"],
        ["Status reason", device.status_reason || "-"],
        ["Last IP", device.last_ip || "-"],
        ["Last seen", formatDate(device.last_seen_at)],
        ["Created", formatDate(device.created_at)],
        [
          "Credential",
          device.has_active_credential ? "Active" : "None"
        ],
        [
          "Re-enrollment request",
          ["blocked", "revoked"].includes(device.status) ? `Not allowed (${device.status})` : (device.reenrollment_requested ? "Requested by client" : "None")
        ],
        ["Device ID", device.id || "-"]
      ];

      deviceDetailGrid.innerHTML = details.map(([label, value]) => `
        <div class="detail-item">
          <div class="detail-label">${escapeHtml(label)}</div>
          <div class="detail-value">${escapeHtml(value)}</div>
        </div>
      `).join("");

      deviceModalActions.innerHTML = modalActionButtons(device);

      deviceActiveConnections.innerHTML = activeConnections.length
        ? activeConnections.map(item => {
            const direction = item.direction === "initiator" ? "Outbound" : "Inbound";
            const peer = item.peer_display_name || item.peer_rustdesk_id || "Unknown peer";
            const kind = item.session_type === "file_transfer" ? "File transfer" : "Remote desktop";
            return `<div class="detail-item"><div class="detail-label">${escapeHtml(direction)} ${escapeHtml(kind)}</div><div class="detail-value">${escapeHtml(peer)}${item.peer_rustdesk_id && item.peer_display_name ? ` (${escapeHtml(item.peer_rustdesk_id)})` : ""}<div class="sub">Established ${escapeHtml(formatDate(item.started_at))} • Last heartbeat ${escapeHtml(formatDate(item.last_heartbeat_at))}</div></div></div>`;
          }).join("")
        : `<div class="detail-item"><div class="detail-label">Current connection</div><div class="detail-value">None</div></div>`;

      const stateLabels = {
        "connection.initiated": "Requested",
        "connection.established": "Established",
        "connection.rejected": "Rejected",
        "connection.denied": "Denied",
        "connection.ended": "Disconnected"
      };
      deviceSessionNote.textContent = result.session_history_note || "";
      deviceSessionEmpty.classList.toggle("hidden", sessionHistory.length !== 0);
      deviceSessionRows.innerHTML = sessionHistory.map(item => {
        const details = item.details || {};
        const peer = item.peer_display_name || item.peer_rustdesk_id || "-";
        const direction = item.direction === "initiator" ? "Outbound" : item.direction === "receiver" ? "Inbound" : "-";
        const kind = item.session_type === "file_transfer" ? "File transfer" : item.session_type === "remote_desktop" ? "Remote desktop" : "-";
        return `<tr><td>${escapeHtml(formatDate(item.occurred_at))}</td><td>${escapeHtml(stateLabels[item.event_type] || item.event_type || "-")}</td><td>${escapeHtml(direction)}</td><td>${escapeHtml(peer)}${item.peer_rustdesk_id && item.peer_display_name ? `<div class="sub">${escapeHtml(item.peer_rustdesk_id)}</div>` : ""}</td><td>${escapeHtml(kind)}</td><td>${escapeHtml(details.reason || "-")}</td></tr>`;
      }).join("");

      deviceHistoryEmpty.classList.toggle(
        "hidden",
        history.length !== 0
      );
      deviceHistoryRows.innerHTML = history.map(item => `
        <tr>
          <td>${escapeHtml(formatDate(item.changed_at))}</td>
          <td>${escapeHtml(item.from_status || "-")}</td>
          <td>${escapeHtml(item.to_status || "-")}</td>
          <td>${escapeHtml(item.reason || "-")}</td>
          <td>${escapeHtml(item.changed_by || "System")}</td>
        </tr>
      `).join("");
    }

    async function showDeviceDetail(deviceId) {
      deviceModalTitle.textContent = "Managed client";
      deviceModalSubtitle.textContent = "Loading device details";
      deviceDetailGrid.innerHTML = "";
      deviceModalActions.innerHTML = "";
      deviceHistoryRows.innerHTML = "";
      deviceHistoryEmpty.classList.add("hidden");
      deviceActiveConnections.innerHTML = "";
      deviceSessionRows.innerHTML = "";
      deviceSessionEmpty.classList.add("hidden");
      deviceSessionNote.textContent = "";
      deviceModal.classList.remove("hidden");
      document.body.classList.add("modal-open");

      const response = await request(
        `/devices/${encodeURIComponent(deviceId)}`
      );

      if (!response.ok) {
        closeDeviceModal();
        showToast(await parseError(response), true);
        return;
      }

      renderDeviceDetail(await response.json());
    }

    async function runDeviceAction(
      deviceId,
      deviceName,
      action
    ) {
      const actionLabels = {
        approve: "approve",
        deny: "deny",
        block: "block",
        revoke: "revoke the credential for",
        delete: "permanently delete"
      };
      const label = actionLabels[action] || action;

      if (!window.confirm(
        `Are you sure you want to ${label} ${deviceName}?`
      )) {
        return;
      }

      let friendlyName = null;
      let reason = "";

      if (action === "approve") {
        friendlyName = window.prompt(
          "Friendly name for this client:",
          deviceName
        );
        if (friendlyName === null) return;

        reason = window.prompt(
          "Approval reason (optional):",
          "Approved from Owner dashboard"
        );
        if (reason === null) return;
      } else {
        reason = window.prompt(
          `Reason to ${label} ${deviceName}:`,
          `Owner dashboard: ${label} ${deviceName}`
        );
        if (reason === null) return;
        if (!reason.trim()) {
          showToast("A reason is required.", true);
          return;
        }
      }

      const payload = { reason: reason.trim() };
      if (action === "approve") {
        payload.friendly_name = friendlyName.trim();
      }
      if (action === "delete") {
        const confirmation = window.prompt(
          `Type DELETE to permanently remove ${deviceName}. The managed identity and live dependent state will be deleted; an audit archive is retained.`,
          ""
        );
        if (confirmation !== "DELETE") {
          if (confirmation !== null) {
            showToast("Deletion cancelled because DELETE was not entered exactly.", true);
          }
          return;
        }
      }

      const response = await request(
        `/devices/${encodeURIComponent(deviceId)}/${
          encodeURIComponent(action)
        }`,
        {
          method: "POST",
          body: JSON.stringify(payload)
        }
      );

      if (!response.ok) {
        showToast(await parseError(response), true);
        return;
      }

      closeDeviceModal();
      showToast(
        `${deviceName}: ${action} completed successfully.`
      );
      await loadDashboard();
    }

    function isProtectedBradAccount(account) {
      return String(account?.username || "").trim().toLowerCase() === "brad";
    }

    function roleSelect(account, current) {
      const bradProtected = isProtectedBradAccount(account);
      if (bradProtected) {
        return `<span class="badge owner">Owner</span><div class="sub">Brad role is permanently protected as Owner.</div>`;
      }
      const disabled = (
        current
        || !account.is_active
      );
      const options = ["owner", "manager", "viewer"]
        .map(role => `
          <option
            value="${role}"
            ${account.role === role ? "selected" : ""}
          >${role[0].toUpperCase() + role.slice(1)}</option>
        `).join("");

      return `
        <select
          class="control-select operator-role-control"
          data-id="${escapeHtml(account.id)}"
          data-name="${escapeHtml(account.username)}"
          data-current-role="${escapeHtml(account.role)}"
          ${disabled ? "disabled" : ""}
          aria-label="Permission for ${escapeHtml(account.username)}"
        >${options}</select>
      `;
    }

    function statusControl(account, current) {
      const bradProtected = isProtectedBradAccount(account);
      const protectedAccount = (
        current || account.role === "owner" || bradProtected
      );

      return `
        <button
          class="status-control ${
            account.is_active ? "active" : "disabled"
          } operator-status-control"
          data-id="${escapeHtml(account.id)}"
          data-name="${escapeHtml(account.username)}"
          data-active="${account.is_active ? "true" : "false"}"
          type="button"
          ${protectedAccount ? "disabled" : ""}
          title="${
            bradProtected
              ? "Brad role/status is permanently protected"
              : protectedAccount
                ? "Owner and current-account status is protected"
                : "Click to change account status"
          }"
        >${account.is_active ? "Active" : "Disabled"}</button>
      `;
    }

    function renderOperators() {
      const managers = operatorItems;
      const pendingInvites = isOwner()
        ? invitationItems.filter(item => item.status === "pending")
        : [];
      operatorEmpty.classList.toggle(
        "hidden",
        managers.length + pendingInvites.length !== 0
      );

      const managerRows = managers.map(account => {
        const current = currentOperator
          && String(currentOperator.id) === String(account.id);
        const activeSessions = Number(account.active_session_count || 0);
        const pendingChange = isOwner() ? roleChangeItems.find(
          item => item.status === "pending"
            && String(item.target_account_id) === String(account.id)
        ) : null;
        const plainRole = `<span class="badge ${escapeHtml(account.role)}">${escapeHtml((account.role || "unknown").replace(/^./, c => c.toUpperCase()))}</span>`;
        const roleCell = !isOwner()
          ? plainRole
          : pendingChange
            ? `${roleSelect(account, current)}
               <div class="sub">Pending → ${escapeHtml(pendingChange.requested_role)}</div>
               <div class="action-row" style="margin-top:6px">
                 <button class="small good role-request-action"
                   data-id="${escapeHtml(pendingChange.id)}"
                   data-name="${escapeHtml(account.username)}"
                   data-action="complete" type="button">Complete</button>
                 <button class="small danger role-request-action"
                   data-id="${escapeHtml(pendingChange.id)}"
                   data-name="${escapeHtml(account.username)}"
                   data-action="cancel" type="button">Cancel</button>
               </div>`
            : roleSelect(account, current);
        const statusCell = isOwner()
          ? statusControl(account, current)
          : `<span class="badge ${account.is_active ? "active" : "disabled"}">${account.is_active ? "Active" : "Disabled"}</span>`;

        return `
          <tr>
            <td><div class="name">${escapeHtml(account.display_name || account.username)}</div><div class="sub">${escapeHtml(account.username)}</div>${account.email ? `<div class="sub">${escapeHtml(account.email)}</div>` : ""}</td>
            <td><span class="${["owner", "manager"].includes(account.role) ? "approval-yes" : "approval-no"}">${["owner", "manager"].includes(account.role) ? "Yes" : "No"}</span></td>
            <td>${roleCell}</td>
            <td>${statusCell}</td>
            <td><span class="badge ${account.totp_enabled ? "active" : "failed"}">${account.totp_enabled ? "TOTP" : "Not enabled"}</span></td>
            <td>${escapeHtml(activeSessions)}</td>
            <td>${escapeHtml(formatDate(account.last_login_at))}<div class="sub">${escapeHtml(account.last_login_ip || "-")}</div></td>
            <td><button class="small operator-detail" data-id="${escapeHtml(account.id)}" type="button">Details</button></td>
          </tr>`;
      });

      const inviteRows = pendingInvites.map(invitation => {
        const requestedRole = String(invitation.requested_role || "manager");
        const canApprove = ["owner", "manager"].includes(requestedRole);
        return `
        <tr>
          <td><div class="name">${escapeHtml(invitation.proposed_display_name || invitation.proposed_username)}</div><div class="sub">${escapeHtml(invitation.proposed_username)}</div></td>
          <td><span class="${canApprove ? "approval-yes" : "approval-no"}">${canApprove ? "Yes" : "No"}</span></td>
          <td><span class="badge ${escapeHtml(requestedRole)}">${escapeHtml(requestedRole[0]?.toUpperCase() + requestedRole.slice(1))}</span></td>
          <td><span class="badge pending">Invitation pending</span><div class="sub">Expires ${escapeHtml(formatDate(invitation.expires_at))}</div></td>
          <td>-</td><td>-</td>
          <td>${escapeHtml(formatDate(invitation.created_at))}<div class="sub">by ${escapeHtml(invitation.created_by_username || "-")}</div></td>
          <td><button class="small danger invitation-action" data-id="${escapeHtml(invitation.id)}" data-name="${escapeHtml(invitation.proposed_username)}" type="button">Revoke Invitation</button></td>
        </tr>`;
      });

      operatorRows.innerHTML = managerRows.concat(inviteRows).join("");
    }


    function closeOperatorModal() {
      operatorModal.classList.add("hidden");
      document.body.classList.remove("modal-open");
      operatorDetailGrid.innerHTML = "";
      operatorEmailEditor.innerHTML = "";
      operatorModalActions.innerHTML = "";
      operatorHistoryRows.innerHTML = "";
      operatorSessionRows.innerHTML = "";
    }

    function managerEventLabel(eventType) {
      const labels = {
        "operator.login_succeeded": "Logged in",
        "operator.login_failed": "Login failed",
        "operator.logout": "Logged out",
        "operator.session_refreshed": "Session refreshed",
        "operator.sessions_revoked": "Sessions revoked",
        "operator.access_reset_created": "Owner recovery created",
        "operator.self_access_reset_created": "Self-service access change created",
        "operator.access_reset_completed": "Access change completed",
        "operator.email_changed": "Email changed",
        "operator.enabled": "Account enabled",
        "operator.disabled": "Account disabled",
        "operator.deleted": "Account deleted",
        "operator.protected_lifecycle_change_blocked": "Protected status change blocked",
        "operator.unlocked": "Account unlocked",
        "operator.role_change_completed": "Role changed"
      };
      return labels[eventType] || eventType || "Event";
    }

    function operatorSessionState(item) {
      if (item.revoked_at) {
        return `Revoked${item.revocation_reason ? ` — ${item.revocation_reason}` : ""}`;
      }
      if (item.expires_at && new Date(item.expires_at).getTime() <= Date.now()) {
        return "Expired";
      }
      return "Active";
    }

    function renderOperatorDetail(result) {
      const account = result.account || {};
      const sessions = result.sessions || [];
      const history = result.activity_history || [];
      const current = currentOperator
        && String(currentOperator.id) === String(account.id);
      const canEditEmail = current || isOwner();

      document.getElementById("operatorModalTitle").textContent =
        account.display_name || account.username || "Client Manager";
      document.getElementById("operatorModalSubtitle").textContent =
        `${account.username || "-"} — ${account.role || "unknown"}`;

      const details = [
        ["Email address", account.email || "-"],
        ["Role", account.role || "-"],
        ["Status", account.is_active ? "Active" : "Disabled"],
        ["Authenticator", account.totp_enabled ? "TOTP enabled" : "Not enabled"],
        ["Active login sessions", account.active_session_count ?? 0],
        ["Last login", formatDate(account.last_login_at)],
        ["Last login IP", account.last_login_ip || "-"],
        ["Password changed", formatDate(account.password_changed_at)],
        ["Authenticator confirmed", formatDate(account.totp_confirmed_at)],
        ["Created", formatDate(account.created_at)],
        ["Created by", account.created_by_username || "Bootstrap / system"],
        ["Locked until", formatDate(account.locked_until)],
        ["Account ID", account.id || "-"]
      ];
      operatorDetailGrid.innerHTML = details.map(([label, value]) => `
        <div class="detail-item"><div class="detail-label">${escapeHtml(label)}</div><div class="detail-value">${escapeHtml(value)}</div></div>
      `).join("");

      operatorEmailEditor.innerHTML = canEditEmail ? `
        <div class="detail-item manager-email-editor">
          <div class="detail-label">Edit Manager email</div>
          <div class="detail-value">
            <input id="operatorEmailInput" type="email" maxlength="320" autocomplete="email" value="${escapeHtml(account.email || "")}" placeholder="manager@example.com">
            <button class="small operator-email-save" data-id="${escapeHtml(account.id || "")}" type="button">Save email</button>
          </div>
        </div>` : "";

      const actions = [];
      if (current) {
        actions.push(
          `<button class="small operator-access-change" data-id="${escapeHtml(account.id)}" data-name="${escapeHtml(account.username)}" data-display-name="${escapeHtml(account.display_name || account.username)}" data-mode="password_only" data-self="true" type="button">Change password</button>`,
          `<button class="small operator-access-change" data-id="${escapeHtml(account.id)}" data-name="${escapeHtml(account.username)}" data-display-name="${escapeHtml(account.display_name || account.username)}" data-mode="totp_only" data-self="true" type="button">Replace authenticator</button>`,
          `<button class="small operator-access-change" data-id="${escapeHtml(account.id)}" data-name="${escapeHtml(account.username)}" data-display-name="${escapeHtml(account.display_name || account.username)}" data-mode="password_totp" data-self="true" type="button">Change password + authenticator</button>`
        );
      } else if (isOwner()) {
        actions.push(
          `<button class="small operator-access-change" data-id="${escapeHtml(account.id)}" data-name="${escapeHtml(account.username)}" data-display-name="${escapeHtml(account.display_name || account.username)}" data-mode="password_only" data-self="false" type="button">Recover password</button>`,
          `<button class="small operator-access-change" data-id="${escapeHtml(account.id)}" data-name="${escapeHtml(account.username)}" data-display-name="${escapeHtml(account.display_name || account.username)}" data-mode="totp_only" data-self="false" type="button">Recover authenticator</button>`,
          `<button class="small operator-access-change" data-id="${escapeHtml(account.id)}" data-name="${escapeHtml(account.username)}" data-display-name="${escapeHtml(account.display_name || account.username)}" data-mode="password_totp" data-self="false" type="button">Recover both</button>`
        );
        if (Number(account.active_session_count || 0) > 0) {
          actions.push(`<button class="small danger operator-detail-action" data-id="${escapeHtml(account.id)}" data-name="${escapeHtml(account.username)}" data-action="revoke-sessions" type="button">Revoke active sessions</button>`);
        }
        if (isProtectedBradAccount(account)) {
          actions.push(`<span class="sub">Brad account role and status are permanently protected.</span>`);
        } else if (account.role === "owner") {
          actions.push(`<span class="sub">Owner account lifecycle is protected.</span>`);
        } else if (account.is_active) {
          actions.push(`<button class="small danger operator-detail-action" data-id="${escapeHtml(account.id)}" data-name="${escapeHtml(account.username)}" data-action="disable" type="button">Disable account</button>`);
        } else {
          actions.push(
            `<button class="small good operator-detail-action" data-id="${escapeHtml(account.id)}" data-name="${escapeHtml(account.username)}" data-action="enable" type="button">Enable account</button>`,
            `<button class="small danger operator-detail-action" data-id="${escapeHtml(account.id)}" data-name="${escapeHtml(account.username)}" data-action="delete" type="button">Delete account</button>`
          );
        }
      }
      operatorModalActions.innerHTML = actions.join("");

      operatorHistoryEmpty.classList.toggle("hidden", history.length !== 0);
      operatorHistoryRows.innerHTML = history.map(item => `
        <tr><td>${escapeHtml(formatDate(item.created_at))}</td><td>${escapeHtml(managerEventLabel(item.event_type))}</td><td>${escapeHtml(item.actor_username || "System")}</td><td>${escapeHtml(item.source_ip || "-")}</td><td><pre class="audit-details">${escapeHtml(formatDetails(item.details))}</pre></td></tr>
      `).join("");

      operatorSessionEmpty.classList.toggle("hidden", sessions.length !== 0);
      operatorSessionRows.innerHTML = sessions.map(item => `
        <tr><td>${escapeHtml(formatDate(item.created_at))}</td><td>${escapeHtml(formatDate(item.last_seen_at))}</td><td>${escapeHtml(formatDate(item.expires_at))}</td><td>${escapeHtml(operatorSessionState(item))}</td><td>${escapeHtml(item.source_ip || "-")}</td></tr>
      `).join("");
    }

    async function showOperatorDetail(accountId) {
      operatorModal.classList.remove("hidden");
      document.body.classList.add("modal-open");
      document.getElementById("operatorModalTitle").textContent = "Client Manager";
      document.getElementById("operatorModalSubtitle").textContent = "Loading Manager details";
      operatorDetailGrid.innerHTML = "";
      operatorEmailEditor.innerHTML = "";
      operatorModalActions.innerHTML = "";
      operatorHistoryRows.innerHTML = "";
      operatorSessionRows.innerHTML = "";
      const response = await request(`/operators/${encodeURIComponent(accountId)}`);
      if (!response.ok) {
        closeOperatorModal();
        showToast(await parseError(response), true);
        return;
      }
      renderOperatorDetail(await response.json());
    }

    async function saveOperatorEmail(accountId) {
      const input = document.getElementById("operatorEmailInput");
      const button = operatorEmailEditor.querySelector(".operator-email-save");
      if (!input || !button) return;
      const email = input.value.trim();
      if (email && !input.checkValidity()) {
        showToast("Enter a valid email address or leave it blank.", true);
        input.focus();
        return;
      }
      button.disabled = true;
      try {
        const response = await request(`/operators/${encodeURIComponent(accountId)}/email`, {
          method: "PUT",
          body: JSON.stringify({email})
        });
        if (!response.ok) {
          showToast(await parseError(response), true);
          return;
        }
        showToast(email ? "Manager email saved." : "Manager email cleared.");
        await loadDashboard();
        await showOperatorDetail(accountId);
      } finally {
        button.disabled = false;
      }
    }


    function formatDetails(details) {
      if (
        details === null
        || details === undefined
        || details === ""
      ) {
        return "-";
      }
      if (typeof details === "string") return details;
      try {
        return JSON.stringify(details, null, 2);
      } catch {
        return String(details);
      }
    }

    function updateEventOptions(items) {
      const selected = eventFilter.value;
      const eventTypes = [
        ...new Set(
          items.map(item => item.event_type).filter(Boolean)
        )
      ].sort();

      eventFilter.innerHTML =
        `<option value="">All event types</option>`
        + eventTypes.map(eventType =>
          `<option value="${escapeHtml(eventType)}">
             ${escapeHtml(eventType)}
           </option>`
        ).join("");

      if (eventTypes.includes(selected)) {
        eventFilter.value = selected;
      }
    }

    function activityEventLabel(eventType) {
      const labels = {
        "client.active": "Client Active",
        "client.inactive": "Client Inactive",
        "connection.initiated": "Connection Initiated",
        "connection.established": "Connection Established",
        "connection.rejected": "Connection Rejected",
        "connection.denied": "Connection Denied",
        "connection.ended": "Connection Ended",
        "device.deleted": "Client Deleted"
      };
      return labels[eventType] || eventType || "Event";
    }

    function renderActivity() {
      const selected = eventFilter.value;
      const search = auditSearch.value.trim().toLowerCase();

      const filtered = auditItems.filter(event => {
        if (selected && event.event_type !== selected) {
          return false;
        }
        if (!search) return true;

        const haystack = [
          event.event_type,
          event.actor_username,
          event.actor_display_name,
          event.target_type,
          event.target_id,
          event.target_username,
          event.target_device_name,
          event.source_ip,
          formatDetails(event.details)
        ].join(" ").toLowerCase();

        return haystack.includes(search);
      });

      auditEmpty.classList.toggle(
        "hidden",
        filtered.length !== 0
      );

      auditRows.innerHTML = filtered.map(event => {
        const actor =
          event.actor_display_name
          || event.actor_username
          || "System";
        const actorSub =
          event.actor_username
          && event.actor_display_name
          && event.actor_username !== event.actor_display_name
            ? event.actor_username
            : "";
        const target =
          event.target_username
          || event.target_device_name
          || event.target_type
          || "-";
        const targetSub =
          event.target_id
            ? `${event.target_type || "target"} · ${event.target_id}`
            : "";

        return `
          <tr>
            <td>${escapeHtml(formatDate(event.created_at))}</td>
            <td>
              <span class="badge">
                ${escapeHtml(activityEventLabel(event.event_type))}
              </span>
            </td>
            <td>
              <div class="name">${escapeHtml(actor)}</div>
              <div class="sub">${escapeHtml(actorSub)}</div>
            </td>
            <td>
              <div class="name">${escapeHtml(target)}</div>
              <div class="sub">${escapeHtml(targetSub)}</div>
            </td>
            <td>${escapeHtml(event.source_ip || "-")}</td>
            <td>
              <div class="details">${escapeHtml(
                formatDetails(event.details)
              )}</div>
            </td>
          </tr>`;
      }).join("");
    }

    function ageText(seconds) {
      const value = Number(seconds);
      if (!Number.isFinite(value) || value < 0) return "-";
      if (value < 120) return `${Math.round(value)} sec`;
      if (value < 7200) return `${Math.round(value / 60)} min`;
      if (value < 172800) return `${Math.round(value / 3600)} hr`;
      return `${Math.round(value / 86400)} days`;
    }

    function renderOperations() {
      const state = operationsState || {};
      const services = state.services || {};
      const backup = state.backup || {};
      const restore = state.restore_verification || {};
      const tls = state.tls || {};
      const clientTls = state.client_tls || {};
      const disk = state.disk || {};
      const rustdesk = state.rustdesk || {};

      const apiOk = services.directory_api === "ok";
      const dbOk = ["healthy", "running"].includes(
        services.database
      );
      const relayEnforced = services.relay_guard === "enforced";
      const relayStaged = services.relay_guard === "staged";
      const restoreOk = restore.status === "ok";
      const backupAge = Number(backup.age_seconds);
      const backupOk = Number.isFinite(backupAge)
        && backupAge < 48 * 3600;
      const tlsDays = Number(tls.days_remaining);
      const tlsOk = Number.isFinite(tlsDays) && tlsDays >= 14;
      const clientTlsDays = Number(clientTls.days_remaining);
      const clientTlsOk = Number.isFinite(clientTlsDays) && clientTlsDays >= 14;
      const diskPct = Number(disk.free_percent);
      const diskOk = Number.isFinite(diskPct) && diskPct >= 10;
      const pinned = Boolean(rustdesk.image_pinned);

      document.getElementById("opsApi").textContent =
        apiOk ? "OK" : (services.directory_api || "Unknown");
      document.getElementById("opsDatabase").textContent =
        dbOk ? "OK" : (services.database || "Unknown");
      document.getElementById("opsRelay").textContent =
        relayEnforced ? "ENFORCED" : relayStaged ? "STAGED" : (services.relay_guard || "Unknown").toUpperCase();
      document.getElementById("opsBackup").textContent =
        backup.path ? ageText(backup.age_seconds) : "None";
      document.getElementById("opsRestore").textContent =
        restoreOk ? "Verified" : (restore.status || "Unknown");
      document.getElementById("opsTls").textContent =
        Number.isFinite(tlsDays) ? `${tlsDays} days` : "Unknown";
      document.getElementById("opsClientTls").textContent =
        Number.isFinite(clientTlsDays) ? `${clientTlsDays} days` : "Unknown";
      document.getElementById("opsDisk").textContent =
        Number.isFinite(diskPct) ? `${diskPct.toFixed(1)}%` : "Unknown";
      document.getElementById("opsRustDesk").textContent =
        rustdesk.hbbs_version || "Unknown";

      const overallOk = (
        apiOk && dbOk && relayEnforced && backupOk
        && restoreOk && tlsOk && clientTlsOk && diskOk && pinned
      );
      const badge = document.getElementById("opsOverallBadge");
      badge.textContent = overallOk ? "HEALTHY" : "ATTENTION";
      badge.className = `badge ${overallOk ? "active" : "pending"}`;

      const details = [];
      details.push(
        `Status generated: ${formatDate(state.generated_at)}`
      );
      details.push(`Relay Guard: ${relayEnforced ? "ENFORCED" : relayStaged ? "STAGED — enforcement not yet enabled" : (services.relay_guard || "Unknown")}`);
      if (backup.path) {
        details.push(
          `Latest daily backup: ${backup.path} (${ageText(backup.age_seconds)} old)`
        );
      }
      if (restore.last_verified_at) {
        details.push(
          `Last restore verification: ${formatDate(restore.last_verified_at)}`
        );
      }
      details.push(
        `Image pin: ${pinned ? "Pinned to immutable digest" : "NOT PINNED"}`
      );
      if (rustdesk.image_reference) {
        details.push(`Image: ${rustdesk.image_reference}`);
      }
      if (tls.not_after) {
        details.push(`${tls.purpose || "Directory HTTPS TLS"}: ${tls.hostname || "origin"} expires ${tls.not_after}`);
      }
      if (tls.issuer) details.push(`Origin TLS issuer: ${tls.issuer}`);
      if (tls.subject) details.push(`Origin TLS subject: ${tls.subject}`);
      if (clientTls.not_after) {
        details.push(`${clientTls.purpose || "Client API HTTPS"}: ${clientTls.hostname || "client"} expires ${clientTls.not_after}`);
      }
      if (clientTls.issuer) details.push(`Client API TLS issuer: ${clientTls.issuer}`);
      if (clientTls.subject) details.push(`Client API TLS subject: ${clientTls.subject}`);
      document.getElementById("opsDetail").textContent =
        details.join(" • ");

      const upstream = state.upstream || {};
      const assessment = String(upstream.assessment || "Unavailable");
      document.getElementById("upstreamRef").textContent =
        upstream.latest_release || upstream.upstream_ref || "Unknown";
      document.getElementById("upstreamCommits").textContent =
        Number.isFinite(Number(upstream.new_commits))
          ? String(Number(upstream.new_commits))
          : "Unknown";
      const cleanCount = Number(upstream.patch_clean_count);
      const reviewCount = Number(upstream.patch_review_count);
      document.getElementById("upstreamPatchCheck").textContent =
        Number.isFinite(cleanCount) && Number.isFinite(reviewCount)
          ? `${cleanCount} clean / ${reviewCount} review`
          : "Unknown";
      document.getElementById("upstreamBase").textContent =
        upstream.base_commit ? String(upstream.base_commit).slice(0, 10) : "Unknown";
      const upstreamBadge = document.getElementById("upstreamBadge");
      upstreamBadge.textContent = assessment.toUpperCase();
      upstreamBadge.className = `badge ${
        assessment.toLowerCase().includes("no action")
          ? "active"
          : assessment.toLowerCase().includes("rebuild")
            ? "blocked"
            : "pending"
      }`;
      const upstreamReasons = Array.isArray(upstream.reasons)
        ? upstream.reasons.join(" • ")
        : (upstream.detail || "No upstream assessment detail.");
      document.getElementById("upstreamDetail").textContent =
        upstreamReasons;

    }

    function renderCriticalHealth(state) {
      const services = state?.services || {};
      const stale = Boolean(state?.stale);
      const checked = state?.generated_at ? formatDate(state.generated_at) : "Never";
      document.querySelectorAll("[data-health]").forEach(pill => {
        const key = pill.dataset.health;
        const item = services[key] || {};
        let serviceStatus = stale ? "unknown" : String(item.status || "unknown");
        if (!['healthy','degraded','down','unknown'].includes(serviceStatus)) {
          serviceStatus = "unknown";
        }
        if (key === "relay_guard") {
          const label = pill.querySelector("span:last-child");
          if (label) {
            label.textContent = serviceStatus === "healthy"
              ? "Relay Guard: ENFORCED"
              : serviceStatus === "degraded" && String(item.detail || "").includes("STAGED")
                ? "Relay Guard: STAGED"
                : serviceStatus === "down"
                  ? "Relay Guard: INACTIVE"
                  : "Relay Guard";
          }
        }
        const dot = pill.querySelector(".dot");
        dot.className = `dot ${
          serviceStatus === "healthy" ? "good"
          : serviceStatus === "degraded" ? "warn"
          : serviceStatus === "down" ? "bad"
          : "unknown"
        }`;
        pill.title = `${pill.textContent.trim()}: ${serviceStatus}${
          item.detail ? ` — ${item.detail}` : ""
        }. Last health check: ${checked}${stale ? " (stale)" : ""}`;
      });
    }

    async function refreshLiveIndicators() {
      if (dashboardView.classList.contains("hidden")) return;
      const [summaryResponse, healthResponse] = await Promise.all([
        request("/summary"),
        request("/system-health")
      ]);
      if (summaryResponse.ok) {
        renderDeviceStats(await summaryResponse.json(), deviceItems);
      }
      if (healthResponse.ok) {
        renderCriticalHealth(await healthResponse.json());
      } else {
        renderCriticalHealth({ stale: true, services: {} });
      }
    }

    function promptReenrollmentLookup() {
      const candidates = deviceItems.filter(
        item => item.status === "denied"
      );
      if (candidates.length === 0) {
        showToast("There are no denied clients available for re-enrollment.");
        return;
      }

      const value = window.prompt(
        "Enter the RustDesk ID, friendly name, or hostname of the denied client to re-enroll:"
      );
      if (value === null) return;
      const key = value.trim().toLowerCase();
      if (!key) return;

      const matches = candidates.filter(item => {
        return [
          item.rustdesk_id,
          item.friendly_name,
          item.hostname
        ].some(field => String(field || "").toLowerCase() === key);
      });

      if (matches.length !== 1) {
        showToast(
          matches.length === 0
            ? "No deactivated client matched that value."
            : "More than one deactivated client matched. Use the exact RustDesk ID.",
          true
        );
        return;
      }

      const device = matches[0];
      openReenrollmentModal(
        device.id,
        device.friendly_name
          || device.hostname
          || device.rustdesk_id
      );
    }

    function openAccessResetModal(
      accountId,
      username,
      displayName,
      mode = "password_only",
      selfService = false
    ) {
      accessResetSelfService = selfService;
      document.getElementById("accessResetAccountId").value = accountId;
      document.getElementById("accessResetSubtitle").textContent = selfService
        ? `Create a one-time access-change link for your account (${username}).`
        : `Create a one-time Owner recovery link for ${displayName} (${username}).`;
      document.getElementById("accessResetMode").value = mode;
      document.getElementById("accessResetReason").value = selfService
        ? `Self-service ${mode.replaceAll("_", " ")} for ${username}`
        : `Owner recovery (${mode.replaceAll("_", " ")}) for ${username}`;
      document.getElementById("accessResetOwnerPassword").value = "";
      document.getElementById("accessResetOwnerTotp").value = "";
      document.getElementById("accessResetPasswordLabel").textContent = selfService
        ? "Current password"
        : "Your Owner password";
      document.getElementById("accessResetTotpLabel").textContent = selfService
        ? "Current 6-digit authenticator code"
        : "Your 6-digit authenticator code";
      document.getElementById("accessResetWarning").textContent = selfService
        ? "Your current access remains valid until you complete the one-time link. Completing it revokes existing login sessions and applies the selected password/authenticator change."
        : "Owner recovery revokes the person's active sessions immediately. Password reset modes invalidate the old password; authenticator reset modes invalidate the old authenticator. The one-time recovery link expires after 30 minutes.";
      document.getElementById("accessResetError").textContent = "";
      document.getElementById("accessResetGenerated").classList.add("hidden");
      document.getElementById("accessResetGeneratedLink").textContent = "";
      accessResetModal.classList.remove("hidden");
      document.body.classList.add("modal-open");
    }

    function closeAccessResetModal() {
      accessResetModal.classList.add("hidden");
      document.body.classList.remove("modal-open");
      accessResetSelfService = false;
      document.getElementById("accessResetOwnerPassword").value = "";
      document.getElementById("accessResetOwnerTotp").value = "";
    }

    async function submitAccessReset(event) {
      event.preventDefault();
      const accountId = document.getElementById("accessResetAccountId").value;
      const mode = document.getElementById("accessResetMode").value;
      const reason = document.getElementById("accessResetReason").value.trim();
      const password = document.getElementById("accessResetOwnerPassword").value;
      const totp = document.getElementById("accessResetOwnerTotp").value.trim();
      const payload = accessResetSelfService
        ? {
            reset_mode: mode,
            reason,
            current_password: password,
            current_totp_code: totp
          }
        : {
            reset_mode: mode,
            reason,
            owner_password: password,
            owner_totp_code: totp
          };
      const errorBox = document.getElementById("accessResetError");
      if (!reason || !/^\d{6}$/.test(totp) || !password) {
        errorBox.textContent = "Reason, current password, and current 6-digit authenticator code are required.";
        return;
      }
      errorBox.textContent = "";
      const button = document.getElementById("accessResetSubmit");
      button.disabled = true; button.textContent = "Creating…";
      try {
        const endpoint = accessResetSelfService
          ? "/operator/self/access-reset"
          : `/operators/${encodeURIComponent(accountId)}/access-reset`;
        const response = await request(endpoint, {
          method: "POST",
          body: JSON.stringify(payload)
        });
        if (!response.ok) {
          errorBox.textContent = await parseError(response);
          return;
        }
        const result = await response.json();
        document.getElementById("accessResetGeneratedLink").textContent = result.reset_url;
        document.getElementById("accessResetGenerated").classList.remove("hidden");
        document.getElementById("accessResetOwnerPassword").value = "";
        document.getElementById("accessResetOwnerTotp").value = "";
        showToast(accessResetSelfService
          ? "One-time access-change link created."
          : `Recovery link created for ${result.username}.`);
        if (!accessResetSelfService) await loadDashboard();
      } finally {
        button.disabled = false;
        button.textContent = accessResetSelfService
          ? "Create access-change link"
          : "Create recovery link";
      }
    }

    async function copyAccessResetLink() {
      const value = document.getElementById("accessResetGeneratedLink").textContent;
      if (!value) return;
      try { await navigator.clipboard.writeText(value); showToast("Recovery link copied."); }
      catch { showToast("Unable to copy automatically.", true); }
    }

    function openReenrollmentModal(deviceId, deviceName) {
      document.getElementById("reenrollmentDeviceId").value = deviceId;
      document.getElementById("reenrollmentDeviceName").value = deviceName;
      document.getElementById("reenrollmentSubtitle").textContent =
        `Allow ${deviceName} to request a fresh Pending enrollment without changing its RustDesk identity.`;
      document.getElementById("reenrollmentReason").value =
        `Owner-authorized re-enrollment for ${deviceName}`;
      document.getElementById("reenrollmentError").textContent = "";
      reenrollmentModal.classList.remove("hidden");
      document.body.classList.add("modal-open");
    }

    function closeReenrollmentModal() {
      reenrollmentModal.classList.add("hidden");
      document.body.classList.remove("modal-open");
    }

    async function submitReenrollmentAuthorization(event) {
      event.preventDefault();
      const deviceId = document.getElementById("reenrollmentDeviceId").value;
      const deviceName = document.getElementById("reenrollmentDeviceName").value;
      const payload = {
        reason: document.getElementById("reenrollmentReason").value.trim(),
        expires_in_minutes: 30
      };
      const errorBox = document.getElementById("reenrollmentError");
      if (!payload.reason) {
        errorBox.textContent = "Reason is required.";
        return;
      }
      errorBox.textContent = "";
      const button = document.getElementById("reenrollmentSubmit");
      button.disabled = true; button.textContent = "Authorizing…";
      try {
        const response = await request(
          `/devices/${encodeURIComponent(deviceId)}/reenrollment-authorization`,
          {method:"POST", body:JSON.stringify(payload)}
        );
        if (!response.ok) { errorBox.textContent = await parseError(response); return; }
        const result = await response.json();
        closeReenrollmentModal();
        closeDeviceModal();
        showToast(
          `${deviceName}: re-enrollment authorized until ${formatDate(result.expires_at)}.`,
          false
        );
        await loadDashboard();
      } finally {
        button.disabled = false; button.textContent = "Authorize re-enrollment";
      }
    }

    async function runOperatorAction(
      accountId,
      username,
      action
    ) {
      const actionNames = {
        "unlock": "unlock",
        "revoke-sessions": "revoke all active sessions for",
        "disable": "disable",
        "enable": "enable",
        "delete": "delete from the active Client Managers list"
      };
      const verb = actionNames[action] || action;

      if (
        !window.confirm(
          `Are you sure you want to ${verb} ${username}?`
        )
      ) {
        return false;
      }

      if (action === "delete" && !window.confirm(
        `This removes ${username} from Client Managers. Immutable audit history is retained. Continue?`
      )) {
        return false;
      }

      const reason = window.prompt(
        `Reason for ${verb} ${username}:`,
        `Owner dashboard: ${verb} ${username}`
      );

      if (reason === null) return false;
      if (!reason.trim()) {
        showToast("A reason is required.", true);
        return false;
      }

      const response = await request(
        `/operators/${encodeURIComponent(accountId)}/${
          encodeURIComponent(action)
        }`,
        {
          method: "POST",
          body: JSON.stringify({ reason: reason.trim() })
        }
      );

      if (!response.ok) {
        showToast(await parseError(response), true);
        return false;
      }

      showToast(action === "delete"
        ? `${username} was removed from Client Managers; audit history was retained.`
        : `Account action completed for ${username}.`);
      await loadDashboard();
      return true;
    }

    async function runStatusChange(
      accountId,
      username,
      isActive
    ) {
      const action = isActive ? "disable" : "enable";
      const verb = isActive ? "disable" : "enable";

      if (
        !window.confirm(
          `Are you sure you want to ${verb} ${username}?`
        )
      ) {
        return;
      }

      const reason = window.prompt(
        `Reason to ${verb} ${username}:`,
        `Owner dashboard: ${verb} ${username}`
      );

      if (reason === null) return;
      if (!reason.trim()) {
        showToast("A reason is required.", true);
        return;
      }

      const response = await request(
        `/operators/${encodeURIComponent(accountId)}/${action}`,
        {
          method: "POST",
          body: JSON.stringify({ reason: reason.trim() })
        }
      );

      if (!response.ok) {
        showToast(await parseError(response), true);
        await loadDashboard();
        return;
      }

      showToast(
        `${username} is now ${isActive ? "disabled" : "active"}.`
      );
      await loadDashboard();
    }

    function updateOwnerReauthVisibility() {
      const currentRole = document.getElementById(
        "roleChangeCurrentRole"
      ).value;
      const requestedRole = document.getElementById(
        "roleChangeRequestedRole"
      ).value;
      const sensitive = (
        currentRole === "owner"
        || requestedRole === "owner"
      );

      document.getElementById(
        "ownerReauthFields"
      ).classList.toggle("hidden", !sensitive);
      document.getElementById(
        "roleChangeWarning"
      ).classList.toggle("hidden", !sensitive);
      document.getElementById(
        "ownerReauthPassword"
      ).required = sensitive;
      document.getElementById(
        "ownerReauthTotp"
      ).required = sensitive;
    }

    function openRoleChangeModal(
      accountId,
      username,
      currentRole,
      requestedRole
    ) {
      document.getElementById(
        "roleChangeAccountId"
      ).value = accountId;
      document.getElementById(
        "roleChangeCurrentRole"
      ).value = currentRole;
      document.getElementById(
        "roleChangeRequestedRole"
      ).value = requestedRole;
      document.getElementById(
        "roleChangeSubtitle"
      ).textContent =
        `${username}: ${currentRole} → ${requestedRole}`;
      document.getElementById(
        "roleChangeReason"
      ).value =
        `Owner dashboard: change ${username} from ${currentRole} to ${requestedRole}`;
      document.getElementById(
        "ownerReauthPassword"
      ).value = "";
      document.getElementById(
        "ownerReauthTotp"
      ).value = "";
      document.getElementById(
        "roleChangeError"
      ).textContent = "";
      updateOwnerReauthVisibility();
      roleChangeModal.classList.remove("hidden");
      document.body.classList.add("modal-open");
    }

    function closeRoleChangeModal() {
      roleChangeModal.classList.add("hidden");
      document.body.classList.remove("modal-open");
      document.getElementById(
        "ownerReauthPassword"
      ).value = "";
      document.getElementById(
        "ownerReauthTotp"
      ).value = "";
      renderOperators();
    }

    async function submitRoleChange(event) {
      event.preventDefault();

      const accountId = document.getElementById(
        "roleChangeAccountId"
      ).value;
      const requestedRole = document.getElementById(
        "roleChangeRequestedRole"
      ).value;
      const currentRole = document.getElementById(
        "roleChangeCurrentRole"
      ).value;
      const reason = document.getElementById(
        "roleChangeReason"
      ).value.trim();
      const sensitive = (
        currentRole === "owner"
        || requestedRole === "owner"
      );
      const ownerPassword = document.getElementById(
        "ownerReauthPassword"
      ).value;
      const ownerTotp = document.getElementById(
        "ownerReauthTotp"
      ).value.trim();
      const errorBox = document.getElementById(
        "roleChangeError"
      );
      const submitButton = document.getElementById(
        "roleChangeSubmitButton"
      );

      errorBox.textContent = "";

      if (!reason) {
        errorBox.textContent = "A reason is required.";
        return;
      }

      if (
        sensitive
        && (
          !ownerPassword
          || ownerTotp.length !== 6
          || !/^\d{6}$/.test(ownerTotp)
        )
      ) {
        errorBox.textContent =
          "Owner password and a 6-digit authenticator code are required.";
        return;
      }

      if (
        !window.confirm(
          `Apply the ${requestedRole} permission now?`
        )
      ) {
        return;
      }

      submitButton.disabled = true;
      submitButton.textContent = "Applying...";

      try {
        const createResponse = await request(
          `/operators/${encodeURIComponent(accountId)}/role-change`,
          {
            method: "POST",
            body: JSON.stringify({
              requested_role: requestedRole,
              reason,
              owner_password: sensitive ? ownerPassword : null,
              owner_totp_code: sensitive ? ownerTotp : null
            })
          }
        );

        if (!createResponse.ok) {
          errorBox.textContent = await parseError(createResponse);
          return;
        }

        const created = await createResponse.json();
        const requestId = created.id;

        if (!requestId) {
          errorBox.textContent =
            "The server did not return a role-change request ID.";
          return;
        }

        const completeResponse = await request(
          `/role-changes/${encodeURIComponent(
            requestId
          )}/complete`,
          {
            method: "POST",
            body: JSON.stringify({
              reason: `Owner dashboard: complete ${reason}`
            })
          }
        );

        if (!completeResponse.ok) {
          errorBox.textContent =
            `The request was created but not completed: ${
              await parseError(completeResponse)
            }. It remains listed in Client Managers.`;
          await loadDashboard();
          return;
        }

        closeRoleChangeModal();
        showToast("Permission changed successfully.");
        await loadDashboard();
      } finally {
        submitButton.disabled = false;
        submitButton.textContent = "Apply permission";
        document.getElementById(
          "ownerReauthPassword"
        ).value = "";
        document.getElementById(
          "ownerReauthTotp"
        ).value = "";
      }
    }

    async function runRoleRequestAction(
      requestId,
      username,
      action
    ) {
      const verb = action === "complete" ? "complete" : "cancel";

      if (
        !window.confirm(
          `Are you sure you want to ${verb} the pending permission change for ${username}?`
        )
      ) {
        return;
      }

      const reason = window.prompt(
        `Reason to ${verb} this permission change:`,
        `Owner dashboard: ${verb} pending permission change`
      );

      if (reason === null) return;
      if (!reason.trim()) {
        showToast("A reason is required.", true);
        return;
      }

      const response = await request(
        `/role-changes/${encodeURIComponent(requestId)}/${action}`,
        {
          method: "POST",
          body: JSON.stringify({ reason: reason.trim() })
        }
      );

      if (!response.ok) {
        showToast(await parseError(response), true);
        return;
      }

      showToast(`Permission request ${verb}d.`);
      await loadDashboard();
    }

    function openInvitePersonModal() {
      document.getElementById("invitePersonForm").reset();
            document.getElementById("inviteExpiry").value = "72";
      document.getElementById(
        "inviteGenerated"
      ).classList.add("hidden");
      document.getElementById(
        "inviteGeneratedLink"
      ).textContent = "";
      document.getElementById(
        "inviteFormError"
      ).textContent = "";
      document.getElementById(
        "inviteSubmitButton"
      ).classList.remove("hidden");
      document.getElementById(
        "inviteCancelButton"
      ).textContent = "Cancel";
      invitePersonModal.classList.remove("hidden");
      document.body.classList.add("modal-open");
    }

    function closeInvitePersonModal() {
      invitePersonModal.classList.add("hidden");
      document.body.classList.remove("modal-open");
    }

    async function submitInvitation(event) {
      event.preventDefault();

      const errorBox = document.getElementById(
        "inviteFormError"
      );
      const submitButton = document.getElementById(
        "inviteSubmitButton"
      );
      errorBox.textContent = "";
      submitButton.disabled = true;
      submitButton.textContent = "Creating...";

      try {
        const response = await request(
          "/invitations",
          {
            method: "POST",
            body: JSON.stringify({
              display_name: document.getElementById(
                "inviteDisplayName"
              ).value.trim(),
              username: document.getElementById(
                "inviteUsername"
              ).value.trim(),
              role: "manager",
              expires_in_hours: Number(
                document.getElementById(
                  "inviteExpiry"
                ).value
              )
            })
          }
        );

        if (!response.ok) {
          errorBox.textContent = await parseError(response);
          return;
        }

        const result = await response.json();
        const invitationLink =
          `${window.location.origin}/ops/invite?token=${
            encodeURIComponent(result.invitation_token)
          }`;

        document.getElementById(
          "inviteGeneratedLink"
        ).textContent = invitationLink;
        document.getElementById(
          "inviteGenerated"
        ).classList.remove("hidden");
        submitButton.classList.add("hidden");
        document.getElementById(
          "inviteCancelButton"
        ).textContent = "Done";
        showToast("Invitation created.");
        await loadDashboard();
      } finally {
        submitButton.disabled = false;
        submitButton.textContent = "Create invitation";
      }
    }

    async function revokeInvitation(
      invitationId,
      username
    ) {
      if (
        !window.confirm(
          `Revoke the pending invitation for ${username}?`
        )
      ) {
        return;
      }

      const reason = window.prompt(
        `Reason to revoke ${username}'s invitation:`,
        "Owner dashboard: invitation no longer needed"
      );

      if (reason === null) return;
      if (!reason.trim()) {
        showToast("A reason is required.", true);
        return;
      }

      const response = await request(
        `/invitations/${encodeURIComponent(
          invitationId
        )}/revoke`,
        {
          method: "POST",
          body: JSON.stringify({ reason: reason.trim() })
        }
      );

      if (!response.ok) {
        showToast(await parseError(response), true);
        return;
      }

      showToast(`Invitation revoked for ${username}.`);
      await loadDashboard();
    }

    async function loadDashboard() {
      const meResponse = await request("/me");

      if (!meResponse.ok) {
        if (meResponse.status !== 401) {
          showLogin(await parseError(meResponse));
        }
        return;
      }

      currentOperator = await meResponse.json();
      applyRoleVisibility();

      document.getElementById("operatorText").textContent =
        `${
          currentOperator.display_name
          || currentOperator.username
        } - ${currentOperator.role}`;

      const [
        summaryResponse,
        systemHealthResponse,
        devicesResponse
      ] = await Promise.all([
        request("/summary"),
        request("/system-health"),
        request("/devices")
      ]);

      if (!devicesResponse.ok) {
        showToast(
          `Management: ${await parseError(devicesResponse)}`,
          true
        );
        return;
      }

      const devices = await devicesResponse.json();
      deviceItems = devices.items || [];
      const summary = summaryResponse.ok ? await summaryResponse.json() : null;
      renderDeviceStats(summary, deviceItems);
      renderDevices();
      renderBlockedRevokedDevices();

      if (systemHealthResponse.ok) {
        renderCriticalHealth(await systemHealthResponse.json());
      } else {
        renderCriticalHealth({ stale: true, services: {} });
      }

      const operatorsResponse = await request("/operators");
      if (operatorsResponse.ok) {
        const operators = await operatorsResponse.json();
        operatorItems = operators.operators || [];
      } else {
        operatorItems = [];
        showToast(
          `Client Managers: ${await parseError(operatorsResponse)}`,
          true
        );
      }

      if (isOwner()) {
        const [
          invitationsResponse,
          roleChangesResponse,
          operationsResponse,
          auditResponse
        ] = await Promise.all([
          request("/invitations"),
          request("/role-changes"),
          request("/operations"),
          request("/activity-feed?limit=200")
        ]);

        if (invitationsResponse.ok) {
          const invitations = await invitationsResponse.json();
          invitationItems = invitations.invitations || [];
        } else {
          invitationItems = [];
          showToast(
            `Invitations: ${
              await parseError(invitationsResponse)
            }`,
            true
          );
        }

        if (roleChangesResponse.ok) {
          const roleChanges = await roleChangesResponse.json();
          roleChangeItems =
            roleChanges.role_change_requests || [];
        } else {
          roleChangeItems = [];
          showToast(
            `Permission changes: ${
              await parseError(roleChangesResponse)
            }`,
            true
          );
        }
        renderOperators();

        if (operationsResponse.ok) {
          operationsState = await operationsResponse.json();
          renderOperations();
        } else {
          showToast(
            `Server Health: ${await parseError(operationsResponse)}`,
            true
          );
        }

        if (auditResponse.ok) {
          const audit = await auditResponse.json();
          auditItems = audit.items || [];
          updateEventOptions(auditItems);
          renderActivity();
        } else {
          showToast(
            `Activity: ${
              await parseError(auditResponse)
            }`,
            true
          );
        }
      } else {
        invitationItems = [];
        roleChangeItems = [];
        auditItems = [];
        renderOperators();
      }

    }


    loginForm.addEventListener("submit", async event => {
      event.preventDefault();
      loginError.textContent = "";
      loginButton.disabled = true;
      loginButton.textContent = "Signing in...";

      const response = await request(
        "/login",
        {
          method: "POST",
          body: JSON.stringify({
            username: document.getElementById("username").value,
            password: document.getElementById("password").value,
            totp_code: document.getElementById("totp").value
          })
        },
        false
      );

      loginButton.disabled = false;
      loginButton.textContent = "Sign in";

      if (!response.ok) {
        loginError.textContent = await parseError(response);
        return;
      }

      document.getElementById("password").value = "";
      document.getElementById("totp").value = "";
      lastHumanActivityAt = Date.now();
      lastActivitySentAt = Date.now();
      showDashboard();
      await loadDashboard();
    });

    document.querySelectorAll(".tab").forEach(button => {
      button.addEventListener("click", () => {
        const tabName = button.dataset.tab;

        document.querySelectorAll(".tab").forEach(tab => {
          tab.classList.toggle(
            "active",
            tab.dataset.tab === tabName
          );
        });

        document.querySelectorAll(".tab-view").forEach(view => {
          view.classList.add("hidden");
        });

        document.getElementById(
          `${tabName}Tab`
        ).classList.remove("hidden");
      });
    });

    document.getElementById(
      "refreshButton"
    ).addEventListener("click", loadDashboard);

    statusFilter.addEventListener("change", renderDevices);
    eventFilter.addEventListener("change", renderActivity);
    auditSearch.addEventListener("input", renderActivity);

    deviceRows.addEventListener("click", event => {
      const detailButton = event.target.closest(".device-detail");
      if (detailButton) {
        void showDeviceDetail(detailButton.dataset.id);
        return;
      }

      const reenrollButton = event.target.closest(".device-reenroll");
      if (reenrollButton) {
        openReenrollmentModal(
          reenrollButton.dataset.id,
          reenrollButton.dataset.name
        );
        return;
      }

      const actionButton = event.target.closest(".device-action");
      if (!actionButton) return;

      void runDeviceAction(
        actionButton.dataset.id,
        actionButton.dataset.name,
        actionButton.dataset.action
      );
    });

    blockedRevokedRows.addEventListener("click", event => {
      const actionButton = event.target.closest(".device-action");
      if (!actionButton) return;
      void runDeviceAction(
        actionButton.dataset.id,
        actionButton.dataset.name,
        actionButton.dataset.action
      );
    });

    deviceModalActions.addEventListener("click", event => {
      const reenrollButton = event.target.closest(".device-reenroll");
      if (reenrollButton) {
        openReenrollmentModal(
          reenrollButton.dataset.id,
          reenrollButton.dataset.name
        );
        return;
      }

      const button = event.target.closest(".device-action");
      if (!button) return;

      void runDeviceAction(
        button.dataset.id,
        button.dataset.name,
        button.dataset.action
      );
    });

    document.getElementById(
      "deviceModalClose"
    ).addEventListener("click", closeDeviceModal);

    deviceModal.addEventListener("click", event => {
      if (event.target === deviceModal) closeDeviceModal();
    });

    window.addEventListener("keydown", event => {
      if (event.key !== "Escape") return;
      closeDeviceModal();
      closeOperatorModal();
      closeInvitePersonModal();
      closeRoleChangeModal();
      closeAccessResetModal();
      closeReenrollmentModal();
    });

    document.getElementById("operatorModalClose").addEventListener("click", closeOperatorModal);
    operatorModal.addEventListener("click", event => {
      if (event.target === operatorModal) closeOperatorModal();
    });
    operatorEmailEditor.addEventListener("click", event => {
      const button = event.target.closest(".operator-email-save");
      if (!button) return;
      void saveOperatorEmail(button.dataset.id);
    });
    operatorModalActions.addEventListener("click", event => {
      const resetButton = event.target.closest(".operator-access-change");
      if (resetButton) {
        openAccessResetModal(
          resetButton.dataset.id,
          resetButton.dataset.name,
          resetButton.dataset.displayName,
          resetButton.dataset.mode,
          resetButton.dataset.self === "true"
        );
        return;
      }

      const actionButton = event.target.closest(".operator-detail-action");
      if (!actionButton) return;
      const action = actionButton.dataset.action;
      void runOperatorAction(
        actionButton.dataset.id,
        actionButton.dataset.name,
        action
      ).then(changed => {
        if (!changed) return;
        if (action === "delete") {
          closeOperatorModal();
          return;
        }
        void showOperatorDetail(actionButton.dataset.id);
      });
    });

    document.getElementById("accessResetClose").addEventListener("click", closeAccessResetModal);
    document.getElementById("accessResetCancel").addEventListener("click", closeAccessResetModal);
    document.getElementById("accessResetForm").addEventListener("submit", submitAccessReset);
    document.getElementById("copyAccessResetLink").addEventListener("click", copyAccessResetLink);
    accessResetModal.addEventListener("click", event => { if (event.target === accessResetModal) closeAccessResetModal(); });
    document.getElementById("reenrollmentClose").addEventListener("click", closeReenrollmentModal);
    document.getElementById("reenrollmentCancel").addEventListener("click", closeReenrollmentModal);
    document.getElementById("reenrollmentForm").addEventListener("submit", submitReenrollmentAuthorization);
    reenrollmentModal.addEventListener("click", event => { if (event.target === reenrollmentModal) closeReenrollmentModal(); });
    document.getElementById("findReenrollmentButton").addEventListener(
      "click",
      promptReenrollmentLookup
    );

    operatorRows.addEventListener("click", event => {
      const detailButton = event.target.closest(".operator-detail");
      if (detailButton) {
        void showOperatorDetail(detailButton.dataset.id);
        return;
      }

      const invitationButton = event.target.closest(".invitation-action");
      if (invitationButton) {
        void revokeInvitation(
          invitationButton.dataset.id,
          invitationButton.dataset.name
        );
        return;
      }
      const roleRequestButton = event.target.closest(".role-request-action");
      if (roleRequestButton) {
        void runRoleRequestAction(
          roleRequestButton.dataset.id,
          roleRequestButton.dataset.name,
          roleRequestButton.dataset.action
        );
        return;
      }
      const statusButton = event.target.closest(
        ".operator-status-control"
      );
      if (statusButton) {
        void runStatusChange(
          statusButton.dataset.id,
          statusButton.dataset.name,
          statusButton.dataset.active === "true"
        );
        return;
      }

    });

    operatorRows.addEventListener("change", event => {
      const control = event.target.closest(
        ".operator-role-control"
      );
      if (!control) return;

      const requestedRole = control.value;
      const currentRole = control.dataset.currentRole;

      if (requestedRole === currentRole) return;

      openRoleChangeModal(
        control.dataset.id,
        control.dataset.name,
        currentRole,
        requestedRole
      );
    });



    document.getElementById(
      "invitePersonButton"
    ).addEventListener("click", openInvitePersonModal);

    document.getElementById(
      "invitePersonClose"
    ).addEventListener("click", closeInvitePersonModal);

    document.getElementById(
      "inviteCancelButton"
    ).addEventListener("click", closeInvitePersonModal);

    document.getElementById(
      "invitePersonForm"
    ).addEventListener("submit", submitInvitation);

    document.getElementById(
      "copyInviteLink"
    ).addEventListener("click", async () => {
      const link = document.getElementById(
        "inviteGeneratedLink"
      ).textContent;

      try {
        await navigator.clipboard.writeText(link);
        showToast("Invitation link copied.");
      } catch {
        showToast(
          "Unable to copy automatically. Select and copy the link.",
          true
        );
      }
    });

    invitePersonModal.addEventListener("click", event => {
      if (event.target === invitePersonModal) {
        closeInvitePersonModal();
      }
    });

    document.getElementById(
      "roleChangeClose"
    ).addEventListener("click", closeRoleChangeModal);

    document.getElementById(
      "roleChangeCancelButton"
    ).addEventListener("click", closeRoleChangeModal);

    document.getElementById(
      "roleChangeRequestedRole"
    ).addEventListener(
      "change",
      updateOwnerReauthVisibility
    );

    document.getElementById(
      "roleChangeForm"
    ).addEventListener("submit", submitRoleChange);

    roleChangeModal.addEventListener("click", event => {
      if (event.target === roleChangeModal) {
        closeRoleChangeModal();
      }
    });

    for (const eventName of [
      "pointerdown",
      "pointermove",
      "keydown",
      "wheel",
      "touchstart",
      "scroll"
    ]) {
      window.addEventListener(
        eventName,
        recordHumanActivity,
        { passive: true }
      );
    }

    document.addEventListener(
      "visibilitychange",
      () => {
        if (!document.hidden && !checkIdleTimeout()) {
          recordHumanActivity();
        }
      }
    );

    document.getElementById(
      "logoutButton"
    ).addEventListener("click", async () => {
      await request("/logout", { method: "POST" });
      showLogin("Signed out.");
    });

    (async () => {
      const response = await request("/me");

      if (response.ok) {
        showDashboard();
        lastActivitySentAt = Date.now();
        void touchServerActivity();
        await loadDashboard();
      } else {
        showLogin();
      }
    })();
  </script>
</body>
</html>
"""

INVITE_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>RustDesk Directory Invitation</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #08111f;
      --panel: #111d2e;
      --panel-2: #17263a;
      --line: #263a53;
      --text: #eef5ff;
      --muted: #9fb0c6;
      --accent: #4da3ff;
      --good: #38bd80;
      --bad: #f87171;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background:
        radial-gradient(circle at top left, #10284a 0, transparent 38%),
        var(--bg);
      color: var(--text);
      font-family:
        Inter, ui-sans-serif, system-ui, -apple-system,
        BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    .shell {
      width: min(700px, calc(100% - 28px));
      margin: 48px auto;
    }
    .card {
      padding: 26px;
      border: 1px solid var(--line);
      border-radius: 18px;
      background: rgba(17, 29, 46, .96);
      box-shadow: 0 24px 70px rgba(0, 0, 0, .35);
    }
    h1 { margin: 0 0 8px; }
    h2 { margin: 24px 0 12px; font-size: 18px; }
    p { color: var(--muted); line-height: 1.55; }
    .summary {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
      margin: 20px 0;
    }
    .summary > div {
      padding: 12px;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: var(--panel-2);
    }
    .label {
      color: var(--muted);
      font-size: 12px;
      margin-bottom: 5px;
    }
    .value { font-weight: 800; overflow-wrap: anywhere; }
    .secret {
      user-select: all;
      font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
      letter-spacing: .04em;
    }
    .authenticator-enrollment {
      display: grid;
      grid-template-columns: minmax(220px, 280px) minmax(0, 1fr);
      gap: 18px;
      align-items: center;
      margin: 18px 0;
    }
    .qr-card {
      display: grid;
      place-items: center;
      min-height: 280px;
      padding: 12px;
      border-radius: 14px;
      background: #fff;
    }
    .totp-qr {
      display: block;
      width: min(260px, 100%);
      height: auto;
      image-rendering: pixelated;
    }
    .authenticator-help {
      color: var(--muted);
      line-height: 1.55;
    }
    .form {
      display: grid;
      gap: 14px;
    }
    .field { display: grid; gap: 7px; }
    label {
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
    }
    input {
      width: 100%;
      padding: 11px 12px;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #0c1727;
      color: var(--text);
      font: inherit;
    }
    button, .button-link {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 42px;
      padding: 10px 16px;
      border: 1px solid transparent;
      border-radius: 10px;
      background: var(--accent);
      color: white;
      font: inherit;
      font-weight: 800;
      text-decoration: none;
      cursor: pointer;
    }
    button:disabled { opacity: .55; cursor: not-allowed; }
    .secondary {
      background: transparent;
      border-color: var(--line);
    }
    .actions {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      justify-content: flex-end;
    }
    .notice {
      padding: 13px 14px;
      border: 1px solid rgba(77, 163, 255, .35);
      border-radius: 10px;
      background: rgba(77, 163, 255, .09);
      color: #cfe7ff;
      line-height: 1.5;
    }
    .error {
      min-height: 22px;
      color: var(--bad);
      font-weight: 700;
    }
    .success {
      padding: 16px;
      border: 1px solid rgba(56, 189, 128, .38);
      border-radius: 12px;
      background: rgba(56, 189, 128, .10);
      color: #baf4d5;
    }
    .hidden { display: none !important; }
    @media (max-width: 640px) {
      .summary { grid-template-columns: 1fr; }
      .authenticator-enrollment { grid-template-columns: 1fr; }
      .qr-card { min-height: 0; }
      .card { padding: 20px; }
    }
  </style>
</head>
<body>
  <main class="shell">
    <section class="card">
      <h1>RustDesk Directory invitation</h1>
      <p id="intro">
        Validating the invitation and loading account setup.
      </p>

      <div id="loadingNotice" class="notice">
        Checking invitation…
      </div>
      <div id="loadError" class="error"></div>

      <section id="setupView" class="hidden">
        <div class="summary">
          <div>
            <div class="label">Name</div>
            <div id="displayName" class="value"></div>
          </div>
          <div>
            <div class="label">Username</div>
            <div id="usernameValue" class="value"></div>
          </div>
          <div>
            <div class="label">Permission</div>
            <div id="roleValue" class="value"></div>
          </div>
          <div>
            <div class="label">Expires</div>
            <div id="expiresValue" class="value"></div>
          </div>
        </div>

        <h2>1. Add the authenticator</h2>
        <div class="notice">
          Scan the QR code with your authenticator app, then enter
          the current 6-digit code below. The QR code and secret are
          unique to this invitation.
        </div>

        <div class="authenticator-enrollment">
          <div class="qr-card">
            <img
              id="totpQr"
              class="totp-qr"
              alt="Authenticator QR code"
            >
          </div>
          <div class="authenticator-help">
            <strong>Scan this QR code</strong>
            <p>
              Use Microsoft Authenticator, Google Authenticator,
              1Password, Authy, or another standard TOTP app.
            </p>
            <p>
              If you are opening this invitation on the same phone,
              use <strong>Open authenticator app</strong> below.
              Manual secret entry remains available as a fallback.
            </p>
          </div>
        </div>

        <div class="summary">
          <div>
            <div class="label">Authenticator secret (manual fallback)</div>
            <div id="totpSecret" class="value secret"></div>
          </div>
          <div>
            <div class="label">Authenticator account</div>
            <div class="value">RustDesk Directory</div>
          </div>
        </div>
        <div class="actions">
          <a
            id="openAuthenticator"
            class="button-link secondary"
            href="#"
          >Open authenticator app</a>
          <button
            id="copySecret"
            class="secondary"
            type="button"
          >Copy secret</button>
        </div>

        <h2>2. Create your account</h2>
        <form id="acceptForm" class="form">
          <div class="field">
            <label for="newPassword">
              Password — at least 12 characters
            </label>
            <input
              id="newPassword"
              type="password"
              minlength="12"
              maxlength="256"
              autocomplete="new-password"
              required
            >
          </div>
          <div class="field">
            <label for="confirmPassword">Confirm password</label>
            <input
              id="confirmPassword"
              type="password"
              minlength="12"
              maxlength="256"
              autocomplete="new-password"
              required
            >
          </div>
          <div class="field">
            <label for="totpCode">
              Current 6-digit authenticator code
            </label>
            <input
              id="totpCode"
              inputmode="numeric"
              pattern="[0-9]{6}"
              maxlength="6"
              autocomplete="one-time-code"
              required
            >
          </div>
          <div id="acceptError" class="error"></div>
          <div class="actions">
            <button id="acceptButton" type="submit">
              Create account
            </button>
          </div>
        </form>
      </section>

      <section id="successView" class="success hidden">
        <strong>Account created successfully.</strong>
        <p>
          Your password and authenticator are now active.
          You can sign in to the RustDesk Directory dashboard.
        </p>
        <a class="button-link" href="/ops">
          Open dashboard
        </a>
      </section>
    </section>
  </main>

  <script>
    const API = "/ops/api/invite";
    const token = new URLSearchParams(
      window.location.search
    ).get("token") || "";
    let setup = null;

    async function errorText(response) {
      try {
        const body = await response.json();
        return body.detail || `Request failed (${response.status})`;
      } catch {
        return `Request failed (${response.status})`;
      }
    }

    function dateText(value) {
      if (!value) return "-";
      const date = new Date(value);
      return Number.isNaN(date.getTime())
        ? String(value)
        : date.toLocaleString();
    }

    async function loadInvitation() {
      const loadingNotice = document.getElementById(
        "loadingNotice"
      );
      const loadError = document.getElementById("loadError");

      if (!token) {
        loadingNotice.classList.add("hidden");
        loadError.textContent =
          "This invitation link does not contain a token.";
        return;
      }

      const response = await fetch(`${API}/setup`, {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ invitation_token: token })
      });

      loadingNotice.classList.add("hidden");

      if (!response.ok) {
        loadError.textContent = await errorText(response);
        return;
      }

      setup = await response.json();
      document.getElementById("intro").textContent =
        "Set a password and confirm your authenticator to accept this invitation.";
      document.getElementById("displayName").textContent =
        setup.display_name || setup.username;
      document.getElementById("usernameValue").textContent =
        setup.username;
      document.getElementById("roleValue").textContent =
        setup.role;
      document.getElementById("expiresValue").textContent =
        dateText(setup.expires_at);
      document.getElementById("totpSecret").textContent =
        setup.totp_secret;
      document.getElementById("totpQr").src =
        setup.totp_qr_data_uri;
      document.getElementById("openAuthenticator").href =
        setup.totp_provisioning_uri;
      document.getElementById(
        "setupView"
      ).classList.remove("hidden");
    }

    document.getElementById(
      "copySecret"
    ).addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(
          setup ? setup.totp_secret : ""
        );
        document.getElementById(
          "copySecret"
        ).textContent = "Copied";
      } catch {
        document.getElementById(
          "acceptError"
        ).textContent =
          "Unable to copy automatically. Select and copy the secret.";
      }
    });

    document.getElementById(
      "acceptForm"
    ).addEventListener("submit", async event => {
      event.preventDefault();

      const password = document.getElementById(
        "newPassword"
      ).value;
      const confirmPassword = document.getElementById(
        "confirmPassword"
      ).value;
      const totpCode = document.getElementById(
        "totpCode"
      ).value.trim();
      const errorBox = document.getElementById(
        "acceptError"
      );
      const button = document.getElementById(
        "acceptButton"
      );

      errorBox.textContent = "";

      if (password.length < 12) {
        errorBox.textContent =
          "Password must contain at least 12 characters.";
        return;
      }

      if (password !== confirmPassword) {
        errorBox.textContent = "Passwords do not match.";
        return;
      }

      if (!/^\d{6}$/.test(totpCode)) {
        errorBox.textContent =
          "Enter the current 6-digit authenticator code.";
        return;
      }

      button.disabled = true;
      button.textContent = "Creating account…";

      try {
        const response = await fetch(`${API}/accept`, {
          method: "POST",
          credentials: "same-origin",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            invitation_token: token,
            password,
            totp_code: totpCode
          })
        });

        if (!response.ok) {
          errorBox.textContent = await errorText(response);
          return;
        }

        document.getElementById(
          "setupView"
        ).classList.add("hidden");
        document.getElementById(
          "successView"
        ).classList.remove("hidden");
        document.getElementById("newPassword").value = "";
        document.getElementById(
          "confirmPassword"
        ).value = "";
        document.getElementById("totpCode").value = "";
      } finally {
        button.disabled = false;
        button.textContent = "Create account";
      }
    });

    void loadInvitation();
  </script>
</body>
</html>
"""

