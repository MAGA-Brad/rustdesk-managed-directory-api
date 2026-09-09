from __future__ import annotations

import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Callable

import jwt
from fastapi import Depends, HTTPException, Header, Request, status

MOBILE_PATH = "/ops/api/mobile"

# Device is "online" iff it heartbeat within this window - matches the exact
# threshold admin_ui.py's own dashboard already uses (isRecent() in the web
# SPA, and the same interval literal in its SQL), so the phone and the web
# dashboard never disagree about whether the same device is online right now.
ONLINE_WINDOW_SECONDS = 45

FCM_TOKEN_SCOPE = "https://www.googleapis.com/auth/firebase.messaging"


def _fetch_google_access_token(service_account: dict[str, Any]) -> str:
    now = int(time.time())
    assertion = jwt.encode(
        {
            "iss": service_account["client_email"],
            "scope": FCM_TOKEN_SCOPE,
            "aud": service_account["token_uri"],
            "iat": now,
            "exp": now + 3600,
        },
        service_account["private_key"],
        algorithm="RS256",
    )

    body = urllib.parse.urlencode(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        service_account["token_uri"],
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=10) as response:
        payload = json.loads(response.read().decode("utf-8"))

    return payload["access_token"]


class FcmUnregisteredError(Exception):
    """Raised when FCM reports the token itself is no longer valid."""


def _send_fcm_message(
    *,
    project_id: str,
    access_token: str,
    fcm_token: str,
    title: str,
    body: str,
    data: dict[str, str] | None = None,
) -> None:
    message = {
        "message": {
            "token": fcm_token,
            "notification": {"title": title, "body": body},
            "data": {str(k): str(v) for k, v in (data or {}).items()},
            "android": {"priority": "high"},
        }
    }

    request = urllib.request.Request(
        f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send",
        data=json.dumps(message).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json; charset=UTF-8",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()
    except urllib.error.HTTPError as error:
        error_body = error.read().decode("utf-8", errors="replace")
        # FCM reports an invalid/uninstalled-app token as NOT_FOUND (404) or
        # an UNREGISTERED error status inside the body - either way the token
        # is dead and the caller should stop retrying it.
        if error.code == 404 or "UNREGISTERED" in error_body:
            raise FcmUnregisteredError(error_body) from error
        raise


def register_mobile_routes(
    *,
    app: Any,
    login_handler: Callable[..., dict[str, Any]],
    refresh_handler: Callable[..., dict[str, Any]],
    logout_handler: Callable[..., dict[str, Any]],
    require_operator_handler: Callable[..., dict[str, Any]],
    require_device_manager_handler: Callable[..., dict[str, Any]],
    list_devices_handler: Callable[..., dict[str, Any]],
    approve_device_handler: Callable[..., dict[str, Any]],
    block_device_handler: Callable[..., dict[str, Any]],
    revoke_device_handler: Callable[..., dict[str, Any]],
    open_database_handler: Callable[..., Any],
    client_ip_handler: Callable[[Request], str | None],
    health_watcher_secret: str,
    firebase_service_account: dict[str, Any] | None,
    firebase_project_id: str | None,
    send_email_handler: Callable[..., None],
) -> None:
    def send_push_to_account(
        account_id,
        *,
        title: str,
        body: str,
        data: dict[str, str] | None = None,
    ) -> None:
        if firebase_service_account is None or firebase_project_id is None:
            return

        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, fcm_token
                    FROM mobile_push_tokens
                    WHERE account_id = %s
                      AND revoked_at IS NULL
                    """,
                    (account_id,),
                )
                tokens = cursor.fetchall()

        if not tokens:
            return

        access_token = _fetch_google_access_token(firebase_service_account)
        dead_token_ids = []

        for row in tokens:
            try:
                _send_fcm_message(
                    project_id=firebase_project_id,
                    access_token=access_token,
                    fcm_token=row["fcm_token"],
                    title=title,
                    body=body,
                    data=data,
                )
            except FcmUnregisteredError:
                dead_token_ids.append(row["id"])
            except (urllib.error.URLError, urllib.error.HTTPError):
                # Best-effort: a transient FCM/network failure must never
                # break the caller (device enrollment, health-event report).
                continue

        if dead_token_ids:
            now = datetime.now(timezone.utc)
            with open_database_handler() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        UPDATE mobile_push_tokens
                        SET revoked_at = %s
                        WHERE id = ANY(%s)
                        """,
                        (now, dead_token_ids),
                    )
                    connection.commit()

    def send_push_to_all_registered(
        *,
        title: str,
        body: str,
        data: dict[str, str] | None = None,
    ) -> None:
        if firebase_service_account is None or firebase_project_id is None:
            return

        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT DISTINCT account_id
                    FROM mobile_push_tokens
                    WHERE revoked_at IS NULL
                    """
                )
                accounts = cursor.fetchall()

        for row in accounts:
            send_push_to_account(
                row["account_id"],
                title=title,
                body=body,
                data=data,
            )

    def notify_pending_device(device: dict[str, Any]) -> None:
        name = device.get("friendly_name") or device.get("hostname") or "A device"
        try:
            send_push_to_all_registered(
                title="Device pending approval",
                body=f"{name} is waiting for approval.",
                data={
                    "type": "device_pending",
                    "device_id": str(device["id"]),
                },
            )
        except Exception:
            # Push delivery is best-effort and must never affect enrollment.
            pass

    @app.post(f"{MOBILE_PATH}/login", include_in_schema=False)
    def mobile_login(payload: dict[str, Any], request: Request):
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))
        totp_code = str(payload.get("totp_code", "")).strip() or None

        if not username or not password:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Username and password are required",
            )

        result = login_handler(
            SimpleNamespace(
                username=username,
                password=password,
                totp_code=totp_code,
            ),
            request,
            scope="mobile",
        )

        if (
            result["operator"]["role"] not in {"owner", "manager"}
            or result["operator"]["must_change_password"]
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This account cannot use the mobile app",
            )

        return {
            "access_token": result["access_token"],
            "refresh_token": result["refresh_token"],
            "token_type": "bearer",
            "access_expires_at": result["access_expires_at"],
            "session_expires_at": result["session_expires_at"],
            "operator": result["operator"],
        }

    @app.post(f"{MOBILE_PATH}/session/refresh", include_in_schema=False)
    def mobile_refresh(payload: dict[str, Any], request: Request):
        refresh_token = str(payload.get("refresh_token", ""))
        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="refresh_token is required",
            )
        return refresh_handler(
            SimpleNamespace(refresh_token=refresh_token),
            request,
        )

    @app.post(f"{MOBILE_PATH}/session/logout", include_in_schema=False)
    def mobile_logout(
        request: Request,
        operator: dict[str, Any] = Depends(require_operator_handler),
    ):
        return logout_handler(request, operator)

    @app.get(f"{MOBILE_PATH}/devices", include_in_schema=False)
    def mobile_devices(
        operator: dict[str, Any] = Depends(require_device_manager_handler),
    ):
        result = list_devices_handler(device_status=None, operator=operator)
        now = datetime.now(timezone.utc)

        items = []
        for device in result["items"]:
            last_seen_at = device.get("last_seen_at")
            online = (
                last_seen_at is not None
                and (now - last_seen_at).total_seconds() <= ONLINE_WINDOW_SECONDS
            )
            items.append(
                {
                    "id": device["id"],
                    "name": device.get("friendly_name") or device.get("hostname"),
                    "enrollment_status": device["status"],
                    "online": online,
                }
            )

        return {"items": items}

    @app.post(
        f"{MOBILE_PATH}/devices/{{device_id}}/approve",
        include_in_schema=False,
    )
    def mobile_approve_device(
        device_id,
        payload: dict[str, Any],
        request: Request,
        operator: dict[str, Any] = Depends(require_device_manager_handler),
    ):
        friendly_name_value = payload.get("friendly_name")
        friendly_name = (
            str(friendly_name_value).strip() if friendly_name_value else None
        )
        return approve_device_handler(
            device_id=device_id,
            payload=SimpleNamespace(
                friendly_name=friendly_name or None,
                reason=None,
            ),
            request=request,
            operator=operator,
        )

    def _mobile_device_status_action(handler, default_reason):
        def action(
            device_id,
            payload: dict[str, Any],
            request: Request,
            operator: dict[str, Any] = Depends(require_device_manager_handler),
        ):
            reason = str(payload.get("reason", "")).strip() or default_reason
            return handler(
                device_id=device_id,
                payload=SimpleNamespace(reason=reason),
                request=request,
                operator=operator,
            )

        return action

    app.post(
        f"{MOBILE_PATH}/devices/{{device_id}}/block",
        include_in_schema=False,
    )(
        _mobile_device_status_action(
            block_device_handler, "Blocked via mobile app"
        )
    )

    app.post(
        f"{MOBILE_PATH}/devices/{{device_id}}/revoke",
        include_in_schema=False,
    )(
        _mobile_device_status_action(
            revoke_device_handler, "Revoked via mobile app"
        )
    )

    @app.post(f"{MOBILE_PATH}/push-token", include_in_schema=False)
    def mobile_register_push_token(
        payload: dict[str, Any],
        operator: dict[str, Any] = Depends(require_operator_handler),
    ):
        fcm_token = str(payload.get("fcm_token", "")).strip()
        platform = str(payload.get("platform", "android")).strip() or "android"

        if not fcm_token:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="fcm_token is required",
            )
        if platform not in {"android", "ios"}:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="platform must be android or ios",
            )

        now = datetime.now(timezone.utc)
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO mobile_push_tokens (
                        account_id, fcm_token, platform, created_at, last_seen_at
                    )
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (fcm_token) DO UPDATE
                    SET account_id = EXCLUDED.account_id,
                        platform = EXCLUDED.platform,
                        last_seen_at = EXCLUDED.last_seen_at,
                        revoked_at = NULL
                    """,
                    (
                        operator["account_id"],
                        fcm_token,
                        platform,
                        now,
                        now,
                    ),
                )
                connection.commit()

        return {"status": "registered"}

    @app.post(
        f"{MOBILE_PATH}/internal/health-event",
        include_in_schema=False,
    )
    def internal_health_event(
        payload: dict[str, Any],
        x_health_watcher_secret: str | None = Header(default=None),
    ):
        # Pre-shared-secret auth, not an operator bearer token - the RDS and
        # Proxmox watcher scripts are not operator accounts and must not need
        # to be one; constant-time compare to avoid a timing side-channel.
        if not health_watcher_secret or not hmac.compare_digest(
            x_health_watcher_secret or "", health_watcher_secret
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid health-watcher credential",
            )

        condition_key = str(payload.get("condition_key", "")).strip()
        is_active = bool(payload.get("is_active"))
        detail = payload.get("detail")
        detail = str(detail).strip()[:2000] if detail else None

        if not condition_key:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="condition_key is required",
            )

        now = datetime.now(timezone.utc)

        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT condition_key, is_active, detail
                    FROM health_alert_state
                    WHERE condition_key = %s
                    FOR UPDATE
                    """,
                    (condition_key,),
                )
                previous = cursor.fetchone()

                state_changed = (
                    previous is None or previous["is_active"] != is_active
                )

                cursor.execute(
                    """
                    INSERT INTO health_alert_state (
                        condition_key, is_active, detail,
                        first_active_at, last_changed_at, last_reported_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (condition_key) DO UPDATE
                    SET is_active = EXCLUDED.is_active,
                        detail = EXCLUDED.detail,
                        first_active_at = CASE
                            WHEN health_alert_state.is_active = FALSE
                                 AND EXCLUDED.is_active = TRUE
                            THEN EXCLUDED.last_reported_at
                            WHEN EXCLUDED.is_active = FALSE THEN NULL
                            ELSE health_alert_state.first_active_at
                        END,
                        last_changed_at = CASE
                            WHEN health_alert_state.is_active != EXCLUDED.is_active
                            THEN EXCLUDED.last_reported_at
                            ELSE health_alert_state.last_changed_at
                        END,
                        last_reported_at = EXCLUDED.last_reported_at
                    """,
                    (
                        condition_key,
                        is_active,
                        detail,
                        now if is_active else None,
                        now,
                        now,
                    ),
                )
                connection.commit()

        if state_changed:
            if is_active:
                title = "Server health issue"
                body = detail or f"{condition_key} needs attention."
            else:
                title = "Server health issue resolved"
                body = f"{condition_key} is back to normal."

            try:
                send_push_to_all_registered(
                    title=title,
                    body=body,
                    data={"type": "health_alert", "condition_key": condition_key},
                )
            except Exception:
                pass

            try:
                send_email_handler(subject=title, body=body)
            except Exception:
                pass

        return {"status": "recorded", "state_changed": state_changed}

    app.state.notify_pending_device = notify_pending_device
