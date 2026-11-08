"""Phone-bound keys for the RDC Mobile Manager app (Brad 2026-10-12: the app is bound to one operator
account and never needs a sign-in, even after the first installation).

- Each app build carries a single-use pairing code for one operator account (create_pairing_code, run
  by an owner on RDS). On first launch the app makes a P-256 key in the phone's hardware keystore
  (non-exportable, usable only while the phone is unlocked) and pairs it: POST /pair. RDS binds the
  public key to that account, spends the code and mails Brad.
- From then on the app signs a fresh challenge whenever it needs a session: POST /key-login gets an
  ordinary mobile-scope session. There is no password, authenticator code or refresh token to lose.
- A paired phone is listed and revoked from the ops console (owner only).

The key stands in for the authenticator code on these sessions: a deliberate exception to "a code on
every sign-in", for mobile scope only, because the key never leaves the phone it was made on.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import Depends, HTTPException, Request, status

MOBILE_PATH = "/ops/api/mobile"
LOGIN_DOMAIN = b"rdc-mobile-key-v1\0"
LOGIN_SKEW_SECONDS = 300
NONCE_RETENTION = timedelta(minutes=15)
CODE_PREFIX = "rdcpair_"
MOBILE_ROLES = ("owner", "manager")


def code_hash(code: str) -> bytes:
    return hashlib.sha256(("mobile-pairing:" + code.strip()).encode()).digest()


def create_pairing_code(open_database_handler: Callable[..., Any], username: str, days: int = 7) -> str:
    """Owner tool (docker exec, PYTHONPATH=/app): a single-use pairing code for `username`'s phone."""
    code = CODE_PREFIX + secrets.token_urlsafe(32)
    with open_database_handler() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id FROM operator_accounts WHERE username = %s AND is_active AND role = ANY(%s) AND deleted_at IS NULL",
                (username, list(MOBILE_ROLES)),
            )
            account = cursor.fetchone()
            if account is None:
                raise SystemExit(f"no active owner/manager account named {username!r}")
            cursor.execute(
                "INSERT INTO mobile_pairing_codes (account_id, code_hash, expires_at) VALUES (%s, %s, now() + %s)",
                (account["id"], code_hash(code), timedelta(days=days)),
            )
        connection.commit()
    return code


def _b64(text: str) -> bytes:
    return base64.b64decode(text.strip(), validate=True)


def _p256_key(spki: bytes) -> ec.EllipticCurvePublicKey:
    key = serialization.load_der_public_key(spki)
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        raise ValueError("not a P-256 key")
    return key


def login_message(key_id: str, ts: int, nonce: bytes) -> bytes:
    return LOGIN_DOMAIN + key_id.encode() + b"\0" + str(ts).encode() + b"\0" + nonce


def register_mobile_key_routes(
    *,
    app: Any,
    admin_path: str,
    open_database_handler: Callable[..., Any],
    client_ip_handler: Callable[[Request], str | None],
    send_email_handler: Callable[..., None],
    issue_mobile_session_handler: Callable[..., dict[str, Any]],
    require_owner_cookie_handler: Callable[..., dict[str, Any]],
    refuse_protected_target_handler: Callable[..., None],
    clean_name_handler: Callable[[str | None], str | None],
) -> None:
    def refused() -> HTTPException:
        # One answer for every failure, so a probe learns nothing about codes or keys.
        return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Phone is not paired")

    @app.post(f"{MOBILE_PATH}/pair", include_in_schema=False)
    def mobile_pair(payload: dict[str, Any], request: Request):
        code = str(payload.get("pairing_code", ""))
        # Control, bidi and invisible characters out (main.clean_display_name): the name goes into
        # the audit row, the Paired phones list and the alert mail's subject.
        device_name = (clean_name_handler(str(payload.get("device_name", ""))) or "")[:120].strip() or "Android phone"
        try:
            spki = _b64(str(payload.get("public_key", "")))
            _p256_key(spki)
        except Exception:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="public_key must be a P-256 key")
        if not code.startswith(CODE_PREFIX):
            raise refused()
        source_ip = client_ip_handler(request)
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT c.id AS code_id, a.id AS account_id, a.username
                    FROM mobile_pairing_codes c JOIN operator_accounts a ON a.id = c.account_id
                    WHERE c.code_hash = %s AND c.used_at IS NULL AND c.expires_at > now()
                      AND a.is_active AND a.role = ANY(%s) AND NOT a.must_change_password AND a.deleted_at IS NULL
                    FOR UPDATE OF c
                    """,
                    (code_hash(code), list(MOBILE_ROLES)),
                )
                row = cursor.fetchone()
                if row is None:
                    raise refused()
                cursor.execute(
                    """
                    INSERT INTO mobile_device_keys (account_id, public_key, device_name, paired_ip)
                    VALUES (%s, %s, %s, %s::inet) RETURNING id
                    """,
                    (row["account_id"], spki, device_name, source_ip),
                )
                key_id = cursor.fetchone()["id"]
                cursor.execute(
                    "UPDATE mobile_pairing_codes SET used_at = now(), used_by_key = %s WHERE id = %s",
                    (key_id, row["code_id"]),
                )
                cursor.execute(
                    """
                    INSERT INTO audit_events (actor_account_id, event_type, target_type, target_id, source_ip, details)
                    VALUES (%s, 'mobile.phone_paired', 'operator_account', %s, %s::inet,
                            jsonb_build_object('username', %s::text, 'key_id', %s::text, 'device', %s::text))
                    """,
                    (row["account_id"], row["account_id"], source_ip, row["username"], str(key_id), device_name),
                )
            connection.commit()
        try:
            send_email_handler(
                subject=f"RDC Mobile Manager paired: {device_name}",
                body=(
                    f"A phone was paired with the RDS account {row['username']} for RDC Mobile Manager.\n\n"
                    f"Phone: {device_name}\nFrom address: {source_ip}\n"
                    f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n"
                    "It signs in with a key that never leaves the phone, so no password or authenticator code "
                    "is asked again. If this wasn't you, revoke it in the ops console (Config, Security, Paired phones)."
                ),
            )
        except Exception:
            pass
        return {"key_id": str(key_id), "username": row["username"]}

    @app.post(f"{MOBILE_PATH}/key-login", include_in_schema=False)
    def mobile_key_login(payload: dict[str, Any], request: Request):
        try:
            key_id = str(uuid.UUID(str(payload.get("key_id", ""))))
            ts = int(payload.get("ts"))
            nonce = _b64(str(payload.get("nonce", "")))
            signature = _b64(str(payload.get("signature", "")))
        except (TypeError, ValueError):
            raise refused()
        if len(nonce) != 16 or abs(time.time() - ts) > LOGIN_SKEW_SECONDS:
            raise refused()
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT k.public_key, a.id AS account_id, a.username, a.display_name, a.role,
                           a.must_change_password, a.totp_enabled
                    FROM mobile_device_keys k JOIN operator_accounts a ON a.id = k.account_id
                    WHERE k.id = %s AND k.revoked_at IS NULL
                      AND a.is_active AND a.role = ANY(%s) AND NOT a.must_change_password AND a.deleted_at IS NULL
                    """,
                    (key_id, list(MOBILE_ROLES)),
                )
                row = cursor.fetchone()
                if row is None:
                    raise refused()
                try:
                    _p256_key(bytes(row["public_key"])).verify(
                        signature, login_message(key_id, ts, nonce), ec.ECDSA(hashes.SHA256())
                    )
                except (InvalidSignature, ValueError):
                    raise refused()
                # Each signed challenge works once (the nonces live as long as the skew window needs).
                cursor.execute(
                    "DELETE FROM mobile_key_nonces WHERE seen_at < now() - %s", (NONCE_RETENTION,)
                )
                cursor.execute(
                    "INSERT INTO mobile_key_nonces (nonce_hash) VALUES (%s) ON CONFLICT DO NOTHING",
                    (hashlib.sha256(nonce).digest(),),
                )
                if cursor.rowcount != 1:
                    raise refused()
                cursor.execute(
                    "UPDATE mobile_device_keys SET last_used_at = now(), last_ip = %s::inet WHERE id = %s",
                    (client_ip_handler(request), key_id),
                )
                result = issue_mobile_session_handler(cursor, row, request, key_id)
            connection.commit()
        return result

    @app.get(f"{admin_path}/api/mobile-phones", include_in_schema=False)
    def list_paired_phones(owner: dict[str, Any] = Depends(require_owner_cookie_handler)):
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT k.id, a.username, k.device_name, k.created_at, k.last_used_at, host(k.paired_ip) AS paired_ip
                    FROM mobile_device_keys k JOIN operator_accounts a ON a.id = k.account_id
                    WHERE k.revoked_at IS NULL ORDER BY k.created_at DESC
                    """
                )
                return {"phones": [{**r, "id": str(r["id"])} for r in cursor.fetchall()]}

    @app.post(f"{admin_path}/api/mobile-phones/{{key_id}}/revoke", include_in_schema=False)
    def revoke_paired_phone(
        key_id: uuid.UUID, request: Request, owner: dict[str, Any] = Depends(require_owner_cookie_handler)
    ):
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT a.id, a.username FROM mobile_device_keys k JOIN operator_accounts a ON a.id = k.account_id
                    WHERE k.id = %s AND k.revoked_at IS NULL
                    """,
                    (key_id,),
                )
                target = cursor.fetchone()
                if target is None:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such paired phone")
                # Brad's phones are Brad's to revoke (main.py refuse_protected_brad_target).
                refuse_protected_target_handler(
                    connection, cursor, owner, target, "revoke_paired_phone", client_ip_handler(request)
                )
                cursor.execute(
                    "UPDATE mobile_device_keys SET revoked_at = now(), revoked_by = %s WHERE id = %s AND revoked_at IS NULL RETURNING account_id",
                    (owner["account_id"], key_id),
                )
                row = cursor.fetchone()
                if row is None:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such paired phone")
                # Its sessions end with it.
                cursor.execute(
                    """
                    UPDATE operator_sessions SET revoked_at = now(), revoked_by = %s, revocation_reason = 'mobile_phone_revoked'
                    WHERE mobile_key_id = %s AND revoked_at IS NULL
                    """,
                    (owner["account_id"], key_id),
                )
                cursor.execute(
                    """
                    INSERT INTO audit_events (actor_account_id, event_type, target_type, target_id, details)
                    VALUES (%s, 'mobile.phone_revoked', 'operator_account', %s, jsonb_build_object('key_id', %s::text))
                    """,
                    (owner["account_id"], row["account_id"], str(key_id)),
                )
            connection.commit()
        return {"revoked": str(key_id)}
