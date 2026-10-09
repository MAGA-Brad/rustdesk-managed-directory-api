"""Cloudflare mTLS client certificates for the RDS edge (client.example.com and ops.example.com).

Cloudflare's managed client CA signs every certificate; a WAF rule at the edge can then refuse any
request that does not present one (enforcement is switched on separately, once every client has one).

- Devices send a CSR: the private key is generated on, and never leaves, the device.
- The Android app sends a CSR the same way.
- Browsers cannot produce a client-certificate request themselves, so RDS generates the key and hands
  it out once as a password-protected PKCS#12 bundle to import.

Revoking a certificate here - or blocking/revoking a device - revokes it at Cloudflare too.
"""
from __future__ import annotations

import base64
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from fastapi import Depends, HTTPException, Request, status

CF_API = "https://api.cloudflare.com/client/v4"
CERT_VALIDITY_DAYS = 365
RENEW_BEFORE_DAYS = 30
DEVICE_REISSUE_MIN_INTERVAL = timedelta(hours=1)
_PASSWORD_ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"


def _cloudflare() -> tuple[str, str]:
    token = os.environ.get("CF_EDGE_CERT_TOKEN", "").strip()
    zone = os.environ.get("CF_ZONE_ID", "").strip()
    if not token or not zone:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Edge client certificates are not configured",
        )
    return token, zone


def _cf_sign(csr_pem: str) -> dict[str, Any]:
    token, zone = _cloudflare()
    with httpx.Client(timeout=20.0) as client:
        response = client.post(
            f"{CF_API}/zones/{zone}/client_certificates",
            headers={"Authorization": f"Bearer {token}"},
            json={"csr": csr_pem, "validity_days": CERT_VALIDITY_DAYS},
        )
    try:
        data = response.json()
    except ValueError:
        data = {}
    if response.status_code >= 300 or not data.get("success"):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Cloudflare could not issue the certificate",
        )
    return data["result"]


def cf_revoke(cf_cert_id: str) -> bool:
    try:
        token, zone = _cloudflare()
    except HTTPException:
        return False
    try:
        with httpx.Client(timeout=20.0) as client:
            response = client.delete(
                f"{CF_API}/zones/{zone}/client_certificates/{cf_cert_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError:
        return False
    return response.status_code < 300


def _validate_csr(csr_pem: str, expected_cn: str) -> None:
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        raise HTTPException(status_code=422, detail="Invalid certificate signing request")
    if not csr.is_signature_valid:
        raise HTTPException(status_code=422, detail="Certificate signing request signature is invalid")
    key = csr.public_key()
    if isinstance(key, ec.EllipticCurvePublicKey):
        if key.curve.name not in ("secp256r1", "secp384r1"):
            raise HTTPException(status_code=422, detail="Unsupported elliptic curve")
    elif isinstance(key, rsa.RSAPublicKey):
        if key.key_size < 2048:
            raise HTTPException(status_code=422, detail="RSA keys must be at least 2048 bits")
    else:
        raise HTTPException(status_code=422, detail="Unsupported key type")
    names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not names or names[0].value != expected_cn:
        raise HTTPException(status_code=422, detail=f"Certificate common name must be {expected_cn}")


def _expires_at(result: dict[str, Any]) -> datetime:
    raw = str(result.get("expires_on") or "")
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc) + timedelta(days=CERT_VALIDITY_DAYS)


def _record(cursor, *, kind: str, result: dict[str, Any], device_id=None, operator_id=None, label: str = "") -> datetime:
    expires_at = _expires_at(result)
    cursor.execute(
        """
        INSERT INTO edge_client_certs
            (kind, device_id, operator_account_id, label, cf_cert_id, serial_number, fingerprint_sha256, expires_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (kind, device_id, operator_id, label[:160], result["id"], result.get("serial_number"),
         result.get("fingerprint_sha256"), expires_at),
    )
    return expires_at


def _revoke_rows(cursor, rows, reason: str) -> int:
    revoked = 0
    for row in rows:
        ok = cf_revoke(row["cf_cert_id"])
        cursor.execute(
            """
            UPDATE edge_client_certs
            SET revoked_at = CASE WHEN %s THEN now() ELSE revoked_at END,
                revoke_reason = %s
            WHERE id = %s
            """,
            (ok, reason if ok else f"{reason} (Cloudflare revoke failed - retry)", row["id"]),
        )
        revoked += 1 if ok else 0
    return revoked


def revoke_device_edge_certs(cursor, device_id, reason: str = "device blocked or revoked") -> int:
    """Called from change_device_status inside its transaction."""
    cursor.execute(
        "SELECT id, cf_cert_id FROM edge_client_certs WHERE device_id = %s AND revoked_at IS NULL",
        (device_id,),
    )
    return _revoke_rows(cursor, cursor.fetchall(), reason)


def note_edge_verification(cursor, device_id, headers, now) -> None:
    """Heartbeat hook: Cloudflare's transform rule sets X-Edge-Client-Cert-Verified (overwriting any
    client-supplied value), and Authenticated Origin Pulls means only Cloudflare reaches this origin."""
    if headers.get("x-edge-client-cert-verified") != "true":
        return
    cursor.execute(
        """
        UPDATE managed_devices
        SET edge_cert_verified_at = %s, edge_cert_fingerprint = %s
        WHERE id = %s
        """,
        (now, str(headers.get("x-edge-client-cert-fingerprint") or "")[:128], device_id),
    )


def _p12_password() -> str:
    return "-".join("".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(5)) for _ in range(4))


def register_edge_cert_routes(
    *,
    app: Any,
    open_database_handler: Callable[..., Any],
    require_device_handler: Callable[..., dict[str, Any]],
    require_operator_bearer_handler: Callable[..., dict[str, Any]],
    require_operator_cookie_handler: Callable[..., dict[str, Any]],
    require_owner_cookie_handler: Callable[..., dict[str, Any]],
    admin_path: str = "/ops",
    mobile_path: str = "/ops/api/mobile",
) -> None:
    @app.post("/v1/device/edge-cert")
    def issue_device_edge_cert(
        payload: dict[str, Any],
        device: dict[str, Any] = Depends(require_device_handler),
    ):
        csr_pem = str(payload.get("csr", ""))
        _validate_csr(csr_pem, f"rdc-device:{device['rustdesk_id']}")
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT max(created_at) AS last FROM edge_client_certs WHERE device_id = %s AND kind = 'device'",
                    (device["device_id"],),
                )
                last = cursor.fetchone()["last"]
                if last is not None and datetime.now(timezone.utc) - last < DEVICE_REISSUE_MIN_INTERVAL:
                    raise HTTPException(status_code=429, detail="A certificate was issued less than an hour ago")
                cursor.execute(
                    "SELECT id, cf_cert_id FROM edge_client_certs WHERE device_id = %s AND kind = 'device' AND revoked_at IS NULL",
                    (device["device_id"],),
                )
                previous = cursor.fetchall()
                result = _cf_sign(csr_pem)
                expires_at = _record(cursor, kind="device", result=result, device_id=device["device_id"],
                                     label=device.get("friendly_name") or device.get("hostname") or "")
                _revoke_rows(cursor, previous, "replaced by a newer device certificate")
                connection.commit()
        return {
            "certificate": result["certificate"],
            "expires_at": expires_at,
            "expires_at_unix": int(expires_at.timestamp()),
            "renew_before_days": RENEW_BEFORE_DAYS,
        }

    def _issue_for_operator(operator: dict[str, Any], label: str, csr_pem: str | None) -> dict[str, Any]:
        common_name = f"rds-operator:{operator['account_id']}"
        if csr_pem:
            _validate_csr(csr_pem, common_name)
            result = _cf_sign(csr_pem)
            kind, response = "mobile", {"certificate": result["certificate"]}
        else:
            key = ec.generate_private_key(ec.SECP256R1())
            csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
                .sign(key, hashes.SHA256())
            )
            result = _cf_sign(csr.public_bytes(serialization.Encoding.PEM).decode("ascii"))
            certificate = x509.load_pem_x509_certificate(result["certificate"].encode("ascii"))
            password = _p12_password()
            encryption = (
                serialization.PrivateFormat.PKCS12.encryption_builder()
                .kdf_rounds(50000)
                .key_cert_algorithm(pkcs12.PBES.PBESv2SHA256AndAES256CBC)
                .hmac_hash(hashes.SHA256())
                .build(password.encode("ascii"))
            )
            bundle = pkcs12.serialize_key_and_certificates(
                name=f"RDS operator {operator['username']}".encode("utf-8"),
                key=key, cert=certificate, cas=None, encryption_algorithm=encryption,
            )
            kind = "browser"
            response = {
                "filename": f"rds-{operator['username']}.p12",
                "p12_base64": base64.b64encode(bundle).decode("ascii"),
                "password": password,
            }
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                expires_at = _record(cursor, kind=kind, result=result, operator_id=operator["account_id"], label=label)
                connection.commit()
        response["expires_at"] = expires_at
        response["renew_before_days"] = RENEW_BEFORE_DAYS
        return response

    @app.post(f"{admin_path}/api/me/edge-cert", include_in_schema=False)
    def issue_browser_edge_cert(
        request: Request,
        operator: dict[str, Any] = Depends(require_operator_cookie_handler),
    ):
        """Ops console: RDS generates the key and returns a password-protected PKCS#12 to import."""
        return _issue_for_operator(operator, str(request.headers.get("user-agent") or ""), None)

    @app.post(f"{mobile_path}/edge-cert", include_in_schema=False)
    def issue_mobile_edge_cert(
        payload: dict[str, Any],
        request: Request,
        operator: dict[str, Any] = Depends(require_operator_bearer_handler),
    ):
        """Android app: sends a CSR at login; its key never leaves the phone."""
        csr_pem = str(payload.get("csr") or "")
        if not csr_pem:
            raise HTTPException(status_code=422, detail="csr is required")
        label = str(payload.get("label") or request.headers.get("user-agent") or "Android app")
        return _issue_for_operator(operator, label, csr_pem)

    @app.get(f"{admin_path}/api/me/edge-certs", include_in_schema=False)
    def list_own_edge_certs(operator: dict[str, Any] = Depends(require_operator_cookie_handler)):
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, kind, label, created_at, expires_at, revoked_at
                    FROM edge_client_certs
                    WHERE operator_account_id = %s
                    ORDER BY created_at DESC
                    """,
                    (operator["account_id"],),
                )
                return {"items": cursor.fetchall()}

    @app.post(f"{admin_path}/api/me/edge-certs/{{cert_id}}/revoke", include_in_schema=False)
    def revoke_own_edge_cert(cert_id: uuid.UUID, operator: dict[str, Any] = Depends(require_operator_cookie_handler)):
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, cf_cert_id FROM edge_client_certs
                    WHERE id = %s AND operator_account_id = %s AND revoked_at IS NULL
                    """,
                    (cert_id, operator["account_id"]),
                )
                rows = cursor.fetchall()
                if not rows:
                    raise HTTPException(status_code=404, detail="Certificate not found")
                revoked = _revoke_rows(cursor, rows, "revoked by its operator")
                connection.commit()
        return {"revoked": revoked}

    @app.get(f"{admin_path}/api/edge-certs/summary", include_in_schema=False)
    def edge_cert_summary(owner: dict[str, Any] = Depends(require_owner_cookie_handler)):
        """Enforcement readiness: every approved device and its newest valid edge certificate."""
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT d.friendly_name, d.reported_build_number, d.last_seen_at,
                           (SELECT max(c.expires_at) FROM edge_client_certs c
                             WHERE c.device_id = d.id AND c.revoked_at IS NULL AND c.expires_at > now()) AS cert_expires_at,
                           d.edge_cert_verified_at
                    FROM managed_devices d
                    WHERE d.status = 'approved'
                    ORDER BY d.friendly_name
                    """
                )
                devices = cursor.fetchall()
                cursor.execute(
                    """
                    SELECT kind, count(*) AS active FROM edge_client_certs
                    WHERE revoked_at IS NULL AND expires_at > now() GROUP BY kind
                    """
                )
                counts = {row["kind"]: row["active"] for row in cursor.fetchall()}
        recent = datetime.now(timezone.utc) - timedelta(hours=24)
        return {
            "devices": devices,
            "devices_ready": sum(1 for d in devices if d["cert_expires_at"] is not None),
            "devices_verified_at_edge_24h": sum(
                1 for d in devices if d["edge_cert_verified_at"] is not None and d["edge_cert_verified_at"] >= recent
            ),
            "devices_total": len(devices),
            "active_by_kind": counts,
        }

