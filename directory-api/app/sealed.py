"""Sealed transport: application-layer end-to-end encryption for managed-client (RDC) API calls.

Networks that inspect HTTPS (schools, hospitals, government buildings, corporate filters) terminate
TLS with their own certificate authority. Build 29+ clients refuse such certificates, so on those
networks the client wraps each API call in an envelope encrypted to RDS's own X25519 key, which is
embedded in the client at build time. Whatever terminates TLS on the way sees only opaque bytes: it
cannot read the call or its credential, alter or replay it, or forge RDS's answer. Clients seal every
call they can, not only on inspected networks, so Cloudflare never sees plaintext API traffic either.

Wire format (binary; the RDC side is src/managed_sealed.rs):
  request  = b"RDS1" | key_id(8) | eph_pub(32) | ChaCha20-Poly1305(k_req, zero nonce, aad=first 44 bytes)(inner)
  response = b"RDR1" | ChaCha20-Poly1305(k_resp, zero nonce, aad=b"RDR1" | eph_pub)(inner)
  k_req | k_resp = HKDF-SHA256(ikm=X25519(eph, server), salt=eph_pub | server_pub, info=b"rdc-sealed-v1", L=64)
  inner = u32 big-endian meta length | meta JSON | body
Every request uses a fresh ephemeral key, so each derived key encrypts exactly one message (the zero
nonce is safe) and the ephemeral public key doubles as the replay identifier.

The decrypted call runs through this same app in-process, so authentication, rate limits and the
caller's real IP apply exactly as for an unsealed call.

Devices on inspected networks are served (the calls are sealed), and each new network or new device
on one alerts Brad by email and push with the details. Brad can block a network; a device set to
'strict' is never served through an inspected network.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import struct
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import urlsplit

import httpx
import jwt
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, Response

SEALED_PATH = "/v1/sealed"
REQ_MAGIC = b"RDS1"
RESP_MAGIC = b"RDR1"
HKDF_INFO = b"rdc-sealed-v1"
HEADER_LEN = 4 + 8 + 32
ZERO_NONCE = b"\x00" * 12
MAX_SEALED_REQUEST = 24 * 1024 * 1024
MAX_INNER_RESPONSE = 32 * 1024 * 1024
CLOCK_SKEW_SECONDS = 600
REPLAY_RETENTION = timedelta(minutes=25)  # must outlast the clock-skew window on both sides
INNER_TIMEOUT_SECONDS = 300.0
ALERT_REPEAT = timedelta(hours=24)
INSPECTED_RETRY_AFTER_SECONDS = 120
PUSH_USERNAMES_SETTING = "inspection.alert_push_usernames"
LOG = logging.getLogger("uvicorn.error")
AUTO_APPROVE_CLASSES = ("school", "hospital", "government")
METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
# What a sealed call may carry. Everything describing the connection itself (client IP, edge
# certificate, host) comes from the outer request instead, so it cannot be forged from inside.
INNER_REQUEST_HEADERS = {
    "authorization", "content-type", "accept", "user-agent", "range",
    "upload-offset", "upload-length", "x-content-sha256", "if-match", "if-none-match",
}
OUTER_FORWARDED_HEADERS = (
    "x-edge-client-cert-verified", "x-edge-client-cert-fingerprint",
    "cf-connecting-ip", "cf-ipcountry", "x-forwarded-for", "x-forwarded-proto",
)
DROP_RESPONSE_HEADERS = {
    "content-length", "content-encoding", "transfer-encoding", "connection", "keep-alive",
    "set-cookie", "server", "date",
}
# Calls that must work before a device holds a credential or an edge certificate.
BOOTSTRAP_PREFIXES = ("/v1/enrollment/", "/v1/device/edge-cert", "/v1/peer-auth/ca")
USER_AGENT = "rustdesk-directory-sealed/1.0"

# Network-ownership evidence only: RDAP registration names and forward-confirmed reverse DNS. The
# inspecting certificate's own name is shown to Brad but never counted, because whoever intercepts
# chooses it.
CLASS_PATTERNS: dict[str, list[str]] = {
    "school": [
        r"\bschools?\b", r"\bk-?12\b", r"\bisd\b", r"\bschool district\b", r"\bacademy\b",
        r"\buniversity\b", r"\bcollege\b", r"\beducation(al)?\b", r"\.edu$", r"\.k12\.[a-z]{2}\.us$",
    ],
    "hospital": [
        r"\bhospitals?\b", r"\bhealth ?(care|system|services)?\b", r"\bmedical\b", r"\bclinics?\b",
    ],
    "government": [
        r"\.gov$", r"\.mil$", r"\bcity of\b", r"\bcounty\b", r"\bstate of\b", r"\bpolice\b",
        r"\bsheriff\b", r"\bdepartment of\b", r"\bgovernment\b", r"\bmunicipal(ity)?\b",
        r"\bpublic safety\b", r"\.(state|co|ci)\.[a-z]{2}\.us$",
    ],
}


class _BadEnvelope(Exception):
    pass


class _ServerKey:
    def __init__(self, private: X25519PrivateKey):
        self.private = private
        self.public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.key_id = hashlib.sha256(self.public).digest()[:8]


def _load_keys() -> dict[bytes, _ServerKey]:
    # The previous key keeps already-shipped clients working while a rotated key rolls out.
    keys: dict[bytes, _ServerKey] = {}
    for name in ("SEALED_X25519_PRIVATE_KEY", "SEALED_X25519_PREVIOUS_PRIVATE_KEY"):
        raw = os.environ.get(name, "").strip()
        if raw:
            key = _ServerKey(X25519PrivateKey.from_private_bytes(base64.b64decode(raw)))
            keys[key.key_id] = key
    return keys


def _derive(shared: bytes, eph_pub: bytes, server_pub: bytes) -> tuple[bytes, bytes]:
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=eph_pub + server_pub, info=HKDF_INFO).derive(shared)
    return okm[:32], okm[32:]


def open_request(keys: dict[bytes, _ServerKey], blob: bytes) -> tuple[bytes, bytes, dict[str, Any], bytes]:
    """Returns (eph_pub, response key, meta, body)."""
    if len(blob) < HEADER_LEN + 4 + 16 or blob[:4] != REQ_MAGIC:
        raise _BadEnvelope("framing")
    key = keys.get(blob[4:12])
    if key is None:
        raise _BadEnvelope("unknown key id")
    eph_pub = blob[12:HEADER_LEN]
    try:
        shared = key.private.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    except ValueError as error:  # low-order point: all-zero shared secret
        raise _BadEnvelope("ephemeral key") from error
    k_req, k_resp = _derive(shared, eph_pub, key.public)
    try:
        inner = ChaCha20Poly1305(k_req).decrypt(ZERO_NONCE, blob[HEADER_LEN:], blob[:HEADER_LEN])
    except InvalidTag as error:
        raise _BadEnvelope("authentication") from error
    (meta_len,) = struct.unpack(">I", inner[:4])
    if meta_len > len(inner) - 4:
        raise _BadEnvelope("meta length")
    try:
        meta = json.loads(inner[4 : 4 + meta_len])
    except ValueError as error:
        raise _BadEnvelope("meta json") from error
    if not isinstance(meta, dict):
        raise _BadEnvelope("meta type")
    return eph_pub, k_resp, meta, inner[4 + meta_len :]


def seal_response(k_resp: bytes, eph_pub: bytes, status_code: int, headers: list[list[str]], body: bytes) -> bytes:
    meta = json.dumps({"s": status_code, "h": headers}, separators=(",", ":")).encode()
    inner = struct.pack(">I", len(meta)) + meta + body
    return RESP_MAGIC + ChaCha20Poly1305(k_resp).encrypt(ZERO_NONCE, inner, RESP_MAGIC + eph_pub)


def inner_target(meta: dict[str, Any]) -> tuple[str, str, list[tuple[str, str]]]:
    method = str(meta.get("m", "")).upper()
    target = str(meta.get("p", ""))
    if method not in METHODS:
        raise _BadEnvelope("method")
    if (
        len(target) > 4096
        or not re.fullmatch(r"[\x21-\x7e]+", target)
        or not target.startswith("/v1/")
        or target.startswith(SEALED_PATH)
    ):
        raise _BadEnvelope("target")
    parts = urlsplit(target)
    if parts.scheme or parts.netloc or parts.fragment:
        raise _BadEnvelope("target form")
    path = parts.path
    if "//" in path or "\\" in path or "%" in path or "/./" in path or "/../" in path or path.endswith(("/.", "/..")):
        raise _BadEnvelope("target path")
    try:
        sent_at = float(meta.get("t"))
    except (TypeError, ValueError) as error:
        raise _BadEnvelope("timestamp") from error
    if abs(time.time() - sent_at) > CLOCK_SKEW_SECONDS:
        raise _BadEnvelope("clock skew")
    raw_headers = meta.get("h") or []
    if not isinstance(raw_headers, list) or len(raw_headers) > 32:
        raise _BadEnvelope("headers")
    headers: list[tuple[str, str]] = []
    for pair in raw_headers:
        if not (isinstance(pair, list) and len(pair) == 2):
            raise _BadEnvelope("header pair")
        name, value = str(pair[0]).lower(), str(pair[1])
        if name not in INNER_REQUEST_HEADERS:
            continue
        if len(value) > 8192 or "\r" in value or "\n" in value:
            raise _BadEnvelope("header value")
        headers.append((name, value))
    return method, target, headers


def inspection_info(meta: dict[str, Any]) -> dict[str, str | None] | None:
    """Present when the client reached RDS through a TLS interceptor (its own report)."""
    info = meta.get("i")
    if not isinstance(info, dict):
        return None

    def text(key: str, limit: int) -> str | None:
        value = info.get(key)
        return str(value)[:limit] if value not in (None, "") else None

    return {
        "issuer": text("issuer", 512),
        "subject": text("subject", 512),
        "ca_key_id": text("ca_key_id", 128),
        "leaf_sha256": text("leaf_sha256", 64),
    }


async def _read_bounded(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Sealed request too large")
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Sealed request too large")
        chunks.append(chunk)
    return b"".join(chunks)


def _bearer(headers: list[tuple[str, str]]) -> str | None:
    for name, value in headers:
        if name == "authorization" and value[:7].lower() == "bearer ":
            return value[7:].strip()
    return None


# --- network classification -------------------------------------------------------------------


def _rdap(ip: str) -> dict[str, Any]:
    with httpx.Client(timeout=10.0, follow_redirects=True, headers={"User-Agent": USER_AGENT}) as client:
        response = client.get(f"https://rdap.org/ip/{ip}")
    response.raise_for_status()
    data = response.json()
    names: list[str] = []

    def walk(entity: dict[str, Any]) -> None:
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1:
            for item in vcard[1]:
                if isinstance(item, list) and len(item) > 3 and item[0] in ("fn", "org") and isinstance(item[3], str):
                    names.append(item[3])
        for child in entity.get("entities") or []:
            if isinstance(child, dict):
                walk(child)

    for entity in data.get("entities") or []:
        if isinstance(entity, dict):
            walk(entity)
    remarks = [
        line
        for remark in data.get("remarks") or []
        for line in (remark.get("description") or [])
        if isinstance(line, str)
    ]
    netblock = None
    address = ipaddress.ip_address(ip)
    for cidr in data.get("cidr0_cidrs") or []:
        prefix = cidr.get("v4prefix") or cidr.get("v6prefix")
        if prefix and cidr.get("length") is not None:
            network = ipaddress.ip_network(f"{prefix}/{cidr['length']}", strict=False)
            if address in network:
                netblock = str(network)
    if netblock is None and data.get("startAddress") and data.get("endAddress"):
        try:
            for network in ipaddress.summarize_address_range(
                ipaddress.ip_address(data["startAddress"]), ipaddress.ip_address(data["endAddress"])
            ):
                if address in network:
                    netblock = str(network)
        except (ValueError, TypeError):
            pass
    org = next((name for name in names if name), None)
    return {
        "network": data.get("name"),
        "org": org,
        "names": names[:12],
        "remarks": remarks[:6],
        "country": data.get("country"),
        "netblock": netblock,
    }


def _reverse_dns(ip: str) -> tuple[str | None, bool]:
    try:
        name = socket.gethostbyaddr(ip)[0].rstrip(".").lower()
    except OSError:
        return None, False
    try:
        confirmed = any(info[4][0] == ip for info in socket.getaddrinfo(name, None))
    except OSError:
        confirmed = False
    return name, confirmed


def classify_network(ip: str) -> dict[str, Any]:
    result: dict[str, Any] = {"evidence": []}
    try:
        rdap = _rdap(ip)
    except Exception as error:  # registry outages must never block the alert itself
        rdap = {}
        result["rdap_error"] = type(error).__name__
    result.update(
        rdap_org=rdap.get("org"),
        rdap_network=rdap.get("network"),
        rdap_netblock=rdap.get("netblock"),
        rdap_country=rdap.get("country"),
    )
    ptr_name, ptr_confirmed = _reverse_dns(ip)
    result.update(ptr_name=ptr_name, ptr_confirmed=ptr_confirmed)

    sources = [("registration", value) for value in [rdap.get("network"), *(rdap.get("names") or []), *(rdap.get("remarks") or [])] if value]
    if ptr_name and ptr_confirmed:
        sources.append(("reverse DNS", ptr_name))
    matched: list[str] = []
    for label, value in sources:
        lowered = value.lower()
        for cls, patterns in CLASS_PATTERNS.items():
            if any(re.search(pattern, lowered) for pattern in patterns):
                result["evidence"].append(f"{cls}: {label} '{value}'")
                if cls not in matched:
                    matched.append(cls)
    result["classification"] = matched[0] if len(matched) == 1 else None
    if len(matched) > 1:
        result["evidence"].append("conflicting classes - left for a manual decision")
    return result


# --- routes -----------------------------------------------------------------------------------


def register_sealed_routes(
    *,
    app: Any,
    admin_path: str,
    open_database_handler: Callable[..., Any],
    validate_device_credential_handler: Callable[[str], dict[str, Any]],
    require_owner_cookie_handler: Callable[..., dict[str, Any]],
    send_alert_email_handler: Callable[..., None],
    alert_account_id: Any,
) -> None:
    keys = _load_keys()
    require_edge_cert = os.environ.get("SEALED_REQUIRE_EDGE_CERT", "").strip() == "1"
    maintenance_started = False

    async def _maintenance_forever() -> None:
        while True:
            try:
                def purge() -> None:
                    with open_database_handler() as connection:
                        with connection.cursor() as cursor:
                            cursor.execute(
                                "DELETE FROM sealed_replay WHERE seen_at < now() - %s",
                                (REPLAY_RETENTION,),
                            )
                        connection.commit()

                await asyncio.to_thread(purge)
            except Exception:
                pass
            await asyncio.sleep(300)

    def _claim_replay_slot(eph_pub: bytes) -> bool:
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO sealed_replay (eph_hash) VALUES (%s) ON CONFLICT DO NOTHING",
                    (hashlib.sha256(eph_pub).digest(),),
                )
                fresh = cursor.rowcount == 1
            connection.commit()
        return fresh

    def _push_account_ids() -> list[Any]:
        """Brad's account plus any owner accounts named in the directory setting
        inspection.alert_push_usernames (a JSON list) - e.g. the account his phone app signs in as."""
        ids = [alert_account_id]
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT setting_value FROM directory_settings WHERE setting_key = %s",
                    (PUSH_USERNAMES_SETTING,),
                )
                row = cursor.fetchone()
                names = row["setting_value"] if row else None
                if isinstance(names, list) and names:
                    cursor.execute(
                        "SELECT id FROM operator_accounts WHERE username = ANY(%s) AND role = 'owner'",
                        ([str(name) for name in names],),
                    )
                    ids += [found["id"] for found in cursor.fetchall() if found["id"] != alert_account_id]
        return ids

    def _alert(subject: str, lines: list[str], push_title: str, push_body: str, network_id: str) -> None:
        try:
            send_alert_email_handler(subject=subject, body="\n".join(lines))
        except Exception:
            pass
        push = getattr(app.state, "send_push_to_account", None)
        if push is None:
            return
        try:
            account_ids = _push_account_ids()
        except Exception:
            account_ids = [alert_account_id]
        for account_id in account_ids:
            try:
                push(
                    account_id,
                    title=push_title,
                    body=push_body,
                    data={"type": "inspection_network", "network_id": network_id},
                )
            except Exception as error:
                LOG.warning("inspection alert push to %s failed: %s: %s", account_id, type(error).__name__, error)
        LOG.info("inspection alert for network %s: email attempted, push to %d account(s)", network_id, len(account_ids))

    def _describe(network: dict[str, Any], device: dict[str, Any] | None, info: dict[str, Any] | None, ops_url: str) -> list[str]:
        ptr = network.get("ptr_name") or "none"
        if network.get("ptr_name"):
            ptr += " (forward-confirmed)" if network.get("ptr_confirmed") else " (not forward-confirmed)"
        evidence = network.get("evidence") or []
        lines = []
        if device is not None:
            lines += [
                f"Device: {device.get('friendly_name') or device.get('hostname')} ({device.get('hostname')}), RustDesk ID {device.get('rustdesk_id')}",
                f"Device policy for inspected networks: {device.get('inspected_network_policy', 'auto')}",
            ]
        lines += [
            f"Public address: {network.get('cidr')}",
            f"Reverse DNS: {ptr}",
            f"Registered to: {network.get('rdap_org') or 'unknown'} (network {network.get('rdap_network') or '?'}, block {network.get('rdap_netblock') or '?'}, country {network.get('rdap_country') or '?'})",
            f"Inspecting certificate: issuer {(info or {}).get('issuer') or network.get('inspector_issuer') or 'not reported'}",
            f"  subject {(info or {}).get('subject') or network.get('inspector_subject') or 'not reported'}",
            f"  CA key id {(info or {}).get('ca_key_id') or network.get('inspector_ca_key_id') or 'not reported'}",
            f"Classification: {network.get('classification') or 'unclassified'}",
        ]
        lines += [f"  evidence - {item}" for item in evidence] or ["  evidence - none found"]
        lines += [
            f"Network status: {network.get('status')}" + (f" by {network['decided_by']}" if network.get("decided_by") else ""),
            "",
            "The device's RDS traffic on this network is sealed end to end: the network can see that it talks to RDS and how much, but cannot read, change or replay any of it.",
            "",
            f"Review or block: {ops_url}",
        ]
        return lines

    def _ops_url(host: str) -> str:
        ops_host = "ops." + host.split(".", 1)[1] if host.count(".") >= 2 else host
        return f"https://{ops_host}{admin_path}/#inspection"

    def _gate(*, path: str, token: str | None, ip: str, country: str | None, info: dict[str, Any], ops_url: str,
              edge_cert_verified: bool) -> tuple[bool, str, list[tuple]]:
        """Decide whether a call that came through a TLS interceptor may be served. Returns
        (allowed, reason, follow-up actions to run on the event loop)."""
        actions: list[tuple] = []
        device = None
        if token:
            try:
                device = validate_device_credential_handler(token)
            except HTTPException:
                device = None
        bootstrap = path.startswith(BOOTSTRAP_PREFIXES)
        if device is None and not bootstrap:
            if require_edge_cert and not edge_cert_verified:
                # The same call without the interception claim is refused for lacking the edge
                # certificate (below the gate); claiming interception must not change that.
                return False, "edge_certificate_required", actions
            return True, "unauthenticated", actions  # the route itself answers 401
        address = ipaddress.ip_address(ip)
        single = f"{address}/{address.max_prefixlen}"
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM inspection_networks WHERE cidr >>= %s::inet ORDER BY masklen(cidr) DESC LIMIT 1",
                    (ip,),
                )
                network = cursor.fetchone()
                new_network = network is None
                if new_network:
                    cursor.execute(
                        """
                        INSERT INTO inspection_networks (cidr, inspector_issuer, inspector_subject, inspector_ca_key_id, rdap_country)
                        VALUES (%s::cidr, %s, %s, %s, %s)
                        ON CONFLICT (cidr) DO UPDATE SET last_seen_at = now()
                        RETURNING *
                        """,
                        (single, info.get("issuer"), info.get("subject"), info.get("ca_key_id"), country),
                    )
                    network = cursor.fetchone()
                else:
                    cursor.execute(
                        """
                        UPDATE inspection_networks
                        SET last_seen_at = now(),
                            inspector_issuer = COALESCE(%s, inspector_issuer),
                            inspector_subject = COALESCE(%s, inspector_subject),
                            inspector_ca_key_id = COALESCE(%s, inspector_ca_key_id)
                        WHERE id = %s
                        """,
                        (info.get("issuer"), info.get("subject"), info.get("ca_key_id"), network["id"]),
                    )
                if device is None:
                    cursor.execute(
                        "UPDATE inspection_networks SET bootstrap_requests = bootstrap_requests + 1 WHERE id = %s",
                        (network["id"],),
                    )
                    connection.commit()
                    if new_network:
                        actions.append(("classify", str(network["id"]), None, info, ops_url))
                    return True, "bootstrap", actions

                cursor.execute(
                    "SELECT inspected_network_policy FROM managed_devices WHERE id = %s",
                    (device["device_id"],),
                )
                row = cursor.fetchone()
                policy = row["inspected_network_policy"] if row else "auto"
                device = {**device, "inspected_network_policy": policy}

                if network["status"] == "denied":
                    allowed, reason = False, "denied"
                elif policy == "strict":
                    allowed, reason = False, "device_strict"
                elif network["status"] == "approved":
                    allowed, reason = True, "approved"
                elif bootstrap:
                    allowed, reason = True, "bootstrap"
                elif require_edge_cert and not edge_cert_verified:
                    # With edge certificates required, claiming interception must not be a way around
                    # them (the client says whether it was intercepted): an unreviewed network is not
                    # served until it is approved.
                    allowed, reason = False, "unreviewed_edge_cert_required"
                else:
                    # Unreviewed networks are allowed: the call is sealed, so the network can't read or
                    # change it. Brad is notified (below) and can still block a network.
                    allowed, reason = True, "allowed"
                if allowed and reason == "approved" and require_edge_cert and not edge_cert_verified:
                    # An interceptor strips the client certificate, so the device must at least hold an
                    # active one; a credential alone is not enough while certificates are required.
                    cursor.execute(
                        """
                        SELECT 1 FROM edge_client_certs
                        WHERE device_id = %s AND kind = 'device' AND revoked_at IS NULL AND expires_at > now()
                        LIMIT 1
                        """,
                        (device["device_id"],),
                    )
                    if cursor.fetchone() is None:
                        allowed, reason = False, "no_edge_cert"

                cursor.execute(
                    """
                    INSERT INTO inspection_observations
                        (network_id, device_id, egress_ip, inspector_issuer, inspector_ca_key_id, request_count, last_decision)
                    VALUES (%s, %s, %s::inet, %s, %s, 1, %s)
                    ON CONFLICT (network_id, device_id) DO UPDATE SET
                        last_seen_at = now(),
                        egress_ip = EXCLUDED.egress_ip,
                        inspector_issuer = COALESCE(EXCLUDED.inspector_issuer, inspection_observations.inspector_issuer),
                        inspector_ca_key_id = COALESCE(EXCLUDED.inspector_ca_key_id, inspection_observations.inspector_ca_key_id),
                        request_count = inspection_observations.request_count + 1,
                        last_decision = EXCLUDED.last_decision
                    RETURNING last_alert_at, (xmax = 0) AS inserted
                    """,
                    (network["id"], device["device_id"], ip, info.get("issuer"), info.get("ca_key_id"), reason),
                )
                observation = cursor.fetchone()
                cursor.execute(
                    "UPDATE managed_devices SET sealed_last_inspected_at = now() WHERE id = %s",
                    (device["device_id"],),
                )
                now = datetime.now(timezone.utc)
                due = observation["last_alert_at"] is None or now - observation["last_alert_at"] > ALERT_REPEAT
                if new_network:
                    actions.append(("classify", str(network["id"]), device, info, ops_url))
                    cursor.execute(
                        "UPDATE inspection_observations SET last_alert_at = now() WHERE network_id = %s AND device_id = %s",
                        (network["id"], device["device_id"]),
                    )
                elif (not allowed or observation["inserted"]) and due:
                    actions.append(("alert", str(network["id"]), device, info, ops_url, reason))
                    cursor.execute(
                        "UPDATE inspection_observations SET last_alert_at = now() WHERE network_id = %s AND device_id = %s",
                        (network["id"], device["device_id"]),
                    )
            connection.commit()
        return allowed, reason, actions

    def _classify_and_alert(network_id: str, device: dict[str, Any] | None, info: dict[str, Any] | None, ops_url: str) -> None:
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT host(cidr) AS ip FROM inspection_networks WHERE id = %s", (network_id,))
                row = cursor.fetchone()
        if row is None:
            return
        found = classify_network(row["ip"])
        auto = found["classification"] in AUTO_APPROVE_CLASSES
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE inspection_networks SET
                        classification = %s, evidence = %s::jsonb, rdap_org = %s, rdap_network = %s,
                        rdap_netblock = %s::cidr, rdap_country = COALESCE(%s, rdap_country), ptr_name = %s, ptr_confirmed = %s,
                        classified_at = now(),
                        status = CASE WHEN %s AND status = 'pending' THEN 'approved' ELSE status END,
                        decided_by = CASE WHEN %s AND status = 'pending' THEN %s ELSE decided_by END,
                        decided_at = CASE WHEN %s AND status = 'pending' THEN now() ELSE decided_at END
                    WHERE id = %s
                    RETURNING *
                    """,
                    (
                        found["classification"], json.dumps(found["evidence"]), found.get("rdap_org"),
                        found.get("rdap_network"), found.get("rdap_netblock"), found.get("rdap_country"),
                        found.get("ptr_name"), found.get("ptr_confirmed"),
                        auto, auto, f"auto ({found['classification']})", auto, network_id,
                    ),
                )
                network = cursor.fetchone()
            connection.commit()
        if network is None:
            return
        name = (device or {}).get("friendly_name") or (device or {}).get("hostname") or "A device enrolling"
        if network["status"] == "approved":
            outcome = f"auto-approved as {network['classification']}"
        elif (device or {}).get("inspected_network_policy") == "strict":
            outcome = "blocked: device is set to strict"
        else:
            outcome = "allowed (sealed)"
        where = network.get("rdap_org") or network.get("ptr_name") or str(network["cidr"])
        _alert(
            f"RDS: {name} is on an inspecting network - {outcome}",
            [f"{name} reached RDS through a network that inspects HTTPS ({outcome}).", "", *_describe(network, device, info, ops_url)],
            f"Inspected network: {name}",
            f"{where} - {outcome}. Open RDS to review.",
            network_id,
        )

    def _alert_existing(network_id: str, device: dict[str, Any], info: dict[str, Any] | None, ops_url: str, reason: str) -> None:
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM inspection_networks WHERE id = %s", (network_id,))
                network = cursor.fetchone()
        if network is None:
            return
        outcome = {
            "denied": "blocked: you denied this network",
            "device_strict": "blocked: device is set to strict",
            "allowed": "allowed (sealed)",
            "approved": "allowed (sealed)",
            "unreviewed_edge_cert_required": "blocked until you approve it: edge certificates are required",
            "no_edge_cert": "blocked: device has no active edge certificate",
            "edge_certificate_required": "blocked: edge certificates are required",
        }.get(reason, reason)
        name = device.get("friendly_name") or device.get("hostname") or "A device"
        where = network.get("rdap_org") or network.get("ptr_name") or str(network["cidr"])
        _alert(
            f"RDS: {name} is on an inspecting network - {outcome}",
            [f"{name} reached RDS through a network that inspects HTTPS ({outcome}).", "", *_describe(network, device, info, ops_url)],
            f"Inspected network: {name}",
            f"{where} - {outcome}. Open RDS to review.",
            network_id,
        )

    def _logged(handler: Callable[..., None], *args: Any) -> None:
        # Background alert work: a failure must be visible in the logs, not lost in a task.
        try:
            handler(*args)
        except Exception:
            LOG.exception("inspection alert work failed")

    def _note_sealed_heartbeat(token: str | None) -> None:
        if not token:
            return
        try:
            # The inner route has just accepted this credential (200), so only its subject is needed.
            device_id = uuid.UUID(jwt.decode(token, options={"verify_signature": False})["sub"])
        except Exception:
            return
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute("UPDATE managed_devices SET sealed_last_at = now() WHERE id = %s", (device_id,))
            connection.commit()

    @app.post(SEALED_PATH, include_in_schema=False)
    async def sealed_call(request: Request):
        nonlocal maintenance_started
        if not maintenance_started:
            maintenance_started = True
            asyncio.create_task(_maintenance_forever())
        if not keys:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Sealed transport is not configured")
        blob = await _read_bounded(request, MAX_SEALED_REQUEST)
        try:
            eph_pub, k_resp, meta, body = open_request(keys, blob)
            method, target, headers = inner_target(meta)
        except _BadEnvelope:
            return JSONResponse(status_code=400, content={"detail": "Invalid sealed request"})
        if not await asyncio.to_thread(_claim_replay_slot, eph_pub):
            return JSONResponse(status_code=400, content={"detail": "Invalid sealed request"})

        def sealed(code: int, response_headers: list[list[str]], content: bytes) -> Response:
            return Response(
                content=seal_response(k_resp, eph_pub, code, response_headers, content),
                media_type="application/octet-stream",
                headers={"Cache-Control": "no-store"},
            )

        # An inspected network that is not (yet) allowed is reported as a temporary outage (503): a
        # 401 or 403 would send the client into credential recovery, which is not what is wrong.
        def refused(detail: str, code: int = 403) -> Response:
            response_headers = [["content-type", "application/json"]]
            if code == 503:
                response_headers.append(["retry-after", str(INSPECTED_RETRY_AFTER_SECONDS)])
            return sealed(code, response_headers, json.dumps({"detail": detail}).encode())

        path = urlsplit(target).path
        token = _bearer(headers)
        info = inspection_info(meta)
        host = request.headers.get("host", "")
        client_host = request.client.host if request.client else "0.0.0.0"
        if info is not None:
            try:
                allowed, reason, actions = await asyncio.to_thread(
                    _gate, path=path, token=token, ip=client_host, country=(request.headers.get("cf-ipcountry") or None),
                    info=info, ops_url=_ops_url(host),
                    edge_cert_verified=request.headers.get("x-edge-client-cert-verified") == "true",
                )
            except ValueError:
                return refused("inspected_network_unknown_source", 503)
            for action in actions:
                handler = _classify_and_alert if action[0] == "classify" else _alert_existing
                asyncio.create_task(asyncio.to_thread(_logged, handler, *action[1:]))
            if not allowed:
                return refused(f"inspected_network_{reason}", 503)
        elif (
            require_edge_cert
            and request.headers.get("x-edge-client-cert-verified") != "true"
            and not path.startswith(BOOTSTRAP_PREFIXES)
        ):
            return refused("edge_certificate_required")

        inner_headers = list(headers)
        for name in OUTER_FORWARDED_HEADERS:
            value = request.headers.get(name)
            if value is not None:
                inner_headers.append((name, value))
        inner_headers += [
            ("host", host),
            ("x-rds-sealed", "1"),
            ("x-rds-sealed-inspected", "1" if info is not None else "0"),
        ]
        transport = httpx.ASGITransport(
            app=app,
            raise_app_exceptions=False,
            client=(client_host, request.client.port if request.client else 0),
        )
        async with httpx.AsyncClient(transport=transport, base_url=f"https://{host or 'rds.internal'}") as client:
            response = await client.request(method, target, headers=inner_headers, content=body, timeout=INNER_TIMEOUT_SECONDS)
        # The access log only shows POST /v1/sealed; record what ran inside (path only: a query
        # string could carry something sensitive).
        LOG.info(
            '%s - "sealed %s %s%s" %d in=%dB out=%dB',
            client_host, method, path, " inspected" if info is not None else "", response.status_code,
            len(blob), len(response.content),
        )
        if len(response.content) > MAX_INNER_RESPONSE:
            return sealed(502, [["content-type", "application/json"]], b'{"detail":"Response too large for sealed transport"}')
        if path == "/v1/device/heartbeat" and response.status_code == 200:
            asyncio.create_task(asyncio.to_thread(_note_sealed_heartbeat, token))
        response_headers = [[k, v] for k, v in response.headers.multi_items() if k.lower() not in DROP_RESPONSE_HEADERS]
        return sealed(response.status_code, response_headers, response.content)

    # --- ops console: inspected networks and per-device policy ---

    @app.get(f"{admin_path}/api/inspection", include_in_schema=False)
    def list_inspection(owner: dict[str, Any] = Depends(require_owner_cookie_handler)):
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, cidr::text AS cidr, status, classification, evidence, rdap_org, rdap_network,
                           rdap_netblock::text AS rdap_netblock, rdap_country, ptr_name, ptr_confirmed,
                           inspector_issuer, inspector_subject, inspector_ca_key_id, decided_by, decided_at,
                           first_seen_at, last_seen_at, classified_at, bootstrap_requests
                    FROM inspection_networks
                    ORDER BY (status = 'pending') DESC, last_seen_at DESC
                    """
                )
                networks = cursor.fetchall()
                cursor.execute(
                    """
                    SELECT o.network_id, o.device_id, d.friendly_name, d.hostname, d.rustdesk_id,
                           host(o.egress_ip) AS egress_ip, o.inspector_issuer, o.first_seen_at, o.last_seen_at,
                           o.request_count, o.last_decision
                    FROM inspection_observations o
                    JOIN managed_devices d ON d.id = o.device_id
                    ORDER BY o.last_seen_at DESC
                    """
                )
                observations = cursor.fetchall()
                cursor.execute(
                    """
                    SELECT id, friendly_name, hostname, rustdesk_id, inspected_network_policy,
                           sealed_last_at, sealed_last_inspected_at
                    FROM managed_devices
                    WHERE status = 'approved'
                    ORDER BY lower(COALESCE(friendly_name, hostname))
                    """
                )
                devices = cursor.fetchall()
        by_network: dict[Any, list[dict[str, Any]]] = {}
        for observation in observations:
            by_network.setdefault(observation["network_id"], []).append(observation)
        return {
            "networks": [{**network, "devices": by_network.get(network["id"], [])} for network in networks],
            "devices": devices,
            "sealed_configured": bool(keys),
            "edge_cert_required": require_edge_cert,
        }

    @app.post(f"{admin_path}/api/inspection/networks/{{network_id}}/decision", include_in_schema=False)
    def decide_network(network_id: uuid.UUID, payload: dict[str, Any], owner: dict[str, Any] = Depends(require_owner_cookie_handler)):
        decision = str(payload.get("decision", ""))
        scope = str(payload.get("scope", "address"))
        status_value = {"approve": "approved", "deny": "denied", "reset": "pending"}.get(decision)
        if status_value is None or scope not in ("address", "netblock"):
            raise HTTPException(status_code=422, detail="decision must be approve, deny or reset; scope address or netblock")
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM inspection_networks WHERE id = %s FOR UPDATE", (network_id,))
                network = cursor.fetchone()
                if network is None:
                    raise HTTPException(status_code=404, detail="Network not found")
                new_cidr = network["cidr"]
                if scope == "netblock":
                    if not network["rdap_netblock"]:
                        raise HTTPException(status_code=409, detail="No registered address block is known for this network")
                    new_cidr = network["rdap_netblock"]
                    # A more specific pending entry inside the block would otherwise win the lookup.
                    cursor.execute(
                        "DELETE FROM inspection_networks WHERE cidr << %s::cidr AND id <> %s AND status = 'pending'",
                        (str(new_cidr), network_id),
                    )
                    cursor.execute(
                        "SELECT 1 FROM inspection_networks WHERE cidr = %s::cidr AND id <> %s",
                        (str(new_cidr), network_id),
                    )
                    if cursor.fetchone():
                        raise HTTPException(status_code=409, detail="That address block already has its own entry")
                cursor.execute(
                    """
                    UPDATE inspection_networks
                    SET status = %s, cidr = %s::cidr,
                        decided_by = CASE WHEN %s = 'pending' THEN NULL ELSE %s END,
                        decided_at = CASE WHEN %s = 'pending' THEN NULL ELSE now() END
                    WHERE id = %s
                    """,
                    (status_value, str(new_cidr), status_value, str(owner.get("username") or "owner"), status_value, network_id),
                )
            connection.commit()
        return {"ok": True, "status": status_value, "cidr": str(new_cidr)}

    @app.post(f"{admin_path}/api/inspection/networks/{{network_id}}/forget", include_in_schema=False)
    def forget_network(network_id: uuid.UUID, owner: dict[str, Any] = Depends(require_owner_cookie_handler)):
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM inspection_networks WHERE id = %s", (network_id,))
                deleted = cursor.rowcount
            connection.commit()
        if not deleted:
            raise HTTPException(status_code=404, detail="Network not found")
        return {"ok": True}

    @app.post(f"{admin_path}/api/devices/{{device_id}}/inspected-network-policy", include_in_schema=False)
    def set_device_policy(device_id: uuid.UUID, payload: dict[str, Any], owner: dict[str, Any] = Depends(require_owner_cookie_handler)):
        policy = str(payload.get("policy", ""))
        if policy not in ("auto", "strict"):
            raise HTTPException(status_code=422, detail="policy must be auto or strict")
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE managed_devices SET inspected_network_policy = %s WHERE id = %s",
                    (policy, device_id),
                )
                updated = cursor.rowcount
            connection.commit()
        if not updated:
            raise HTTPException(status_code=404, detail="Device not found")
        return {"ok": True, "policy": policy}
