"""Device passports: the job link for the CA VM.

Runs as its own container on port 9443 of an internal interface (CA_LINK_BIND) with mutual TLS: uvicorn only accepts clients whose
certificate the link CA signed, and only the CA VM holds one. Nothing else is served here.
The CA VM always calls in; RDS never connects to it.
"""

import base64
import binascii
import json
import os
import time
from typing import Any

import psycopg
from fastapi import FastAPI, Query
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

# A job handed out but not answered within this long is handed out again (the CA VM treats repeats safely).
REDELIVER_AFTER = "2 minutes"


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


@app.get("/ca/v1/jobs")
def get_jobs(wait: int = Query(default=25, ge=0, le=50)):
    deadline = time.monotonic() + wait
    while True:
        with open_database() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"""
                    UPDATE ca_jobs SET picked_at = now(), attempts = attempts + 1
                    WHERE id IN (
                        SELECT id FROM ca_jobs
                        WHERE done_at IS NULL
                          AND (picked_at IS NULL OR picked_at < now() - interval '{REDELIVER_AFTER}')
                        ORDER BY id
                        LIMIT 50
                        FOR UPDATE SKIP LOCKED
                    )
                    RETURNING id, kind, payload
                    """
                )
                rows = cursor.fetchall()
            connection.commit()
        if rows or time.monotonic() >= deadline:
            return {"jobs": [{"id": r["id"], "kind": r["kind"], "payload": r["payload"]} for r in sorted(rows, key=lambda r: r["id"])]}
        time.sleep(1)


class JobResult(BaseModel):
    id: int
    ok: bool
    error: str | None = Field(default=None, max_length=1000)
    passport: str | None = Field(default=None, max_length=4096)
    serial: str | None = Field(default=None, max_length=64)
    nbf: int | None = None
    exp: int | None = None
    idk: str | None = Field(default=None, max_length=128)
    prot: str | None = Field(default=None, max_length=16)


class Results(BaseModel):
    results: list[JobResult] = Field(max_length=100)


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _on_file_key(cursor, device_id) -> tuple[str | None, str | None, str | None]:
    """The identity key RDS lists for the device (its RustDesk key until a key update), its rid and did."""
    cursor.execute(
        "SELECT rustdesk_id, identity_public_key, device_public_key FROM managed_devices WHERE id = %s",
        (device_id,),
    )
    d = cursor.fetchone()
    if not d:
        return None, None, None
    key = d["identity_public_key"]
    if not key and d["device_public_key"]:
        key = base64.urlsafe_b64encode(bytes(d["device_public_key"])).rstrip(b"=").decode("ascii")
    return key, d["rustdesk_id"], str(device_id)


def passport_mismatch(kind: str, payload: dict[str, Any], on_file: tuple, result: JobResult) -> str | None:
    """Why a CA result can't be taken, or None. RDS decides which identity key a device has: the key
    on file, or for a key update the new key RDS verified itself (expected_idk). A result for any
    other key - in the result fields or inside the passport - is refused, so the CA alone can't
    re-key a device (the two-box rule)."""
    key, rid, did = on_file
    if kind == "keyupdate":
        expected = payload.get("expected_idk")
        if not expected:
            return "key update was not verified by RDS"
    else:
        expected = key
    if not expected:
        return "no key on file"
    if result.idk is not None and result.idk != expected:
        return "result key differs from the key RDS verified"
    try:
        parts = (result.passport or "").split(".")
        if len(parts) != 5 or parts[0] != "rdcp1":
            return "malformed passport"
        body = json.loads(_unb64(parts[3]))
    except (binascii.Error, ValueError):
        return "malformed passport"
    if not isinstance(body, dict):
        return "malformed passport"
    if body.get("idk") != expected:
        return "passport key differs from the key RDS verified"
    if body.get("rid") != rid or body.get("did") != did:
        return "passport is for another device"
    if result.serial is not None and body.get("serial") != result.serial:
        return "passport serial differs from the result"
    return None


@app.post("/ca/v1/results")
def post_results(body: Results):
    with open_database() as connection:
        with connection.cursor() as cursor:
            for r in body.results:
                cursor.execute(
                    """
                    UPDATE ca_jobs SET done_at = now(), ok = %s, error = %s
                    WHERE id = %s AND done_at IS NULL
                    RETURNING device_id, kind, payload
                    """,
                    (r.ok, r.error, r.id),
                )
                job = cursor.fetchone()
                if not job or not r.ok or not r.passport or not job["device_id"]:
                    continue
                payload = job["payload"] if isinstance(job["payload"], dict) else {}
                problem = passport_mismatch(job["kind"], payload, _on_file_key(cursor, job["device_id"]), r)
                if problem:
                    print(f"ca-link: refused CA result for job {r.id} ({job['kind']}): {problem}", flush=True)
                    cursor.execute(
                        "UPDATE ca_jobs SET ok = false, error = %s WHERE id = %s",
                        (f"RDS refused the result: {problem}", r.id),
                    )
                    continue
                cursor.execute(
                    """
                    INSERT INTO device_passports (serial, device_id, kind, passport, nbf, expires_at, job_id)
                    VALUES (%s, %s, %s, %s, to_timestamp(%s), to_timestamp(%s), %s)
                    ON CONFLICT (serial) DO NOTHING
                    """,
                    (r.serial, job["device_id"], job["kind"], r.passport, r.nbf, r.exp, r.id),
                )
                # The key and its protection come from what RDS verified, never from the CA's result.
                new_key = payload.get("expected_idk") if job["kind"] == "keyupdate" else None
                new_prot = payload.get("expected_prot") if job["kind"] == "keyupdate" else None
                cursor.execute(
                    """
                    UPDATE managed_devices
                    SET passport_serial = %s,
                        passport_expires_at = to_timestamp(%s),
                        identity_public_key = COALESCE(%s, identity_public_key),
                        key_protection = COALESCE(%s, key_protection),
                        identity_key_alg = COALESCE(identity_key_alg, 'ed25519')
                    WHERE id = %s
                    """,
                    (r.serial, r.exp, new_key, new_prot, job["device_id"]),
                )
        connection.commit()
    return {"ok": True}


@app.post("/ca/v1/heartbeat")
def post_heartbeat(body: dict[str, Any]):
    status = body.get("status")
    if not isinstance(status, dict):
        return {"ok": False}
    with open_database() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO ca_status (id, status, updated_at) VALUES (1, %s, now())
                ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, updated_at = now()
                """,
                (Jsonb(status),),
            )
        connection.commit()
    return {"ok": True}
