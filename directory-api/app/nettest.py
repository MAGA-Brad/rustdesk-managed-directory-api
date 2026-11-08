"""Reports from rdc-nettest.exe (Brad 2026-10-14): which of our names a network's filter blocks and
whether Encrypted Client Hello gets through (a network security filter may block it). The tool runs on users'
PCs, so it uploads its own report instead of someone copying console text around.

Write-only and unauthenticated by device: the tool carries a shared token (only its hash is set here),
reports are capped in size and per source address, and they are read from the database."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from collections import deque
from typing import Any, Callable

from fastapi import HTTPException, Request, status

NETTEST_PATH = "/v1/diag/nettest"
# Replace with the hex SHA-256 of your deployment's nettest token; left empty, every report is refused.
TOKEN_SHA256 = ""
MAX_BODY_BYTES = 64 * 1024
MAX_PER_SOURCE_PER_HOUR = 30

_recent_by_source: dict[str, deque[float]] = {}
_table_ready = False


def register_nettest_routes(
    *,
    app: Any,
    open_database_handler: Callable[..., Any],
    client_ip_handler: Callable[[Request], str | None],
) -> None:
    def _store(source_ip: str, hostname: str, result: str, report: dict[str, Any]) -> int:
        global _table_ready
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                if not _table_ready:
                    cursor.execute(
                        """
                        CREATE TABLE IF NOT EXISTS nettest_reports (
                            id bigserial PRIMARY KEY,
                            received_at timestamptz NOT NULL DEFAULT now(),
                            source_ip text,
                            hostname text,
                            result text,
                            report jsonb NOT NULL
                        )
                        """
                    )
                    _table_ready = True
                cursor.execute(
                    """
                    INSERT INTO nettest_reports (source_ip, hostname, result, report)
                    VALUES (%s, %s, %s, %s::jsonb)
                    RETURNING id
                    """,
                    (source_ip, hostname, result, json.dumps(report)),
                )
                row = cursor.fetchone()
            connection.commit()
        return int(row["id"])

    @app.post(NETTEST_PATH, include_in_schema=False)
    async def post_nettest_report(request: Request):
        token = request.headers.get("x-rdc-nettest-token", "")
        if not hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), TOKEN_SHA256):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

        source_ip = client_ip_handler(request) or "unknown"
        now = time.monotonic()
        recent = _recent_by_source.setdefault(source_ip, deque())
        while recent and now - recent[0] > 3600:
            recent.popleft()
        if len(recent) >= MAX_PER_SOURCE_PER_HOUR:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS)
        recent.append(now)

        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
        body = bytearray()
        async for chunk in request.stream():
            body += chunk
            if len(body) > MAX_BODY_BYTES:
                raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
        try:
            report = json.loads(body)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="report is not JSON")
        if not isinstance(report, dict):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="report is not an object")

        verdict = report.get("verdict") if isinstance(report.get("verdict"), dict) else {}
        hostname = str(report.get("computer_name") or report.get("hostname") or "")[:64]
        result = str(verdict.get("result") or report.get("result") or "")[:16]
        report_id = await asyncio.to_thread(_store, source_ip, hostname, result, report)
        return {"id": report_id}
