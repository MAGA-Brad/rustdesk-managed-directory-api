"""Signed diagnostic scripts for build 38+ RDC clients.

A job is created on the RDS host by rdc-diag-post, which signs it with a key only root there can
read; this API never sees that key and cannot make a job a client will run. The heartbeat tells a
device how many jobs wait for it, the device fetches them here, checks the signature against the
key built into it, runs the script and posts the output back."""
from __future__ import annotations

from typing import Any, Callable

from fastapi import Depends, HTTPException, status
from pydantic import BaseModel, Field

DIAG_JOBS_PATH = "/v1/device/diag-jobs"
MAX_OUTPUT_CHARS = 512 * 1024


class DiagResult(BaseModel):
    exit_code: int | None = None
    timed_out: bool = False
    duration_ms: int | None = Field(default=None, ge=0)
    output: str = Field(default="", max_length=MAX_OUTPUT_CHARS)
    client_error: str | None = Field(default=None, max_length=2000)


def pending_count(cursor, device_id: Any) -> int:
    cursor.execute(
        """
        SELECT count(*) AS n FROM diag_jobs
        WHERE device_id = %s AND result_at IS NULL AND expires_at > now()
        """,
        (device_id,),
    )
    row = cursor.fetchone()
    return int(row["n"]) if row else 0


def register_diag_job_routes(
    *,
    app: Any,
    require_device_handler: Callable[..., dict[str, Any]],
    open_database_handler: Callable[..., Any],
) -> None:
    @app.get(DIAG_JOBS_PATH)
    def list_diag_jobs(device: dict[str, Any] = Depends(require_device_handler)):
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE diag_jobs SET fetched_at = coalesce(fetched_at, now())
                    WHERE device_id = %s AND result_at IS NULL AND expires_at > now()
                    RETURNING id, script, script_sha256, timeout_s,
                              floor(extract(epoch FROM expires_at))::bigint AS expires_at, signature
                    """,
                    (device["device_id"],),
                )
                jobs = [
                    {
                        "id": str(row["id"]),
                        "script": row["script"],
                        "script_sha256": row["script_sha256"],
                        "timeout_s": row["timeout_s"],
                        "expires_at": row["expires_at"],
                        "signature": row["signature"],
                    }
                    for row in cursor.fetchall()
                ]
            connection.commit()
        return {"device_id": str(device["device_id"]), "jobs": jobs}

    @app.post(DIAG_JOBS_PATH + "/{job_id}/result")
    def post_diag_result(
        job_id: str,
        payload: DiagResult,
        device: dict[str, Any] = Depends(require_device_handler),
    ):
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE diag_jobs
                    SET result_at = now(), exit_code = %s, timed_out = %s, duration_ms = %s,
                        output = %s, client_error = %s
                    WHERE id::text = %s AND device_id = %s AND result_at IS NULL
                    RETURNING id
                    """,
                    (
                        payload.exit_code,
                        payload.timed_out,
                        payload.duration_ms,
                        payload.output,
                        payload.client_error,
                        job_id,
                        device["device_id"],
                    ),
                )
                updated = cursor.fetchone()
            connection.commit()
        if updated is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
        return {"stored": True}
