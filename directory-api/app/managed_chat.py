from __future__ import annotations

import asyncio
import json
import logging
import math
import re
import time
import uuid
from collections import deque
from datetime import timedelta
from typing import Any, Callable

from fastapi import Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field, field_validator
from pydantic_core import PydanticCustomError

CHAT_PATH = "/v1/messaging"

# sec8 Phase E: an end-to-end body is
# rdce1:<sealed key>.<sender rustdesk id>.<nonce + secretbox>.<signature>, base64url apart from the
# id. RDS can't open it, so only its shape is checked. Plain bodies keep the 4000-character limit;
# sealed ones may be longer, since 4000 characters of multi-byte text grow past 16000 once sealed
# and encoded.
CHAT_PLAIN_BODY_MAX = 4000
CHAT_E2E_BODY_MAX = 32000
CHAT_E2E_PREFIX = "rdce1:"
_B64URL_PART = re.compile(r"[A-Za-z0-9_-]+={0,2}")
_SENDER_ID_PART = re.compile(r"[A-Za-z0-9_-]{1,64}")

# Safety net for a recipient that never comes back online: without this, an
# undelivered message (and its receipt rows) would sit in Postgres forever.
# Applies regardless of delivery state - it's a bound on how long the server
# will hold onto anything, not a substitute for delivery-based purging.
CHAT_MESSAGE_MAX_AGE = timedelta(days=30)
CHAT_SWEEP_INTERVAL_SECONDS = 3600

# Chat websocket delivery protocol.
#
# Legacy connections (build 41 and older never acknowledge): a message counts as delivered as soon
# as the write to the socket succeeds. Catch-up marks every pending message delivered and purges it
# before pushing; a live push marks it after a successful write. A dead socket loses the message.
#
# Acknowledged connections: the client sends the header "X-RDC-Chat-Ack: 1" on the upgrade request
# (the header only selects delivery semantics for a connection the credential and device proof have
# already authenticated). Then:
#  - Server -> client, unchanged: {"type": "message", "conversation_id": ..., "message": {...}} and
#    {"type": "delivered", "conversation_id": ..., "message_id": ...}.
#  - Client -> server, once the message is in its local store (or already was):
#    {"type": "ack", "message_ids": ["<message uuid>", ...]}, at most CHAT_ACK_MAX_IDS per frame.
#    Malformed frames and unknown, foreign or already acknowledged ids are ignored.
#  - Only an ack sets the receipt's delivered_at, purges the message once every recipient has it,
#    and tells the sender: in the send response's delivered_to when the ack arrives within
#    CHAT_ACK_WAIT_SECONDS, otherwise with a "delivered" push.
#  - Catch-up on every connect pushes every unacknowledged message again without marking it, so a
#    message written into a dead socket comes back on the next connection. Clients deduplicate by
#    message id and acknowledge duplicates too.
CHAT_ACK_HEADER = "x-rdc-chat-ack"
CHAT_ACK_WAIT_SECONDS = 3.0
CHAT_ACK_MAX_IDS = 500
# Each ack frame is a database write. A reconnect after days offline legitimately acks a few
# hundred messages at once, so frames beyond the burst are slowed down, not refused.
CHAT_ACK_FRAME_MAX_CHARS = 64 * 1024
CHAT_ACK_FRAMES_PER_SECOND = 20
CHAT_ACK_FRAME_BURST = 200
# Ids waiting for their batched write, per socket; beyond this they are resent on reconnect.
CHAT_ACK_PENDING_MAX = 5000

# Per sender device, across all of its conversations: an approved device must not be able to flood
# another device's desktop with chat windows.
CHAT_SEND_LIMIT = 30
CHAT_SEND_WINDOW_SECONDS = 60.0

# An open chat websocket re-checks its device's credential and approval this often, and is closed
# with CHAT_CLOSE_DEVICE_REMOVED once either is gone (see also close_device_sockets).
CHAT_REVALIDATE_SECONDS = 60
CHAT_CLOSE_DEVICE_REMOVED = 4403

_log = logging.getLogger("managed_chat")


class StartConversationRequest(BaseModel):
    # The client only ever has the RustDesk numeric id readily at hand
    # (Peer.id in the Directory tab) - not RDS's own internal device UUID -
    # so this accepts that directly rather than forcing an extra lookup
    # round-trip client-side just to resolve a peer it's already showing.
    peer_rustdesk_id: str = Field(min_length=1, max_length=64)


def is_end_to_end_body(body: str) -> bool:
    if not body.startswith(CHAT_E2E_PREFIX):
        return False
    parts = body[len(CHAT_E2E_PREFIX):].split(".")
    return (
        len(parts) == 4
        and all(_B64URL_PART.fullmatch(parts[i]) for i in (0, 2, 3))
        and _SENDER_ID_PART.fullmatch(parts[1]) is not None
    )


class SendMessageRequest(BaseModel):
    body: str = Field(min_length=1, max_length=CHAT_E2E_BODY_MAX)

    @field_validator("body")
    @classmethod
    def _plain_body_limit(cls, body: str) -> str:
        if len(body) > CHAT_PLAIN_BODY_MAX and not is_end_to_end_body(body):
            raise PydanticCustomError(
                "string_too_long",
                "String should have at most {max_length} characters",
                {"max_length": CHAT_PLAIN_BODY_MAX},
            )
        return body


class ConnectionManager:
    """In-process registry of currently-connected devices' chat sockets.

    A single API instance serves the whole fleet, so a plain dict is
    enough - no cross-process pub/sub needed. A device can hold at most
    one live chat connection; a new one replaces (and closes) any prior
    connection for that device, matching how a device's directory
    heartbeat/session already works elsewhere in this codebase.
    """

    def __init__(self) -> None:
        self._connections: dict[uuid.UUID, WebSocket] = {}
        # Connections that acknowledge deliveries (see the protocol note at the top).
        self._acking: set[WebSocket] = set()
        # (message id, recipient device id) -> the send_message call waiting for that ack.
        self._ack_waiters: dict[tuple[uuid.UUID, uuid.UUID], asyncio.Future[bool]] = {}
        # The event loop the sockets live on, for close_device_sockets from other threads.
        self._loop: asyncio.AbstractEventLoop | None = None
        self._closing: set[asyncio.Task[int]] = set()

    async def connect(
        self, device_id: uuid.UUID, websocket: WebSocket, acking: bool = False
    ) -> None:
        self._loop = asyncio.get_running_loop()
        existing = self._connections.get(device_id)
        if existing is not None and existing is not websocket:
            try:
                await existing.close()
            except Exception:
                pass
        self._connections[device_id] = websocket
        if acking:
            self._acking.add(websocket)

    def disconnect(self, device_id: uuid.UUID, websocket: WebSocket) -> None:
        self._acking.discard(websocket)
        if self._connections.get(device_id) is websocket:
            del self._connections[device_id]

    def acks(self, device_id: uuid.UUID) -> bool:
        websocket = self._connections.get(device_id)
        return websocket is not None and websocket in self._acking

    def expect_ack(self, message_id: uuid.UUID, device_id: uuid.UUID) -> asyncio.Future[bool]:
        waiter: asyncio.Future[bool] = asyncio.get_running_loop().create_future()
        self._ack_waiters[(message_id, device_id)] = waiter
        return waiter

    def forget_ack(self, message_id: uuid.UUID, device_id: uuid.UUID) -> None:
        self._ack_waiters.pop((message_id, device_id), None)

    def ack_awaited(self, message_id: uuid.UUID, device_id: uuid.UUID) -> bool:
        """Hands an ack to the send_message call still waiting for it. False when none is (it
        timed out first, or the message came from catch-up): the sender then needs a push."""
        waiter = self._ack_waiters.pop((message_id, device_id), None)
        if waiter is None or waiter.done():
            return False
        waiter.set_result(True)
        return True

    async def close_device(self, device_id: uuid.UUID, code: int) -> int:
        websocket = self._connections.pop(device_id, None)
        if websocket is None:
            return 0
        self._acking.discard(websocket)
        try:
            await websocket.close(code=code)
        except Exception:
            pass
        return 1

    def close_device_sockets(self, device_id: uuid.UUID, code: int) -> int:
        """Thread-safe close_device (see the module-level close_device_sockets)."""
        loop = self._loop
        if loop is None or loop.is_closed():
            return 0
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            task = loop.create_task(self.close_device(device_id, code))
            self._closing.add(task)
            task.add_done_callback(self._closing.discard)
            return 0
        try:
            return asyncio.run_coroutine_threadsafe(
                self.close_device(device_id, code), loop
            ).result(timeout=5)
        except Exception:
            _log.warning(
                "managed chat: closing the websocket of device %s failed",
                device_id,
                exc_info=True,
            )
            return 0

    async def push(self, device_id: uuid.UUID, payload: dict[str, Any]) -> bool:
        websocket = self._connections.get(device_id)
        if websocket is None:
            return False
        try:
            await websocket.send_json(payload)
            return True
        except Exception:
            self.disconnect(device_id, websocket)
            return False


# Every ConnectionManager register_chat_routes has made, for close_device_sockets.
_managers: list[ConnectionManager] = []


def close_device_sockets(
    device_id: uuid.UUID | str, code: int = CHAT_CLOSE_DEVICE_REMOVED
) -> int:
    """Closes a device's chat websocket with code 4403. Call it after a block, revoke or delete
    has committed, so the reconnect that follows is refused. Safe from any thread (main.py's plain
    def handlers run in the threadpool; this waits up to 5 s for the close) and from the event loop
    (there the close is only scheduled). Returns how many sockets it closed."""
    device_id = uuid.UUID(str(device_id))
    return sum(manager.close_device_sockets(device_id, code) for manager in list(_managers))


class _SendRateLimiter:
    """At most CHAT_SEND_LIMIT messages per CHAT_SEND_WINDOW_SECONDS per sender device. In
    process, like ConnectionManager, and only used from the event loop."""

    def __init__(self) -> None:
        self._sent: dict[uuid.UUID, deque[float]] = {}

    def retry_after(self, device_id: uuid.UUID) -> float | None:
        now = time.monotonic()
        sent = self._sent.setdefault(device_id, deque())
        while sent and now - sent[0] >= CHAT_SEND_WINDOW_SECONDS:
            sent.popleft()
        if len(sent) >= CHAT_SEND_LIMIT:
            return CHAT_SEND_WINDOW_SECONDS - (now - sent[0])
        sent.append(now)
        return None


def _direct_pair_key(a: uuid.UUID, b: uuid.UUID) -> str:
    lo, hi = sorted((str(a), str(b)))
    return f"{lo}:{hi}"


def _serialize_message(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "sender_device_id": str(row["sender_device_id"]),
        "body": row["body"],
        "sent_at": row["sent_at"].isoformat(),
    }


def _purge_if_fully_delivered(cursor, message_id: uuid.UUID) -> None:
    """Delete the message once every recipient's receipt shows delivered.

    The server is a mailbox, not an archive - once nobody still needs the
    content relayed to them, there's no reason to keep it. Long-term
    scrollback is each client's own local, user-controlled responsibility.
    """
    cursor.execute(
        "SELECT 1 FROM chat_message_receipts WHERE message_id = %s AND delivered_at IS NULL LIMIT 1",
        (message_id,),
    )
    if cursor.fetchone() is None:
        cursor.execute("DELETE FROM chat_messages WHERE id = %s", (message_id,))


def _select_pending(
    cursor, conversation_id: uuid.UUID, self_id: uuid.UUID
) -> list[dict[str, Any]]:
    """This device's undelivered messages in one conversation, oldest first."""
    cursor.execute(
        """
        SELECT m.id, m.sender_device_id, m.body, m.sent_at
        FROM chat_messages m
        JOIN chat_message_receipts r ON r.message_id = m.id
        WHERE m.conversation_id = %s
          AND r.device_id = %s
          AND r.delivered_at IS NULL
        ORDER BY m.sent_at ASC
        """,
        (conversation_id, self_id),
    )
    return [dict(row) for row in cursor.fetchall()]


def _fetch_and_ack_pending(
    cursor, conversation_id: uuid.UUID, self_id: uuid.UUID
) -> list[dict[str, Any]]:
    """Drain this device's undelivered messages in one conversation.

    Marks every returned message delivered for this device, then purges
    any message that is now delivered to every participant. Must run
    inside an already-open transaction; the caller commits.
    """
    pending = _select_pending(cursor, conversation_id, self_id)
    if not pending:
        return []

    message_ids = [row["id"] for row in pending]
    cursor.execute(
        """
        UPDATE chat_message_receipts
        SET delivered_at = now()
        WHERE device_id = %s AND message_id = ANY(%s::uuid[])
        """,
        (self_id, message_ids),
    )
    for message_id in message_ids:
        _purge_if_fully_delivered(cursor, message_id)

    return [_serialize_message(row) for row in pending]


async def _sweep_stale_messages(open_database_handler: Callable[..., Any]) -> None:
    def delete_stale() -> None:
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM chat_messages WHERE sent_at < now() - %s::interval",
                    (f"{CHAT_MESSAGE_MAX_AGE.days} days",),
                )
                connection.commit()

    while True:
        await asyncio.sleep(CHAT_SWEEP_INTERVAL_SECONDS)
        try:
            # Off the event loop, like every other database call in this module's async code.
            await asyncio.to_thread(delete_stale)
        except Exception:
            _log.exception("managed chat sweep failed")


def register_chat_routes(
    *,
    app: Any,
    require_device_handler: Callable[..., dict[str, Any]],
    validate_device_credential_handler: Callable[..., dict[str, Any]],
    open_database_handler: Callable[..., Any],
    chat_e2e_required_handler: Callable[[Any, str], bool],
) -> ConnectionManager:
    manager = ConnectionManager()
    _managers.append(manager)
    send_limiter = _SendRateLimiter()

    # This FastAPI version has no add_event_handler("startup", ...) /
    # on_event() (both removed in favor of the lifespan protocol, which
    # main.py's plain FastAPI() doesn't set up) - so the sweep is instead
    # lazily started the first time any device actually connects to the
    # chat websocket, which happens automatically on every real client's
    # startup. asyncio.create_task needs a running loop, which register_
    # chat_routes (called at plain import time) doesn't have yet, but the
    # websocket handler below does.
    _sweep_started = False

    def _ensure_sweep_started() -> None:
        nonlocal _sweep_started
        if not _sweep_started:
            _sweep_started = True
            asyncio.create_task(_sweep_stale_messages(open_database_handler))

    async def _notify_senders_delivered(
        conversation_id: uuid.UUID,
        messages: list[dict[str, Any]],
        self_id: uuid.UUID,
    ) -> None:
        """Best-effort: tells each message's original sender, if they're
        currently connected, that this device has now received it - lets
        their client clear its own "pending delivery" indicator for that
        specific message. Called after the drain transaction that marked
        these messages delivered has already committed (matching the
        existing catch-up push pattern below), never from inside it -
        this is a plain websocket send, not something that needs to hold
        a DB transaction open.

        If the sender isn't connected right now, this is simply skipped -
        no retry, no queueing. Their own UI just keeps showing "pending"
        until they reopen the conversation, exactly like it already does
        when this confirmation is never delivered at all (e.g. sender's
        device is gone). This mirrors the same "best effort, local
        fallback always available" design as every other push in this
        module.
        """
        for message in messages:
            sender_id_raw = message.get("sender_device_id")
            if sender_id_raw is None:
                continue
            sender_id = uuid.UUID(str(sender_id_raw))
            if sender_id == self_id:
                continue
            await manager.push(sender_id, {
                "type": "delivered",
                "conversation_id": str(conversation_id),
                "message_id": str(message["id"]),
            })

    def _ack_frame_ids(text: str) -> list[uuid.UUID]:
        """The message ids of an acknowledging client's frame (see the protocol note at the top);
        anything else yields none."""
        if len(text) > CHAT_ACK_FRAME_MAX_CHARS:
            return []
        try:
            frame = json.loads(text)
        except ValueError:
            return []
        if not isinstance(frame, dict) or frame.get("type") != "ack":
            return []
        raw_ids = frame.get("message_ids")
        if not isinstance(raw_ids, list):
            return []
        message_ids: list[uuid.UUID] = []
        for raw_id in raw_ids[:CHAT_ACK_MAX_IDS]:
            try:
                message_ids.append(uuid.UUID(str(raw_id)))
            except ValueError:
                continue
        return message_ids

    async def _record_acks(message_ids: list[uuid.UUID], self_id: uuid.UUID) -> None:
        """Marks the acknowledged messages delivered and tells their senders."""
        if not message_ids:
            return

        def mark_delivered() -> list[dict[str, Any]]:
            with open_database_handler() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        UPDATE chat_message_receipts r
                        SET delivered_at = now()
                        FROM chat_messages m
                        WHERE m.id = r.message_id
                          AND r.device_id = %s
                          AND r.message_id = ANY(%s::uuid[])
                          AND r.delivered_at IS NULL
                        RETURNING m.id, m.conversation_id, m.sender_device_id
                        """,
                        (self_id, message_ids),
                    )
                    rows = [dict(row) for row in cursor.fetchall()]
                    for row in rows:
                        _purge_if_fully_delivered(cursor, row["id"])
                    connection.commit()
            return rows

        # Off the event loop: a new connection plus a write per frame would stall every other request.
        acked = await asyncio.to_thread(mark_delivered)

        unannounced: dict[uuid.UUID, list[dict[str, Any]]] = {}
        for row in acked:
            if not manager.ack_awaited(row["id"], self_id):
                unannounced.setdefault(row["conversation_id"], []).append(row)
        for conversation_id, rows in unannounced.items():
            await _notify_senders_delivered(conversation_id, rows, self_id)

    async def _revalidate(websocket: WebSocket, token: str, self_id: uuid.UUID) -> None:
        """Closes the socket once the device's credential or approval is gone (blocked, revoked,
        deleted) - the upgrade checked them only once."""
        while True:
            await asyncio.sleep(CHAT_REVALIDATE_SECONDS)
            try:
                await asyncio.to_thread(validate_device_credential_handler, token)
            except HTTPException as error:
                if error.status_code not in (
                    status.HTTP_401_UNAUTHORIZED,
                    status.HTTP_403_FORBIDDEN,
                ):
                    continue
                _log.info(
                    "managed chat: closing the websocket of device %s: no longer approved",
                    self_id,
                )
                manager.disconnect(self_id, websocket)
                try:
                    await websocket.close(code=CHAT_CLOSE_DEVICE_REMOVED)
                except Exception:
                    pass
                return
            except Exception:
                _log.warning(
                    "managed chat: could not re-check device %s", self_id, exc_info=True
                )

    def _conversation_summary(cursor, conversation_id: uuid.UUID) -> dict[str, Any]:
        # No last_message/unread_count here - the server doesn't reliably
        # have either once messages are purged on delivery, and both are
        # now purely local concepts each client tracks from its own store.
        cursor.execute(
            """
            SELECT
                c.id,
                c.conversation_type,
                c.name,
                c.created_at,
                (
                    SELECT json_agg(json_build_object(
                        'device_id', p.device_id,
                        'friendly_name', d.friendly_name,
                        'rustdesk_id', d.rustdesk_id
                    ))
                    FROM chat_participants p
                    JOIN managed_devices d ON d.id = p.device_id
                    WHERE p.conversation_id = c.id
                ) AS participants
            FROM chat_conversations c
            WHERE c.id = %s
            """,
            (conversation_id,),
        )
        row = cursor.fetchone()
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Conversation not found",
            )
        return dict(row)

    def _require_participant(
        cursor, conversation_id: uuid.UUID, device_id: uuid.UUID
    ) -> None:
        cursor.execute(
            "SELECT 1 FROM chat_participants WHERE conversation_id = %s AND device_id = %s",
            (conversation_id, device_id),
        )
        if cursor.fetchone() is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Conversation not found",
            )

    @app.post(f"{CHAT_PATH}/conversations")
    def start_conversation(
        payload: StartConversationRequest,
        device: dict[str, Any] = Depends(require_device_handler),
    ):
        self_id = device["device_id"]

        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT id, platform FROM managed_devices WHERE rustdesk_id = %s AND status = 'approved'",
                    (payload.peer_rustdesk_id,),
                )
                peer_row = cursor.fetchone()
                if peer_row is None:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Peer device not found",
                    )
                if peer_row["platform"] in ("android", "linux"):
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="This device can't receive chat messages",
                    )
                peer_id = peer_row["id"]

                if peer_id == self_id:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Cannot start a conversation with yourself",
                    )

                pair_key = _direct_pair_key(self_id, peer_id)

                cursor.execute(
                    "SELECT id FROM chat_conversations WHERE direct_pair_key = %s",
                    (pair_key,),
                )
                existing = cursor.fetchone()
                if existing is not None:
                    conversation_id = existing["id"]
                else:
                    cursor.execute(
                        """
                        INSERT INTO chat_conversations
                            (conversation_type, direct_pair_key, created_by_device_id)
                        VALUES ('direct', %s, %s)
                        RETURNING id
                        """,
                        (pair_key, self_id),
                    )
                    conversation_id = cursor.fetchone()["id"]
                    cursor.execute(
                        """
                        INSERT INTO chat_participants (conversation_id, device_id)
                        VALUES (%s, %s), (%s, %s)
                        """,
                        (conversation_id, self_id, conversation_id, peer_id),
                    )
                connection.commit()

                return _conversation_summary(cursor, conversation_id)

    @app.get(f"{CHAT_PATH}/conversations")
    def list_conversations(device: dict[str, Any] = Depends(require_device_handler)):
        self_id = device["device_id"]
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT conversation_id FROM chat_participants
                    WHERE device_id = %s
                    """,
                    (self_id,),
                )
                conversation_ids = [row["conversation_id"] for row in cursor.fetchall()]
                summaries = [
                    _conversation_summary(cursor, cid) for cid in conversation_ids
                ]

        summaries.sort(key=lambda summary: summary["created_at"], reverse=True)
        return {"conversations": summaries}

    @app.get(f"{CHAT_PATH}/conversations/{{conversation_id}}/messages")
    async def get_messages(
        conversation_id: uuid.UUID,
        device: dict[str, Any] = Depends(require_device_handler),
    ):
        """Fetch-and-acknowledge: drains whatever is still queued for this
        device in this conversation. The server holds no long-term
        history, so there's nothing to page through - each call simply
        returns what's piled up since this device was last online, and
        purges it server-side in the same transaction.
        """
        self_id = device["device_id"]

        def drain() -> list[dict[str, Any]]:
            with open_database_handler() as connection:
                with connection.cursor() as cursor:
                    _require_participant(cursor, conversation_id, self_id)
                    drained = _fetch_and_ack_pending(cursor, conversation_id, self_id)
                    connection.commit()
            return drained

        # Off the event loop: a blocking connect and query here would stall every other request.
        messages = await asyncio.to_thread(drain)
        await _notify_senders_delivered(conversation_id, messages, self_id)
        return {"messages": messages}

    @app.post(f"{CHAT_PATH}/conversations/{{conversation_id}}/messages")
    async def send_message(
        conversation_id: uuid.UUID,
        payload: SendMessageRequest,
        device: dict[str, Any] = Depends(require_device_handler),
    ):
        self_id = device["device_id"]
        retry_after = send_limiter.retry_after(self_id)
        if retry_after is not None:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many chat messages; try again shortly",
                headers={"Retry-After": str(max(1, math.ceil(retry_after)))},
            )
        end_to_end = is_end_to_end_body(payload.body)

        def store() -> tuple[dict[str, Any], list[Any]]:
            with open_database_handler() as connection:
                with connection.cursor() as cursor:
                    _require_participant(cursor, conversation_id, self_id)
                    # Chat end-to-end switch: Enforce (or Test, for a test device) refuses plain text.
                    if not end_to_end and chat_e2e_required_handler(cursor, device["rustdesk_id"]):
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail="Chat messages must be end-to-end encrypted",
                        )

                    cursor.execute(
                        """
                        INSERT INTO chat_messages (conversation_id, sender_device_id, body)
                        VALUES (%s, %s, %s)
                        RETURNING id, sender_device_id, body, sent_at
                        """,
                        (conversation_id, self_id, payload.body),
                    )
                    stored = dict(cursor.fetchone())

                    cursor.execute(
                        """
                        SELECT p.device_id, d.status
                        FROM chat_participants p
                        JOIN managed_devices d ON d.id = p.device_id
                        WHERE p.conversation_id = %s AND p.device_id != %s
                        """,
                        (conversation_id, self_id),
                    )
                    recipients = cursor.fetchall()
                    recipient_ids = [row["device_id"] for row in recipients]

                    for recipient_id in recipient_ids:
                        cursor.execute(
                            "INSERT INTO chat_message_receipts (message_id, device_id) VALUES (%s, %s)",
                            (stored["id"], recipient_id),
                        )

                    # Count-only, for dashboard/Client Management stats - see
                    # chat_message_send_events' own comment. No body/content
                    # here or anywhere else this table is touched, ever -
                    # end_to_end only records whether the body was sealed.
                    cursor.execute(
                        "INSERT INTO chat_message_send_events (sender_device_id, end_to_end) VALUES (%s, %s)",
                        (self_id, end_to_end),
                    )
                    connection.commit()
            # A device that is no longer approved keeps its receipt (it catches up if it is
            # approved again) but is never pushed to, even over a socket still open.
            return stored, [row["device_id"] for row in recipients if row["status"] == "approved"]

        # Both database blocks run off the event loop (the HTTPException above still reaches
        # the caller through to_thread).
        message, live_recipient_ids = await asyncio.to_thread(store)

        serialized = _serialize_message(message)
        push_payload = {
            "type": "message",
            "conversation_id": str(conversation_id),
            "message": serialized,
        }
        # written: legacy connections, delivered once the write succeeds. waiting: acknowledging
        # connections, delivered only by their ack (recorded by _record_acks).
        written: list[str] = []
        waiting: list[tuple[uuid.UUID, asyncio.Future[bool]]] = []
        for recipient_id in live_recipient_ids:
            # Registered before the push: the ack can arrive before push() returns.
            waiter = (
                manager.expect_ack(message["id"], recipient_id)
                if manager.acks(recipient_id)
                else None
            )
            if await manager.push(recipient_id, push_payload):
                if waiter is None:
                    written.append(str(recipient_id))
                else:
                    waiting.append((recipient_id, waiter))
            elif waiter is not None:
                manager.forget_ack(message["id"], recipient_id)

        if written:
            def mark_written() -> None:
                with open_database_handler() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            """
                            UPDATE chat_message_receipts
                            SET delivered_at = now()
                            WHERE message_id = %s AND device_id = ANY(%s::uuid[])
                            """,
                            (message["id"], written),
                        )
                        _purge_if_fully_delivered(cursor, message["id"])
                        connection.commit()

            await asyncio.to_thread(mark_written)

        delivered_to = list(written)
        if waiting:
            await asyncio.wait(
                [waiter for _, waiter in waiting], timeout=CHAT_ACK_WAIT_SECONDS
            )
            for recipient_id, waiter in waiting:
                # An ack after this gets a "delivered" push instead.
                manager.forget_ack(message["id"], recipient_id)
                if waiter.done():
                    delivered_to.append(str(recipient_id))

        return {**serialized, "delivered_to": delivered_to}

    @app.websocket(f"{CHAT_PATH}/ws")
    async def chat_websocket(websocket: WebSocket):
        auth_header = websocket.headers.get("authorization", "")
        scheme, _, token = auth_header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            await websocket.close(code=4401)
            return

        # proof_scope: the device key proof (X-RDC-Proof on the upgrade, checked as GET with the
        # path and query as received) under the same switch as every other device call.
        try:
            device = await asyncio.to_thread(
                validate_device_credential_handler, token, proof_scope=websocket.scope
            )
        except HTTPException:
            await websocket.close(code=4401)
            return

        self_id = device["device_id"]
        acking = websocket.headers.get(CHAT_ACK_HEADER, "").strip() == "1"
        await websocket.accept()
        await manager.connect(self_id, websocket, acking)
        _ensure_sweep_started()

        # Catch up: drain anything that piled up in every conversation this
        # device is part of while it was offline, and push the actual
        # content over this same connection - mirrors the fetch-and-ack GET
        # endpoint, but proactively, so a reconnecting client doesn't have
        # to poll each conversation itself just to find out what it missed.
        # An acknowledging client gets everything it hasn't acknowledged,
        # unmarked: only its acks mark it delivered.
        def catch_up() -> dict[Any, list[dict[str, Any]]]:
            with open_database_handler() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT conversation_id FROM chat_participants WHERE device_id = %s",
                        (self_id,),
                    )
                    conversation_ids = [row["conversation_id"] for row in cursor.fetchall()]
                    if acking:
                        pending = {
                            conversation_id: [
                                _serialize_message(row)
                                for row in _select_pending(cursor, conversation_id, self_id)
                            ]
                            for conversation_id in conversation_ids
                        }
                    else:
                        pending = {
                            conversation_id: _fetch_and_ack_pending(cursor, conversation_id, self_id)
                            for conversation_id in conversation_ids
                        }
                    connection.commit()
            return pending

        # Off the event loop. The socket is already registered, so a message sent meanwhile is
        # pushed live and may come again here; clients deduplicate by message id.
        pending_by_conversation = await asyncio.to_thread(catch_up)

        for conversation_id, messages in pending_by_conversation.items():
            for message in messages:
                await manager.push(
                    self_id,
                    {
                        "type": "message",
                        "conversation_id": str(conversation_id),
                        "message": message,
                    },
                )
            if not acking:
                await _notify_senders_delivered(conversation_id, messages, self_id)

        revalidation = asyncio.create_task(_revalidate(websocket, token, self_id))
        ack_tokens, ack_refilled = float(CHAT_ACK_FRAME_BURST), time.monotonic()
        pending_acks: list[uuid.UUID] = []
        ack_writer: asyncio.Task | None = None

        async def write_pending_acks() -> None:
            # Acks that arrive while a write runs are gathered and written together next, so a
            # burst costs a few database writes rather than one per frame.
            while pending_acks:
                batch = pending_acks[:CHAT_ACK_MAX_IDS]
                del pending_acks[: len(batch)]
                try:
                    await _record_acks(batch, self_id)
                except Exception:
                    # Unrecorded, the messages stay pending and are resent on reconnect.
                    _log.exception("managed chat: recording an ack from %s failed", self_id)

        try:
            while True:
                # Sending a message always goes through the REST endpoint
                # above; a client only ever sends acks here. We still need to
                # await something so a client disconnect (or a dead TCP
                # connection) is noticed promptly rather than leaking a
                # stale entry in the connection manager.
                text = await websocket.receive_text()
                if acking:
                    now = time.monotonic()
                    ack_tokens = min(
                        float(CHAT_ACK_FRAME_BURST),
                        ack_tokens + (now - ack_refilled) * CHAT_ACK_FRAMES_PER_SECOND,
                    )
                    ack_refilled = now
                    if ack_tokens < 1:
                        await asyncio.sleep((1 - ack_tokens) / CHAT_ACK_FRAMES_PER_SECOND)
                        ack_tokens, ack_refilled = 1.0, time.monotonic()
                    ack_tokens -= 1
                    message_ids = _ack_frame_ids(text)
                    if message_ids and len(pending_acks) < CHAT_ACK_PENDING_MAX:
                        pending_acks.extend(message_ids)
                        if ack_writer is None or ack_writer.done():
                            ack_writer = asyncio.create_task(write_pending_acks())
        except WebSocketDisconnect:
            pass
        finally:
            revalidation.cancel()
            manager.disconnect(self_id, websocket)

    return manager
