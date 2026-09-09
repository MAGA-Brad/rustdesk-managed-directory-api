from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import timedelta
from typing import Any, Callable

from fastapi import Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field

CHAT_PATH = "/v1/messaging"

# Safety net for a recipient that never comes back online: without this, an
# undelivered message (and its receipt rows) would sit in Postgres forever.
# Applies regardless of delivery state - it's a bound on how long the server
# will hold onto anything, not a substitute for delivery-based purging.
CHAT_MESSAGE_MAX_AGE = timedelta(days=30)
CHAT_SWEEP_INTERVAL_SECONDS = 3600

_log = logging.getLogger("managed_chat")


class StartConversationRequest(BaseModel):
    # The client only ever has the RustDesk numeric id readily at hand
    # (Peer.id in the Directory tab) - not RDS's own internal device UUID -
    # so this accepts that directly rather than forcing an extra lookup
    # round-trip client-side just to resolve a peer it's already showing.
    peer_rustdesk_id: str = Field(min_length=1, max_length=64)


class SendMessageRequest(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


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

    async def connect(self, device_id: uuid.UUID, websocket: WebSocket) -> None:
        existing = self._connections.get(device_id)
        if existing is not None and existing is not websocket:
            try:
                await existing.close()
            except Exception:
                pass
        self._connections[device_id] = websocket

    def disconnect(self, device_id: uuid.UUID, websocket: WebSocket) -> None:
        if self._connections.get(device_id) is websocket:
            del self._connections[device_id]

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


def _fetch_and_ack_pending(
    cursor, conversation_id: uuid.UUID, self_id: uuid.UUID
) -> list[dict[str, Any]]:
    """Drain this device's undelivered messages in one conversation.

    Marks every returned message delivered for this device, then purges
    any message that is now delivered to every participant. Must run
    inside an already-open transaction; the caller commits.
    """
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
    pending = [dict(row) for row in cursor.fetchall()]
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
    while True:
        await asyncio.sleep(CHAT_SWEEP_INTERVAL_SECONDS)
        try:
            with open_database_handler() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM chat_messages WHERE sent_at < now() - %s::interval",
                        (f"{CHAT_MESSAGE_MAX_AGE.days} days",),
                    )
                    connection.commit()
        except Exception:
            _log.exception("managed chat sweep failed")


def register_chat_routes(
    *,
    app: Any,
    require_device_handler: Callable[..., dict[str, Any]],
    validate_device_credential_handler: Callable[[str], dict[str, Any]],
    open_database_handler: Callable[..., Any],
) -> ConnectionManager:
    manager = ConnectionManager()

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
                        'hostname', d.hostname
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
                    "SELECT id FROM managed_devices WHERE rustdesk_id = %s AND status = 'approved'",
                    (payload.peer_rustdesk_id,),
                )
                peer_row = cursor.fetchone()
                if peer_row is None:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Peer device not found",
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
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                _require_participant(cursor, conversation_id, self_id)
                messages = _fetch_and_ack_pending(cursor, conversation_id, self_id)
                connection.commit()
        await _notify_senders_delivered(conversation_id, messages, self_id)
        return {"messages": messages}

    @app.post(f"{CHAT_PATH}/conversations/{{conversation_id}}/messages")
    async def send_message(
        conversation_id: uuid.UUID,
        payload: SendMessageRequest,
        device: dict[str, Any] = Depends(require_device_handler),
    ):
        self_id = device["device_id"]
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                _require_participant(cursor, conversation_id, self_id)

                cursor.execute(
                    """
                    INSERT INTO chat_messages (conversation_id, sender_device_id, body)
                    VALUES (%s, %s, %s)
                    RETURNING id, sender_device_id, body, sent_at
                    """,
                    (conversation_id, self_id, payload.body),
                )
                message = dict(cursor.fetchone())

                cursor.execute(
                    "SELECT device_id FROM chat_participants WHERE conversation_id = %s AND device_id != %s",
                    (conversation_id, self_id),
                )
                recipient_ids = [row["device_id"] for row in cursor.fetchall()]

                for recipient_id in recipient_ids:
                    cursor.execute(
                        "INSERT INTO chat_message_receipts (message_id, device_id) VALUES (%s, %s)",
                        (message["id"], recipient_id),
                    )

                # Count-only, for dashboard/Client Management stats - see
                # chat_message_send_events' own comment. No body/content
                # here or anywhere else this table is touched, ever.
                cursor.execute(
                    "INSERT INTO chat_message_send_events (sender_device_id) VALUES (%s)",
                    (self_id,),
                )
                connection.commit()

        serialized = _serialize_message(message)
        push_payload = {
            "type": "message",
            "conversation_id": str(conversation_id),
            "message": serialized,
        }
        delivered_to: list[str] = []
        for recipient_id in recipient_ids:
            if await manager.push(recipient_id, push_payload):
                delivered_to.append(str(recipient_id))

        if delivered_to:
            with open_database_handler() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        UPDATE chat_message_receipts
                        SET delivered_at = now()
                        WHERE message_id = %s AND device_id = ANY(%s::uuid[])
                        """,
                        (message["id"], delivered_to),
                    )
                    _purge_if_fully_delivered(cursor, message["id"])
                    connection.commit()

        return {**serialized, "delivered_to": delivered_to}

    @app.websocket(f"{CHAT_PATH}/ws")
    async def chat_websocket(websocket: WebSocket):
        auth_header = websocket.headers.get("authorization", "")
        scheme, _, token = auth_header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            await websocket.close(code=4401)
            return

        try:
            device = validate_device_credential_handler(token)
        except HTTPException:
            await websocket.close(code=4401)
            return

        self_id = device["device_id"]
        await websocket.accept()
        await manager.connect(self_id, websocket)
        _ensure_sweep_started()

        # Catch up: drain anything that piled up in every conversation this
        # device is part of while it was offline, and push the actual
        # content over this same connection - mirrors the fetch-and-ack GET
        # endpoint, but proactively, so a reconnecting client doesn't have
        # to poll each conversation itself just to find out what it missed.
        with open_database_handler() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT conversation_id FROM chat_participants WHERE device_id = %s",
                    (self_id,),
                )
                conversation_ids = [row["conversation_id"] for row in cursor.fetchall()]
                pending_by_conversation = {
                    conversation_id: _fetch_and_ack_pending(cursor, conversation_id, self_id)
                    for conversation_id in conversation_ids
                }
                connection.commit()

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
            await _notify_senders_delivered(conversation_id, messages, self_id)

        try:
            while True:
                # Server-to-client push only - sending a message always
                # goes through the REST endpoint above. We still need to
                # await something so a client disconnect (or a dead TCP
                # connection) is noticed promptly rather than leaking a
                # stale entry in the connection manager.
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            manager.disconnect(self_id, websocket)

    return manager
