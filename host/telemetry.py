"""Telemetry channel of an artifact-export-v1 session (Runner contract §4, §5).

    wss://<host>:<control port>/scrp/v1/telemetry
    Authorization: Bearer <HELLO_ACK channel_credentials.telemetry.token>

    Runner: CHANNEL_HELLO {channel: telemetry}        (sequence 1, no connection_id)
    Host:   CHANNEL_ACK  {channel, max_event_bytes}   (new connection_id, status OK)
    Runner: SECURITY_EVENT {event_id, observed_at, category: ARTIFACT_CANDIDATE, relative_path}
    Host:   EVENT_ACK {event_id}  STORED, or REJECTED + error {code: STORAGE_REJECTED}

The token is a separate single-use credential bound to the session, runtime and
generation it was issued for; the identity in CHANNEL_HELLO must match it, and
every later message is checked like on the Control channel (sequence, ids,
nonce, clock). A message over 16 KiB, or anything but SECURITY_EVENT, closes the
channel. When the channel ends, that Runtime's exports stop (ArtifactBroker).
"""

from __future__ import annotations

import asyncio
import logging

from websockets.exceptions import ConnectionClosed

from host.artifacts import TELEMETRY_MAX_EVENT_BYTES, ArtifactBroker
from host.connection import Connection
from host.session_registry import TELEMETRY_KINDS, AuthError, SessionRegistry, bearer_token
from scrp.validate import ARTIFACT_EXPORT_V1, ProtocolError, parse_and_validate

log = logging.getLogger("host-telemetry")

HELLO_TIMEOUT_S = 5.0


async def handle_telemetry(ws, registry: SessionRegistry, sessions, artifacts: ArtifactBroker) -> None:
    raw = await asyncio.wait_for(ws.recv(), timeout=HELLO_TIMEOUT_S)
    hello = parse_and_validate(raw if isinstance(raw, bytes) else raw.encode("utf-8"),
                               ARTIFACT_EXPORT_V1, TELEMETRY_MAX_EVENT_BYTES)
    if hello["type"] != "CHANNEL_HELLO":
        raise ProtocolError("PROTOCOL_DENIED", f"first Telemetry message must be CHANNEL_HELLO, got {hello['type']}")
    try:
        rec = registry.consume(bearer_token(ws.request.headers.get("Authorization")), TELEMETRY_KINDS)
    except AuthError as e:
        raise ProtocolError("PROTOCOL_DENIED", str(e)) from None
    claimed = (hello["session_id"], hello["runtime_id"], hello["generation"])
    if claimed != rec.identity():
        raise ProtocolError("PROTOCOL_DENIED", f"CHANNEL_HELLO names {claimed}, token was issued for {rec.identity()}")
    session = sessions.get(rec.identity())
    if session.terminated or session.contract != ARTIFACT_EXPORT_V1:
        raise ProtocolError("SESSION_TERMINATED", f"{rec.session_id} has no artifact channel")

    conn = Connection(ws, hello, rec.identity(), profile=ARTIFACT_EXPORT_V1, prefix="TEL",
                      max_bytes=TELEMETRY_MAX_EVENT_BYTES)
    await conn.send(conn.me.reply(hello, "CHANNEL_ACK",
                                  {"channel": "telemetry", "max_event_bytes": TELEMETRY_MAX_EVENT_BYTES}))
    artifacts.channel_up(rec.identity())
    log.info("TELEMETRY %s up for %s gen %d", conn.id, rec.session_id, rec.generation)
    why = "closed"
    try:
        async for raw in ws:
            try:
                msg = conn.parse(raw)
                conn.check(msg)
                if msg["type"] != "SECURITY_EVENT":
                    raise ProtocolError("PROTOCOL_DENIED", f"{msg['type']} is not allowed on the Telemetry channel")
            except ProtocolError as e:
                log.error("TELEMETRY %s rejected inbound: %s", conn.id, e)
                why = f"protocol error ({e.code})"
                await ws.close(code=1008, reason=e.code)
                break
            stored = artifacts.store(rec.identity(), msg["payload"])
            ack = conn.me.envelope("EVENT_ACK", {"event_id": msg["payload"]["event_id"]},
                                   correlation_id=msg["message_id"], status="STORED" if stored else "REJECTED",
                                   error=None if stored else {"code": "STORAGE_REJECTED"})
            await conn.send(ack)
    except ConnectionClosed as e:
        why = f"connection closed ({e.rcvd.code if e.rcvd else 'no close frame'})"
    finally:
        conn.closed.set()
        artifacts.channel_down(rec.identity(), why)
        log.info("TELEMETRY %s down: %s", conn.id, why)
