"""One Runner connection: inbound checks and request/response pairing.

A connection lives from HELLO to close. Everything that must survive a
reconnect (action history, id counters, health) lives in RuntimeSession
instead; sequence numbers, seen message_ids and nonces are per connection
(protocol doc §7) and start over with the next one.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone

from websockets.exceptions import ConnectionClosed

from scrp.envelope import Endpoint, parse_utc
from scrp.validate import ProtocolError, parse_and_validate, validate

log = logging.getLogger("host-sender")

CLOCK_SKEW_S = 60


class Connection:
    def __init__(self, ws, hello: dict, identity: tuple[str, str, int]):
        self.ws = ws
        # Identity comes from the session registry, not from what the Runner claims.
        self.me = Endpoint(*identity, connection_id=f"CONN-{uuid.uuid4().hex[:8]}")
        self.expected_in_seq = hello["sequence_number"] + 1
        self.seen_message_ids = {hello["message_id"]}
        self.seen_nonces = {hello["nonce"]}
        self.pending: dict[str, asyncio.Queue] = {}    # correlation_id -> replies for it
        self.closed = asyncio.Event()

    @property
    def id(self) -> str:
        return self.me.connection_id

    # -- sending -------------------------------------------------------------
    async def send(self, msg: dict) -> None:
        validate(msg)
        await self.ws.send(json.dumps(msg, ensure_ascii=False))
        log.info("SENT %-16s seq=%s", msg["type"], msg["sequence_number"])

    async def request(self, msg: dict, expect: tuple[str, ...], timeout: float = 10.0,
                      final_if=None) -> dict:
        """Send a request and wait for the response(s) correlated to it.

        Returns the last message in `expect`; earlier ones (e.g. ACK before
        ACTION_RESULT) are checked on the way. Raises ProtocolError with
        ACTION_TIMEOUT when a reply is late and RUNTIME_UNAVAILABLE when the
        connection goes away first. Never re-sends.
        """
        if self.closed.is_set():
            raise ProtocolError("RUNTIME_UNAVAILABLE", f"connection {self.id} is closed")
        # A queue, not a single future: ACK and ACTION_RESULT can arrive back to
        # back, before this coroutine resumes, and neither may be dropped.
        inbox: asyncio.Queue = asyncio.Queue()
        self.pending[msg["message_id"]] = inbox
        try:
            try:
                await self.send(msg)
            except ConnectionClosed:
                raise ProtocolError("RUNTIME_UNAVAILABLE", f"connection closed before {msg['type']} was sent") from None
            reply = None
            for wanted in expect:
                try:
                    reply = await asyncio.wait_for(inbox.get(), timeout)
                except asyncio.TimeoutError:
                    raise ProtocolError("ACTION_TIMEOUT", f"no {wanted} for {msg['type']} within {timeout}s") from None
                if reply is None:
                    raise ProtocolError("RUNTIME_UNAVAILABLE", f"connection closed while waiting for {wanted}")
                if reply["type"] == "ERROR":           # the Runner refused this request, with a reason
                    err = reply["error"]
                    raise ProtocolError(err["code"], err["message"])
                if reply["type"] != wanted:
                    raise ProtocolError("PROTOCOL_DENIED", f"expected {wanted}, got {reply['type']}")
                if final_if is not None and final_if(reply):
                    return reply                     # e.g. ACK REJECTED: no ACTION_RESULT will follow
            return reply
        finally:
            self.pending.pop(msg["message_id"], None)

    # -- receiving -----------------------------------------------------------
    def check(self, msg: dict) -> None:
        if (msg["session_id"], msg["runtime_id"], msg["generation"]) != \
           (self.me.session_id, self.me.runtime_id, self.me.generation):
            raise ProtocolError("PROTOCOL_DENIED", "session/runtime/generation mismatch")
        if msg["connection_id"] != self.me.connection_id:
            raise ProtocolError("PROTOCOL_DENIED", "connection_id mismatch")
        if msg["sequence_number"] != self.expected_in_seq:
            raise ProtocolError("PROTOCOL_DENIED",
                                f"expected sequence {self.expected_in_seq}, got {msg['sequence_number']}")
        if msg["message_id"] in self.seen_message_ids:
            raise ProtocolError("PROTOCOL_DENIED", "duplicate message_id")
        if msg["nonce"] in self.seen_nonces:
            raise ProtocolError("PROTOCOL_DENIED", "duplicate nonce")
        skew = abs((datetime.now(timezone.utc) - parse_utc(msg["timestamp"])).total_seconds())
        if skew > CLOCK_SKEW_S:
            raise ProtocolError("PROTOCOL_DENIED", f"timestamp skew {skew:.0f}s")
        self.expected_in_seq += 1
        self.seen_message_ids.add(msg["message_id"])
        self.seen_nonces.add(msg["nonce"])

    async def reader(self) -> None:
        """Validate every inbound message and hand it to whoever is waiting."""
        try:
            async for raw in self.ws:
                try:
                    msg = parse_and_validate(raw if isinstance(raw, bytes) else raw.encode("utf-8"))
                    self.check(msg)
                except ProtocolError as e:
                    log.error("REJECTED inbound: %s", e)
                    await self.send(self.me.error(e.code, e.detail, next_step="RECONNECT"))
                    await self.ws.close(code=1008, reason=e.code)
                    break
                log.info("RECV %-16s seq=%s corr=%s", msg["type"], msg["sequence_number"],
                         (msg["correlation_id"] or "-")[:8])
                if msg["type"] == "ERROR":
                    log.error("runner ERROR: %s", msg["error"])
                inbox = self.pending.get(msg["correlation_id"])
                if inbox is not None:
                    inbox.put_nowait(msg)
        except ConnectionClosed as e:
            log.info("connection %s closed: %s", self.id, e)
        finally:
            self.closed.set()
            for inbox in self.pending.values():
                inbox.put_nowait(None)   # wake waiters: the connection is gone
