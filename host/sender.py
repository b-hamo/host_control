"""Host-side sender for the SCRP control channel (WBS 3.4).

The Runner connects to us (reverse direction, protocol doc §3); we answer HELLO
with HELLO_ACK and then drive the session: OBSERVE, ACTION_REQUEST, HEARTBEAT,
STATE_REQUEST, TERMINATE. Every inbound message is validated against the
schema and checked for session binding, sequence order, duplicate message_id
and clock skew, exactly like the Runner checks ours.

Run:
  python host/sender.py            # wait for a Runner, run the demo sequence
  python host/sender.py --no-demo  # just answer HELLO_ACK and idle
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # run as `python host/sender.py`

from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed

from scrp.envelope import Endpoint, parse_utc
from scrp.validate import ProtocolError, parse_and_validate, validate

log = logging.getLogger("host-sender")

HOST, PORT = "0.0.0.0", 17443
SESSION_ID = "SES-20260922-001"
POLICY_VERSION = "POL-0.1.0"
CLOCK_SKEW_S = 60

# W1 PoC default values; the real Lifecycle Manager will issue these per session.
ALLOWED_CAPABILITIES = ["gui.observe", "gui.input", "ui.automation"]
LIMITS = {
    "max_message_bytes": 65536,
    "max_queue_depth": 32,
    "heartbeat_interval_ms": 5000,
    "alive_timeout_ms": 3000,
}


def _token() -> str:
    return uuid.uuid4().hex + uuid.uuid4().hex  # 64 chars, placeholder until W4 auth


def _expiry() -> str:
    return "2026-12-31T00:00:00Z"


class Connection:
    """One Runner connection: identity, sequence checks, request/response pairing."""

    def __init__(self, ws, hello: dict):
        self.ws = ws
        self.me = Endpoint(hello["session_id"], hello["runtime_id"], hello["generation"],
                           connection_id=f"CONN-{uuid.uuid4().hex[:8]}")
        self.expected_in_seq = hello["sequence_number"] + 1
        self.seen_message_ids = {hello["message_id"]}
        self.pending: dict[str, asyncio.Future] = {}   # correlation_id -> waiter
        self.task_seq = 0
        self.action_seq = 0
        self.closed = asyncio.Event()

    # -- ids -----------------------------------------------------------------
    def next_task(self) -> str:
        self.task_seq += 1
        return f"TASK-{self.task_seq:06d}"

    def next_action(self) -> str:
        self.action_seq += 1
        return f"ACT-{self.action_seq:06d}"

    # -- sending -------------------------------------------------------------
    async def send(self, msg: dict) -> None:
        validate(msg)
        await self.ws.send(json.dumps(msg, ensure_ascii=False))
        log.info("SENT %-16s seq=%s", msg["type"], msg["sequence_number"])

    async def request(self, msg: dict, expect: tuple[str, ...], timeout: float = 10.0) -> dict:
        """Send a request and wait for the response(s) correlated to it.

        Returns the last message in `expect`; earlier ones (e.g. ACK before
        ACTION_RESULT) are logged and checked on the way.
        """
        waiter: asyncio.Future = asyncio.get_running_loop().create_future()
        self.pending[msg["message_id"]] = waiter
        await self.send(msg)
        reply = None
        for wanted in expect:
            try:
                reply = await asyncio.wait_for(waiter, timeout)
            except asyncio.TimeoutError:
                self.pending.pop(msg["message_id"], None)
                raise ProtocolError("ACTION_TIMEOUT", f"no {wanted} for {msg['type']} within {timeout}s") from None
            if reply["type"] != wanted:
                raise ProtocolError("PROTOCOL_DENIED", f"expected {wanted}, got {reply['type']}")
            if wanted != expect[-1]:
                waiter = asyncio.get_running_loop().create_future()
                self.pending[msg["message_id"]] = waiter
        self.pending.pop(msg["message_id"], None)
        return reply

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
        skew = abs((datetime.now(timezone.utc) - parse_utc(msg["timestamp"])).total_seconds())
        if skew > CLOCK_SKEW_S:
            raise ProtocolError("PROTOCOL_DENIED", f"timestamp skew {skew:.0f}s")
        self.expected_in_seq += 1
        self.seen_message_ids.add(msg["message_id"])

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
                waiter = self.pending.get(msg["correlation_id"])
                if waiter and not waiter.done():
                    waiter.set_result(msg)
        except ConnectionClosed as e:
            log.info("connection closed: %s", e)
        finally:
            self.closed.set()
            for w in self.pending.values():
                if not w.done():
                    w.cancel()

    # -- operations ----------------------------------------------------------
    async def observe(self) -> dict:
        upload_id = uuid.uuid4().hex + uuid.uuid4().hex[:8]   # one-time, >=16 chars
        msg = self.me.envelope("OBSERVE", {
            "display_id": "primary", "capture_format": "png", "upload_id": upload_id,
        }, task_id=self.next_task(), action_id=self.next_action())
        result = await self.request(msg, ("OBSERVE_RESULT",))
        p = result["payload"]
        log.info("  observation %s %sx%s sha256=%s…", p["observation_id"], p["width"], p["height"], p["sha256"][:12])
        return p

    async def action(self, operation: str, arguments: dict, observation_id: str, timeout_ms: int = 10000) -> dict:
        msg = self.me.envelope("ACTION_REQUEST", {
            "operation": operation, "arguments": arguments, "observation_id": observation_id,
            "policy_version": POLICY_VERSION, "timeout_ms": timeout_ms,
        }, task_id=self.next_task(), action_id=self.next_action())
        result = await self.request(msg, ("ACK", "ACTION_RESULT"))
        log.info("  %s -> %s %s", operation, result["status"], result["payload"]["result"])
        return result

    async def heartbeat(self) -> dict:
        msg = self.me.envelope("HEARTBEAT", {"lease_expires_at": _expiry()})
        alive = await self.request(msg, ("ALIVE",), timeout=3.0)
        log.info("  alive: %s queue=%s", alive["payload"]["runtime_state"], alive["payload"]["queue_depth"])
        return alive

    async def state(self, action_id: str | None = None) -> dict:
        msg = self.me.envelope("STATE_REQUEST", {"action_id": action_id})
        state = await self.request(msg, ("STATE_RESULT",))
        log.info("  state: %s action=%s", state["payload"]["runtime_state"], state["payload"]["action_state"])
        return state

    async def terminate(self, reason: str = "TASK_COMPLETE") -> dict:
        msg = self.me.envelope("TERMINATE", {"reason": reason, "grace_ms": 1000})
        return await self.request(msg, ("TERMINATE_RESULT",), timeout=5.0)


async def demo(conn: Connection) -> None:
    """The round trip WBS 3.4 has to prove: observe, click, type, heartbeat, state, terminate."""
    log.info("--- demo sequence ---")
    obs = await conn.observe()
    await conn.action("mouse.click", {"x": 640, "y": 420, "button": "left", "click_count": 1}, obs["observation_id"])
    typed = await conn.action("keyboard.type", {"text": "안녕하세요"}, obs["observation_id"])
    await conn.heartbeat()
    await conn.state(typed["action_id"])
    await conn.terminate()
    log.info("--- demo complete ---")


async def handle(ws, run_demo: bool) -> None:
    peer = ws.remote_address
    log.info("CONNECTED from %s path=%s", peer, ws.request.path)

    raw = await asyncio.wait_for(ws.recv(), timeout=5.0)
    hello = parse_and_validate(raw if isinstance(raw, bytes) else raw.encode("utf-8"))
    if hello["type"] != "HELLO":
        raise ProtocolError("PROTOCOL_DENIED", f"first message must be HELLO, got {hello['type']}")
    log.info("RECV %-16s runner=%s caps=%s", "HELLO", hello["payload"]["runner_version"],
             hello["payload"]["capabilities"])

    conn = Connection(ws, hello)
    granted = [c for c in hello["payload"]["capabilities"] if c in ALLOWED_CAPABILITIES]
    await conn.send(conn.me.reply(hello, "HELLO_ACK", {
        "selected_version": "1.0",
        "allowed_capabilities": granted,
        "limits": LIMITS,
        "channel_credentials": {
            "telemetry": {"token": _token(), "expires_at": _expiry()},
            "reconnect": {"token": _token(), "expires_at": _expiry()},
        },
    }))
    log.info("READY connection_id=%s granted=%s", conn.me.connection_id, granted)

    reader = asyncio.create_task(conn.reader())
    try:
        if run_demo:
            await demo(conn)
        else:
            await conn.closed.wait()
    except ProtocolError as e:
        log.error("session aborted: %s", e)
    finally:
        reader.cancel()


async def main(run_demo: bool) -> None:
    async def handler(ws):
        try:
            await handle(ws, run_demo)
        except ProtocolError as e:
            log.error("handshake rejected: %s", e)
            await ws.close(code=1008, reason=e.code)
        except asyncio.TimeoutError:
            log.error("runner did not send HELLO in time")
            await ws.close(code=1008, reason="HELLO timeout")

    async with serve(handler, HOST, PORT, max_size=64 * 1024):
        log.info("listening on ws://%s:%d/scrp/v1/control", HOST, PORT)
        await asyncio.Future()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="SCRP Host sender (WBS 3.4)")
    ap.add_argument("--no-demo", action="store_true", help="only do the handshake, then idle")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-5s %(message)s")
    try:
        asyncio.run(main(not args.no_demo))
    except KeyboardInterrupt:
        pass
