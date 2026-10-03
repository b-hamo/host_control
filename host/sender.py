"""Host-side sender for the SCRP control channel (WBS 3.4, 4.6).

The Runner connects to us (reverse direction, protocol doc §3); we answer HELLO
with HELLO_ACK and then drive the session: OBSERVE, ACTION_REQUEST, HEARTBEAT,
STATE_REQUEST, TERMINATE. Every inbound message is validated against the
schema and checked for session binding, sequence order, duplicate message_id
and clock skew, exactly like the Runner checks ours.

Security (protocol doc §4, WBS 4.6): the channel is wss:// only (TLS 1.2+, no
plaintext fallback). At start-up the Host registers one session, issues a
one-time bootstrap token for it and writes host/.bootstrap/bootstrap.json for
the Runner. The upgrade request must carry `Authorization: Bearer <token>`;
the token is checked before the upgrade and used up when HELLO arrives, and
HELLO must name the session the token was issued for. One Host process serves
one session: restart it for a new token.

Run:
  python host/sender.py            # wait for a Runner, run the demo sequence
  python host/sender.py --no-demo  # just answer HELLO_ACK and idle
"""

from __future__ import annotations

import argparse
import asyncio
import http
import json
import logging
import re
import secrets
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # run as `python host/sender.py`

from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed

from host import tls
from host.bootstrap import CONTROL_PATH, write_bootstrap
from host.session_registry import AuthError, SessionRegistry, bearer_token
from scrp.envelope import Endpoint, parse_utc
from scrp.validate import ProtocolError, parse_and_validate, validate

log = logging.getLogger("host-sender")


class RedactAuthorization(logging.Filter):
    """websockets logs every request header at DEBUG, the bootstrap token included."""

    _HEADER = re.compile(r"(?i)(authorization:\s*)(bearer\s+)?\S+")

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        if "authorization" in msg.lower():
            record.msg, record.args = self._HEADER.sub(r"\1\2[REDACTED]", msg), ()
        return True


logging.getLogger("websockets.server").addFilter(RedactAuthorization())

HOST, PORT = "0.0.0.0", 17443
HOST_DIR = Path(__file__).resolve().parent
CERT_DIR = HOST_DIR / ".certs"
BOOTSTRAP_FILE = HOST_DIR / ".bootstrap" / "bootstrap.json"
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


CHANNEL_CREDENTIAL_TTL_S = 300


def _expiry(seconds: float = CHANNEL_CREDENTIAL_TTL_S) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _credential() -> dict:
    # Telemetry/reconnect channels are not served yet (WBS 4.4); the tokens are
    # already real random values so nothing guessable is ever handed out.
    return {"token": secrets.token_urlsafe(32), "expires_at": _expiry()}


class Connection:
    """One Runner connection: identity, sequence checks, request/response pairing."""

    def __init__(self, ws, hello: dict, identity: tuple[str, str, int]):
        self.ws = ws
        # Identity comes from the session registry, not from what the Runner claims.
        self.me = Endpoint(*identity, connection_id=f"CONN-{uuid.uuid4().hex[:8]}")
        self.expected_in_seq = hello["sequence_number"] + 1
        self.seen_message_ids = {hello["message_id"]}
        self.seen_nonces = {hello["nonce"]}
        self.pending: dict[str, asyncio.Queue] = {}    # correlation_id -> replies for it
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
        # A queue, not a single future: ACK and ACTION_RESULT can arrive back to
        # back, before this coroutine resumes, and neither may be dropped.
        inbox: asyncio.Queue = asyncio.Queue()
        self.pending[msg["message_id"]] = inbox
        try:
            await self.send(msg)
            reply = None
            for wanted in expect:
                try:
                    reply = await asyncio.wait_for(inbox.get(), timeout)
                except asyncio.TimeoutError:
                    raise ProtocolError("ACTION_TIMEOUT", f"no {wanted} for {msg['type']} within {timeout}s") from None
                if reply is None:
                    raise ProtocolError("RUNTIME_UNAVAILABLE", f"connection closed while waiting for {wanted}")
                if reply["type"] != wanted:
                    raise ProtocolError("PROTOCOL_DENIED", f"expected {wanted}, got {reply['type']}")
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
            log.info("connection closed: %s", e)
        finally:
            self.closed.set()
            for inbox in self.pending.values():
                inbox.put_nowait(None)   # wake waiters: the connection is gone

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


def make_process_request(registry: SessionRegistry):
    """Reject before the WebSocket upgrade: wrong path, or no valid token.

    The token is only checked here, not used up; that happens when HELLO
    arrives. The client gets a bare 401 whatever the reason, so it learns
    nothing about which tokens exist; the reason goes to our log.
    """
    def process_request(connection, request):
        peer = connection.remote_address
        if request.path != CONTROL_PATH:
            log.warning("REFUSED %s: path %s", peer, request.path)
            return connection.respond(http.HTTPStatus.NOT_FOUND, "Not Found\n")
        try:
            registry.check(bearer_token(request.headers.get("Authorization")))
        except AuthError as e:
            log.warning("REFUSED %s: %s", peer, e)
            return connection.respond(http.HTTPStatus.UNAUTHORIZED, "Unauthorized\n")
        return None
    return process_request


async def handle(ws, run_demo: bool, registry: SessionRegistry) -> None:
    peer = ws.remote_address
    log.info("CONNECTED from %s path=%s (TLS)", peer, ws.request.path)

    raw = await asyncio.wait_for(ws.recv(), timeout=5.0)
    hello = parse_and_validate(raw if isinstance(raw, bytes) else raw.encode("utf-8"))
    if hello["type"] != "HELLO":
        raise ProtocolError("PROTOCOL_DENIED", f"first message must be HELLO, got {hello['type']}")

    # Use the token up now. Another connection that passed the pre-check with
    # the same token loses here, and the token can never be used again.
    try:
        rec = registry.consume(bearer_token(ws.request.headers.get("Authorization")))
    except AuthError as e:
        raise ProtocolError("PROTOCOL_DENIED", str(e)) from None
    claimed = (hello["session_id"], hello["runtime_id"], hello["generation"])
    if claimed != rec.identity():
        raise ProtocolError("PROTOCOL_DENIED",
                            f"HELLO names {claimed}, token was issued for {rec.identity()}")
    log.info("RECV %-16s runner=%s caps=%s session=%s (token accepted)", "HELLO",
             hello["payload"]["runner_version"], hello["payload"]["capabilities"], rec.session_id)

    conn = Connection(ws, hello, rec.identity())
    granted = [c for c in hello["payload"]["capabilities"] if c in ALLOWED_CAPABILITIES]
    await conn.send(conn.me.reply(hello, "HELLO_ACK", {
        "selected_version": "1.0",
        "allowed_capabilities": granted,
        "limits": LIMITS,
        "channel_credentials": {
            "telemetry": _credential(),
            "reconnect": _credential(),
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


def make_handler(run_demo: bool, registry: SessionRegistry):
    async def handler(ws):
        try:
            await handle(ws, run_demo, registry)
        except ProtocolError as e:
            log.error("handshake rejected: %s", e)
            await ws.close(code=1008, reason=e.code)
        except asyncio.TimeoutError:
            log.error("runner did not send HELLO in time")
            await ws.close(code=1008, reason="HELLO timeout")
    return handler


def start_server(registry: SessionRegistry, cert_path: Path, key_path: Path,
                 run_demo: bool = True, host: str = HOST, port: int = PORT):
    """The wss:// server. There is deliberately no plaintext variant."""
    return serve(make_handler(run_demo, registry), host, port,
                 ssl=tls.server_context(cert_path, key_path),
                 process_request=make_process_request(registry),
                 max_size=64 * 1024)


async def main(run_demo: bool, session: tuple[str, str, int], bootstrap_file: Path) -> None:
    cert_path, key_path = tls.ensure_dev_cert(CERT_DIR)
    cert_pem = cert_path.read_text(encoding="ascii")
    registry = SessionRegistry()
    rec = registry.issue(*session)
    write_bootstrap(bootstrap_file, rec, cert_pem, PORT)
    # The token itself is never logged.
    log.info("session %s / %s / gen %s registered; token valid until %s, single use",
             *rec.identity(), rec.expires_utc)
    log.info("bootstrap written to %s", bootstrap_file)
    log.info("host certificate sha256=%s", tls.fingerprint(cert_pem))

    async with start_server(registry, cert_path, key_path, run_demo):
        log.info("listening on wss://%s:%d%s", HOST, PORT, CONTROL_PATH)
        await asyncio.Future()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="SCRP Host sender (WBS 3.4, 4.6)")
    ap.add_argument("--no-demo", action="store_true", help="only do the handshake, then idle")
    ap.add_argument("--session", default="SES-001")
    ap.add_argument("--runtime", default="RT-SBX-001")
    ap.add_argument("--generation", type=int, default=1)
    ap.add_argument("--bootstrap-out", type=Path, default=BOOTSTRAP_FILE,
                    help="where to write the Runner's bootstrap config")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-5s %(message)s")
    try:
        asyncio.run(main(not args.no_demo, (args.session, args.runtime, args.generation),
                         args.bootstrap_out))
    except KeyboardInterrupt:
        pass
