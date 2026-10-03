"""Host-side sender for the SCRP control channel (WBS 3.4, 4.4, 4.5, 4.6).

The Runner connects to us (reverse direction, protocol doc §3); we answer HELLO
with HELLO_ACK and then drive the session: OBSERVE, ACTION_REQUEST, HEARTBEAT,
STATE_REQUEST, TERMINATE. Every inbound message is validated against the
schema and checked for session binding, sequence order, duplicate message_id
and nonce, and clock skew, exactly like the Runner checks ours.

Security (protocol doc §4, WBS 4.6): the channel is wss:// only (TLS 1.2+, no
plaintext fallback). At start-up the Host registers one session, issues a
one-time bootstrap token for it and writes host/.bootstrap/bootstrap.json for
the Runner. The upgrade request must carry `Authorization: Bearer <token>`;
the token is checked before the upgrade and used up when HELLO arrives, and
HELLO must name the session the token was issued for.

Liveness and reconnect (protocol doc §4, §7, WBS 4.4): each HELLO_ACK carries
a fresh one-time reconnect token. If the connection drops, the Runner comes
back with it and the same RuntimeSession continues on the new connection,
after asking STATE_REQUEST about anything left unfinished. HEARTBEAT runs
every 5 s while connected. See host/runtime_session.py.

Startup Verification (protocol doc §4 step 6, WBS 4.5): a Runner that has
connected is not READY yet. The Host checks its HELLO (version, capabilities,
monitors, clock) and then asks it to prove it works (Worker state, a first
capture, a heartbeat). Only then do actions flow. If that does not happen
within 120 s of registration the session fails. See host/startup.py.

Run:
  python host/sender.py                # wait for a Runner, run the protocol demo
  python host/sender.py --demo broker  # same, but as MCP tool calls through the Broker (WBS 5.6)
  python host/sender.py --no-demo      # handshake and heartbeats only
"""

from __future__ import annotations

import argparse
import asyncio
import http
import logging
import re
import secrets
import ssl
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # run as `python host/sender.py`

from websockets.asyncio.server import serve

from host import tls
from host.audit import AuditLog
from host.broker import Broker
from host.bootstrap import CONTROL_PATH, write_bootstrap
from host.connection import Connection
from host.observation_store import ObservationUploads
from host.upload_server import UPLOAD_PATH, UPLOAD_PORT, start_upload_server
from host.runtime_session import (ALIVE_TIMEOUT_S, HEARTBEAT_INTERVAL_S, RECONNECT_GRACE_S,
                                  RuntimeSession)
from host.session_registry import TELEMETRY_KINDS, AuthError, SessionRegistry, bearer_token
from host.startup import STARTUP_TIMEOUT_S, StartupProfile
from scrp.validate import ARTIFACT_EXPORT_V1, ProtocolError, parse_and_validate

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
AUDIT_DIR = HOST_DIR / ".audit"
RESUME_WAIT_S = 60.0        # how long the demo waits for a dropped Runner to come back

# W1 PoC default values; the real Lifecycle Manager will issue these per session.
ALLOWED_CAPABILITIES = ["gui.observe", "gui.input", "ui.automation"]
TELEMETRY_CREDENTIAL_TTL_S = 300


ARTIFACT_CAPABILITY = "artifact.export.v1"      # only for sessions that selected artifact-export-v1
TELEMETRY_PATH = "/scrp/v1/telemetry"


def _telemetry_credential(registry: SessionRegistry, session: RuntimeSession) -> dict:
    if session.contract == ARTIFACT_EXPORT_V1:
        # A real, registered credential: it opens only this session's Telemetry channel, once.
        rec = registry.issue_telemetry(session.identity)
        return {"token": rec.token, "expires_at": rec.expires_utc}
    # No Telemetry channel is served for this session; still a random value so
    # nothing guessable is ever handed out, and the registry does not know it.
    expires = datetime.now(timezone.utc) + timedelta(seconds=TELEMETRY_CREDENTIAL_TTL_S)
    return {"token": secrets.token_urlsafe(32), "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ")}


async def demo(session: RuntimeSession) -> None:
    """The round trip WBS 3.4 has to prove, resilient to a drop (WBS 4.4).

    If the connection is lost mid-step, the step is NOT repeated: the session
    resyncs on reconnect (STATE_REQUEST + new observation) and the demo goes
    on with the next step.
    """
    steps = [
        ("observe", lambda: session.observe()),
        ("mouse.click", lambda: session.action("mouse.click", {"x": 640, "y": 420, "button": "left", "click_count": 1})),
        ("keyboard.type", lambda: session.action("keyboard.type", {"text": "안녕하세요"})),
        ("heartbeat", lambda: session.heartbeat_once()),
        ("state", lambda: session.state(session.last_action_id)),
        ("terminate", lambda: session.terminate()),
    ]
    log.info("--- demo sequence ---")
    for name, step in steps:
        try:
            await session.wait_ready(RESUME_WAIT_S)
            await step()
        except ProtocolError as e:
            if e.code == "RUNTIME_UNAVAILABLE" and not session.terminated and session.disconnected():
                log.warning("step %s cut off (%s); not re-sending, will resync after reconnect", name, e.detail)
                continue
            log.error("demo stopped at %s: %s", name, e)
            return
    log.info("--- demo complete --- actions: %s", session.actions)


async def broker_demo(session: RuntimeSession) -> None:
    """What Codex will do in 6.1, scripted: tool calls go through the Broker, which
    checks each one and only then turns it into SCRP messages. Three calls are
    meant to be refused and never reach the Runner."""
    broker = Broker(session, audit=AuditLog(AUDIT_DIR / f"{session.identity[0]}.jsonl"))
    await session.wait_ready(RESUME_WAIT_S)
    log.info("--- broker demo: %d tools available: %s ---", len(broker.tools()),
             ", ".join(t["name"] for t in broker.tools()))
    calls = [
        ("computer_observe", {}),                                          # refused: no task yet
        ("task_submit", {"goal": "메모장에 인사말 입력"}),
        ("computer_observe", {}),
        ("computer_click", {"x": 640, "y": 420}),                          # defaults: left, single
        ("computer_click", {"x": 5000, "y": 100}),                         # refused: outside the screen
        ("computer_hotkey", {"keys": ["win", "r"]}),                       # refused: policy (Run dialog)
        ("computer_type", {"text": "안녕하세요"}),
        ("runtime_get_state", {}),
        ("session_stop", {"reason": "TASK_COMPLETE"}),
    ]
    last_action = None
    for tool, args in calls:
        if tool == "runtime_get_state":
            args = {"action_id": last_action}
        result = await broker.call(tool, args)
        if result.ok and result.action_id:
            last_action = result.action_id
        await asyncio.sleep(0.25)                  # stay under the 5/s input rate limit
    ok = sum(1 for r in broker.audit.records if r["result"]["ok"])
    log.info("--- broker demo complete --- %d calls, %d ok, %d refused; audit: %s",
             len(broker.audit.records), ok, len(broker.audit.records) - ok, broker.audit.path)


class Sessions:
    """RuntimeSessions by identity; one Host process may hold several."""

    def __init__(self, registry: SessionRegistry, *,
                 on_end: Callable[[tuple[str, str, int]], None] | None = None, **session_kwargs):
        self.registry = registry
        self._on_end = on_end                        # e.g. stop the Sandbox (host/lifecycle.py)
        self.artifacts = None                        # host/artifacts.py ArtifactBroker: serves /scrp/v1/telemetry
        self._kwargs = session_kwargs
        self._by_id: dict[tuple[str, str, int], RuntimeSession] = {}

    def register(self, identity: tuple[str, str, int]) -> RuntimeSession:
        """Create the session at registration and start its startup clock."""
        session = self.get(identity)
        session.start_watchdog()
        return session

    def get(self, identity: tuple[str, str, int]) -> RuntimeSession:
        if identity not in self._by_id:
            self._by_id[identity] = RuntimeSession(identity, on_terminated=self._ended, **self._kwargs)
        return self._by_id[identity]

    def _ended(self, identity: tuple[str, str, int]) -> None:
        self.registry.revoke(identity)               # every token of this session
        if self._on_end:
            self._on_end(identity)


def make_process_request(registry: SessionRegistry, telemetry: bool = False):
    """Reject before the WebSocket upgrade: wrong path, or no valid token.

    The token is only checked here, not used up; that happens when HELLO
    (or CHANNEL_HELLO) arrives. The client gets a bare 401 whatever the reason,
    so it learns nothing about which tokens exist; the reason goes to our log.
    Each path accepts only its own token kinds: a Telemetry token never opens
    the Control channel, and the reverse.
    """
    def process_request(connection, request):
        peer = connection.remote_address
        if request.path == CONTROL_PATH:
            kinds = None
        elif telemetry and request.path == TELEMETRY_PATH:
            kinds = TELEMETRY_KINDS
        else:
            log.warning("REFUSED %s: path %s", peer, request.path)
            return connection.respond(http.HTTPStatus.NOT_FOUND, "Not Found\n")
        try:
            token = bearer_token(request.headers.get("Authorization"))
            registry.check(token) if kinds is None else registry.check(token, kinds)
        except AuthError as e:
            log.warning("REFUSED %s: %s", peer, e)
            return connection.respond(http.HTTPStatus.UNAUTHORIZED, "Unauthorized\n")
        return None
    return process_request


async def handle(ws, run_demo: str | None, sessions: Sessions, limits: dict) -> None:
    registry = sessions.registry
    peer = ws.remote_address
    log.info("CONNECTED from %s path=%s (TLS)", peer, ws.request.path)
    if ws.request.path == TELEMETRY_PATH and sessions.artifacts is not None:
        from host.telemetry import handle_telemetry
        return await handle_telemetry(ws, registry, sessions, sessions.artifacts)

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
    session = sessions.get(rec.identity())
    if session.terminated:
        raise ProtocolError("SESSION_TERMINATED", f"{rec.session_id} is terminated")
    await session.admit_hello(hello)                  # no credentials for a Runner that fails this
    log.info("RECV %-16s runner=%s caps=%s session=%s (%s token accepted)", "HELLO",
             hello["payload"]["runner_version"], hello["payload"]["capabilities"], rec.session_id, rec.kind)

    conn = Connection(ws, hello, rec.identity(), profile=session.contract)
    reconnect = registry.issue_reconnect(rec.identity())
    allowed = ALLOWED_CAPABILITIES + ([ARTIFACT_CAPABILITY] if session.contract == ARTIFACT_EXPORT_V1 else [])
    granted = [c for c in hello["payload"]["capabilities"] if c in allowed]
    session.granted_capabilities = set(granted)       # the Broker's tool catalog follows this (B-11)
    await conn.send(conn.me.reply(hello, "HELLO_ACK", {
        "selected_version": "1.0",
        "allowed_capabilities": granted,
        "limits": limits,
        "channel_credentials": {
            "telemetry": _telemetry_credential(registry, session),
            "reconnect": {"token": reconnect.token, "expires_at": reconnect.expires_utc},
        },
    }))
    log.info("CONNECTION %s up (connection #%d of %s) granted=%s",
             conn.id, session.connections + 1, rec.session_id, granted)
    if not session.verified:
        log.info("Runner says it is ready; the Host verifies before READY")

    reader = asyncio.create_task(conn.reader())
    heartbeat = None
    try:
        await session.attach(conn)
        heartbeat = asyncio.create_task(session.heartbeat_loop(conn))
        if run_demo and session.connections == 1:
            demo_fn = broker_demo if run_demo == "broker" else demo
            session.demo_task = asyncio.create_task(demo_fn(session))   # outlives this connection
        await conn.closed.wait()
    except ProtocolError as e:
        log.error("connection %s aborted: %s", conn.id, e)
    finally:
        session.detach(conn)
        for t in (heartbeat, reader):
            if t:
                t.cancel()


def make_handler(run_demo: str | bool | None, sessions: Sessions, limits: dict):
    run_demo = "protocol" if run_demo is True else (run_demo or None)
    async def handler(ws):
        try:
            await handle(ws, run_demo, sessions, limits)
        except ProtocolError as e:
            log.error("handshake rejected: %s", e)
            await ws.close(code=1008, reason=e.code)
        except asyncio.TimeoutError:
            log.error("runner did not send HELLO in time")
            await ws.close(code=1008, reason="HELLO timeout")
    return handler


def start_server(registry: SessionRegistry, cert_path: Path, key_path: Path,
                 run_demo: str | bool | None = True, host: str = HOST, port: int = PORT, *,
                 sessions: Sessions | None = None,
                 heartbeat_interval_s: float = HEARTBEAT_INTERVAL_S,
                 alive_timeout_s: float = ALIVE_TIMEOUT_S,
                 reconnect_grace_s: float = RECONNECT_GRACE_S,
                 profile: StartupProfile | None = None, ssl_context: ssl.SSLContext | None = None):
    """The wss:// server. There is deliberately no plaintext variant.

    Pass ssl_context to keep a handle on it: load_cert_chain() on it again
    switches new connections to a new certificate (host/mcp_server.py does
    this once the Sandbox's Host address is known)."""
    if sessions is None:
        sessions = Sessions(registry, heartbeat_interval_s=heartbeat_interval_s,
                            alive_timeout_s=alive_timeout_s, reconnect_grace_s=reconnect_grace_s,
                            profile=profile)
    limits = {
        "max_message_bytes": 65536,
        "max_queue_depth": 32,
        "heartbeat_interval_ms": max(1000, int(heartbeat_interval_s * 1000)),   # schema minimums
        "alive_timeout_ms": max(500, int(alive_timeout_s * 1000)),
    }
    return serve(make_handler(run_demo, sessions, limits), host, port,
                 ssl=ssl_context or tls.server_context(cert_path, key_path),
                 process_request=make_process_request(registry, telemetry=sessions.artifacts is not None),
                 max_size=64 * 1024)


async def main(run_demo: str | None, session: tuple[str, str, int], bootstrap_file: Path,
               startup_timeout_s: float = STARTUP_TIMEOUT_S, advertise: str | None = None) -> None:
    # advertise: the Host address the Runner connects to (Sandbox Manager's start()).
    # It goes into the certificate SAN and the bootstrap file.
    cert_path, key_path = tls.ensure_dev_cert(CERT_DIR, addresses=[advertise] if advertise else ())
    cert_pem = cert_path.read_text(encoding="ascii")
    registry = SessionRegistry()
    uploads = ObservationUploads()
    sessions = Sessions(registry, profile=StartupProfile(timeout_s=startup_timeout_s), uploads=uploads)
    rec = registry.issue(*session)
    write_bootstrap(bootstrap_file, rec, cert_pem, PORT, host=advertise, upload_port=UPLOAD_PORT)
    # The token itself is never logged.
    log.info("session %s / %s / gen %s registered; token valid until %s, single use",
             *rec.identity(), rec.expires_utc)
    log.info("bootstrap written to %s", bootstrap_file)
    log.info("host certificate sha256=%s", tls.fingerprint(cert_pem))

    upload_server = await start_upload_server(uploads, tls.server_context(cert_path, key_path), HOST, UPLOAD_PORT)
    async with upload_server, start_server(registry, cert_path, key_path, run_demo, sessions=sessions):
        log.info("listening on wss://%s:%d%s", HOST, PORT, CONTROL_PATH)
        log.info("screenshot uploads on https://%s:%d%s<upload_id>", HOST, UPLOAD_PORT, UPLOAD_PATH)
        sessions.register(rec.identity())
        log.info("waiting for the Runner; READY must be reached within %.0fs", startup_timeout_s)
        await asyncio.Future()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="SCRP Host sender (WBS 3.4, 4.4, 4.5, 4.6, 5.6)")
    ap.add_argument("--no-demo", action="store_true", help="handshake and heartbeats only")
    ap.add_argument("--demo", choices=["protocol", "broker"], default="protocol",
                    help="protocol: SCRP messages directly; broker: MCP tool calls through the Broker")
    ap.add_argument("--session", default="SES-001")
    ap.add_argument("--runtime", default="RT-SBX-001")
    ap.add_argument("--generation", type=int, default=1)
    ap.add_argument("--bootstrap-out", type=Path, default=BOOTSTRAP_FILE,
                    help="where to write the Runner's bootstrap config")
    ap.add_argument("--startup-timeout", type=float, default=STARTUP_TIMEOUT_S,
                    help="seconds from registration to READY before the session fails (default 120)")
    ap.add_argument("--advertise-address", default=None,
                    help="Host address the Runner connects to (goes into the certificate SAN and bootstrap host)")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-5s %(message)s")
    try:
        asyncio.run(main(None if args.no_demo else args.demo, (args.session, args.runtime, args.generation),
                         args.bootstrap_out, args.startup_timeout, args.advertise_address))
    except KeyboardInterrupt:
        pass
