"""The smallest Runner that can talk to the Host, for tests.

Connects the way a Runner must (wss, pinned certificate, bearer token, HELLO
first) and answers OBSERVE / ACTION_REQUEST / STATE_REQUEST / HEARTBEAT /
TERMINATE. What it executed survives a reconnect, like a real Runner's
record keeping (protocol doc §7).
"""

from __future__ import annotations

import asyncio
import hashlib
import http.client
import json
import struct
import zlib
from datetime import datetime, timedelta, timezone

from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

from host import tls
from host.bootstrap import CONTROL_PATH
from scrp.envelope import Endpoint, new_nonce
from scrp.validate import parse_and_validate


DEFAULT_CAPABILITIES = ["gui.observe", "gui.input"]
DEFAULT_COVERAGE = {"process": False, "file": True, "network": False, "script": False, "registry": False}


def make_png(width: int, height: int, shade: int = 0) -> bytes:
    """A valid grey PNG, standard library only."""
    def chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + bytes([shade % 256]) * width for _ in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def put_png(port: int, cert_pem: str, upload_id: str, data: bytes) -> int:
    """PUT a screenshot the way a Runner must (pinned certificate). Returns the HTTP status."""
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=tls.client_context(cert_pem), timeout=10)
    try:
        conn.request("PUT", f"/scrp/v1/observations/{upload_id}", body=data,
                     headers={"Content-Type": "image/png", "Content-Length": str(len(data))})
        return conn.getresponse().status
    finally:
        conn.close()


def hello_msg(me: Endpoint, capabilities=None, coverage=None) -> dict:
    return me.envelope("HELLO", {
        "supported_versions": ["1.0"],
        "os": {"family": "windows", "build": "26200.9457"},
        "runner_version": "mini-0.1.0",
        "capabilities": DEFAULT_CAPABILITIES if capabilities is None else capabilities,
        "monitoring_coverage": DEFAULT_COVERAGE if coverage is None else coverage,
        "client_nonce": new_nonce(),
    })


class MiniRunner:
    def __init__(self, port: int, cert_pem: str, identity: tuple[str, str, int], *,
                 answer_heartbeats: bool = True, drop_after_first_ack: bool = False,
                 worker_alive: bool = True, answer_observe: bool = True,
                 capabilities: list[str] | None = None, coverage: dict | None = None,
                 reject_actions: bool = False, action_status: str = "SUCCESS",
                 action_error: dict | None = None, observe_error: dict | None = None,
                 capture_clock_offset_s: float = 0.0,
                 upload_port: int | None = None, upload_tamper: bool = False,
                 screen: tuple[int, int] = (1280, 720)):
        self.url = f"wss://127.0.0.1:{port}{CONTROL_PATH}"
        self.cert_pem = cert_pem
        self.identity = identity
        self.answer_heartbeats = answer_heartbeats
        self.drop_after_first_ack = drop_after_first_ack
        self.worker_alive = worker_alive
        self.answer_observe = answer_observe
        self.capabilities = capabilities
        self.coverage = coverage
        self.reject_actions = reject_actions
        self.action_status = action_status
        self.action_error = action_error          # envelope error on ACK REJECTED / ACTION_RESULT
        self.observe_error = observe_error        # answer OBSERVE with a correlated ERROR instead
        self.capture_clock_offset_s = capture_clock_offset_s   # skew the Runner's captured_at
        self.upload_port = upload_port            # None: behave like a Runner that does not upload yet
        self.upload_tamper = upload_tamper        # upload one PNG, report another
        self.screen = screen
        self.uploads: list[int] = []              # HTTP status of each upload
        self.requests: list[dict] = []          # every ACTION_REQUEST as received
        self.executed: list[str] = []          # action_ids, in order
        self.state_requests: list[str | None] = []
        self.heartbeats = 0
        self.reconnect_token: str | None = None
        self.ws = None
        self.me: Endpoint | None = None
        self.profile: str | None = None           # artifact-export-v1 runners set this (artifact_runner.py)

    async def connect(self, token: str) -> dict:
        """HELLO → HELLO_ACK. Raises ConnectionClosed if the Host refuses at HELLO."""
        self.ws = await connect(self.url, ssl=tls.client_context(self.cert_pem),
                                additional_headers={"Authorization": f"Bearer {token}"}, open_timeout=5)
        self.me = Endpoint(*self.identity)
        hello = hello_msg(self.me, self.capabilities, self.coverage)
        await self.ws.send(json.dumps(hello))
        ack = parse_and_validate((await asyncio.wait_for(self.ws.recv(), 5)).encode())
        assert ack["type"] == "HELLO_ACK", ack
        self.me.connection_id = ack["connection_id"]
        self.reconnect_token = ack["payload"]["channel_credentials"]["reconnect"]["token"]
        return ack

    async def _send(self, msg: dict) -> None:
        await self.ws.send(json.dumps(msg, ensure_ascii=False))

    async def serve(self) -> str:
        """Answer until the connection ends. Returns "terminated", "dropped" or "closed"."""
        try:
            async for raw in self.ws:
                msg = parse_and_validate(raw.encode() if isinstance(raw, str) else raw, self.profile)
                t = msg["type"]
                if t == "HEARTBEAT":
                    self.heartbeats += 1
                    if self.answer_heartbeats:
                        await self._send(self.me.reply(msg, "ALIVE", {
                            "runtime_state": "READY", "worker_alive": True, "queue_depth": 0, "uptime_ms": 1}))
                elif t == "OBSERVE":
                    if not self.answer_observe:
                        continue
                    if self.observe_error:
                        await self._send(self.me.error(self.observe_error["code"], self.observe_error["message"],
                                                       correlation_id=msg["message_id"]))
                        continue
                    stamp = (datetime.now(timezone.utc) + timedelta(seconds=self.capture_clock_offset_s)
                             ).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
                    w, h = self.screen
                    png = make_png(w, h, len(self.uploads))
                    sha = hashlib.sha256(png).hexdigest()
                    if self.upload_port is not None:              # PUT first, then OBSERVE_RESULT (§8)
                        sent = make_png(w, h, 200) if self.upload_tamper else png
                        self.uploads.append(await asyncio.to_thread(
                            put_png, self.upload_port, self.cert_pem, msg["payload"]["upload_id"], sent))
                    await self._send(self.me.reply(msg, "OBSERVE_RESULT", {
                        "observation_id": f"OBS-{msg['action_id']}", "width": w, "height": h,
                        "captured_at": stamp, "sha256": sha,
                        "upload_id": msg["payload"]["upload_id"]}))
                elif t == "ACTION_REQUEST":
                    self.requests.append(msg)
                    if self.reject_actions:
                        ack = self.me.reply(msg, "ACK", {"queue_position": None, "reject_reason": "queue full"},
                                            status="REJECTED")
                        if self.action_error:
                            ack["error"] = self.action_error
                        await self._send(ack)
                        continue
                    self.executed.append(msg["action_id"])
                    await self._send(self.me.reply(msg, "ACK", {"queue_position": 0, "reject_reason": None},
                                                   status="ACCEPTED"))
                    if self.drop_after_first_ack:
                        self.drop_after_first_ack = False
                        self.ws.transport.abort()          # the result never reaches the Host
                        return "dropped"
                    result = {"input_delivered": self.action_status == "SUCCESS"}
                    if self.action_status != "SUCCESS":
                        result["detail"] = "element not found"
                    done = self.me.reply(msg, "ACTION_RESULT", {"execution_time_ms": 1, "result": result},
                                         status=self.action_status)
                    if self.action_error and self.action_status != "SUCCESS":
                        done["error"] = self.action_error
                    await self._send(done)
                elif t == "STATE_REQUEST":
                    target = msg["payload"]["action_id"]
                    self.state_requests.append(target)
                    await self._send(self.me.reply(msg, "STATE_RESULT", {
                        "runtime_state": "READY", "worker_alive": self.worker_alive, "queue_depth": 0,
                        "action_state": {"action_id": target, "status": "SUCCESS"}
                        if target in self.executed else None}))
                elif t == "ARTIFACT_REQUEST":
                    await self.on_artifact_request(msg)
                elif t == "TERMINATE":
                    await self._send(self.me.reply(msg, "TERMINATE_RESULT", {
                        "worker_stopped": True, "pending_actions_dropped": 0}))
                    await self.ws.close()
                    return "terminated"
        except ConnectionClosed:
            pass
        return "closed"

    async def on_artifact_request(self, msg: dict) -> None:
        """Overridden by ArtifactRunner; a plain MiniRunner never gets one."""
        raise AssertionError("unexpected ARTIFACT_REQUEST")

    def drop(self) -> None:
        self.ws.transport.abort()
