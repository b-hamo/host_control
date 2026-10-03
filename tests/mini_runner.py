"""The smallest Runner that can talk to the Host, for tests.

Connects the way a Runner must (wss, pinned certificate, bearer token, HELLO
first) and answers OBSERVE / ACTION_REQUEST / STATE_REQUEST / HEARTBEAT /
TERMINATE. What it executed survives a reconnect, like a real Runner's
record keeping (protocol doc §7).
"""

from __future__ import annotations

import asyncio
import json

from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

from host import tls
from host.bootstrap import CONTROL_PATH
from scrp.envelope import Endpoint, new_nonce
from scrp.validate import parse_and_validate


def hello_msg(me: Endpoint) -> dict:
    return me.envelope("HELLO", {
        "supported_versions": ["1.0"],
        "os": {"family": "windows", "build": "26200.9457"},
        "runner_version": "mini-0.1.0",
        "capabilities": ["gui.observe", "gui.input"],
        "monitoring_coverage": {"process": False, "file": True, "network": False, "script": False, "registry": False},
        "client_nonce": new_nonce(),
    })


class MiniRunner:
    def __init__(self, port: int, cert_pem: str, identity: tuple[str, str, int], *,
                 answer_heartbeats: bool = True, drop_after_first_ack: bool = False):
        self.url = f"wss://127.0.0.1:{port}{CONTROL_PATH}"
        self.cert_pem = cert_pem
        self.identity = identity
        self.answer_heartbeats = answer_heartbeats
        self.drop_after_first_ack = drop_after_first_ack
        self.executed: list[str] = []          # action_ids, in order
        self.state_requests: list[str | None] = []
        self.heartbeats = 0
        self.reconnect_token: str | None = None
        self.ws = None
        self.me: Endpoint | None = None

    async def connect(self, token: str) -> dict:
        self.ws = await connect(self.url, ssl=tls.client_context(self.cert_pem),
                                additional_headers={"Authorization": f"Bearer {token}"}, open_timeout=5)
        self.me = Endpoint(*self.identity)
        hello = hello_msg(self.me)
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
                msg = parse_and_validate(raw.encode() if isinstance(raw, str) else raw)
                t = msg["type"]
                if t == "HEARTBEAT":
                    self.heartbeats += 1
                    if self.answer_heartbeats:
                        await self._send(self.me.reply(msg, "ALIVE", {
                            "runtime_state": "READY", "worker_alive": True, "queue_depth": 0, "uptime_ms": 1}))
                elif t == "OBSERVE":
                    await self._send(self.me.reply(msg, "OBSERVE_RESULT", {
                        "observation_id": f"OBS-{msg['action_id']}", "width": 1280, "height": 720,
                        "captured_at": msg["timestamp"], "sha256": "0" * 64,
                        "upload_id": msg["payload"]["upload_id"]}))
                elif t == "ACTION_REQUEST":
                    self.executed.append(msg["action_id"])
                    await self._send(self.me.reply(msg, "ACK", {"queue_position": 0, "reject_reason": None},
                                                   status="ACCEPTED"))
                    if self.drop_after_first_ack:
                        self.drop_after_first_ack = False
                        self.ws.transport.abort()          # the result never reaches the Host
                        return "dropped"
                    await self._send(self.me.reply(msg, "ACTION_RESULT", {
                        "execution_time_ms": 1, "result": {"input_delivered": True}}, status="SUCCESS"))
                elif t == "STATE_REQUEST":
                    target = msg["payload"]["action_id"]
                    self.state_requests.append(target)
                    await self._send(self.me.reply(msg, "STATE_RESULT", {
                        "runtime_state": "READY", "worker_alive": True, "queue_depth": 0,
                        "action_state": {"action_id": target, "status": "SUCCESS"}
                        if target in self.executed else None}))
                elif t == "TERMINATE":
                    await self._send(self.me.reply(msg, "TERMINATE_RESULT", {
                        "worker_stopped": True, "pending_actions_dropped": 0}))
                    await self.ws.close()
                    return "terminated"
        except ConnectionClosed:
            pass
        return "closed"

    def drop(self) -> None:
        self.ws.transport.abort()
