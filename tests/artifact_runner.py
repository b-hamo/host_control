"""A test Runner for artifact-export-v1, built on MiniRunner (tests only, not a real Runner).

It behaves like the Runner contract (sandbox_runner 3270091, docs/artifact-export-contract.md):
HELLO advertises artifact.export.v1, the Telemetry channel is opened with the token from
HELLO_ACK, candidates are four-field SECURITY_EVENTs, and an ARTIFACT_REQUEST is answered by a
PUT with the request's token, then one ARTIFACT_RESULT on the Control connection. Knobs make it
misbehave the ways the contract lists, to test the Host's refusals.
"""

from __future__ import annotations

import asyncio
import http.client
import json
import uuid
from datetime import datetime, timezone

from websockets.asyncio.client import connect

from host import tls
from mini_runner import DEFAULT_CAPABILITIES, MiniRunner
from scrp.envelope import Endpoint
from scrp.validate import ARTIFACT_EXPORT_V1, parse_and_validate

CAP = "artifact.export.v1"


def put_artifact(port: int, cert_pem: str, upload_id: str, token: str | None, data: bytes, *,
                 content_type: str = "application/octet-stream", length: int | None = None,
                 extra_headers: dict | None = None) -> tuple[int, bytes]:
    """PUT like the Runner's HttpsUploader (pinned certificate). Returns (status, body)."""
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=tls.client_context(cert_pem), timeout=10)
    headers = {"Content-Type": content_type, "Content-Length": str(len(data) if length is None else length)}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    headers.update(extra_headers or {})
    try:
        conn.putrequest("PUT", f"/scrp/v1/artifacts/{upload_id}", skip_accept_encoding=True)
        for k, v in headers.items():
            conn.putheader(k, v)
        conn.endheaders()
        if data:
            conn.send(data)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


class ArtifactRunner(MiniRunner):
    def __init__(self, port: int, cert_pem: str, identity, *, upload_port: int,
                 artifact_port: int | None = None, **kw):
        kw.setdefault("capabilities", [*DEFAULT_CAPABILITIES, CAP])
        super().__init__(port, cert_pem, identity, upload_port=upload_port, **kw)
        self.profile = ARTIFACT_EXPORT_V1
        self.port = port
        self.artifact_port = artifact_port if artifact_port is not None else upload_port
        self.files: dict[str, tuple[str, bytes]] = {}       # event_id -> (relative_path, bytes)
        self.artifact_requests: list[dict] = []
        self.puts: list[tuple[int, bytes]] = []              # (status, body) of every artifact PUT
        self.results: list[dict] = []
        self.telemetry_token: str | None = None
        self.tws = None
        self.tme: Endpoint | None = None
        # misbehaviour
        self.unavailable: set[str] = set()                  # answer CANDIDATE_UNAVAILABLE for these
        self.wrong_bytes_sent = False
        self.skip_result = False
        self.skip_put = False
        self.put_token_override: str | None = None
        self.hold_put: asyncio.Event | None = None           # wait for this before the PUT

    async def connect(self, token: str) -> dict:
        ack = await super().connect(token)
        self.telemetry_token = ack["payload"]["channel_credentials"]["telemetry"]["token"]
        self.granted = ack["payload"]["allowed_capabilities"]
        return ack

    async def open_telemetry(self, token: str | None = None) -> dict:
        url = f"wss://127.0.0.1:{self.port}/scrp/v1/telemetry"
        self.tws = await connect(url, ssl=tls.client_context(self.cert_pem), open_timeout=5,
                                 additional_headers={"Authorization": f"Bearer {token or self.telemetry_token}"})
        self.tme = Endpoint(*self.identity)
        await self.tws.send(json.dumps(self.tme.envelope("CHANNEL_HELLO", {"channel": "telemetry"})))
        ack = parse_and_validate(await asyncio.wait_for(self.tws.recv(), 5), ARTIFACT_EXPORT_V1, 16384)
        assert ack["type"] == "CHANNEL_ACK", ack
        self.tme.connection_id = ack["connection_id"]
        return ack

    async def report(self, relative_path: str, data: bytes, event_id: str | None = None,
                     payload_override: dict | None = None) -> dict:
        """A file appeared in Output: send the candidate, return the EVENT_ACK."""
        event_id = event_id or str(uuid.uuid4())
        self.files.setdefault(event_id, (relative_path, data))
        observed = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        payload = payload_override or {"event_id": event_id, "observed_at": observed,
                                       "category": "ARTIFACT_CANDIDATE", "relative_path": relative_path}
        await self.tws.send(json.dumps(self.tme.envelope("SECURITY_EVENT", payload), ensure_ascii=False))
        return parse_and_validate(await asyncio.wait_for(self.tws.recv(), 5), ARTIFACT_EXPORT_V1, 16384)

    async def on_artifact_request(self, msg: dict) -> None:
        self.artifact_requests.append(msg)
        asyncio.get_running_loop().create_task(self._transfer(msg))   # never block the Control channel

    async def _transfer(self, msg: dict) -> None:
        p = msg["payload"]
        ev = p["candidate_event_id"]
        if ev in self.unavailable or ev not in self.files:
            return await self._result(msg, "FAILED", 0, "CANDIDATE_UNAVAILABLE", "Candidate unavailable")
        data = self.files[ev][1]
        if self.hold_put is not None:
            await self.hold_put.wait()
        if not self.skip_put:
            status, body = await asyncio.to_thread(put_artifact, self.artifact_port, self.cert_pem, p["upload_id"],
                                                   self.put_token_override or p["upload_token"], data)
            self.puts.append((status, body))
            if status != 201 or body:
                return await self._result(msg, "FAILED", len(data), "UPLOAD_FAILED", "Upload failed")
        if self.skip_result:
            return
        await self._result(msg, "UPLOADED", len(data) + (1 if self.wrong_bytes_sent else 0))

    async def _result(self, msg: dict, transfer: str, sent: int, code: str | None = None,
                      message: str = "") -> None:
        p = msg["payload"]
        payload = {"candidate_event_id": p["candidate_event_id"], "upload_id": p["upload_id"],
                   "transfer": transfer, "bytes_sent": sent}
        if code is None:
            out = self.me.reply(msg, "ARTIFACT_RESULT", payload)
        else:
            out = self.me.envelope("ARTIFACT_RESULT", payload, correlation_id=msg["message_id"], status="ERROR",
                                   error={"code": code, "message": message, "retryable": False,
                                          "recommended_next_step": None})
        self.results.append(out)
        try:
            await self._send(out)
        except Exception:  # noqa: BLE001 - the connection may be gone in drop tests
            pass
