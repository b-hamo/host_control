"""host/scanner_client.py against a scripted pipe server (mock IPC, Windows only).

The stub answers each request with whatever the test scripts: wrong request ids, views of other
jobs, silence, a dropped connection. The client must turn every one of them into an error,
never into a result the Host would act on.
"""

import asyncio
import json
import secrets
import sys
import time

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Named Pipes are Windows only")
pytest.importorskip("win32file")

from host.scanner_client import ScannerServiceClient, ScannerServiceError, _check_view, job_identity  # noqa: E402
from scanner_service.ipc_server import ClientInfo, NamedPipeServer, current_user_sid, pipe_sddl  # noqa: E402
from scanner_service.models import PROTOCOL_VERSION  # noqa: E402

IDENT = job_identity(("SES-001", "RT-1", 1), "ART-000001")
JOB = "job-" + "a" * 32


def view(**kw):
    v = {"job_id": JOB, "session_id": "SES-001", "runtime_id": "RT-1", "generation": 1, "artifact_id": "ART-000001",
         "state": "RECEIVED", "outcome": None, "size": 3, "sha256": "0" * 64}
    v.update(kw)
    return v


class Stub:
    """Scripted handler: script(request) -> response dict, None (drop), or "sleep"."""

    def __init__(self, script):
        self.script = script
        self.requests = []

    def error_frame(self, code, message, request_id=None, retryable=False):
        return json.dumps({"protocol_version": PROTOCOL_VERSION, "request_id": request_id, "status": "ERROR",
                           "error": {"code": code, "message": message, "retryable": retryable}}).encode()

    def handle(self, raw: bytes, client: ClientInfo) -> bytes:
        req = json.loads(raw)
        self.requests.append(req)
        out = self.script(req)
        if out == "sleep":
            time.sleep(3)
            out = ok(req, view())
        if out is None:
            raise ConnectionAbortedError("stub drops the connection")
        return json.dumps(out).encode()


def ok(req, result):
    return {"protocol_version": PROTOCOL_VERSION, "request_id": req["request_id"], "status": "OK", "result": result}


@pytest.fixture
def stub():
    servers = []

    def start(script):
        h = Stub(script)
        name = r"\\.\pipe\sas-stub-" + secrets.token_hex(5)
        srv = NamedPipeServer(name, h, sddl=pipe_sddl(current_user_sid(), (current_user_sid(),)), max_instances=2,
                              max_request_bytes=512 * 1024, idle_timeout_s=5)
        srv.start()
        servers.append(srv)
        return ScannerServiceClient(name, verify_server=False, timeout_s=1.5, connect_timeout_s=1.0), h
    yield start
    for s in servers:
        s.stop(2)


def code_of(coro) -> str:
    with pytest.raises(ScannerServiceError) as e:
        asyncio.run(coro)
    return e.value.code


def test_a_normal_answer(stub):
    client, h = stub(lambda req: ok(req, view(state="SCANNED")))
    v = asyncio.run(client.status(IDENT, JOB))
    assert v["state"] == "SCANNED"
    req = h.requests[0]
    assert req["command"] == "GET_STATUS" and req["job_id"] == JOB and req["session_id"] == "SES-001"
    assert req["generation"] == 1 and req["artifact_id"] == "ART-000001"


def test_answer_to_another_request_is_refused(stub):
    client, _ = stub(lambda req: {**ok(req, view()), "request_id": "someone-else"})
    assert code_of(client.status(IDENT, JOB)) == "SCANNER_UNAVAILABLE"


@pytest.mark.parametrize("field,value", [("job_id", "job-" + "b" * 32), ("session_id", "SES-002"),
                                         ("runtime_id", "RT-2"), ("generation", 2), ("artifact_id", "ART-9")])
def test_view_of_another_job_is_refused(stub, field, value):
    client, _ = stub(lambda req: ok(req, view(**{field: value})))
    assert code_of(client.status(IDENT, JOB)) == "RESPONSE_MISMATCH"
    assert code_of(client.publish(IDENT, JOB, {})) == "RESPONSE_MISMATCH"


def test_dropped_connection_and_silence_are_unavailable(stub):
    client, _ = stub(lambda req: None)
    assert code_of(client.scan(IDENT, JOB)) == "SCANNER_UNAVAILABLE"
    client, _ = stub(lambda req: "sleep")                      # longer than the client's 1.5 s timeout
    t = time.monotonic()
    assert code_of(client.status(IDENT, JOB)) == "SCANNER_UNAVAILABLE"
    assert time.monotonic() - t < 3


def test_missing_service_fails_fast():
    client = ScannerServiceClient(r"\\.\pipe\sas-none-" + secrets.token_hex(4), verify_server=False,
                                  connect_timeout_s=1.0)
    t = time.monotonic()
    assert code_of(client.health()) == "SCANNER_UNAVAILABLE"
    assert time.monotonic() - t < 2.5


def test_pipe_held_by_another_process_is_refused(stub):
    client, _ = stub(lambda req: ok(req, view()))
    client.verify_server = True                               # the SCM's SecureArtifactScanner pid differs
    import host.scanner_client as sc
    original = sc.service_pid
    sc.service_pid = lambda: 4                                 # "the service is pid 4": the stub is not
    try:
        assert code_of(client.status(IDENT, JOB)) == "SCANNER_UNAVAILABLE"
    finally:
        sc.service_pid = original


def test_service_not_running_by_the_scm(monkeypatch):
    import host.scanner_client as sc
    monkeypatch.setattr(sc, "service_pid", lambda: None)
    assert code_of(ScannerServiceClient().health()) == "SCANNER_UNAVAILABLE"


@pytest.mark.parametrize("code,retryable", [("SERVICE_STOPPING", True), ("STORAGE_FULL", True), ("DISK_FULL", True),
                                            ("TOO_MANY_JOBS", True), ("JOB_NOT_FOUND", False),
                                            ("ALREADY_PUBLISHED", False)])
def test_service_errors_keep_their_code(stub, code, retryable):
    client, _ = stub(lambda req: {"protocol_version": PROTOCOL_VERSION, "request_id": req["request_id"],
                                  "status": "ERROR", "error": {"code": code, "message": "x", "retryable": False}})
    with pytest.raises(ScannerServiceError) as e:
        asyncio.run(client.status(IDENT, JOB))
    assert e.value.code == code and e.value.retryable == retryable


def test_upload_stream_checks_every_answer(stub):
    def script(req):
        if req["command"] == "BEGIN_UPLOAD":
            return ok(req, view(state="CREATED"))
        if req["command"] == "WRITE_CHUNK":
            return ok(req, {"job_id": JOB, "state": "RECEIVING", "received_bytes": 1})   # always says 1
        return ok(req, view())
    client, h = stub(script)

    async def body():
        up = client.upload(IDENT)
        await up.begin("a.txt", 10)
        await up.write(b"a")
        try:
            await up.write(b"bc")                              # service claims 1 byte, not 3
        finally:
            await up.close()
    assert code_of(body()) == "RESPONSE_MISMATCH"
    assert [r["command"] for r in h.requests] == ["BEGIN_UPLOAD", "WRITE_CHUNK", "WRITE_CHUNK"]
    assert h.requests[2]["payload"]["offset"] == 1


def test_event_loop_is_not_blocked(stub):
    client, _ = stub(lambda req: "sleep")

    async def body():
        ticks = 0

        async def ticker():
            nonlocal ticks
            while True:
                await asyncio.sleep(0.05)
                ticks += 1
        t = asyncio.create_task(ticker())
        try:
            await client.status(IDENT, JOB)
        except ScannerServiceError:
            pass
        t.cancel()
        return ticks
    assert asyncio.run(body()) >= 10                            # the loop kept running during the 1.5 s call


def test_aborts_finish_before_the_host_exits(stub):
    calls = []

    def script(req):
        time.sleep(0.3)
        calls.append(req["command"])
        return ok(req, view(state="DISPOSED", outcome="CANCELLED"))
    client, _ = stub(script)
    client.abort_soon(IDENT, JOB, "session ended")
    client.abort_soon(IDENT, JOB, "session ended")
    assert client.drain(5) == 0 and calls == ["ABORT", "ABORT"]


def test_check_view_helper():
    assert _check_view(view(), IDENT, JOB)["job_id"] == JOB
    with pytest.raises(ScannerServiceError):
        _check_view(view(generation="1"), IDENT, JOB)
