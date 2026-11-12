"""SecureArtifactScanner: job states, export conditions, IPC requests, the Named Pipe (Windows only).

FakeScanner stands in for Defender. The pipe tests run a real NamedPipeServer in this
process on a unique pipe name, allowed for the current user (no service install needed).
"""

import base64
import hashlib
import json
import secrets
import sys
import threading
import time
from dataclasses import replace

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows service component")
pytest.importorskip("win32file")

import _winapi  # noqa: E402

from scanner_helpers import (IDENT, TEXT, FakeScanner, approval, begin, make_config, make_manager,  # noqa: E402
                             quarantine_files, scanned, upload, wait_state)
from scanner_service import pipe_io  # noqa: E402
from scanner_service.config import load_config  # noqa: E402
from scanner_service.ipc_client import ScannerClient  # noqa: E402
from scanner_service.ipc_server import (ClientInfo, NamedPipeServer, RequestHandler, current_user_sid,  # noqa: E402
                                        pipe_sddl)
from scanner_service.models import (FINISHED, PROTOCOL_VERSION, TRANSITIONS, Identity, JobState,  # noqa: E402
                                    ScannerError, Verdict, check_transition)

S = JobState


def err(fn, *a, **kw) -> ScannerError:
    with pytest.raises(ScannerError) as e:
        fn(*a, **kw)
    return e.value


# ----------------------------------------------------------------------------- state machine
def test_transition_table():
    path = [S.CREATED, S.RECEIVING, S.RECEIVED, S.SCANNING, S.SCANNED, S.PUBLISHING, S.EXPORTED, S.DISPOSED]
    for a, b in zip(path, path[1:]):
        check_transition("j", a, b)
    for a in path[:-2]:
        for end in (S.BLOCKED, S.FAILED, S.CANCELLED):
            check_transition("j", a, end)
            check_transition("j", end, S.DISPOSED)
    for bad in [(S.CREATED, S.SCANNING), (S.RECEIVED, S.PUBLISHING), (S.SCANNING, S.EXPORTED),
                (S.BLOCKED, S.SCANNED), (S.FAILED, S.PUBLISHING), (S.DISPOSED, S.CREATED), (S.EXPORTED, S.CANCELLED)]:
        assert err(check_transition, "j", *bad).code == "INVALID_STATE"
    assert TRANSITIONS[S.DISPOSED] == ()


# ----------------------------------------------------------------------------- normal flow
def test_upload_scan_publish_dispose(tmp_path):
    m = make_manager(tmp_path)
    job = begin(m)
    assert job.state == S.CREATED and job.job_id.startswith("job-")
    for off in range(0, len(TEXT), 5):
        m.write_chunk(IDENT, job.job_id, off, TEXT[off:off + 5])
    assert job.state == S.RECEIVING
    m.complete_upload(IDENT, job.job_id)
    assert job.state == S.RECEIVED and job.size == len(TEXT) and job.sha256 == hashlib.sha256(TEXT).hexdigest()
    m.start_scan(IDENT, job.job_id)
    wait_state(job, ("SCANNED",))
    assert m.scanner.scanned == [m.quarantine.root / "session-SES-001" / job.job_id / "payload.part"]
    m.publish(IDENT, job.job_id, approval(job))
    assert job.outcome == S.EXPORTED and job.state == S.DISPOSED
    dest = tmp_path / "Export" / "SES-001" / "ART-000001" / "결과.txt"     # Guest path → file name only
    assert dest.read_bytes() == TEXT and job.export_path == str(dest)
    assert quarantine_files(m) == [] and m.quarantine.reserved == 0
    assert [p.name for p in dest.parent.iterdir()] == ["결과.txt"]          # no partial file left
    view = m.status(IDENT, job.job_id).view()
    assert view["outcome"] == "EXPORTED" and view["scan"]["verdict"] == "CLEAN"


def test_empty_file(tmp_path):
    m = make_manager(tmp_path)
    job = upload(m, b"", name="empty.txt")
    m.start_scan(IDENT, job.job_id)
    wait_state(job, ("SCANNED",))
    m.publish(IDENT, job.job_id, approval(job))
    assert (tmp_path / "Export" / "SES-001" / "ART-000001" / "empty.txt").read_bytes() == b""


# ----------------------------------------------------------------------------- refusals
def test_invalid_order_is_refused(tmp_path):
    m = make_manager(tmp_path)
    job = begin(m)
    assert err(m.start_scan, IDENT, job.job_id).code == "INVALID_STATE"
    assert err(m.publish, IDENT, job.job_id, approval(job)).code == "INVALID_STATE"
    m.write_chunk(IDENT, job.job_id, 0, TEXT)
    m.complete_upload(IDENT, job.job_id)
    assert err(m.write_chunk, IDENT, job.job_id, len(TEXT), b"x").code == "INVALID_STATE"
    assert err(m.complete_upload, IDENT, job.job_id).code == "INVALID_STATE"
    m.start_scan(IDENT, job.job_id)
    assert err(m.start_scan, IDENT, job.job_id).code == "INVALID_STATE"        # no second scan
    wait_state(job, ("SCANNED",))
    m.publish(IDENT, job.job_id, approval(job))
    assert err(m.publish, IDENT, job.job_id, approval(job)).code == "ALREADY_PUBLISHED"


def test_duplicate_job_is_refused_until_the_first_ends(tmp_path):
    m = make_manager(tmp_path)
    first = begin(m)
    assert err(begin, m).code == "DUPLICATE_JOB"
    other = begin(m, ident=replace(IDENT, artifact_id="ART-000002"))
    assert other.job_id != first.job_id
    m.abort(IDENT, first.job_id)
    assert begin(m).job_id not in (first.job_id, other.job_id)


@pytest.mark.parametrize("field, value", [("session_id", "SES-999"), ("runtime_id", "RT-OTHER"),
                                          ("generation", 2), ("artifact_id", "ART-999999")])
def test_every_request_must_name_the_jobs_identity(tmp_path, field, value):
    m = make_manager(tmp_path)
    job = begin(m)
    wrong = replace(IDENT, **{field: value})
    for call in (lambda: m.write_chunk(wrong, job.job_id, 0, b"x"), lambda: m.status(wrong, job.job_id),
                 lambda: m.abort(wrong, job.job_id), lambda: m.start_scan(wrong, job.job_id)):
        assert err(call).code == "JOB_NOT_FOUND"
    assert job.state == S.CREATED


def test_unknown_job_id(tmp_path):
    m = make_manager(tmp_path)
    begin(m)
    for jid in ("job-" + "0" * 32, "../../etc", None, 5):
        assert err(m.status, IDENT, jid).code == "JOB_NOT_FOUND"


def test_new_generation_invalidates_the_old_one(tmp_path):
    m = make_manager(tmp_path)
    old = upload(m)
    newer = replace(IDENT, generation=2)
    begin(m, ident=newer)
    assert old.outcome == S.CANCELLED and old.error["code"] == "RUNTIME_REPLACED" and old.state == S.DISPOSED
    assert err(begin, m, ident=replace(IDENT, artifact_id="ART-2")).code == "STALE_GENERATION"


def test_size_and_hash_checks(tmp_path):
    m = make_manager(tmp_path)
    assert err(m.begin_upload, IDENT, {"file_name": "a.txt", "size": 64 * 1024 + 1, "sha256": "0" * 64}).code \
        == "FILE_TOO_LARGE"
    assert err(m.begin_upload, IDENT, {"file_name": "a.txt", "size": 1, "sha256": "XYZ"}).code == "INVALID_ARGUMENT"
    assert err(m.begin_upload, IDENT, {"file_name": "a\x00.txt", "size": 1, "sha256": "0" * 64}).code \
        == "INVALID_ARGUMENT"
    job = m.begin_upload(IDENT, {"file_name": "a.txt", "size": len(TEXT), "sha256": "0" * 64})
    m.write_chunk(IDENT, job.job_id, 0, TEXT)
    assert err(m.complete_upload, IDENT, job.job_id).code == "HASH_MISMATCH"
    assert job.outcome == S.FAILED and job.state == S.DISPOSED and quarantine_files(m) == []
    job = begin(m, ident=replace(IDENT, artifact_id="ART-2"))
    assert err(m.write_chunk, job.identity, job.job_id, 0, b"x" * 4097).code == "CHUNK_TOO_LARGE"
    e = err(m.write_chunk, job.identity, job.job_id, 3, b"abc")
    assert e.code == "BAD_OFFSET" and job.state == S.RECEIVING                 # resend allowed
    assert err(m.write_chunk, job.identity, job.job_id, 0, TEXT + b"!").code == "SIZE_EXCEEDED"
    assert job.outcome == S.FAILED


# ----------------------------------------------------------------------------- verdicts block export
@pytest.mark.parametrize("verdict, code", [(Verdict.DETECTED, "MALWARE_DETECTED"), (Verdict.ERROR, "SCAN_ERROR"),
                                           (Verdict.TIMEOUT, "SCAN_TIMEOUT"),
                                           (Verdict.UNAVAILABLE, "SCANNER_UNAVAILABLE"),
                                           (Verdict.UNVERIFIABLE, "SCAN_UNVERIFIABLE")])
def test_anything_but_clean_blocks(tmp_path, verdict, code):
    m = make_manager(tmp_path, FakeScanner(verdict))
    job = scanned(m)
    assert job.outcome == S.BLOCKED and job.error["code"] == code and job.state == S.DISPOSED
    assert err(m.publish, IDENT, job.job_id, approval(job)).code == "INVALID_STATE"
    assert quarantine_files(m) == [] and list((tmp_path / "Export").iterdir()) == []


def test_scanner_crash_blocks(tmp_path):
    m = make_manager(tmp_path, FakeScanner(error=RuntimeError("boom")))
    job = scanned(m)
    assert job.outcome == S.BLOCKED and job.error["code"] == "SCAN_ERROR"


@pytest.mark.parametrize("name, data, code", [("tool.exe", TEXT, "FORMAT_NOT_ALLOWED"),
                                              ("a.txt", b"\xff\xfe\x00bin", "NOT_UTF8")])
def test_format_policy_first(tmp_path, name, data, code):
    m = make_manager(tmp_path)
    job = scanned(m, data, name=name)
    assert job.outcome == S.BLOCKED and job.error["code"] == code
    assert m.scanner.scanned == []                    # not even handed to Defender


@pytest.mark.parametrize("winerror, code", [(225, "MALWARE_DETECTED"), (226, "MALWARE_DETECTED"),
                                             (5, "CONTENT_REMOVED")])
def test_real_time_protection_refusing_reads(tmp_path, monkeypatch, winerror, code):
    """Seen as the service account: the EICAR upload reopens fine, then reading it fails with 225."""
    m = make_manager(tmp_path)
    job = upload(m)

    def refuse(st):
        raise OSError(0, "virus", str(st.payload_path), winerror)
    monkeypatch.setattr(m.quarantine, "read_payload", refuse)
    m.start_scan(IDENT, job.job_id)
    wait_state(job, ("DISPOSED",))
    assert job.outcome == S.BLOCKED and job.error["code"] == code and m.scanner.scanned == []


def test_file_changed_after_scan_is_not_published(tmp_path, monkeypatch):
    m = make_manager(tmp_path)
    job = scanned(m)
    monkeypatch.setattr(m.quarantine, "verify_unchanged", lambda st: "content changed")
    assert err(m.publish, IDENT, job.job_id, approval(job)).code == "CONTENT_CHANGED"
    assert job.outcome == S.BLOCKED and list((tmp_path / "Export").rglob("*.txt")) == []


# ----------------------------------------------------------------------------- approval and publish
@pytest.mark.parametrize("override, code", [({"approved": False}, "APPROVAL_DENIED"),
                                            ({"sha256": "0" * 64}, "APPROVAL_MISMATCH"),
                                            ({"artifact_id": "ART-X"}, "APPROVAL_MISMATCH"),
                                            ({"session_id": "SES-X"}, "APPROVAL_MISMATCH"),
                                            ({"job_id": "job-" + "1" * 32}, "APPROVAL_MISMATCH"),
                                            ({"approval_id": "../x"}, "APPROVAL_INVALID"),
                                            ({"path": "C:\\Windows"}, "APPROVAL_INVALID")])
def test_publish_needs_a_matching_approval(tmp_path, override, code):
    m = make_manager(tmp_path)
    job = scanned(m)
    assert err(m.publish, IDENT, job.job_id, approval(job, **override)).code == code
    assert job.state == S.SCANNED and not job.published                       # still publishable
    assert err(m.publish, IDENT, job.job_id, None).code == "APPROVAL_INVALID"
    m.publish(IDENT, job.job_id, approval(job))
    assert job.outcome == S.EXPORTED


def test_publish_disabled_without_export_root(tmp_path):
    m = make_manager(tmp_path, export=False)
    job = scanned(m)
    assert err(m.publish, IDENT, job.job_id, approval(job)).code == "PUBLISH_DISABLED"
    assert job.state == S.SCANNED


def test_publish_never_overwrites(tmp_path):
    m = make_manager(tmp_path)
    job = scanned(m, name="report.txt")
    dest = tmp_path / "Export" / "SES-001" / "ART-000001" / "report.txt"
    dest.parent.mkdir(parents=True)
    dest.write_text("user's own file")
    assert err(m.publish, IDENT, job.job_id, approval(job)).code == "PUBLISH_CONFLICT"
    assert dest.read_text() == "user's own file" and job.outcome == S.FAILED
    assert sorted(p.name for p in dest.parent.iterdir()) == ["report.txt"]


def test_publish_does_not_follow_a_planted_junction(tmp_path):
    m = make_manager(tmp_path)
    job = scanned(m)
    outside = tmp_path / "outside"
    outside.mkdir()
    _winapi.CreateJunction(str(outside), str(tmp_path / "Export" / "SES-001"))
    assert err(m.publish, IDENT, job.job_id, approval(job)).code == "PUBLISH_FAILED"
    assert list(outside.rglob("*")) == [] and job.outcome == S.FAILED


def test_guest_file_name_never_becomes_a_path(tmp_path):
    m = make_manager(tmp_path)
    job = scanned(m, name="..\\..\\..\\Windows\\evil.txt")
    m.publish(IDENT, job.job_id, approval(job))
    assert (tmp_path / "Export" / "SES-001" / "ART-000001" / "evil.txt").exists()
    job2 = scanned(m, ident=replace(IDENT, artifact_id="ART-2"), name="CON.txt")
    m.publish(job2.identity, job2.job_id, approval(job2))
    assert (tmp_path / "Export" / "SES-001" / "ART-2" / "_CON.txt").exists()


# ----------------------------------------------------------------------------- cancel / session end
def test_abort_during_scan(tmp_path):
    fake = FakeScanner(wait_for_cancel=True)
    m = make_manager(tmp_path, fake)
    job = upload(m)
    m.start_scan(IDENT, job.job_id)
    assert fake.started.wait(5)
    m.abort(IDENT, job.job_id, "user stopped it")
    wait_state(job, ("DISPOSED",))
    assert job.outcome == S.CANCELLED and job.error == {"code": "ABORTED", "message": "user stopped it"}
    assert quarantine_files(m) == []


def test_session_end_cancels_all_its_jobs(tmp_path):
    m = make_manager(tmp_path)
    a = upload(m)
    b = begin(m, ident=replace(IDENT, artifact_id="ART-2"))
    c = begin(m, ident=Identity("SES-OTHER", "RT-1", 1, "ART-1"))
    assert m.abort_session("SES-001") == 2
    assert a.outcome == b.outcome == S.CANCELLED and a.error["code"] == "SESSION_ENDED"
    assert c.state == S.CREATED


def test_stopping_service_refuses_new_work_and_cancels_running(tmp_path):
    fake = FakeScanner(wait_for_cancel=True)
    m = make_manager(tmp_path, fake)
    job = upload(m)
    m.start_scan(IDENT, job.job_id)
    fake.started.wait(5)
    t = time.monotonic()
    m.shutdown(5)
    assert time.monotonic() - t < 5
    assert job.outcome == S.CANCELLED and job.error["code"] == "SERVICE_STOPPING"
    assert err(begin, m, ident=replace(IDENT, artifact_id="ART-9")).code == "SERVICE_STOPPING"
    assert quarantine_files(m) == []


def test_idle_upload_and_old_jobs_expire(tmp_path):
    now = [1000.0]
    m = make_manager(tmp_path, clock=lambda: now[0], upload_idle_timeout_s=10, job_ttl_s=100)
    idle = begin(m)
    done = scanned(m, ident=replace(IDENT, artifact_id="ART-2"))
    now[0] += 11
    m.sweep()
    assert idle.outcome == S.CANCELLED and idle.error["code"] == "UPLOAD_TIMEOUT"
    assert done.state == S.SCANNED
    now[0] += 100
    m.sweep()
    assert done.outcome == S.CANCELLED and done.error["code"] == "JOB_EXPIRED"
    now[0] += 1000
    m.sweep()
    assert err(m.status, done.identity, done.job_id).code == "JOB_NOT_FOUND"     # record forgotten later
    assert quarantine_files(m) == []


# ----------------------------------------------------------------------------- IPC requests
def handler(m, **kw):
    return RequestHandler(m, lambda payload: {"ok": True}, max_chunk_bytes=m.config.max_chunk_bytes,
                          max_response_bytes=kw.get("max_response_bytes", 64 * 1024))


def req(command, **kw):
    r = {"protocol_version": PROTOCOL_VERSION, "request_id": "r1", "command": command, "session_id": IDENT.session_id,
         "runtime_id": IDENT.runtime_id, "generation": IDENT.generation, "artifact_id": IDENT.artifact_id,
         "payload": {}}
    r.update(kw)
    return json.dumps(r).encode()


CLIENT = ClientInfo(1, "S-1-5-21-1")


def call(h, raw: bytes) -> dict:
    return json.loads(h.handle(raw, CLIENT))


@pytest.mark.parametrize("raw, code", [
    (b"\xff\xfe", "BAD_REQUEST"),
    (b"[1,2]", "BAD_REQUEST"),
    (json.dumps({"command": "HEALTH_CHECK", "protocol_version": PROTOCOL_VERSION}).encode(), "BAD_REQUEST"),
    (req("HEALTH_CHECK", protocol_version="scanner-ipc-v0"), "UNSUPPORTED_PROTOCOL"),
    (req("RUN_COMMAND"), "UNKNOWN_COMMAND"),
    (req("SCAN_PATH", payload={"path": "C:\\Windows\\System32\\cmd.exe"}), "UNKNOWN_COMMAND"),
    (req("HEALTH_CHECK", path="C:\\x"), "BAD_REQUEST"),
    (req("BEGIN_UPLOAD", payload={"file_name": "a.txt", "size": 1, "sha256": "0" * 64, "dest": "C:\\x"}),
     "BAD_REQUEST"),
    (req("BEGIN_UPLOAD", payload=[1]), "BAD_REQUEST"),
    (req("BEGIN_UPLOAD", session_id="..\\..", payload={"file_name": "a.txt", "size": 1, "sha256": "0" * 64}),
     "INVALID_ARGUMENT"),
    (req("BEGIN_UPLOAD", generation="1", payload={"file_name": "a.txt", "size": 1, "sha256": "0" * 64}),
     "INVALID_ARGUMENT"),
    (req("BEGIN_UPLOAD", job_id="job-" + "0" * 32, payload={"file_name": "a.txt", "size": 1, "sha256": "0" * 64}),
     "BAD_REQUEST"),
    (req("GET_STATUS", job_id="job-" + "0" * 32), "JOB_NOT_FOUND"),
    (req("GET_STATUS"), "JOB_NOT_FOUND"),
    (req("ABORT", payload={"scope": "machine"}), "INVALID_ARGUMENT"),
])
def test_bad_requests_are_refused(tmp_path, raw, code):
    h = handler(make_manager(tmp_path))
    r = call(h, raw)
    assert r["status"] == "ERROR" and r["error"]["code"] == code, r
    assert list((tmp_path / "Quarantine").iterdir()) == []


def test_requests_drive_a_job(tmp_path):
    m = make_manager(tmp_path)
    h = handler(m)
    sha = hashlib.sha256(TEXT).hexdigest()
    r = call(h, req("BEGIN_UPLOAD", payload={"file_name": "a.txt", "size": len(TEXT), "sha256": sha}))
    assert r["status"] == "OK" and r["request_id"] == "r1"
    jid = r["result"]["job_id"]
    bad = call(h, req("WRITE_CHUNK", job_id=jid, payload={"offset": 0, "data": "@@not base64@@"}))
    assert bad["error"]["code"] == "BAD_REQUEST"
    big = call(h, req("WRITE_CHUNK", job_id=jid, payload={"offset": 0, "data": "A" * 6000}))
    assert big["error"]["code"] == "CHUNK_TOO_LARGE"
    ok = call(h, req("WRITE_CHUNK", job_id=jid, payload={"offset": 0, "data": base64.b64encode(TEXT).decode()}))
    assert ok["result"]["received_bytes"] == len(TEXT)
    assert call(h, req("COMPLETE_UPLOAD", job_id=jid))["result"]["state"] == "RECEIVED"
    assert call(h, req("SCAN", job_id=jid))["result"]["state"] == "SCANNING"
    job = m.status(IDENT, jid)
    wait_state(job, ("SCANNED",))
    pub = call(h, req("PUBLISH", job_id=jid, payload={"approval": approval(job)}))
    assert pub["result"]["outcome"] == "EXPORTED" and pub["result"]["export_path"].endswith("a.txt")
    s = call(h, req("ABORT", payload={"scope": "session"}))
    assert s["result"] == {"cancelled_jobs": 0}


def test_response_size_limit(tmp_path):
    h = RequestHandler(make_manager(tmp_path), lambda p: {"x": "y" * 5000}, max_chunk_bytes=4096,
                       max_response_bytes=1024)
    assert call(h, req("HEALTH_CHECK"))["error"]["code"] == "RESPONSE_TOO_LARGE"


# ----------------------------------------------------------------------------- the real pipe
@pytest.fixture
def pipe_server(tmp_path):
    m = make_manager(tmp_path)
    name = r"\\.\pipe\sas-test-" + secrets.token_hex(6)
    srv = NamedPipeServer(name, handler(m), sddl=pipe_sddl(current_user_sid(), (current_user_sid(),)),
                          max_instances=2, max_request_bytes=m.config.max_request_bytes, idle_timeout_s=5)
    srv.start()
    yield name, m, srv
    srv.stop(2)


def test_pipe_round_trip(pipe_server):
    name, m, _ = pipe_server
    with ScannerClient(name, timeout_s=5) as c:
        assert c.health() == {"ok": True}
        job = c.upload(IDENT, "결과.txt", TEXT, chunk=10)
        assert job["state"] == "RECEIVED" and job["size"] == len(TEXT)
        view = c.scan(IDENT, job["job_id"], 10)
        assert view["state"] == "SCANNED"
        pub = c.publish(IDENT, view)
        assert pub["outcome"] == "EXPORTED"
        with pytest.raises(ScannerError) as e:
            c.call("GET_STATUS", replace(IDENT, session_id="SES-OTHER"), job["job_id"])
        assert e.value.code == "JOB_NOT_FOUND"


def test_pipe_refuses_oversized_requests(pipe_server):
    name, m, _ = pipe_server
    with ScannerClient(name, timeout_s=5) as c:
        pipe_io.write_all(c.handle, pipe_io.HEADER.pack(m.config.max_request_bytes + 1))
        raw = pipe_io.read_frame(c.handle, 1 << 20, timeout_s=5)
        assert json.loads(raw)["error"]["code"] == "REQUEST_TOO_LARGE"
        assert pipe_io.read_frame(c.handle, 1 << 20, timeout_s=5) is None     # then the connection is closed
    with ScannerClient(name, timeout_s=5) as c:                                # the server keeps serving
        assert c.health() == {"ok": True}


def test_pipe_name_cannot_be_shared(pipe_server):
    name, m, _ = pipe_server
    other = NamedPipeServer(name, handler(m), sddl=pipe_sddl(current_user_sid(), ()), max_instances=1,
                            max_request_bytes=1024, idle_timeout_s=1)
    with pytest.raises(RuntimeError, match="already in use"):
        other.start()


def test_client_checks_who_serves_the_pipe(pipe_server):
    name, _, _ = pipe_server
    with pytest.raises(ConnectionError, match="not the service"):
        ScannerClient(name, timeout_s=2, expected_server_pid=4).connect()


def test_pipe_server_stops_promptly_with_idle_clients(tmp_path):
    m = make_manager(tmp_path)
    name = r"\\.\pipe\sas-test-" + secrets.token_hex(6)
    srv = NamedPipeServer(name, handler(m), sddl=pipe_sddl(current_user_sid(), (current_user_sid(),)),
                          max_instances=2, max_request_bytes=1024, idle_timeout_s=60)
    srv.start()
    c = ScannerClient(name, timeout_s=5)
    c.connect()                                          # connected, never sends anything
    t = time.monotonic()
    srv.stop(5)
    assert time.monotonic() - t < 3 and not any(th.is_alive() for th in srv._threads)
    c.close()


def test_pipe_dacl():
    sddl = pipe_sddl("S-1-5-80-1", ("S-1-5-21-9",))
    assert sddl.startswith("D:P(D;;GA;;;NU)")                      # protected, network logons denied
    assert "(A;;0x12019b;;;S-1-5-21-9)" in sddl                    # clients: no FILE_CREATE_PIPE_INSTANCE
    assert "(A;;GA;;;S-1-5-80-1)" in sddl and "WD" not in sddl and "AU" not in sddl


# ----------------------------------------------------------------------------- configuration
def test_config_file(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"quarantine_root": str(tmp_path / "Q"), "state_dir": str(tmp_path / "S"),
                             "export_root": None, "pipe_client_sids": ["S-1-5-21-1"], "max_file_bytes": 2048}))
    c = load_config(p)
    assert c.export_root is None and c.pipe_client_sids == ("S-1-5-21-1",) and c.max_file_bytes == 2048
    p.write_text(json.dumps({"quarantine_root": "C:\\Q", "max_file_byte": 1}))
    with pytest.raises(ValueError, match="unknown setting"):
        load_config(p)
    p.write_text(json.dumps({"max_file_bytes": 60 * 1024 * 1024}))
    with pytest.raises(ValueError, match="max_file_bytes"):
        load_config(p)
    assert make_config(tmp_path).log_dir == tmp_path / "State" / "logs"
    assert FINISHED                                                  # imported for the state table


# ----------------------------------------------------------------------------- streaming uploads (Host side)
def test_sha256_may_be_declared_when_the_upload_completes(tmp_path):
    """A streaming sender (the Host's HTTPS receiver) knows the hash only at the end."""
    m = make_manager(tmp_path)
    job = m.begin_upload(IDENT, {"file_name": "a.txt", "size": len(TEXT)})
    m.write_chunk(IDENT, job.job_id, 0, TEXT)
    assert err(m.complete_upload, IDENT, job.job_id).code == "INVALID_ARGUMENT"      # declared nowhere
    assert job.state == S.RECEIVING
    m.complete_upload(IDENT, job.job_id, hashlib.sha256(TEXT).hexdigest())
    assert job.state == S.RECEIVED and job.sha256 == hashlib.sha256(TEXT).hexdigest()
    other = m.begin_upload(replace(IDENT, artifact_id="ART-2"), {"file_name": "a.txt", "size": 3})
    m.write_chunk(other.identity, other.job_id, 0, b"abc")
    assert err(m.complete_upload, other.identity, other.job_id, "0" * 64).code == "HASH_MISMATCH"
    assert other.outcome == S.FAILED
    both = begin(m, ident=replace(IDENT, artifact_id="ART-3"))                     # declared at BEGIN too
    m.write_chunk(both.identity, both.job_id, 0, TEXT)
    assert err(m.complete_upload, both.identity, both.job_id, "1" * 64).code == "HASH_MISMATCH"
