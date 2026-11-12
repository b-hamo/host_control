"""defender-service: attacks and failures between the HTTPS receiver, the pipe and the service (Windows only).

Every case ends the same way: no file that was not received in full, scanned clean and approved is
ever EXPORTED, and nothing is left in the service's quarantine. The service runs in this process
(the installed one is tested in test_scanner_integration.py).
"""

import asyncio
import hashlib
import os
import socket
import ssl
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="the scanner service is Windows only")
pytest.importorskip("win32file")

import _winapi  # noqa: E402

from scanner_helpers import FakeScanner  # noqa: E402
from test_artifact_export import Approver, Host, candidate_id  # noqa: E402
from test_artifact_scanner_service import Service, export_one, no_host_file, run  # noqa: E402

from host import tls  # noqa: E402
from host.artifacts import _check_published  # noqa: E402
from host.scanner_client import ScannerServiceClient, ScannerServiceError, job_identity  # noqa: E402
from scanner_service.models import ScannerError  # noqa: E402


@pytest.fixture
def service(tmp_path):
    made = []

    def make(fake=None, **kw):
        s = Service(tmp_path, fake or FakeScanner(), **kw)
        made.append(s)
        return s
    yield make
    for s in made:
        s.stop()


def exported_files(tmp_path):
    return [p for p in (tmp_path / "exp").rglob("*") if p.is_file()]


def raw_put(port: int, pem: str, upload_id: str, token: str, declared: int, parts: list, between=None):
    """A PUT that sends its body in parts and may stop early (an interrupted Runner upload)."""
    ctx = tls.client_context(pem)
    with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as s:
            s.sendall((f"PUT /scrp/v1/artifacts/{upload_id} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\n"
                       f"Content-Type: application/octet-stream\r\nContent-Length: {declared}\r\n\r\n").encode())
            for i, part in enumerate(parts):
                s.sendall(part)
                if between and i == 0:
                    between()
            try:
                s.settimeout(10)
                return s.recv(4096).split(b"\r\n", 1)[0].decode()
            except (OSError, ssl.SSLError) as e:
                return f"closed ({type(e).__name__})"


async def grant_for(host, name="a.txt", max_bytes=1024 * 1024):
    grants = host.backend.artifacts.grants
    g, tok = grants.issue(host.backend.session.identity, "ART-RAW", str(uuid.uuid4()), max_bytes, 30.0,
                          file_name=name)
    return grants, g, tok


# --------------------------------------------------------------------- interrupted transfers
def test_interrupted_https_upload_leaves_nothing(tmp_path, service):
    svc = service()

    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=svc.scanner())
        r, serving = await host.start()
        grants, g, tok = await grant_for(host)
        port, pem = host.boot["artifact_upload"]["port"], host.boot["host_certificate_pem"]

        def cut_short():                     # 1000 bytes promised, 10 sent, then the connection closes
            ctx = tls.client_context(pem)
            with socket.create_connection(("127.0.0.1", port), timeout=10) as raw, \
                    ctx.wrap_socket(raw, server_hostname="127.0.0.1") as s:
                s.sendall((f"PUT /scrp/v1/artifacts/{g.upload_id} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {tok}"
                           "\r\nContent-Type: application/octet-stream\r\nContent-Length: 1000\r\n\r\n").encode())
                s.sendall(b"0123456789")
        await asyncio.to_thread(cut_short)
        await asyncio.sleep(1.0)
        state = g.state
        await host.close(serving)
        return state, g

    state, g = run(body())
    assert state == "FAILED" and g.size is None and g.scanner_job_id is None
    assert svc.wait_empty() == [] and no_host_file(tmp_path) and not exported_files(tmp_path)


def test_pipe_lost_in_the_middle_of_an_upload(tmp_path, service):
    svc = service()

    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=svc.scanner())
        r, serving = await host.start()
        grants, g, tok = await grant_for(host)
        port, pem = host.boot["artifact_upload"]["port"], host.boot["host_certificate_pem"]
        first, rest = b"a" * 100_000, b"b" * 100_000
        status = await asyncio.to_thread(raw_put, port, pem, g.upload_id, tok, 200_000, [first, rest],
                                         lambda: (time.sleep(0.5), svc.stop()))
        await host.close(serving)
        return status, g

    status, g = run(body())
    assert status.startswith("HTTP/1.1 5") or status.startswith("closed"), status     # never a 201
    assert g.state == "FAILED" and no_host_file(tmp_path) and not exported_files(tmp_path)


def test_body_larger_than_the_service_accepts(tmp_path, service):
    svc = service(max_file_bytes=1024)                   # the Host would take 1 MiB, the service only 1 KiB

    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=svc.scanner())
        r, serving = await host.start()
        _, _, final = await export_one(host, r, "big.txt", b"x" * 2048)
        await host.close(serving)
        return final, r

    final, r = run(body())
    assert r.puts[0][0] == 413 and final["status"] == "BLOCKED" and final["result"]["code"] == "UPLOAD_FAILED"
    assert svc.wait_empty() == [] and not exported_files(tmp_path)


def test_service_storage_cap(tmp_path, service):
    svc = service(store_limit_bytes=16)

    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=svc.scanner())
        r, serving = await host.start()
        _, _, final = await export_one(host, r, "a.txt", b"x" * 64)
        await host.close(serving)
        return final, r

    final, r = run(body())
    assert r.puts[0][0] == 503 and final["result"]["code"] == "UPLOAD_FAILED" and final["can_export"]
    assert not exported_files(tmp_path)


# --------------------------------------------------------------------- approval and identity
def test_no_approval_no_job(tmp_path, service):
    svc = service()

    async def body():
        host = Host(tmp_path, approver=Approver(answer=False), scanner=svc.scanner())
        r, serving = await host.start()
        await r.report("a.txt", b"abc")
        aid = candidate_id(await host.call("artifact_list", {}), "a.txt")
        res = await host.call("artifact_export", {"artifact_id": aid})
        jobs = svc.rt.manager.counts()
        await host.close(serving)
        return res, jobs, r

    res, jobs, r = run(body())
    assert res["error"] == "POLICY_DENIED" and r.artifact_requests == [] and r.puts == []
    assert jobs == {} and not exported_files(tmp_path)


def test_other_sessions_and_generations_cannot_touch_a_job(tmp_path, service):
    svc = service()
    client = ScannerServiceClient(svc.pipe, verify_server=False)
    mine = job_identity(("SES-001", "RT-1", 1), "ART-000001")

    async def body():
        up = client.upload(mine)
        job = await up.begin("a.txt", 3)
        await up.write(b"abc")
        await up.complete(hashlib.sha256(b"abc").hexdigest())
        await up.close()
        codes = {}
        for name, other in {"session": ("SES-002", "RT-1", 1), "runtime": ("SES-001", "RT-2", 1)}.items():
            ident = job_identity(other, "ART-000001")
            for call in (client.status(ident, job), client.scan(ident, job), client.abort(ident, job, "x"),
                         client.publish(ident, job, {})):
                try:
                    await call
                    codes[name] = "ACCEPTED"
                except ScannerServiceError as e:
                    codes.setdefault(name, e.code)
        newer = job_identity(("SES-001", "RT-1", 2), "ART-000002")
        up2 = client.upload(newer)
        await up2.begin("b.txt", 1)                       # generation 2 of the runtime starts
        await up2.close()
        old = await client.status(mine, job)
        try:
            await client.upload(job_identity(("SES-001", "RT-1", 1), "ART-000003")).begin("c.txt", 1)
            stale = "ACCEPTED"
        except ScannerServiceError as e:
            stale = e.code
        return codes, old, stale

    codes, old, stale = run(body())
    assert codes == {"session": "JOB_NOT_FOUND", "runtime": "JOB_NOT_FOUND"}
    assert old["outcome"] == "CANCELLED" and old["error"]["code"] == "RUNTIME_REPLACED"
    assert stale == "STALE_GENERATION"


# --------------------------------------------------------------------- publishing
@pytest.mark.parametrize("when", ["before_rename", "after_rename"])
def test_cancel_while_the_service_publishes(tmp_path, service, when):
    """A late PUBLISH success after the export was cancelled never leaves a published file."""
    svc = service()
    publishing = threading.Event()
    real = svc.rt.publisher.publish

    def slow_publish(job, st, cancel):
        publishing.set()
        if when == "before_rename":
            time.sleep(1.5)                               # the service sees the ABORT before renaming
            return real(job, st, cancel)
        out = real(job, st, cancel)                       # renamed already: the service reports success late
        time.sleep(1.5)
        return out
    svc.rt.publisher.publish = slow_publish

    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=svc.scanner())
        r, serving = await host.start()
        await r.report("a.txt", b"abc")
        aid = candidate_id(await host.call("artifact_list", {}), "a.txt")
        await host.call("artifact_export", {"artifact_id": aid})
        await asyncio.to_thread(publishing.wait, 10)
        await host.call("session_stop", {"reason": "TASK_COMPLETE"})
        await asyncio.sleep(3.0)                          # the late answer arrives meanwhile
        lst = host.backend.artifacts.list(host.backend.session, "ANY")
        await host.close(serving)
        return lst

    lst = run(body())
    art = lst["artifacts"][0]
    assert art["status"] != "EXPORTED" and art["export_path"] is None, art
    deadline = time.monotonic() + 5
    while exported_files(tmp_path) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not exported_files(tmp_path)
    assert svc.wait_empty() == []


def test_publish_failure_exports_nothing(tmp_path, service):
    svc = service()

    def broken(job, st, cancel):
        raise ScannerError("PUBLISH_FAILED", "disk error while copying")
    svc.rt.publisher.publish = broken

    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=svc.scanner())
        r, serving = await host.start()
        _, _, final = await export_one(host, r, "a.txt", b"abc")
        await host.close(serving)
        return final

    final = run(body())
    assert final["status"] == "BLOCKED" and final["result"]["code"] == "PUBLISH_FAILED" and not final["can_export"]
    assert not exported_files(tmp_path) and svc.wait_empty() == []


def test_exported_file_acl_and_hash(tmp_path, service):
    import win32security
    svc = service()

    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=svc.scanner())
        r, serving = await host.start()
        _, _, final = await export_one(host, r, "결과.txt", "내용\n".encode())
        await host.close(serving)
        return final

    final = run(body())
    path = Path(final["export_path"])
    assert hashlib.sha256(path.read_bytes()).hexdigest() == final["sha256"]
    sd = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
                                            win32security.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    aces = [dacl.GetAce(i) for i in range(dacl.GetAceCount())]
    assert aces and all(a[0][1] & win32security.INHERITED_ACE for a in aces)    # only what the folder gives
    wide = {"S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-7"}                  # Everyone, AU, Users, Anonymous
    writers = {win32security.ConvertSidToStringSid(a[2]) for a in aces if a[1] & 0x40000116}
    assert not writers & wide


def test_host_refuses_published_files_reached_through_links(tmp_path):
    real = tmp_path / "real" / "S" / "A"
    real.mkdir(parents=True)
    (real / "a.txt").write_bytes(b"abc")
    sha = hashlib.sha256(b"abc").hexdigest()
    (tmp_path / "exp").mkdir()
    _winapi.CreateJunction(str(tmp_path / "real" / "S"), str(tmp_path / "exp" / "S"))
    expected = tmp_path / "exp" / "S" / "A" / "a.txt"
    assert "link" in _check_published(expected, expected, 3, sha)


def test_host_refuses_a_published_symlink(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"abc")
    sha = hashlib.sha256(b"abc").hexdigest()
    real = tmp_path
    try:
        os.symlink(real / "a.txt", tmp_path / "link.txt")
    except OSError:
        pytest.skip("creating symbolic links needs Developer Mode or the privilege")
    assert "link" in _check_published(tmp_path / "link.txt", tmp_path / "link.txt", 3, sha)


# --------------------------------------------------------------------- the Host going away
def test_host_exit_during_a_scan_reaches_the_service(tmp_path, service):
    svc = service(FakeScanner(wait_for_cancel=True))

    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=svc.scanner())
        r, serving = await host.start()
        await r.report("a.txt", b"abc")
        aid = candidate_id(await host.call("artifact_list", {}), "a.txt")
        await host.call("artifact_export", {"artifact_id": aid})
        await asyncio.to_thread(svc.fake.started.wait, 10)
        await host.close(serving)                         # Host shuts down mid-scan
    run(body())
    assert svc.quarantine() == [] or svc.wait_empty(2) == []           # aborted by the time close() returned
    assert not exported_files(tmp_path)
