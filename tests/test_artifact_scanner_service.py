"""artifact-export-v1 with --artifact-scanner defender-service (Windows only).

The whole way: Runner PUT (HTTPS) → ArtifactGrants → Named Pipe → SecureArtifactScanner job →
scan → user approval already given → PUBLISH by the service → Host check → EXPORTED.

The service runs in this process (scanner_service ScannerRuntime on a unique pipe, the same code
as the installed service) with FakeScanner in place of MpCmdRun. The installed service itself is
used in tests/test_scanner_integration.py.
"""

import asyncio
import hashlib
import secrets
import sys
import time
import uuid
from dataclasses import replace
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="the scanner service is Windows only")
pytest.importorskip("win32file")

from artifact_runner import put_artifact  # noqa: E402
from scanner_helpers import FakeScanner, make_config  # noqa: E402
from test_artifact_export import HANGUL_TXT, TEXT, Approver, Host, candidate_id  # noqa: E402

from host.artifact_scan import DefenderServiceScanner  # noqa: E402
from host.artifacts import _check_published, _remove_if_same  # noqa: E402
from host.scanner_client import ScannerServiceClient, ScannerServiceError, job_identity  # noqa: E402
from scanner_service.models import Verdict  # noqa: E402
from scanner_service.runtime import ScannerRuntime, token_info  # noqa: E402



class Service:
    """A SecureArtifactScanner runtime in this process, publishing into the Host's export folder."""

    def __init__(self, tmp_path: Path, fake: FakeScanner, export_root: Path | None = None, **cfg):
        if token_info()["is_admin"]:
            pytest.skip("elevated: the in-process service would run as an administrator, which the Host "
                        "(correctly) refuses; run these as a standard user")
        self.pipe = r"\\.\pipe\sas-host-" + secrets.token_hex(5)
        export_root = export_root or tmp_path / "exp"
        export_root.mkdir(parents=True, exist_ok=True)
        cfg = {"max_file_bytes": 1024 * 1024, "max_chunk_bytes": 256 * 1024, "max_request_bytes": 512 * 1024, **cfg}
        self.config = replace(make_config(tmp_path / "svc", **cfg),
                              export_root=export_root, pipe_name=self.pipe)
        self.fake = fake
        self.rt = ScannerRuntime(self.config, scanner=fake, dev_mode=True)
        self.rt.start()

    def quarantine(self) -> list[Path]:
        return list(self.config.quarantine_root.rglob("*"))

    def wait_empty(self, timeout: float = 5.0) -> list[Path]:
        deadline = time.monotonic() + timeout
        while self.quarantine() and time.monotonic() < deadline:
            time.sleep(0.1)
        return self.quarantine()

    def scanner(self, **kw) -> DefenderServiceScanner:
        return DefenderServiceScanner(ScannerServiceClient(self.pipe, verify_server=False, timeout_s=10),
                                      expected_account=None, **kw)

    def stop(self):
        self.rt.stop(5)


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


def run(coro, timeout=60):
    return asyncio.run(asyncio.wait_for(coro, timeout))


async def export_one(host, r, path, data, timeout=15):
    await r.report(path, data)
    aid = candidate_id(await host.call("artifact_list", {}), path)
    accepted = await host.call("artifact_export", {"artifact_id": aid})
    final = await host.wait_artifact(aid, timeout=timeout)
    return aid, accepted, final


def no_host_file(tmp_path) -> bool:
    inc = tmp_path / "art" / "incoming"
    return not inc.exists() or not list(inc.iterdir())


# --------------------------------------------------------------------- the whole way
@pytest.mark.parametrize("path,data", [(HANGUL_TXT, TEXT), ("빈파일.txt", b""), ("큰파일.txt", ("가" * 100_000).encode())])
def test_export_through_the_service(tmp_path, service, path, data):
    svc = service()
    approver = Approver()

    async def body():
        host = Host(tmp_path, approver=approver, scanner=svc.scanner())
        r, serving = await host.start()
        aid, accepted, final = await export_one(host, r, path, data)
        again = await host.call("artifact_export", {"artifact_id": aid})
        await host.close(serving)
        return accepted, final, again, r

    accepted, final, again, r = run(body())
    assert accepted["accepted"] and final["status"] == "EXPORTED", final
    exported = Path(final["export_path"])
    assert exported.read_bytes() == data and exported.name == Path(path.replace("\\", "/")).name
    assert exported.parent == tmp_path / "exp" / "SES-ART-001" / final["artifact_id"]
    assert final["sha256"] == hashlib.sha256(data).hexdigest() and final["size_bytes"] == len(data)
    assert final["result"]["engine"] == "defender-service"
    assert r.puts == [(201, b"")]                                   # the HTTPS contract is unchanged
    assert len(svc.fake.scanned) == 1 and svc.fake.scanned[0].name == "payload.part"
    assert no_host_file(tmp_path)                                   # never a Host .part file
    assert svc.wait_empty() == []                                   # service quarantine disposed
    assert again["status"] == "EXPORTED" and len(r.artifact_requests) == 1 and len(approver.calls) == 1


@pytest.mark.parametrize("fake,path,data,code", [
    (FakeScanner(Verdict.DETECTED, detail="Virus:DOS/EICAR_Test_File"), "a.txt", b"x", "MALWARE_DETECTED"),
    (FakeScanner(Verdict.ERROR), "a.txt", b"x", "SCAN_ERROR"),
    (FakeScanner(Verdict.UNVERIFIABLE), "a.txt", b"x", "SCAN_UNVERIFIABLE"),
    (FakeScanner(Verdict.UNAVAILABLE), "a.txt", b"x", "SCANNER_UNAVAILABLE"),
    (FakeScanner(error=RuntimeError("MpCmdRun crashed")), "a.txt", b"x", "SCAN_ERROR"),
    (FakeScanner(), "tool.exe", b"MZ", "FORMAT_NOT_ALLOWED"),
    (FakeScanner(), "a.txt", b"\xff\xfe\x00bad", "NOT_UTF8"),
])
def test_service_verdicts_block_and_publish_nothing(tmp_path, service, fake, path, data, code):
    svc = service(fake)

    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=svc.scanner())
        r, serving = await host.start()
        _, _, final = await export_one(host, r, path, data)
        await host.close(serving)
        return final

    final = run(body())
    assert final["status"] == "BLOCKED" and final["result"]["code"] == code, final
    assert final["export_path"] is None and not final["can_export"]
    assert not [p for p in (tmp_path / "exp").rglob("*") if p.is_file()]
    assert svc.wait_empty() == [] and no_host_file(tmp_path)


def test_scan_timeout_blocks_and_cancels_the_job(tmp_path, service):
    svc = service(FakeScanner(wait_for_cancel=True))

    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=svc.scanner(scan_timeout_s=1.0))
        r, serving = await host.start()
        _, _, final = await export_one(host, r, "a.txt", b"slow")
        await host.close(serving)
        return final

    final = run(body())
    assert final["status"] == "BLOCKED" and final["result"]["code"] == "SCAN_TIMEOUT"
    assert svc.wait_empty() == [] and not list((tmp_path / "exp").rglob("*.txt"))


def test_changed_bytes_are_never_published(tmp_path, service, monkeypatch):
    """Before the scan the service says it holds other bytes: CONTENT_CHANGED, nothing published."""
    svc = service()
    scanner = svc.scanner()
    real_status, real_scan = scanner.client.status, scanner.client.scan

    async def lying_status(ident, job_id):
        return {**await real_status(ident, job_id), "sha256": "0" * 64}

    async def lying_scan(ident, job_id):
        await real_scan(ident, job_id)
        return await lying_status(ident, job_id)
    monkeypatch.setattr(scanner.client, "status", lying_status)
    monkeypatch.setattr(scanner.client, "scan", lying_scan)

    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=scanner)
        r, serving = await host.start()
        _, _, final = await export_one(host, r, "a.txt", b"abc")
        await host.close(serving)
        return final

    final = run(body())
    assert final["status"] == "BLOCKED" and final["result"]["code"] == "CONTENT_CHANGED", final
    assert not list((tmp_path / "exp").rglob("*.txt")) and svc.wait_empty() == []


def test_service_side_change_after_scan_blocks(tmp_path, service, monkeypatch):
    svc = service()
    monkeypatch.setattr(svc.rt.quarantine, "verify_unchanged", lambda st: "content changed")

    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=svc.scanner())
        r, serving = await host.start()
        _, _, final = await export_one(host, r, "a.txt", b"abc")
        await host.close(serving)
        return final

    final = run(body())
    assert final["status"] == "BLOCKED" and final["result"]["code"] == "CONTENT_CHANGED", final
    assert not list((tmp_path / "exp").rglob("*.txt"))


# --------------------------------------------------------------------- service missing or failing
def test_no_service_means_no_export_and_no_approval_prompt(tmp_path):
    approver = Approver()
    scanner = DefenderServiceScanner(ScannerServiceClient(r"\\.\pipe\sas-missing-" + secrets.token_hex(4),
                                                          verify_server=False, timeout_s=1))

    async def body():
        host = Host(tmp_path, approver=approver, scanner=scanner)
        r, serving = await host.start()
        await r.report("a.txt", b"abc")
        aid = candidate_id(await host.call("artifact_list", {}), "a.txt")
        res = await host.call("artifact_export", {"artifact_id": aid})
        lst = await host.call("artifact_list", {})
        await host.close(serving)
        return res, lst, r

    res, lst, r = run(body())
    assert res["error"] == "SCANNER_UNAVAILABLE" and "scanner pipe" in res["message"], res
    assert approver.calls == [] and r.artifact_requests == []           # nobody asked, nothing sent
    assert lst["artifacts"][0]["status"] == "PENDING" and lst["artifacts"][0]["can_export"]


def test_service_publishing_elsewhere_is_not_used(tmp_path, service):
    svc = service(export_root=tmp_path / "somewhere-else")

    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=svc.scanner())
        r, serving = await host.start()
        await r.report("a.txt", b"abc")
        aid = candidate_id(await host.call("artifact_list", {}), "a.txt")
        res = await host.call("artifact_export", {"artifact_id": aid})
        await host.close(serving)
        return res

    res = run(body())
    assert res["error"] == "SCANNER_UNAVAILABLE" and "export folder" in res["message"]


def test_service_lost_before_the_upload_refuses_it(tmp_path, service):
    svc = service()

    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=svc.scanner())
        r, serving = await host.start()
        await r.report("a.txt", b"abc")
        aid = candidate_id(await host.call("artifact_list", {}), "a.txt")
        svc.stop()                                                    # gone after the health check
        await host.call("artifact_export", {"artifact_id": aid})
        final = await host.wait_artifact(aid)
        await host.close(serving)
        return final, r

    final, r = run(body())
    assert r.puts and r.puts[0][0] == 503                              # the PUT is refused, not stored
    assert final["status"] == "BLOCKED" and final["result"]["code"] == "UPLOAD_FAILED" and final["can_export"]
    assert no_host_file(tmp_path) and not list((tmp_path / "exp").rglob("*.txt"))


def test_service_stopping_during_the_scan_blocks(tmp_path, service):
    svc = service(FakeScanner(wait_for_cancel=True))

    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=svc.scanner())
        r, serving = await host.start()
        await r.report("a.txt", b"abc")
        aid = candidate_id(await host.call("artifact_list", {}), "a.txt")
        await host.call("artifact_export", {"artifact_id": aid})
        await asyncio.to_thread(svc.fake.started.wait, 10)
        await asyncio.to_thread(svc.stop)
        final = await host.wait_artifact(aid)
        await host.close(serving)
        return final

    final = run(body())
    assert final["status"] == "BLOCKED" and final["result"]["code"] in ("SCAN_ERROR", "SCANNER_UNAVAILABLE"), final
    assert not list((tmp_path / "exp").rglob("*.txt"))


# --------------------------------------------------------------------- grants, results, cancellation
def test_receiver_rules_hold_in_service_mode(tmp_path, service):
    svc = service()

    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=svc.scanner(), artifact_max_bytes=8,
                    artifact_tuning={"upload_lifetime_s": 30.0})
        r, serving = await host.start()
        grants = host.backend.artifacts.grants
        port, pem = host.boot["artifact_upload"]["port"], host.boot["host_certificate_pem"]
        ident = host.backend.session.identity
        g, tok = grants.issue(ident, "ART-X", str(uuid.uuid4()), 8, 30.0, file_name="x.txt")
        res = {"no_token": await asyncio.to_thread(put_artifact, port, pem, g.upload_id, None, b"abc"),
               "bad_token": await asyncio.to_thread(put_artifact, port, pem, g.upload_id, "B" * 43, b"abc"),
               "ok": await asyncio.to_thread(put_artifact, port, pem, g.upload_id, tok, b"abc"),
               "reuse": await asyncio.to_thread(put_artifact, port, pem, g.upload_id, tok, b"abc")}
        job = await svc.scanner().client.status(job_identity(ident, "ART-X"), g.scanner_job_id)
        g2, tok2 = grants.issue(ident, "ART-Y", str(uuid.uuid4()), 8, 30.0, file_name="y.txt")
        res["too_big"] = await asyncio.to_thread(put_artifact, port, pem, g2.upload_id, tok2, b"123456789")
        g3, tok3 = grants.issue(ident, "ART-Z", str(uuid.uuid4()), 8, 0.2, file_name="z.txt")
        await asyncio.sleep(0.4)
        res["expired"] = await asyncio.to_thread(put_artifact, port, pem, g3.upload_id, tok3, b"1")
        grants.cancel(g)                                              # drops the received job too
        await host.close(serving)
        return res, g, job

    res, g, job = run(body())
    assert res["no_token"][0] == 401 and res["bad_token"][0] == 403
    assert res["ok"] == (201, b"") and res["reuse"][0] == 409
    assert res["too_big"][0] == 413 and res["expired"][0] == 410
    assert job["state"] == "RECEIVED" and job["size"] == 3 and job["sha256"] == hashlib.sha256(b"abc").hexdigest()
    assert g.path is None and g.scanner_job_id is None and no_host_file(tmp_path)
    assert svc.wait_empty() == []


def test_result_mismatch_drops_the_job(tmp_path, service):
    svc = service()

    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=svc.scanner())
        r, serving = await host.start()
        r.wrong_bytes_sent = True
        _, _, final = await export_one(host, r, "lie.txt", b"abc")
        await host.close(serving)
        return final

    final = run(body())
    assert final["status"] == "BLOCKED" and final["result"]["code"] == "RESULT_MISMATCH"
    assert svc.fake.scanned == [] and svc.wait_empty() == []


@pytest.mark.parametrize("how", ["telemetry", "session_stop"])
def test_channel_loss_or_session_end_cancels_the_service_job(tmp_path, service, how):
    svc = service(FakeScanner(wait_for_cancel=True))

    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=svc.scanner())
        r, serving = await host.start()
        await r.report("a.txt", b"abc")
        aid = candidate_id(await host.call("artifact_list", {}), "a.txt")
        await host.call("artifact_export", {"artifact_id": aid})
        await asyncio.to_thread(svc.fake.started.wait, 10)              # the service is scanning it
        if how == "telemetry":
            await r.tws.close()
            final = await host.wait_artifact(aid)
        else:
            await host.call("session_stop", {"reason": "TASK_COMPLETE"})
            final = None
        await asyncio.sleep(0.5)
        await host.close(serving)
        return final

    final = run(body())
    if final is not None:
        assert final["status"] == "BLOCKED" and final["result"]["code"] == "TELEMETRY_LOST"
    assert svc.wait_empty() == [] and not list((tmp_path / "exp").rglob("*.txt"))


def test_a_published_job_cannot_be_published_again(tmp_path, service):
    svc = service()

    async def body():
        scanner = svc.scanner()
        host = Host(tmp_path, approver=Approver(), scanner=scanner)
        r, serving = await host.start()
        grants = host.backend.artifacts.grants
        jobs = []
        orig = grants.release

        def remember(g):
            jobs.append((g.identity, g.artifact_id, g.scanner_job_id, g.sha256))
            orig(g)
        grants.release = remember
        _, _, final = await export_one(host, r, "a.txt", b"abc")
        ident, aid, job, sha = jobs[0]
        try:
            await scanner.client.publish(job_identity(ident, aid), job, {
                "approved": True, "approval_id": "again", "approved_by": "test", "job_id": job, "artifact_id": aid,
                "session_id": ident[0], "sha256": sha})
            err = None
        except ScannerServiceError as e:
            err = e.code
        await host.close(serving)
        return final, err

    final, err = run(body())
    assert final["status"] == "EXPORTED" and err == "ALREADY_PUBLISHED"
    assert len(list((tmp_path / "exp").rglob("*.txt"))) == 1


def test_host_checks_of_the_published_file(tmp_path):
    exp = tmp_path / "exp" / "S" / "A"
    exp.mkdir(parents=True)
    f = exp / "a.txt"
    f.write_bytes(b"abc")
    sha = hashlib.sha256(b"abc").hexdigest()
    assert _check_published(f, f, 3, sha) is None
    assert "expected" in _check_published(tmp_path / "other.txt", f, 3, sha)
    assert "differ" in _check_published(f, f, 3, "0" * 64)
    _remove_if_same(f, 3, "0" * 64)                                     # not ours: kept
    assert f.exists()
    _remove_if_same(f, 3, sha)
    assert not f.exists()


def test_response_must_name_the_requested_job(tmp_path, service):
    svc = service()
    client = ScannerServiceClient(svc.pipe, verify_server=False)
    ident = job_identity(("SES-001", "RT-1", 1), "ART-1")

    async def body():
        up = client.upload(ident)
        job = await up.begin("a.txt", 3)
        await up.write(b"abc")
        await up.complete(hashlib.sha256(b"abc").hexdigest())
        await up.close()
        other = job_identity(("SES-001", "RT-1", 1), "ART-2")
        with pytest.raises(ScannerServiceError) as e:
            await client.status(other, job)                          # the service: no such job for ART-2
        return job, e.value.code

    job, code = run(body())
    assert code == "JOB_NOT_FOUND"
    from host.scanner_client import _check_view
    with pytest.raises(ScannerServiceError) as e:
        _check_view({"job_id": job, "session_id": "SES-001", "runtime_id": "RT-1", "generation": 1,
                     "artifact_id": "ART-9"}, ident, job)
    assert e.value.code == "RESPONSE_MISMATCH"


# The installed service itself: tests/test_scanner_integration.py
