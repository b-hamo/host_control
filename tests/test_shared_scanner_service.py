"""Real Windows files/locks + Named Pipe + service job manager; Defender is a test double.

No installed service, real malware or host-wide configuration change is needed.
"""
import asyncio
import hashlib
import os
import secrets
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows file locks and Named Pipes")
pytest.importorskip("win32file")

from scanner_helpers import FakeScanner, IDENT, approval, make_config, make_manager, scanned, wait_state
from host.scanner_client import ScannerServiceClient
from host.shared_scanner import ServiceSharedFinisher
from scanner_service.models import JobState, ScannerError, Verdict
from scanner_service.runtime import ScannerRuntime


@pytest.fixture
def service(tmp_path):
    made = []
    def start(fake=None, **kw):
        cfg = make_config(tmp_path / f"svc-{len(made)}", shared_scan_enabled=True,
                          pipe_name=r"\\.\pipe\shared-test-" + secrets.token_hex(8), **kw)
        cfg.export_root.mkdir(parents=True)
        runtime = ScannerRuntime(cfg, scanner=fake or FakeScanner(), dev_mode=True)
        runtime.start()
        made.append(runtime)
        return runtime, ScannerServiceClient(cfg.pipe_name, verify_server=False, timeout_s=3)
    yield start
    for runtime in made:
        runtime.stop(5)


def source(tmp_path, files=None):
    share = tmp_path / "shared" / "SES-SHARED-1"
    share.mkdir(parents=True)
    for name, data in (files or {"App/tool.exe": b"MZ\x00\xffbinary", "문서.pdf": b"%PDF-test", "empty.txt": b""}).items():
        path = share / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return share


def finisher(client, **kw):
    return ServiceSharedFinisher(client, expected_account=None, **kw)


def test_keep_scans_service_quarantine_then_downloads_with_hash_and_motw(tmp_path, service, monkeypatch):
    runtime, client = service()
    share = source(tmp_path)
    downloads = tmp_path / "Downloads"
    monkeypatch.setattr("sandbox_manager.importer.downloads_folder", lambda: downloads)
    monkeypatch.setattr("sandbox_manager.shared.defender_scan", lambda *_: pytest.fail("legacy scan fallback"))
    def choose(result):
        assert result["status"] == "CLEAN" and len(runtime.scanner.scanned) == 3
        assert not downloads.exists()
        # Both writes and renames of a scanned source are denied while the person decides.
        with pytest.raises(OSError):
            (share / "문서.pdf").write_bytes(b"changed")
        with pytest.raises(OSError):
            (share / "App").rename(share / "Other")
        return "keep"
    result = finisher(client)(share, decide=choose)
    assert result["status"] == "EXPORTED", result
    target = downloads / "SandboxShared" / share.name
    assert result["dest"] == str(target) and not share.exists()
    for item in result["files"]:
        path = target / item["name"]
        assert path.stat().st_size == item["size"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"]
        assert "ZoneId=3" in Path(str(path) + ":Zone.Identifier").read_text()
    assert all(p.name == "payload.part" for p in runtime.scanner.scanned)
    assert not list(runtime.config.quarantine_root.rglob("payload.part"))


@pytest.mark.parametrize("verdict,status", [(Verdict.DETECTED, "BLOCKED"), (Verdict.ERROR, "QUARANTINED"),
                                           (Verdict.UNVERIFIABLE, "QUARANTINED"), (Verdict.TIMEOUT, "QUARANTINED")])
def test_failed_scan_never_offers_or_copies(tmp_path, service, verdict, status):
    runtime, client = service(FakeScanner(verdict))
    share, dest = source(tmp_path), tmp_path / "Downloads"
    result = finisher(client)(share, dest, lambda _: pytest.fail("offered failed scan"))
    assert result["status"] == status and result["dest"] is None, result
    assert share.exists() and not dest.exists()
    assert not list(runtime.config.quarantine_root.rglob("payload.part"))


@pytest.mark.parametrize("choice,status", [("delete", "DELETED"), ("hold", "HELD"), (None, "HELD")])
def test_keep_delete_hold_contract(tmp_path, service, choice, status):
    _, client = service()
    share, dest = source(tmp_path), tmp_path / "Downloads"
    result = finisher(client)(share, dest, (lambda _: choice) if choice else None)
    assert result["status"] == status and not dest.exists()
    assert share.exists() == (status == "HELD")


def test_added_file_at_approval_blocks_entire_export(tmp_path, service):
    _, client = service()
    share, dest = source(tmp_path), tmp_path / "Downloads"
    def choose(_):
        (share / "unscanned.exe").write_bytes(b"unscanned")
        return "keep"
    result = finisher(client)(share, dest, choose)
    assert result["status"] == "BLOCKED" and "CONTENT_CHANGED" in result["scan"]
    assert not dest.exists() and (share / "unscanned.exe").exists()


def test_missing_service_has_no_legacy_fallback(tmp_path):
    share, dest = source(tmp_path), tmp_path / "Downloads"
    client = ScannerServiceClient(r"\\.\pipe\missing-" + secrets.token_hex(8), verify_server=False,
                                  connect_timeout_s=0.1)
    result = finisher(client)(share, dest, lambda _: "keep")
    assert result["status"] == "QUARANTINED" and not dest.exists()


def test_old_or_disabled_service_blocks_shared(tmp_path, service):
    runtime, client = service()
    real_health = client.health
    async def old_health():
        health = await real_health()
        health.pop("shared_scan")
        return health
    client.health = old_health
    result = finisher(client)(source(tmp_path), tmp_path / "Downloads", lambda _: "keep")
    assert result["status"] == "QUARANTINED" and "SHARED_SCAN_DISABLED" in result["scan"]
    assert runtime.scanner.scanned == []


def test_forged_scan_receipt_is_not_copied(tmp_path, service):
    runtime, client = service(FakeScanner(delay=0.1))
    real_status = client.status
    async def wrong_status(*args):
        result = await real_status(*args)
        return result | {"sha256": "0" * 64}
    client.status = wrong_status
    # Force asynchronous completion so the altered status receipt is checked.
    result = finisher(client)(source(tmp_path), tmp_path / "Downloads", lambda _: "keep")
    assert result["status"] == "QUARANTINED" and "RESPONSE_MISMATCH" in result["scan"]


def test_timeout_cancels_service_job_and_keeps_source(tmp_path, service):
    runtime, client = service(FakeScanner(wait_for_cancel=True))
    share, dest = source(tmp_path), tmp_path / "Downloads"
    result = finisher(client, timeout_s=0.2)(share, dest, lambda _: "keep")
    assert result["status"] == "QUARANTINED" and "SCAN_TIMEOUT" in result["scan"]
    assert share.exists() and not dest.exists()


def test_hardlink_blocks_without_scanning(tmp_path, service):
    runtime, client = service()
    share = source(tmp_path, {"a.txt": b"a"})
    os.link(share / "a.txt", share / "b.txt")
    result = finisher(client)(share, tmp_path / "Downloads", lambda _: "keep")
    assert result["status"] == "BLOCKED" and runtime.scanner.scanned == []


def test_host_shutdown_cancels_publication_after_choice(tmp_path, service):
    _, client = service()
    finish = finisher(client)
    share, dest = source(tmp_path), tmp_path / "Downloads"
    def choose(_):
        finish.cancel()
        return "keep"
    result = finish(share, dest, choose)
    assert result["status"] == "QUARANTINED" and "CANCELLED" in result["scan"]
    assert not dest.exists() and share.exists()


def test_copy_failure_removes_partial_tree_but_keeps_source(tmp_path, service, monkeypatch):
    _, client = service()
    share, dest = source(tmp_path), tmp_path / "Downloads"
    monkeypatch.setattr(os, "fsync", lambda *_: (_ for _ in ()).throw(OSError("disk full")))
    result = finisher(client)(share, dest, lambda _: "keep")
    assert result["status"] == "QUARANTINED" and share.exists()
    assert list(dest.iterdir()) == []


def test_shared_profile_is_opt_in_and_cannot_publish(tmp_path):
    disabled = make_manager(tmp_path / "disabled")
    payload = {"file_name": "tool.exe", "size": 2, "scan_profile": "shared"}
    with pytest.raises(ScannerError, match="SHARED_SCAN_DISABLED"):
        disabled.begin_upload(IDENT, payload)
    enabled = make_manager(tmp_path / "enabled", shared_scan_enabled=True)
    job = enabled.begin_upload(IDENT, payload)
    enabled.write_chunk(IDENT, job.job_id, 0, b"MZ")
    enabled.complete_upload(IDENT, job.job_id, hashlib.sha256(b"MZ").hexdigest())
    enabled.start_scan(IDENT, job.job_id)
    wait_state(job, ("SCANNED",))
    with pytest.raises(ScannerError, match="scan-only"):
        enabled.publish(IDENT, job.job_id, approval(job))
    enabled.abort(IDENT, job.job_id)
    # Enabling Shared must never relax artifact-export-v1's format policy.
    artifact = scanned(enabled, b"MZ", name="tool.exe")
    assert artifact.outcome == JobState.BLOCKED and artifact.error["code"] == "FORMAT_NOT_ALLOWED"
    disabled.shutdown(3)
    enabled.shutdown(3)


def test_profile_limits_are_separate(tmp_path):
    manager = make_manager(tmp_path, shared_scan_enabled=True, max_file_bytes=2, shared_max_file_bytes=4)
    with pytest.raises(ScannerError, match="FILE_TOO_LARGE"):
        manager.begin_upload(IDENT, {"file_name": "a.txt", "size": 3})
    with pytest.raises(ScannerError, match="FILE_TOO_LARGE"):
        manager.begin_upload(IDENT, {"file_name": "a.exe", "size": 5, "scan_profile": "shared"})
    job = manager.begin_upload(IDENT, {"file_name": "a.exe", "size": 4, "scan_profile": "shared"})
    manager.abort(IDENT, job.job_id)
    manager.shutdown(3)


def test_host_selects_service_for_shared_without_artifact_export(tmp_path):
    from host.mcp_server import HostBackend
    from test_sandbox_launch import FakeManager, args
    a = args(tmp_path)
    a.shared, a.artifact_scanner, a.scanner_pipe = tmp_path / "shared", "defender-service", r"\\.\pipe\selected"
    backend = HostBackend(a, sandbox_manager=FakeManager(tmp_path / "sbx"))
    backend.start()
    try:
        assert backend.ready.wait(20) and not backend.error, backend.error
        finish = backend.launcher._finish_shared
        assert isinstance(finish, ServiceSharedFinisher)
        assert finish.client.pipe_name == a.scanner_pipe
        assert backend.artifacts is None
    finally:
        backend.shutdown()


def test_window_close_runs_service_finisher_after_shutdown(tmp_path, service):
    from test_window_close import WindowManager, Host, start_ready, finished
    runtime, client = service()
    share, dest = source(tmp_path), tmp_path / "Downloads"
    manager = WindowManager(tmp_path / "sbx")
    scan_file = runtime.scanner.scan_file
    def scan_after_shutdown(*a, **kw):
        assert "stop" in manager.names() and "cleanup" in manager.names()
        return scan_file(*a, **kw)
    runtime.scanner.scan_file = scan_after_shutdown
    async def body():
        host = Host(tmp_path, manager)
        runner, boot, serving = await start_ready(host, manager, tmp_path)
        launcher = host.backend.launcher
        launcher.shared = share
        async def keep(_):
            return "keep"
        launcher._choose_shared = keep
        launcher._finish_shared = lambda folder, decide: finisher(client)(folder, dest, decide)
        manager.window = "CLOSED"
        await asyncio.wait_for(serving, 10)
        await finished(host)
        try:
            assert launcher.shared_result["status"] == "EXPORTED", launcher.shared_result
            assert (dest / share.name / "App" / "tool.exe").read_bytes() == b"MZ\x00\xffbinary"
        finally:
            await asyncio.to_thread(host.backend.shutdown)
    asyncio.run(body())


def test_cleanup_failure_prevents_shared_scan(tmp_path):
    from test_window_close import WindowManager, Host, start_ready, finished
    manager = WindowManager(tmp_path / "sbx")
    manager.cleanup = lambda _: {"removed": [], "failed": ["VM still present"]}
    async def body():
        host = Host(tmp_path, manager)
        _, _, serving = await start_ready(host, manager, tmp_path)
        launcher = host.backend.launcher
        launcher.shared = source(tmp_path)
        launcher._finish_shared = lambda *a, **kw: pytest.fail("scanned before shutdown confirmed")
        manager.window = "CLOSED"
        await asyncio.wait_for(serving, 10)
        await finished(host)
        assert launcher.state == "FAILED" and launcher.shared_result is None
        await asyncio.to_thread(host.backend.shutdown)
    asyncio.run(body())
