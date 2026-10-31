"""Shared pieces for the SecureArtifactScanner tests (a tool, not a test file).

FakeScanner stands in for Defender, so these tests never run MpCmdRun.exe; the real
Defender tests are opt-in (SCANNER_DEFENDER_TESTS=1, tests/test_defender_scanner.py).
"""

from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import replace
from pathlib import Path

from scanner_service.artifact_publisher import ArtifactPublisher, HostAssertedApproval
from scanner_service.config import ScannerConfig
from scanner_service.models import Identity, ScanOutcome, Verdict
from scanner_service.quarantine_manager import QuarantineManager
from scanner_service.scan_job_manager import ScanJobManager

TEXT = "검사 대상 텍스트\nsecond line\n".encode("utf-8")
IDENT = Identity("SES-001", "RT-SBX-001", 1, "ART-000001")


class FakeScanner:
    name = "fake"

    def __init__(self, verdict: Verdict = Verdict.CLEAN, *, detail: str = "fake", delay: float = 0.0,
                 error: Exception | None = None, wait_for_cancel: bool = False):
        self.verdict, self.detail, self.delay, self.error = verdict, detail, delay, error
        self.wait_for_cancel = wait_for_cancel
        self.scanned: list[Path] = []
        self.started = threading.Event()

    def scan_file(self, path: Path, cancel: threading.Event | None = None) -> ScanOutcome:
        self.scanned.append(path)
        self.started.set()
        if self.wait_for_cancel:
            cancel.wait(10)
            return ScanOutcome(Verdict.CANCELLED, "cancelled", "fake")
        if self.delay:
            time.sleep(self.delay)
        if self.error:
            raise self.error
        return ScanOutcome(self.verdict, self.detail, "fake", exit_code=0, duration_s=0.01,
                           threats=["Test:Fake"] if self.verdict == Verdict.DETECTED else [])

    def health(self) -> dict:
        return {"available": True, "selftest": None}

    def ensure_selftest(self, cancel=None, *, force=False):
        return True, "fake"


def make_config(tmp_path: Path, **kw) -> ScannerConfig:
    base = ScannerConfig(quarantine_root=tmp_path / "Quarantine", state_dir=tmp_path / "State",
                         export_root=tmp_path / "Export", min_free_bytes=0, max_file_bytes=64 * 1024,
                         max_chunk_bytes=4096, max_request_bytes=64 * 1024, store_limit_bytes=1024 * 1024,
                         selftest_enabled=False, event_settle_s=0.0, cleanup_interval_s=3600)
    return replace(base, **kw).validate()


def make_manager(tmp_path: Path, scanner=None, *, export=True, clock=time.monotonic, **kw):
    cfg = make_config(tmp_path, **kw)
    if export:
        cfg.export_root.mkdir(parents=True, exist_ok=True)
    else:
        cfg = replace(cfg, export_root=None)
    q = QuarantineManager(cfg.quarantine_root, max_file_bytes=cfg.storage_file_limit,
                          store_limit_bytes=cfg.store_limit_bytes, min_free_bytes=cfg.min_free_bytes,
                          max_jobs=cfg.max_active_jobs, create_root=True)
    q.ensure_root()
    pub = ArtifactPublisher(cfg.export_root, HostAssertedApproval(), max_file_bytes=cfg.max_file_bytes)
    pub.ensure_root()
    m = ScanJobManager(cfg, q, scanner or FakeScanner(), pub, clock=clock)
    return m


def begin(m, data: bytes = TEXT, ident: Identity = IDENT, name: str = "보고서\\결과.txt"):
    return m.begin_upload(ident, {"file_name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})


def upload(m, data: bytes = TEXT, ident: Identity = IDENT, name: str = "보고서\\결과.txt", chunk: int = 7):
    job = begin(m, data, ident, name)
    for off in range(0, len(data), chunk):
        m.write_chunk(ident, job.job_id, off, data[off:off + chunk])
    return m.complete_upload(ident, job.job_id)


def wait_state(job, states, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if job.state.value in states and not job.busy:
            return job
        time.sleep(0.02)
    raise AssertionError(f"{job.job_id} stayed {job.state.value}")


def scanned(m, data: bytes = TEXT, ident: Identity = IDENT, name: str = "보고서\\결과.txt"):
    job = upload(m, data, ident, name)
    m.start_scan(ident, job.job_id)
    return wait_state(job, ("SCANNED", "DISPOSED"))


def approval(job, **override) -> dict:
    a = {"approved": True, "approval_id": "APR-1", "approved_by": "user", "job_id": job.job_id,
         "artifact_id": job.identity.artifact_id, "session_id": job.identity.session_id, "sha256": job.sha256}
    a.update(override)
    return a


def quarantine_files(m) -> list[Path]:
    return [p for p in m.quarantine.root.rglob("*")]
