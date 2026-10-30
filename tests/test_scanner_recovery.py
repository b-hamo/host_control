"""SecureArtifactScanner after a crash, kill or reboot: leftovers are discarded, never resumed (Windows only)."""

import json
import secrets
import sys
from dataclasses import replace

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows service component")
win32file = pytest.importorskip("win32file")

from scanner_helpers import IDENT, FakeScanner, approval, make_config, make_manager, scanned, upload  # noqa: E402
from scanner_service.ipc_client import ScannerClient  # noqa: E402
from scanner_service.models import ScannerError  # noqa: E402
from scanner_service.quarantine_manager import QuarantineManager  # noqa: E402
from scanner_service.recovery_manager import RecoveryManager  # noqa: E402
from scanner_service.runtime import ScannerRuntime  # noqa: E402


def fresh_quarantine(cfg):
    q = QuarantineManager(cfg.quarantine_root, max_file_bytes=cfg.max_file_bytes,
                          store_limit_bytes=cfg.store_limit_bytes, min_free_bytes=0, max_jobs=8, create_root=True)
    q.ensure_root()
    return q


def crash(m):
    """The process died: handles gone, nothing deleted, nothing marked."""
    for st in list(m.quarantine._jobs.values()):
        win32file.CloseHandle(st.lock_handle) if st.lock_handle else None
        win32file.CloseHandle(st.write_handle) if st.write_handle else None
        st.lock_handle = st.write_handle = None


def test_restart_discards_unfinished_jobs_and_never_publishes_them(tmp_path):
    m = make_manager(tmp_path)
    receiving = m.begin_upload(replace(IDENT, artifact_id="ART-R"),
                               {"file_name": "a.txt", "size": 10, "sha256": "0" * 64})
    m.write_chunk(receiving.identity, receiving.job_id, 0, b"12345")
    done = scanned(m)                                       # SCANNED, approved later … but the service dies
    RecoveryManager(m.quarantine, m.config.work_dir)._write_marker(running=True)   # as the first run's start did
    crash(m)

    cfg = m.config
    q2 = fresh_quarantine(cfg)
    rec = RecoveryManager(q2, cfg.work_dir, cfg.export_root)
    report = rec.recover_on_start()
    assert report.previous_run_unclean
    assert {d["job_id"] for d in report.discarded_jobs} == {receiving.job_id, done.job_id}
    assert {d["last_state"] for d in report.discarded_jobs} == {"RECEIVING", "SCANNED"}
    assert list(cfg.quarantine_root.rglob("*")) == [] and not report.cleanup_failed

    m2 = make_manager(tmp_path)                             # the restarted service knows no job
    with pytest.raises(ScannerError) as e:
        m2.publish(IDENT, done.job_id, approval(done))
    assert e.value.code == "JOB_NOT_FOUND"
    assert list(cfg.export_root.rglob("*")) == []


def test_clean_stop_is_remembered(tmp_path):
    cfg = make_config(tmp_path)
    rec = RecoveryManager(fresh_quarantine(cfg), cfg.work_dir)
    assert not rec.recover_on_start().previous_run_unclean      # first start ever
    rec.mark_stopped()
    assert not RecoveryManager(fresh_quarantine(cfg), cfg.work_dir).recover_on_start().previous_run_unclean
    marker = json.loads((cfg.work_dir / "service-run.json").read_text())
    assert marker["running"] is True


def test_partial_exports_from_a_crash_are_removed(tmp_path):
    cfg = make_config(tmp_path)
    d = cfg.export_root / "SES-001" / "ART-000001"
    d.mkdir(parents=True)
    partial = d / (".job-" + "c" * 32 + ".partial")
    partial.write_text("half")
    (d / "report.txt").write_text("a published file")            # the user's results stay
    (d / ".hidden-user-file").write_text("not ours")
    report = RecoveryManager(fresh_quarantine(cfg), cfg.work_dir, cfg.export_root).recover_on_start()
    assert report.partial_exports_removed == 1 and not partial.exists()
    assert (d / "report.txt").exists() and (d / ".hidden-user-file").exists()


def test_failed_delete_is_kept_private_and_retried(tmp_path):
    m = make_manager(tmp_path)
    job = upload(m)
    crash(m)
    payload = m.quarantine.root / "session-SES-001" / job.job_id / "payload.part"
    h = win32file.CreateFile(str(payload), win32file.GENERIC_READ, 0, None, win32file.OPEN_EXISTING, 0, None)
    try:
        q2 = fresh_quarantine(m.config)
        report = RecoveryManager(q2, m.config.work_dir).recover_on_start()
        assert report.cleanup_failed and payload.exists()          # still in the private quarantine
    finally:
        h.Close()
    m2 = make_manager(tmp_path)
    m2.sweep()                                                     # the next sweep finishes the job
    assert not payload.exists()


def test_runtime_restart_end_to_end(tmp_path):
    """Two service runs on one data root, over the real pipe; the first one is 'killed'."""
    cfg = replace(make_config(tmp_path), pipe_name=r"\\.\pipe\sas-rec-" + secrets.token_hex(5))
    cfg.export_root.mkdir()
    rt = ScannerRuntime(cfg, scanner=FakeScanner(), dev_mode=True)
    rt.start()
    with ScannerClient(cfg.pipe_name, timeout_s=5) as c:
        job = c.upload(IDENT, "a.txt", b"text\n")
        c.scan(IDENT, job["job_id"], 10)
    rt.server.stop(2)                                               # killed: no shutdown, no cleanup
    rt._sweep_stop.set()
    crash(rt.manager)

    rt2 = ScannerRuntime(replace(cfg, pipe_name=cfg.pipe_name + "-2"), scanner=FakeScanner(), dev_mode=True)
    rt2.start()
    try:
        assert rt2.recovery.last.previous_run_unclean and len(rt2.recovery.last.discarded_jobs) == 1
        with ScannerClient(cfg.pipe_name + "-2", timeout_s=5) as c:
            h = c.health()
            assert h["recovery"]["discarded_jobs"] == 1 and h["accepting"]
            with pytest.raises(ScannerError) as e:
                c.call("GET_STATUS", IDENT, job["job_id"])
            assert e.value.code == "JOB_NOT_FOUND"
            again = c.upload(IDENT, "a.txt", b"text\n")              # the same artifact can start over
            assert again["job_id"] != job["job_id"]
    finally:
        rt2.stop(5)
    assert list(cfg.quarantine_root.rglob("*")) == []
    assert not json.loads((cfg.work_dir / "service-run.json").read_text())["running"]
