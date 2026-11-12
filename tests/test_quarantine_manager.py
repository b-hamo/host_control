"""SecureArtifactScanner quarantine: per-job directories, limits, locks, links (Windows only)."""

import hashlib
import os
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows service component")
win32file = pytest.importorskip("win32file")

import _winapi  # noqa: E402

from scanner_service import winfile  # noqa: E402
from scanner_service.models import ScannerError  # noqa: E402
from scanner_service.quarantine_manager import META, PAYLOAD, QuarantineManager  # noqa: E402

DATA = b"hello quarantine\n"
SHA = hashlib.sha256(DATA).hexdigest()


def make(tmp_path, root_name="Q", **kw):
    args = dict(max_file_bytes=1024, store_limit_bytes=4096, min_free_bytes=0, max_jobs=3, create_root=True)
    args.update(kw)
    q = QuarantineManager(tmp_path / root_name, **args)
    q.ensure_root()
    return q


def filled(q, session="SES-001", data=DATA):
    st = q.create_job(session, len(data))
    q.write_chunk(st, 0, data)
    q.finalize_upload(st, hashlib.sha256(data).hexdigest())
    return st


def code(excinfo):
    return excinfo.value.code


def test_job_layout_and_disposal(tmp_path):
    q = make(tmp_path)
    st = q.create_job("SES-001", len(DATA), meta={"artifact_id": "ART-1"})
    assert st.job_dir.parent.name == "session-SES-001" and st.job_dir.name.startswith("job-")
    assert st.payload_path.name == PAYLOAD and (st.job_dir / META).exists()
    assert winfile.attributes(st.payload_path) & winfile.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
    q.write_chunk(st, 0, DATA[:5])
    q.write_chunk(st, 5, DATA[5:])
    assert q.finalize_upload(st, SHA) == (len(DATA), SHA)
    assert q.verify_unchanged(st) is None
    q.delete_job(st)
    assert not st.job_dir.exists() and not st.job_dir.parent.exists()
    assert q.reserved == 0 and q.get_job(st.job_id) is None


def test_every_job_gets_a_new_directory(tmp_path):
    q = make(tmp_path)
    a, b = q.create_job("SES-001", 1), q.create_job("SES-001", 1)
    assert a.job_dir != b.job_dir and a.job_dir.parent == b.job_dir.parent
    with pytest.raises(ScannerError) as e:
        q.create_job("SES-001", 1, job_id=a.job_id)                # never reuse a directory
    assert code(e) == "JOB_EXISTS"
    assert a.job_dir.exists() and (a.job_dir / META).exists()     # the existing job is untouched


@pytest.mark.parametrize("session", ["..", "..\\x", "a/b", "C:", "", "x" * 65, "SES 1", "SES-1\x00", "-x"])
def test_session_ids_cannot_form_paths(tmp_path, session):
    q = make(tmp_path)
    with pytest.raises(ScannerError) as e:
        q.create_job(session, 1)
    assert code(e) == "INVALID_ARGUMENT"
    assert list(q.root.iterdir()) == []


@pytest.mark.parametrize("job_id", ["job-../../x", "job-" + "A" * 32, "../job-" + "0" * 32, "job-0"])
def test_job_ids_are_service_made(tmp_path, job_id):
    q = make(tmp_path)
    with pytest.raises(ScannerError) as e:
        q.create_job("SES-001", 1, job_id=job_id)
    assert code(e) == "INVALID_ARGUMENT"


def test_size_limits(tmp_path):
    q = make(tmp_path)
    with pytest.raises(ScannerError) as e:
        q.create_job("SES-001", 1025)
    assert code(e) == "FILE_TOO_LARGE"
    st = q.create_job("SES-001", 4)
    with pytest.raises(ScannerError) as e:
        q.write_chunk(st, 0, b"12345")
    assert code(e) == "SIZE_EXCEEDED"
    q.write_chunk(st, 0, b"12")
    with pytest.raises(ScannerError) as e:
        q.write_chunk(st, 5, b"34")                 # chunks only in order, no holes, no seeking back
    assert code(e) == "BAD_OFFSET"
    with pytest.raises(ScannerError) as e:
        q.finalize_upload(st, SHA)                  # 2 of 4 bytes
    assert code(e) == "SIZE_MISMATCH"


def test_hash_mismatch(tmp_path):
    q = make(tmp_path)
    st = q.create_job("SES-001", len(DATA))
    q.write_chunk(st, 0, DATA)
    with pytest.raises(ScannerError) as e:
        q.finalize_upload(st, "0" * 64)
    assert code(e) == "HASH_MISMATCH"


def test_store_job_and_disk_limits(tmp_path):
    q = make(tmp_path, max_jobs=2)
    q.create_job("SES-001", 1000)
    q.create_job("SES-001", 1000)
    with pytest.raises(ScannerError) as e:
        q.create_job("SES-001", 1)
    assert code(e) == "TOO_MANY_JOBS" and e.value.retryable
    q2 = make(tmp_path, "Q2", store_limit_bytes=1500)
    q2.create_job("SES-001", 1000)
    with pytest.raises(ScannerError) as e:
        q2.create_job("SES-001", 1000)
    assert code(e) == "STORAGE_FULL"
    q3 = make(tmp_path, "Q3", min_free_bytes=1 << 62)
    with pytest.raises(ScannerError) as e:
        q3.create_job("SES-001", 1)
    assert code(e) == "DISK_FULL"


def test_locked_file_cannot_be_written_while_held(tmp_path):
    q = make(tmp_path)
    st = filled(q)
    with pytest.raises(PermissionError):
        open(st.payload_path, "r+b")
    with pytest.raises(PermissionError):
        open(st.payload_path, "ab")
    assert q.verify_unchanged(st) is None


def test_replaced_file_is_noticed(tmp_path):
    q = make(tmp_path)
    st = filled(q)
    os.rename(st.payload_path, st.job_dir / "moved")          # delete sharing allows a rename …
    st.payload_path.write_bytes(DATA)                          # … but a new file is another file
    assert q.verify_unchanged(st) == "replaced"
    os.remove(st.payload_path)
    assert q.verify_unchanged(st) == "removed"


def test_root_reached_through_a_junction_is_refused(tmp_path):
    real = tmp_path / "real"
    (real / "Q").mkdir(parents=True)
    _winapi.CreateJunction(str(real), str(tmp_path / "link"))
    q = QuarantineManager(tmp_path / "link" / "Q", max_file_bytes=1, store_limit_bytes=1, min_free_bytes=0, max_jobs=1)
    with pytest.raises(OSError):
        q.ensure_root()
    _winapi.CreateJunction(str(real), str(tmp_path / "rootlink"))
    q = QuarantineManager(tmp_path / "rootlink", max_file_bytes=1, store_limit_bytes=1, min_free_bytes=0, max_jobs=1)
    with pytest.raises(OSError):
        q.ensure_root()


def test_planted_session_junction_is_refused(tmp_path):
    q = make(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    _winapi.CreateJunction(str(outside), str(q.root / "session-SES-002"))
    with pytest.raises(ScannerError) as e:
        q.create_job("SES-002", 1)
    assert code(e) == "STORAGE_ERROR"
    assert list(outside.iterdir()) == []                       # nothing was written through the link
    assert q.reserved == 0


def test_cleanup_never_follows_links(tmp_path):
    q = make(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep")
    orphan = q.root / "session-SES-003" / ("job-" + "a" * 32)
    orphan.mkdir(parents=True)
    (orphan / PAYLOAD).write_bytes(b"x")
    _winapi.CreateJunction(str(outside), str(orphan / "link"))
    report = q.cleanup_expired_jobs(set())
    assert "session-SES-003/job-" + "a" * 32 in report.removed and not report.failed
    assert not orphan.exists() and (outside / "keep.txt").read_text() == "keep"


def test_cleanup_keeps_live_jobs_and_retries_failed_deletes(tmp_path):
    q = make(tmp_path)
    live = q.create_job("SES-001", 1)
    orphan = q.root / "session-SES-001" / ("job-" + "b" * 32)
    orphan.mkdir()
    f = orphan / PAYLOAD
    f.write_bytes(b"x")
    h = win32file.CreateFile(str(f), win32file.GENERIC_READ, 0, None, win32file.OPEN_EXISTING, 0, None)
    try:
        report = q.cleanup_expired_jobs({live.job_id})
        assert report.failed and orphan.exists()               # in use: kept, reported, retried later
    finally:
        h.Close()
    report = q.cleanup_expired_jobs({live.job_id})
    assert not report.failed and not orphan.exists() and live.job_dir.exists()


def test_selftest_dirs_in_use_survive_cleanup(tmp_path):
    q = make(tmp_path)
    d = q.new_selftest_dir()
    q.cleanup_expired_jobs(set())
    assert d.exists()
    q.remove_selftest_dir(d)
    assert not d.exists()
    stale = q.root / "_selftest-0123456789abcdef"
    stale.mkdir()
    q.cleanup_expired_jobs(set())
    assert not stale.exists()


def test_read_meta_is_best_effort(tmp_path):
    q = make(tmp_path)
    st = q.create_job("SES-001", 1, meta={"artifact_id": "ART-9"})
    q.update_meta(st, state="RECEIVING")
    meta = q.read_meta(st.job_dir)
    assert meta["artifact_id"] == "ART-9" and meta["state"] == "RECEIVING" and meta["job_id"] == st.job_id
    (st.job_dir / META).write_text("{broken")
    assert q.read_meta(st.job_dir) is None
