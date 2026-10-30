"""SecureArtifactScanner Defender scan: verdict rules, process control, trust checks.

Unit tests use a fake MpCmdRun result and a fake detection log. The real Defender
tests run only with SCANNER_DEFENDER_TESTS=1 (they write the EICAR test string to
disk, which raises a Defender alert on the machine).
"""

import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows service component")
pytest.importorskip("win32file")

from scanner_service import defender_scanner as ds  # noqa: E402
from scanner_service.defender_scanner import (DefenderScanner, DefenderUnavailable, DetectionLogUnavailable,  # noqa: E402
                                              ProcessResult, run_process, status_problem,
                                              verify_trusted_executable)
from scanner_service.models import Verdict  # noqa: E402
from scanner_service.quarantine_manager import QuarantineManager  # noqa: E402

REAL = os.environ.get("SCANNER_DEFENDER_TESTS") == "1"
GOOD_STATUS = {"service_running": True, "platform_version": "4.18.1-0", "engine_version": "1.1.1",
               "signature_version": "1.463.31.0", "passive_mode": False, "disabled_by_policy": False}


class FakeLog:
    def __init__(self, events=None, error=None):
        self.events, self.error, self.calls = events or [], error, []

    def query(self, since, path):
        self.calls.append((since, path))
        if self.error:
            raise DetectionLogUnavailable(self.error)
        return list(self.events)


class FakeRunner:
    def __init__(self, result: ProcessResult):
        self.result, self.argv = result, []

    def __call__(self, argv, *, timeout_s, cancel=None, env=None, cwd=None):
        self.argv.append(argv)
        self.env = env
        return self.result


def res(code=0, out=b"", err=b"", **kw):
    return ProcessResult(code, out, err, 0.1, **kw)


CLEAN_OUT = b"Scan starting...\r\nScan finished.\r\nScanning C:\\q\\payload.part found no threats.\r\n"
FOUND_OUT = b"Scanning C:\\q\\payload.part found 1 threats.\r\nCleaning started...\r\nCleaning finished.\r\n"


def scanner(tmp_path, result=None, log=None, status=None, **kw):
    target = tmp_path / "payload.part"
    if not target.exists():
        target.write_bytes(b"x")
    return DefenderScanner(work_dir=tmp_path / "work", event_settle_s=0, selftest_enabled=False,
                           locator=lambda: Path(r"C:\Defender\MpCmdRun.exe"),
                           status=lambda: dict(status or GOOD_STATUS),
                           runner=FakeRunner(result or res(0, CLEAN_OUT)), detection_log=log or FakeLog(), **kw), target


def test_clean_needs_every_signal(tmp_path):
    s, target = scanner(tmp_path)
    out = s.scan_file(target)
    assert out.verdict == Verdict.CLEAN and out.exit_code == 0
    assert out.evidence == {"output_threats": None, "output_no_threats_line": True, "detection_events": 0,
                            "file_present": True}
    argv = s.runner.argv[0]
    assert argv == [r"C:\Defender\MpCmdRun.exe", "-Scan", "-ScanType", "3", "-File", str(target)]
    assert "-DisableRemediation" not in argv
    assert s.runner.env["TEMP"] == str(tmp_path / "work") and "USERPROFILE" not in s.runner.env


def test_exit_code_zero_with_threats_reported_is_a_detection(tmp_path):
    s, target = scanner(tmp_path, res(0, FOUND_OUT))
    out = s.scan_file(target)
    assert out.verdict == Verdict.DETECTED and out.evidence["output_threats"] == 1


def test_exit_code_zero_but_file_removed_is_a_detection(tmp_path):
    s, target = scanner(tmp_path, res(0, b"(localized text the scanner does not understand)"))
    target.unlink()
    assert s.scan_file(target).verdict == Verdict.DETECTED


def test_detection_event_wins_over_a_clean_looking_output(tmp_path):
    log = FakeLog([{"event_id": 1116, "threat": "Virus:DOS/EICAR_Test_File", "action": ""}])
    s, target = scanner(tmp_path, res(0, CLEAN_OUT), log)
    out = s.scan_file(target)
    assert out.verdict == Verdict.DETECTED and out.threats == ["Virus:DOS/EICAR_Test_File"]
    assert log.calls[0][1] == str(target)


def test_localized_output_alone_does_not_decide(tmp_path):
    s, target = scanner(tmp_path, res(0, "검사 완료".encode("utf-8")))
    out = s.scan_file(target)
    assert out.verdict == Verdict.CLEAN and out.evidence["output_no_threats_line"] is False


def test_failures_are_not_clean(tmp_path):
    failed = res(2, "[Failed][0x80070002] 지정된 파일을 찾을 수 없습니다.\r\nCmdTool: Failed with hr = 0x80070002.".encode())
    s, target = scanner(tmp_path, failed)
    out = s.scan_file(target)
    assert out.verdict == Verdict.ERROR and "0x80070002" in out.detail
    s, target = scanner(tmp_path, res(None, timed_out=True))
    assert s.scan_file(target).verdict == Verdict.TIMEOUT
    s, target = scanner(tmp_path, res(None, cancelled=True))
    assert s.scan_file(target).verdict == Verdict.CANCELLED
    s, target = scanner(tmp_path, ProcessResult(None, b"", b"", 0.0, error="FileNotFoundError"))
    assert s.scan_file(target).verdict == Verdict.ERROR


def test_unreadable_detection_log_means_unverifiable(tmp_path):
    s, target = scanner(tmp_path, log=FakeLog(error="access denied"))
    out = s.scan_file(target)
    assert out.verdict == Verdict.UNVERIFIABLE and "access denied" in out.evidence["detection_log_error"]
    s, target = scanner(tmp_path, log=FakeLog(error="access denied"), require_detection_log=False)
    assert s.scan_file(target).verdict == Verdict.CLEAN
    s, target = scanner(tmp_path, res(0, FOUND_OUT), log=FakeLog(error="access denied"))
    assert s.scan_file(target).verdict == Verdict.DETECTED       # a detection needs no log to count


@pytest.mark.parametrize("change, why", [
    ({"service_running": False}, "not running"),
    ({"service_running": None}, "not running"),
    ({"passive_mode": True}, "passive"),
    ({"disabled_by_policy": True}, "policy"),
    ({"signature_version": None}, "intelligence"),
])
def test_defender_must_be_active(tmp_path, change, why):
    st = {**GOOD_STATUS, **change}
    assert why in status_problem(st)
    s, target = scanner(tmp_path, status=st)
    out = s.scan_file(target)
    assert out.verdict == Verdict.UNAVAILABLE and why in out.detail
    assert s.runner.argv == []                                # MpCmdRun never started


def test_untrusted_mpcmdrun_is_never_run(tmp_path):
    def locator():
        raise DefenderUnavailable("no trusted MpCmdRun.exe")
    s, target = scanner(tmp_path)
    s.locator = locator
    assert s.scan_file(target).verdict == Verdict.UNAVAILABLE and s.runner.argv == []
    fake = tmp_path / "Platform" / "MpCmdRun.exe"
    fake.parent.mkdir()
    fake.write_bytes(b"MZ")
    roots = ds.trusted_roots()
    assert "outside" in verify_trusted_executable(fake, roots)
    assert verify_trusted_executable(fake, (fake.parent,)) is not None   # user-writable: not trusted


def test_real_mpcmdrun_location_is_trusted():
    exe = ds.locate_mpcmdrun()
    assert exe.name.lower() == "mpcmdrun.exe"
    assert verify_trusted_executable(exe, ds.trusted_roots()) is None


# ----------------------------------------------------------------------------- self-test
def selftest_scanner(tmp_path, result, **kw):
    q = QuarantineManager(tmp_path / "Q", max_file_bytes=1024, store_limit_bytes=4096, min_free_bytes=0, max_jobs=2,
                          create_root=True)
    q.ensure_root()
    s, target = scanner(tmp_path, result, **kw)
    s.selftest_enabled = True
    s.selftest_dirs = (q.new_selftest_dir, q.remove_selftest_dir)
    return s, target, q


def test_selftest_gates_scanning(tmp_path):
    s, target, q = selftest_scanner(tmp_path, res(0, CLEAN_OUT))     # EICAR "not detected": excluded/broken
    out = s.scan_file(target)
    assert out.verdict == Verdict.UNAVAILABLE and "self-test" in out.detail
    assert not any(p.name.startswith("_selftest-") for p in q.root.iterdir())   # test file removed
    n = len(s.runner.argv)
    s.scan_file(target)
    assert len(s.runner.argv) == n                              # failure cached for selftest_retry_s


def test_selftest_pass_is_cached(tmp_path):
    s, target, q = selftest_scanner(tmp_path, res(0, FOUND_OUT))
    ok, why = s.ensure_selftest()
    assert ok and "detected" in why
    assert s.runner.argv[0][-1].endswith("payload.part") and "_selftest-" in s.runner.argv[0][-1]
    s.ensure_selftest()
    assert len(s.runner.argv) == 1
    assert s.health()["selftest"]["ok"] is True


# ----------------------------------------------------------------------------- process control
def _alive(pid: int) -> bool:
    import win32api
    import win32con
    import win32process
    try:
        h = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    except Exception:  # noqa: BLE001
        return False
    try:
        return win32process.GetExitCodeProcess(h) == 259          # STILL_ACTIVE
    finally:
        h.Close()


def test_timeout_kills_the_process_tree(tmp_path):
    pidfile = tmp_path / "child.pid"
    code = ("import subprocess, sys, time; "
            f"p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
            f"open(r'{pidfile}', 'w').write(str(p.pid)); time.sleep(60)")
    t = time.monotonic()
    r = run_process([sys.executable, "-c", code], timeout_s=3.0)
    assert r.timed_out and r.exit_code is None and time.monotonic() - t < 15
    time.sleep(0.5)
    assert pidfile.exists() and not _alive(int(pidfile.read_text()))   # the grandchild died with it


def test_cancel_stops_the_scan_process(tmp_path):
    cancel = threading.Event()
    threading.Timer(0.5, cancel.set).start()
    r = run_process([sys.executable, "-c", "import time; time.sleep(60)"], timeout_s=30, cancel=cancel)
    assert r.cancelled and r.duration_s < 10


def test_arguments_are_never_a_shell_command(tmp_path):
    marker = tmp_path / "injected"
    evil = f"x.txt & echo pwned > {marker}"
    r = run_process([sys.executable, "-c", "import sys; print(sys.argv[1])", evil], timeout_s=30)
    assert r.exit_code == 0 and r.stdout.decode().strip() == evil and not marker.exists()


def test_missing_executable_is_an_error(tmp_path):
    r = run_process([str(tmp_path / "nope.exe")], timeout_s=5)
    assert r.error and r.exit_code is None


# ----------------------------------------------------------------------------- real Defender (opt-in)
real = pytest.mark.skipif(not REAL, reason="set SCANNER_DEFENDER_TESTS=1 to run Microsoft Defender itself")


@real
def test_real_defender_benign_file(tmp_path):
    q = QuarantineManager(tmp_path / "Q", max_file_bytes=1024, store_limit_bytes=4096, min_free_bytes=0, max_jobs=2,
                          create_root=True)
    q.ensure_root()
    s = DefenderScanner(work_dir=tmp_path / "work", selftest_dirs=(q.new_selftest_dir, q.remove_selftest_dir))
    assert s.health()["available"], s.health()
    f = tmp_path / "Q" / "benign.part"
    f.write_text("hello\n")
    out = s.scan_file(f)
    assert out.verdict == Verdict.CLEAN, out.view()
    assert s.health()["selftest"]["ok"] is True


@real
def test_real_defender_eicar_is_detected_and_remediated(tmp_path):
    s = DefenderScanner(work_dir=tmp_path / "work", selftest_enabled=False)
    f = tmp_path / "eicar.part"
    try:
        f.write_bytes(ds.eicar())
    except OSError as e:
        assert getattr(e, "winerror", None) in (225, 226)       # real-time protection refused the write
        return
    out = s.scan_file(f)
    assert out.verdict == Verdict.DETECTED, out.view()
    assert not f.exists()                                       # remediation removed it
    found = s.detections_since(f, datetime.fromtimestamp(time.time() - 120, timezone.utc))
    assert found and any("EICAR" in t for t in found)
