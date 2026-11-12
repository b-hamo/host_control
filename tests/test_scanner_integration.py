"""SecureArtifactScanner on a real Windows: the installed service, the real pipe and Microsoft Defender.

Not part of the normal run (each group is switched on separately):

    SCANNER_DEFENDER_TESTS=1        MpCmdRun.exe itself, as the current user (writes EICAR: Defender alerts)
    SCANNER_SERVICE_TESTS=1         the installed service as a STANDARD user: ACLs, pipe, Host end to end
    SCANNER_SERVICE_ADMIN_TESTS=1   elevated only: kill / stop / restart the service, uninstall + reinstall

Install first: installer\\build.ps1, then (elevated) installer\\install.ps1 -ExportRoot <folder>.
EICAR is the only "malware" used; it is assembled in memory (scanner_service.defender_scanner.eicar).
Elevated runs: pass --basetemp <own folder>, or pytest's admin-owned temp link breaks later user runs.
"""

import asyncio
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
pytest.importorskip("win32file")

from scanner_helpers import TEXT  # noqa: E402
from test_artifact_export import Approver, Host  # noqa: E402
from test_artifact_scanner_service import export_one, no_host_file  # noqa: E402

from host.artifact_scan import DefenderServiceScanner  # noqa: E402
from host.scanner_client import ScannerServiceClient, ScannerServiceError, job_identity  # noqa: E402
from scanner_service.config import SERVICE_ACCOUNT, SERVICE_NAME, default_data_root  # noqa: E402
from scanner_service.defender_scanner import DefenderScanner, eicar  # noqa: E402
from scanner_service.ipc_client import service_pid  # noqa: E402
from scanner_service.models import Verdict  # noqa: E402
from scanner_service.runtime import token_info  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DATA = default_data_root()
QUARANTINE = DATA / "Quarantine"
INSTALL = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "SecureRuntime" / "ScannerService"
ME = token_info()

defender = pytest.mark.skipif(os.environ.get("SCANNER_DEFENDER_TESTS") != "1",
                              reason="set SCANNER_DEFENDER_TESTS=1 to run Microsoft Defender itself")
installed = pytest.mark.skipif(os.environ.get("SCANNER_SERVICE_TESTS") != "1" or ME["is_admin"],
                               reason="set SCANNER_SERVICE_TESTS=1 and run as a standard (non-elevated) user")
admin = pytest.mark.skipif(os.environ.get("SCANNER_SERVICE_ADMIN_TESTS") != "1" or not ME["is_admin"],
                           reason="set SCANNER_SERVICE_ADMIN_TESTS=1 and run elevated")


def run(coro, timeout=420):
    return asyncio.run(asyncio.wait_for(coro, timeout))


def client() -> ScannerServiceClient:
    return ScannerServiceClient()                       # the real pipe; the server must be the SCM's service


async def upload(c, ident, data: bytes, name="a.txt") -> str:
    up = c.upload(ident)
    try:
        job = await up.begin(name, len(data))
        for off in range(0, len(data), 64 * 1024):
            await up.write(data[off:off + 64 * 1024])
        await up.complete(hashlib.sha256(data).hexdigest())
        return job
    finally:
        await up.close()


async def scanned(c, ident, job, timeout=240.0) -> dict:
    v = await c.scan(ident, job)
    deadline = time.monotonic() + timeout
    while v["state"] == "SCANNING" and time.monotonic() < deadline:
        await asyncio.sleep(0.25)
        v = await c.status(ident, job)
    return v


def new_ident(artifact="ART-000001", gen=1):
    return job_identity(("SES-IT-" + secrets.token_hex(3).upper(), "RT-IT", gen), artifact)


# ===================================================================== MpCmdRun.exe itself
def _scan(path: Path, **kw):
    s = DefenderScanner(work_dir=path.parent / "work", selftest_enabled=False, **kw)
    return s, s.scan_file(path)


@defender
def test_exit_code_versus_real_detection(tmp_path):
    """The measured facts the verdict rules rest on (scanner_service/README.md §8)."""
    clean = tmp_path / "clean.part"
    clean.write_text("hello\n")
    _, c = _scan(clean)
    bad = tmp_path / "eicar.part"
    try:
        bad.write_bytes(eicar())
    except OSError as e:
        pytest.skip(f"real-time protection refused the write first (winerror {getattr(e, 'winerror', None)})")
    s, d = _scan(bad)
    print(json.dumps({"clean": c.view(), "eicar": d.view()}, ensure_ascii=False, indent=1))
    assert c.verdict == Verdict.CLEAN and c.exit_code == 0 and c.evidence["output_no_threats_line"]
    assert d.verdict == Verdict.DETECTED
    assert d.exit_code == c.exit_code == 0                         # same exit code: it cannot decide alone
    assert d.evidence["output_threats"] == 1 and d.evidence["file_present"] is False   # remediated (deleted)
    assert d.evidence["detection_events"] >= 1 and any("EICAR" in t for t in d.threats)


@defender
def test_detection_events_belong_to_the_scanned_file(tmp_path):
    bad, other = tmp_path / "x" / "eicar.part", tmp_path / "y" / "clean.part"
    bad.parent.mkdir()
    other.parent.mkdir()
    other.write_text("clean\n")
    since = datetime.now(timezone.utc) - timedelta(seconds=5)
    try:
        bad.write_bytes(eicar())
    except OSError:
        pytest.skip("real-time protection refused the write first")
    s, d = _scan(bad)
    assert d.verdict == Verdict.DETECTED
    assert s.detections_since(bad, since)                           # this path: the EICAR events
    assert s.detections_since(other, since) == []                   # same time window, other path: none
    assert s.detections_since(tmp_path / "x" / "eicar.part.other", since) == []


@defender
def test_engine_error_is_not_clean(tmp_path):
    s, out = _scan(tmp_path / "does-not-exist.part")
    assert out.verdict == Verdict.ERROR and out.exit_code == 2 and "0x80070002" in out.detail


@defender
def test_real_scan_timeout_kills_mpcmdrun(tmp_path):
    f = tmp_path / "clean.part"
    f.write_text("hello\n")
    t = time.monotonic()
    _, out = _scan(f, scan_timeout_s=0.005)
    assert out.verdict == Verdict.TIMEOUT and out.exit_code is None and time.monotonic() - t < 10
    time.sleep(0.5)
    left = subprocess.run(["tasklist", "/FI", "IMAGENAME eq MpCmdRun.exe", "/FO", "CSV", "/NH"],
                          capture_output=True, text=True).stdout
    mine = [ln for ln in left.splitlines() if "MpCmdRun" in ln]
    assert len(mine) <= 1                                           # ours is gone (another may be Windows')


# ===================================================================== installed service, standard user
@installed
def test_service_identity_and_packaging():
    h = run(client().health())
    t, py = h["token"], h["python"]
    assert t["account"] == SERVICE_ACCOUNT and t["sid"].startswith("S-1-5-80-")
    assert not t["is_admin"] and not t["administrators_group"] and not t["is_local_system"]
    assert set(p.split(" ")[0] for p in t["privileges"]) <= {"SeChangeNotifyPrivilege", "SeImpersonatePrivilege"}
    assert py["frozen"] and Path(py["executable"]) == INSTALL / f"{SERVICE_NAME}.exe" and py["sys_path_ok"]
    for name, path in py["pywin32_modules"].items():                # pywin32 and its DLLs from the bundle only
        assert path and Path(path).is_relative_to(INSTALL), (name, path)
    assert h["defender"]["available"] and h["publish"]["enabled"]


@installed
@pytest.mark.parametrize("what,path,mode", [
    ("list the quarantine", QUARANTINE, "list"),
    ("list the service logs", DATA / "ScannerService" / "logs", "list"),
    ("read config.json", DATA / "ScannerService" / "config.json", "read"),
    ("write into the install dir", INSTALL / "planted.dll", "create"),
    ("replace the executable", INSTALL / f"{SERVICE_NAME}.exe", "write"),
    ("create a folder in the quarantine", QUARANTINE / "session-EVIL", "mkdir"),
])
def test_standard_user_is_kept_out(what, path, mode):
    with pytest.raises(PermissionError):
        if mode == "list":
            list(path.iterdir())
        elif mode == "read":
            path.read_bytes()
        elif mode == "create":
            path.write_bytes(b"x")
        elif mode == "write":
            open(path, "r+b").close()
        else:
            path.mkdir()


@installed
def test_service_reads_and_disposes_its_own_files():
    """The service account can write, scan and delete in the quarantine it was given (no files left)."""
    c = client()
    ident = new_ident()

    async def body():
        job = await upload(c, ident, TEXT)
        v = await scanned(c, ident, job)
        end = await c.abort(ident, job, "integration test done")
        return v, end
    v, end = run(body())
    assert v["state"] == "SCANNED" and v["scan"]["verdict"] == "CLEAN", v
    ev = v["scan"]["evidence"]
    assert v["scan"]["exit_code"] == 0 and ev["detection_events"] == 0 and ev["file_present"]
    assert end["state"] == "DISPOSED" and end["cleanup_error"] is None


@installed
def test_service_blocks_eicar_with_evidence():
    c = client()
    ident = new_ident()

    async def body():
        try:
            job = await upload(c, ident, eicar(), "e.txt")
        except ScannerServiceError as e:                        # real-time protection at upload completion
            return {"refused_at_upload": e.code}
        return await scanned(c, ident, job)
    v = run(body())
    print(json.dumps(v, ensure_ascii=False, indent=1))
    if "refused_at_upload" in v:
        assert v["refused_at_upload"] == "MALWARE_DETECTED"
    else:
        assert v["outcome"] == "BLOCKED" and v["error"]["code"] == "MALWARE_DETECTED"
        assert "EICAR" in v["error"]["message"]


@installed
def test_service_limits_over_the_real_pipe():
    c = client()

    async def body():
        out = {}
        try:
            await c.upload(new_ident()).begin("big.txt", 2 * 1024 * 1024)
        except ScannerServiceError as e:
            out["too_big"] = e.code
        ident = new_ident()
        job = await upload(c, ident, b"abc")
        try:
            await c.status(job_identity((ident.session_id, ident.runtime_id, 2), ident.artifact_id), job)
        except ScannerServiceError as e:
            out["other_generation"] = e.code
        try:
            await c.publish(ident, job, {"approved": True, "approval_id": "x", "approved_by": "t", "job_id": job,
                                         "artifact_id": ident.artifact_id, "session_id": ident.session_id,
                                         "sha256": hashlib.sha256(b"abc").hexdigest()})
        except ScannerServiceError as e:
            out["publish_unscanned"] = e.code
        await c.abort(ident, job, "done")
        return out
    out = run(body())
    assert out == {"too_big": "FILE_TOO_LARGE", "other_generation": "JOB_NOT_FOUND",
                   "publish_unscanned": "INVALID_STATE"}


@installed
@pytest.mark.parametrize("size", [0, 1024 * 1024])
def test_host_end_to_end_with_the_installed_service(tmp_path, size):
    scanner = DefenderServiceScanner()
    export_root = Path(run(scanner.client.health())["publish"]["export_root"])
    session = "SES-E2E-" + secrets.token_hex(3).upper()
    data = (TEXT * (size // len(TEXT) + 1))[:size]
    data = data[: len(data.decode("utf-8", "ignore").encode("utf-8"))]        # whole UTF-8 characters only

    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=scanner, export_dir=export_root, session=session)
        r, serving = await host.start()
        _, _, clean = await export_one(host, r, "결과.txt", data, timeout=240)
        _, _, bad = await export_one(host, r, "eicar.txt", eicar(), timeout=240)
        await host.close(serving)
        return clean, bad, r
    clean, bad, r = run(body())
    try:
        assert clean["status"] == "EXPORTED", clean
        assert Path(clean["export_path"]).read_bytes() == data and clean["sha256"] == hashlib.sha256(data).hexdigest()
        assert bad["status"] == "BLOCKED" and bad["result"]["code"] == "MALWARE_DETECTED", bad
        assert not (export_root / session / bad["artifact_id"]).exists() or \
            not list((export_root / session / bad["artifact_id"]).iterdir())
        assert r.puts == [(201, b""), (201, b"")] and no_host_file(tmp_path)
    finally:
        _remove_tree(export_root / session)


def _remove_tree(d: Path):
    if d.exists():
        for p in sorted(d.rglob("*"), reverse=True):
            p.unlink() if p.is_file() else p.rmdir()
        d.rmdir()


# ===================================================================== elevated: stop, kill, reinstall
def _svc(action: str, timeout=90):
    import win32service
    import win32serviceutil
    if action == "stop":
        win32serviceutil.StopService(SERVICE_NAME)
        win32serviceutil.WaitForServiceStatus(SERVICE_NAME, win32service.SERVICE_STOPPED, timeout)
    else:
        win32serviceutil.StartService(SERVICE_NAME)
        win32serviceutil.WaitForServiceStatus(SERVICE_NAME, win32service.SERVICE_RUNNING, timeout)


def _kill_service():
    import win32api
    import win32con
    pid = service_pid()
    h = win32api.OpenProcess(win32con.PROCESS_TERMINATE, False, pid)
    win32api.TerminateProcess(h, 1)
    h.Close()
    deadline = time.monotonic() + 30
    while service_pid() == pid and time.monotonic() < deadline:
        time.sleep(0.2)
    return pid


def _ensure_running():
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            if service_pid():
                return
            _svc("start")
            return
        except Exception:  # noqa: BLE001 - the SCM may be restarting it right now
            time.sleep(1)


def _quarantine_jobs():
    return [p for p in QUARANTINE.rglob("*")] if QUARANTINE.exists() else []


@admin
def test_stopping_the_service_cleans_up():
    c = client()
    ident = new_ident()
    run(upload(c, ident, TEXT))                                  # received, not scanned, then the service stops
    assert _quarantine_jobs()
    pid = service_pid()
    _svc("stop")
    try:
        assert _quarantine_jobs() == []                           # cancelled and deleted on the way out
        marker = json.loads((DATA / "ScannerService" / "work" / "service-run.json").read_text())
        assert marker["running"] is False
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True).stdout
        assert str(pid) not in out                                # process gone
        with pytest.raises(ScannerServiceError) as e:
            run(ScannerServiceClient(verify_server=False, connect_timeout_s=1).health())
        assert e.value.code == "SCANNER_UNAVAILABLE"              # pipe gone with it
    finally:
        _svc("start")


@admin
def test_killed_during_a_scan_nothing_survives():
    """Kill the service while it scans (the first scan after a start includes the EICAR self-test)."""
    _svc("stop")
    _svc("start")
    c = client()
    ident = new_ident()

    async def start_scan():
        job = await upload(c, ident, TEXT)
        await c.scan(ident, job)
        return job
    job = run(start_scan())
    time.sleep(1.0)
    _kill_service()
    _ensure_running()
    try:
        h = run(client().health())
        assert h["recovery"]["previous_run_unclean"] and h["recovery"]["discarded_jobs"] >= 1
        assert _quarantine_jobs() == []
        with pytest.raises(ScannerServiceError) as e:
            run(client().status(ident, job))
        assert e.value.code == "JOB_NOT_FOUND"                    # never resumed, never publishable
    finally:
        _ensure_running()


@admin
def test_killed_while_the_host_waits_for_the_scan(tmp_path):
    scanner = DefenderServiceScanner()
    export_root = Path(run(scanner.client.health())["publish"]["export_root"])
    session = "SES-KILL-" + secrets.token_hex(3).upper()
    _svc("stop")
    _svc("start")                                                 # next scan runs the self-test (seconds)

    async def body():
        host = Host(tmp_path, approver=Approver(), scanner=scanner, export_dir=export_root, session=session)
        r, serving = await host.start()
        await r.report("a.txt", TEXT)
        lst = await host.call("artifact_list", {})
        aid = lst["artifacts"][0]["artifact_id"]
        await host.call("artifact_export", {"artifact_id": aid})
        deadline = time.monotonic() + 30
        while host.backend.artifacts.get(aid).stage != "SCANNING" and time.monotonic() < deadline:
            await asyncio.sleep(0.1)
        await asyncio.to_thread(_kill_service)
        final = await host.wait_artifact(aid, timeout=120)
        await host.close(serving)
        return final
    try:
        final = run(body())
        assert final["status"] == "BLOCKED" and final["result"]["code"] in ("SCANNER_UNAVAILABLE", "SCAN_ERROR")
        assert not (export_root / session).exists() or not [p for p in (export_root / session).rglob("*")
                                                             if p.is_file()]
    finally:
        _ensure_running()
        _remove_tree(export_root / session)


@admin
def test_uninstall_and_reinstall():
    h = run(client().health())
    export_root = Path(h["publish"]["export_root"])
    keep = export_root / "kept-by-uninstall.txt"
    keep.write_text("an earlier export")
    ps = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]
    try:
        u = subprocess.run(ps + [str(ROOT / "installer" / "uninstall.ps1")], capture_output=True, text=True, timeout=300)
        assert u.returncode == 0, u.stdout + u.stderr
        assert subprocess.run(["sc.exe", "query", SERVICE_NAME], capture_output=True).returncode != 0
        assert not INSTALL.exists() and not QUARANTINE.exists()
        assert keep.read_text() == "an earlier export"            # exports are never removed
    finally:
        i = subprocess.run(ps + [str(ROOT / "installer" / "install.ps1"), "-ExportRoot", str(export_root),
                                 "-SkipVerify"], capture_output=True, text=True, timeout=600)
        keep.unlink(missing_ok=True)
    assert i.returncode == 0, i.stdout + i.stderr
    assert run(client().health())["token"]["account"] == SERVICE_ACCOUNT
