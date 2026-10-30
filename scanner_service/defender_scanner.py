"""Microsoft Defender scan of one quarantined file with MpCmdRun.exe, as a non-admin account.

    MpCmdRun.exe -Scan -ScanType 3 -File <quarantine>\\session-..\\job-..\\payload.part

Measured on Windows 11 (platform 4.18.26100.4, as a standard user):
  benign file      exit 0, "... found no threats."
  EICAR file       exit 0 (!), "... found 1 threats. Cleaning started... Cleaning finished.",
                   file removed, event 1116 in Microsoft-Windows-Windows Defender/Operational
  missing file     exit 2, "[Failed][0x80070002] <localized message>"
So exit code 0 does not mean clean. The verdict combines four signals and is CLEAN only
when all agree: exit code 0, no threat count in the output, the file still there and
unchanged (checked by the job manager through its lock), and no detection event naming
the file since the scan began. Any detection signal → DETECTED; anything that cannot be
confirmed (detection log unreadable, timeout, other exit codes) → not CLEAN.

Before scanning:
- MpCmdRun.exe is located from Defender's own registry value, must sit in the Defender
  platform or program directory, must not be a link, and no one but SYSTEM,
  Administrators or TrustedInstaller may write it or its directories. A path from a
  request is never run.
- WinDefend must be running, not in passive mode, not disabled by policy, with a known
  security intelligence version.
- Exclusions cannot be read without administrator rights, so instead an EICAR self-test
  runs in the quarantine (same file name as real payloads) before the first scan and then
  every few hours: unless Defender detects it there, the path counts as excluded or
  Defender as broken, and every scan is SCANNER_UNAVAILABLE. Remediation stays on (no
  -DisableRemediation): a detection may delete the file, which is itself a detection signal.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from scanner_service.models import ScanOutcome, Verdict

log = logging.getLogger("scanner.defender")

DEFENDER_KEY = r"SOFTWARE\Microsoft\Windows Defender"
POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows Defender"
DETECTION_CHANNEL = "Microsoft-Windows-Windows Defender/Operational"
# malware found / action taken / action failed / suspicious, old (100x) and new (111x) ids
DETECTION_EVENT_IDS = (1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119)
MAX_OUTPUT = 8 * 1024
MAX_EVENTS = 256

TRUSTED_WRITERS = {
    "S-1-5-18",                                                        # SYSTEM
    "S-1-5-32-544",                                                    # Administrators
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",  # TrustedInstaller
}
WRITE_RIGHTS = (0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000
                | 0x10000000 | 0x40000000)     # write/append/EA/delete child/attrs/DELETE/DAC/owner/GA/GW
INHERIT_ONLY_ACE = 0x08

_FOUND = re.compile(r"found\s+(\d+)\s+threats?", re.IGNORECASE)
_NO_THREATS = re.compile(r"found\s+no\s+threats", re.IGNORECASE)
_HR = re.compile(r"hr\s*=\s*(0x[0-9a-fA-F]{8})")


class DefenderUnavailable(Exception):
    pass


class DetectionLogUnavailable(Exception):
    pass


def eicar() -> bytes:
    """The standard antivirus test string, assembled at run time (not stored in the source as is)."""
    return ("X5O!P%@AP[4" + "\\" + "PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()


# ----------------------------------------------------------------------------- locating MpCmdRun
def _reg(path: str, name: str, *, hive=None):
    import winreg
    hive = hive if hive is not None else winreg.HKEY_LOCAL_MACHINE
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def _program_files() -> Path:
    v = _reg(r"SOFTWARE\Microsoft\Windows\CurrentVersion", "ProgramFilesDir")
    return Path(v or os.environ.get("ProgramW6432") or r"C:\Program Files")


def trusted_roots() -> tuple[Path, Path]:
    from scanner_service.config import _program_data
    return _program_data() / "Microsoft" / "Windows Defender" / "Platform", _program_files() / "Windows Defender"


def check_writers(path: Path) -> str | None:
    """None if only SYSTEM / Administrators / TrustedInstaller own or can modify `path`."""
    import win32security
    try:
        sd = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
                                                win32security.OWNER_SECURITY_INFORMATION
                                                | win32security.DACL_SECURITY_INFORMATION)
    except Exception as e:  # noqa: BLE001 - pywintypes.error; unreadable means untrusted
        return f"security descriptor unreadable ({e})"
    owner = win32security.ConvertSidToStringSid(sd.GetSecurityDescriptorOwner())
    if owner not in TRUSTED_WRITERS:
        return f"owned by {owner}"
    dacl = sd.GetSecurityDescriptorDacl()
    if dacl is None:
        return "no DACL (everyone has full access)"
    for i in range(dacl.GetAceCount()):
        ace = dacl.GetAce(i)
        (ace_type, flags), mask = ace[0], ace[1]
        if ace_type != 0 or flags & INHERIT_ONLY_ACE:          # only ACCESS_ALLOWED that apply to it
            continue
        sid = win32security.ConvertSidToStringSid(ace[2])
        if mask & WRITE_RIGHTS and sid not in TRUSTED_WRITERS:
            return f"{sid} may modify it (mask 0x{mask:08X})"
    return None


def verify_trusted_executable(exe: Path, roots: tuple[Path, ...]) -> str | None:
    """None if `exe` is a real file inside one of `roots` that only trusted principals can change."""
    from scanner_service import winfile
    root = next((r for r in roots if winfile.is_within(exe, r) or winfile.same_path(exe.parent, r)), None)
    if root is None:
        return f"{exe} is outside the Defender directories"
    a = winfile.attributes(exe)
    if a is None:
        return f"{exe} does not exist"
    if a & (winfile.FILE_ATTRIBUTE_REPARSE_POINT | winfile.FILE_ATTRIBUTE_DIRECTORY):
        return f"{exe} is a link or a directory"
    try:
        h = winfile.open_entry(exe)
        try:
            real = winfile.final_path(h)
        finally:
            winfile.close(h)
    except OSError as e:
        return f"{exe} cannot be opened ({e})"
    if not winfile.same_path(real, exe):
        return f"{exe} resolves to {real}"
    p = exe
    while True:
        why = check_writers(p)
        if why:
            return f"{p}: {why}"
        if winfile.same_path(p, root):
            return None
        p = p.parent


def locate_mpcmdrun() -> Path:
    """The MpCmdRun.exe of the running Defender platform, verified. Raises DefenderUnavailable."""
    roots = trusted_roots()
    candidates = []
    install = _reg(DEFENDER_KEY, "InstallLocation")
    if install:
        candidates.append(Path(install) / "MpCmdRun.exe")
    candidates.append(roots[1] / "MpCmdRun.exe")
    problems = []
    for exe in candidates:
        why = verify_trusted_executable(exe, roots)
        if why is None:
            return exe
        problems.append(why)
    raise DefenderUnavailable("no trusted MpCmdRun.exe: " + "; ".join(problems))


# ----------------------------------------------------------------------------- Defender state
def defender_status() -> dict:
    """What a non-admin account can learn: service state (SCM) and the public registry values."""
    st = {"service_running": None, "platform_version": None, "engine_version": None,
          "signature_version": None, "passive_mode": None, "disabled_by_policy": False}
    try:
        import win32service
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        try:
            svc = win32service.OpenService(scm, "WinDefend", win32service.SERVICE_QUERY_STATUS)
            try:
                q = win32service.QueryServiceStatusEx(svc)
                st["service_running"] = q["CurrentState"] == win32service.SERVICE_RUNNING
            finally:
                win32service.CloseServiceHandle(svc)
        finally:
            win32service.CloseServiceHandle(scm)
    except Exception as e:  # noqa: BLE001 - fall back to Defender's own flag
        log.debug("WinDefend status via SCM failed: %s", e)
        running = _reg(DEFENDER_KEY, "IsServiceRunning")
        st["service_running"] = None if running is None else bool(running)
    install = _reg(DEFENDER_KEY, "InstallLocation")
    if install:
        st["platform_version"] = Path(install).name or Path(install).parent.name
    st["engine_version"] = _reg(DEFENDER_KEY + r"\Signature Updates", "EngineVersion")
    st["signature_version"] = _reg(DEFENDER_KEY + r"\Signature Updates", "AVSignatureVersion")
    passive = _reg(DEFENDER_KEY, "PassiveMode")
    st["passive_mode"] = bool(passive) if passive is not None else False
    for name in ("DisableAntiSpyware", "DisableAntiVirus"):
        if _reg(POLICY_KEY, name) == 1:
            st["disabled_by_policy"] = True
    return st


def status_problem(st: dict) -> str | None:
    if st.get("disabled_by_policy"):
        return "Microsoft Defender Antivirus is disabled by policy"
    if st.get("service_running") is not True:
        return "the Microsoft Defender Antivirus service (WinDefend) is not running"
    if st.get("passive_mode"):
        return "Microsoft Defender Antivirus is in passive mode (another antivirus is primary)"
    if not st.get("signature_version"):
        return "security intelligence version unknown"
    return None


# ----------------------------------------------------------------------------- detection log
class DetectionLog:
    """Defender's detection events (readable by service accounts: channel ACL grants SU read)."""

    def query(self, since: datetime, path: str) -> list[dict]:
        import pywintypes
        import win32evtlog
        stamp = (since - timedelta(seconds=2)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        ids = " or ".join(f"EventID={i}" for i in DETECTION_EVENT_IDS)
        xpath = f"*[System[({ids}) and TimeCreated[@SystemTime>='{stamp}']]]"
        try:
            q = win32evtlog.EvtQuery(DETECTION_CHANNEL,
                                     win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection, xpath)
        except pywintypes.error as e:
            raise DetectionLogUnavailable(f"{DETECTION_CHANNEL}: {e.strerror} ({e.winerror})") from None
        want = os.path.normcase(str(path))
        found, seen = [], 0
        while seen < MAX_EVENTS:
            try:
                batch = win32evtlog.EvtNext(q, 32, 1000)
            except pywintypes.error as e:
                if e.winerror in (259, 1460):          # ERROR_NO_MORE_ITEMS / timeout: done
                    break
                raise DetectionLogUnavailable(f"reading {DETECTION_CHANNEL}: {e.strerror}") from None
            if not batch:
                break
            for ev in batch:
                seen += 1
                hit = _parse_event(win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml))
                if hit and want in os.path.normcase(hit.pop("path", "")):
                    found.append(hit)
        return found


def _parse_event(xml: str) -> dict | None:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    eid = root.findtext("e:System/e:EventID", default="", namespaces=ns)
    data = {d.get("Name"): (d.text or "") for d in root.findall("e:EventData/e:Data", ns)}
    return {"event_id": int(eid) if eid.isdigit() else None, "threat": data.get("Threat Name", ""),
            "action": data.get("Action Name", ""), "path": data.get("Path", "")}


# ----------------------------------------------------------------------------- running MpCmdRun
@dataclass
class ProcessResult:
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    duration_s: float
    timed_out: bool = False
    cancelled: bool = False
    error: str | None = None          # could not be started


def _kill_on_close_job():
    import win32job
    job = win32job.CreateJobObject(None, "")
    info = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
    info["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, info)
    return job


def run_process(argv: list[str], *, timeout_s: float, cancel: threading.Event | None = None,
                env: dict | None = None, cwd: str | None = None) -> ProcessResult:
    """Run without a shell; stop it (and anything it started) on timeout or cancel."""
    import win32api
    import win32con
    import win32job
    start = time.monotonic()
    try:
        proc = subprocess.Popen(argv, shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=env, cwd=cwd,
                                creationflags=subprocess.CREATE_NO_WINDOW)
    except OSError as e:
        return ProcessResult(None, b"", b"", time.monotonic() - start, error=f"{type(e).__name__}: {e}")
    job = None
    try:
        job = _kill_on_close_job()
        ph = win32api.OpenProcess(win32con.PROCESS_TERMINATE | win32con.PROCESS_SET_QUOTA, False, proc.pid)
        try:
            win32job.AssignProcessToJobObject(job, ph)
        finally:
            ph.Close()
    except Exception as e:  # noqa: BLE001 - still killable through proc.kill()
        log.debug("job object not used: %s", e)
    timed_out = cancelled = False
    deadline = start + timeout_s
    try:
        while True:
            try:
                out, err = proc.communicate(timeout=max(0.01, min(0.25, deadline - time.monotonic())))
                break
            except subprocess.TimeoutExpired:
                if cancel is not None and cancel.is_set():
                    cancelled = True
                elif time.monotonic() >= deadline:
                    timed_out = True
                else:
                    continue
                _stop(proc, job)
                try:
                    out, err = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    out, err = b"", b""
                break
    finally:
        if job is not None:
            job.Close()                                       # KILL_ON_JOB_CLOSE: nothing outlives this
        if proc.poll() is None:
            proc.kill()
    return ProcessResult(None if (timed_out or cancelled) else proc.returncode, (out or b"")[:MAX_OUTPUT],
                         (err or b"")[:MAX_OUTPUT], time.monotonic() - start, timed_out, cancelled)


def _stop(proc, job) -> None:
    try:
        if job is not None:
            import win32job
            win32job.TerminateJobObject(job, 1)
    except Exception:  # noqa: BLE001
        pass
    try:
        proc.kill()
    except OSError:
        pass


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("mbcs" if os.name == "nt" else "latin-1", errors="replace")


# ----------------------------------------------------------------------------- the scanner
class DefenderScanner:
    """Scanner interface used by the job manager: scan_file(path, cancel) -> ScanOutcome."""

    name = "defender"

    def __init__(self, *, work_dir: Path, scan_timeout_s: float = 120.0, require_detection_log: bool = True,
                 event_settle_s: float = 2.0, selftest_enabled: bool = True,
                 selftest_interval_s: float = 6 * 3600.0, selftest_retry_s: float = 300.0,
                 locator: Callable[[], Path] = locate_mpcmdrun, status: Callable[[], dict] = defender_status,
                 runner: Callable[..., ProcessResult] = run_process, detection_log=None,
                 selftest_dirs: tuple[Callable[[], Path], Callable[[Path], None]] | None = None,
                 clock=time.monotonic, sleep=time.sleep):
        self.work_dir = Path(work_dir)
        self.scan_timeout_s = scan_timeout_s
        self.require_detection_log = require_detection_log
        self.event_settle_s = event_settle_s
        self.selftest_enabled = selftest_enabled
        self.selftest_interval_s = selftest_interval_s
        self.selftest_retry_s = selftest_retry_s
        self.locator, self.status, self.runner = locator, status, runner
        self.detection_log = detection_log if detection_log is not None else DetectionLog()
        self.selftest_dirs = selftest_dirs
        self.clock, self.sleep = clock, sleep
        self._selftest_lock = threading.Lock()
        self._selftest: tuple[bool, str, float] | None = None     # (ok, why, when)

    # -- readiness -----------------------------------------------------------
    def check_ready(self) -> tuple[Path | None, dict, str | None]:
        st = {}
        try:
            st = self.status()
            problem = status_problem(st)
            if problem:
                return None, st, problem
            return self.locator(), st, None
        except DefenderUnavailable as e:
            return None, st, str(e)
        except Exception as e:  # noqa: BLE001 - anything unexpected means "not usable"
            return None, st, f"{type(e).__name__}: {e}"

    def health(self) -> dict:
        exe, st, problem = self.check_ready()
        out = {"available": problem is None, "problem": problem, "mpcmdrun": str(exe) if exe else None, **st}
        if self._selftest:
            ok, why, when = self._selftest
            out["selftest"] = {"ok": ok, "detail": why, "age_s": round(self.clock() - when, 1)}
        else:
            out["selftest"] = None if self.selftest_enabled else {"ok": None, "detail": "disabled"}
        return out

    def _env(self) -> dict:
        root = os.environ.get("SystemRoot", r"C:\Windows")
        work = str(self.work_dir)
        return {"SystemRoot": root, "windir": root, "SystemDrive": os.environ.get("SystemDrive", "C:"),
                "PATH": os.path.join(root, "System32"), "TEMP": work, "TMP": work,
                "ProgramData": os.environ.get("ProgramData", r"C:\ProgramData"),
                "ProgramFiles": str(_program_files()) if os.name == "nt" else "", "ALLUSERSPROFILE":
                os.environ.get("ALLUSERSPROFILE", r"C:\ProgramData")}

    # -- self-test -----------------------------------------------------------
    def ensure_selftest(self, cancel: threading.Event | None = None, *, force: bool = False) -> tuple[bool, str]:
        if not self.selftest_enabled:
            return True, "self-test disabled by configuration"
        with self._selftest_lock:
            now = self.clock()
            if self._selftest and not force:
                ok, why, when = self._selftest
                if (ok and now - when < self.selftest_interval_s) or (not ok and now - when < self.selftest_retry_s):
                    return ok, why
            ok, why = self._run_selftest(cancel)
            self._selftest = (ok, why, self.clock())
            (log.info if ok else log.error)("DEFENDER self-test %s: %s", "passed" if ok else "FAILED", why)
            return ok, why

    def _run_selftest(self, cancel) -> tuple[bool, str]:
        if self.selftest_dirs is None:
            return False, "no place for the self-test file"
        from scanner_service import winfile
        from scanner_service.quarantine_manager import PAYLOAD
        make_dir, remove_dir = self.selftest_dirs
        try:
            d = make_dir()
        except OSError as e:
            return False, f"self-test directory not created ({e})"
        try:
            target = d / PAYLOAD                          # same name as real payloads (extension exclusions)
            try:
                h = winfile.create_new(target)
                try:
                    winfile.write_all(h, eicar())
                finally:
                    winfile.close(h)
            except OSError as e:
                if getattr(e, "winerror", None) in (225, 226):  # ERROR_VIRUS_INFECTED / _DELETED
                    return True, "real-time protection refused the EICAR test file in quarantine"
                return False, f"self-test file not written ({e})"
            self.sleep(0.5)
            try:
                gone = winfile.attributes(target) is None
            except OSError:
                gone = True                               # being removed by real-time protection
            if gone:
                return True, "real-time protection removed the EICAR test file from quarantine"
            outcome = self._scan(target, cancel)
            if outcome.verdict == Verdict.DETECTED:
                return True, f"EICAR test file in quarantine detected ({outcome.detail})"
            return False, (f"EICAR test file in quarantine NOT detected ({outcome.verdict.value}: {outcome.detail}); "
                           "the quarantine may be excluded from scanning or Defender is not working")
        finally:
            remove_dir(d)

    def detections_since(self, path: Path, since: datetime) -> list[str] | None:
        """Threat names Defender logged for `path` since `since`; None if the log is unreadable."""
        try:
            return sorted({e["threat"] or "unnamed threat" for e in self.detection_log.query(since, str(path))})
        except DetectionLogUnavailable:
            return None

    # -- scanning ------------------------------------------------------------
    def scan_file(self, path: Path, cancel: threading.Event | None = None) -> ScanOutcome:
        ok, why = self.ensure_selftest(cancel)
        if cancel is not None and cancel.is_set():
            return ScanOutcome(Verdict.CANCELLED, "cancelled before the scan")
        if not ok:
            return ScanOutcome(Verdict.UNAVAILABLE, f"Defender self-test failed: {why}")
        return self._scan(path, cancel)

    def _scan(self, path: Path, cancel) -> ScanOutcome:
        exe, st, problem = self.check_ready()
        engine = f"defender platform {st.get('platform_version')} engine {st.get('engine_version')} " \
                 f"sig {st.get('signature_version')}"
        if problem:
            return ScanOutcome(Verdict.UNAVAILABLE, problem, engine)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        since = datetime.now(timezone.utc)
        res = self.runner([str(exe), "-Scan", "-ScanType", "3", "-File", str(path)],
                          timeout_s=self.scan_timeout_s, cancel=cancel, env=self._env(), cwd=str(self.work_dir))
        return self.classify(res, path, since, engine)

    def classify(self, res: ProcessResult, path: Path, since: datetime, engine: str = "defender") -> ScanOutcome:
        from scanner_service import winfile
        base = {"exit_code": res.exit_code, "duration_s": res.duration_s, "engine": engine}
        if res.cancelled:
            return ScanOutcome(Verdict.CANCELLED, "scan cancelled", **base)
        if res.error:
            return ScanOutcome(Verdict.ERROR, f"MpCmdRun.exe could not be started ({res.error})", **base)
        if res.timed_out:
            return ScanOutcome(Verdict.TIMEOUT, f"no scan result within {self.scan_timeout_s:.0f}s; "
                                                "MpCmdRun.exe was stopped", **base)
        text = _decode(res.stdout) + "\n" + _decode(res.stderr)
        m = _FOUND.search(text)
        output_threats = int(m.group(1)) if m else None
        output_clean = bool(_NO_THREATS.search(text))
        if self.event_settle_s:
            self.sleep(self.event_settle_s)                    # detection events are written just after
        try:
            events = self.detection_log.query(since, str(path))
            log_error = None
        except DetectionLogUnavailable as e:
            events, log_error = None, str(e)
        try:
            present = winfile.attributes(path) is not None
        except OSError:
            present = False          # delete pending (Defender is removing it while we hold it) or refused
        evidence = {"output_threats": output_threats, "output_no_threats_line": output_clean,
                    "detection_events": None if events is None else len(events), "file_present": present}
        if log_error:
            evidence["detection_log_error"] = log_error
        threats = sorted({e["threat"] for e in events or [] if e.get("threat")})
        if events or (output_threats or 0) > 0 or (res.exit_code == 0 and not present):
            why = ", ".join(threats) if threats else (
                f"{output_threats} threat(s) reported" if output_threats else "Defender removed the file")
            return ScanOutcome(Verdict.DETECTED, f"Defender detection: {why}", threats=threats,
                               evidence=evidence, **base)
        if res.exit_code != 0:
            hr = _HR.search(text)
            return ScanOutcome(Verdict.ERROR, f"MpCmdRun.exe failed (exit {res.exit_code}"
                               + (f", hr {hr.group(1)}" if hr else "") + ")", evidence=evidence, **base)
        if events is None and self.require_detection_log:
            return ScanOutcome(Verdict.UNVERIFIABLE, f"detection log unreadable, result not confirmed ({log_error})",
                               evidence=evidence, **base)
        return ScanOutcome(Verdict.CLEAN, "no threats (exit 0, no detection event, file unchanged)",
                           evidence=evidence, **base)
