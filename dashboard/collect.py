"""Build the dashboard overview from what is already on disk (docs: dashboard/README.md).

Sources, all read-only:
  - Sandbox Manager sessions: <root>/sessions/<id>/state.json (state, runtime type, termination reason,
    events with times and received file names). Roots: the default Manager root, --root, and every
    sandbox_root a Host status file names.
  - Host status files: <dashboard dir>/hosts/<id>.json and .png (host/dashboard_status.py).
  - `wsb list` for whether a Windows Sandbox is running at all.
  - Host CPU and memory: GetSystemTimes, GlobalMemoryStatusEx.
  - Per session CPU and memory: Hyper-V compute system statistics (HCS). Windows lets only
    administrators read them, so without that they stay null and `metrics.per_session` says why.
Standard library only; this package imports nothing from host/.
"""
from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ACTIVE = ("PREPARED", "STARTING", "STARTED", "RUNNING", "RESTARTING")
UP = ("STARTED", "RUNNING", "RESTARTING")
WSB, MICRO = "WINDOWS_SANDBOX", "MICRO_VM_APP_WINDOW"
KEEP_ENDED_S = 600          # an ended session stays on the board this long
VM_MAX = 8                  # sandbox_manager MicroVmManager max_active default

EXECUTABLE = {".exe", ".msi", ".msix", ".appx", ".com", ".scr"}
SCRIPT = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta", ".py", ".rb", ".sh", ".pl", ".php"}
MACRO_DOC = {".docm", ".xlsm", ".pptm", ".doc", ".xls", ".ppt", ".dotm", ".xltm"}
ARCHIVE = {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz"}
TOOL_LABEL = {"router_capture": "웹페이지 명령", "router_execute": "웹페이지 명령", "inbox_download": "파일 받기",
              "inbox_import": "파일 받기", "artifact_export": "결과 반출", "artifact_list": "결과 반출"}


def default_manager_root() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(base) / "SecureCUA" / "sandbox-manager"


def default_dashboard_dir() -> Path:
    return default_manager_root().parent / "dashboard"


def _ts(text: str | None) -> float | None:
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _iso(t: float | None) -> str | None:
    return None if t is None else datetime.fromtimestamp(t, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def risk_type(files: list[str], last_tool: str | None) -> str:
    """Why this session needed isolation, from what it was handed (not a verdict; see README)."""
    for name in reversed(files):
        suffix = Path(name).suffix.lower()
        if suffix in EXECUTABLE:
            return f"미확인 실행파일 ({name})"
        if suffix in SCRIPT:
            return f"스크립트 실행 ({name})"
        if suffix in MACRO_DOC:
            return f"매크로 문서 ({name})"
        if suffix in ARCHIVE:
            return f"외부 프로젝트 ({name})"
        return f"받은 파일 열기 ({name})"
    if last_tool in TOOL_LABEL:
        return TOOL_LABEL[last_tool]
    if last_tool and last_tool.startswith("computer_"):
        return "화면 작업"
    return "일반 작업"


def _user_files(events: list) -> list[str]:
    """Files the user's task brought in, without the Host's own run helpers (run-<id>.json/.ps1)."""
    names = []
    for e in events:
        name = e.get("name") if isinstance(e, dict) and e.get("kind") == "INBOX_FILE_REGISTERED" else None
        if isinstance(name, str) and not (name.startswith("run-") and Path(name).suffix in (".json", ".ps1")):
            names.append(name)
    return names


# --------------------------------------------------------------------- Windows measurements
class _FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]

    @property
    def value(self) -> int:
        return self.high << 32 | self.low


class _MemoryStatus(ctypes.Structure):
    _fields_ = [("length", ctypes.c_uint32), ("load", ctypes.c_uint32), ("total", ctypes.c_uint64),
                ("avail", ctypes.c_uint64), ("page_total", ctypes.c_uint64), ("page_avail", ctypes.c_uint64),
                ("virtual_total", ctypes.c_uint64), ("virtual_avail", ctypes.c_uint64), ("ext", ctypes.c_uint64)]


class HostMeter:
    """Whole-PC CPU (between two reads) and memory load, in percent."""

    def __init__(self):
        self._last = self._times()

    @staticmethod
    def _times():
        if sys.platform != "win32":
            return None
        idle, kernel, user = _FileTime(), _FileTime(), _FileTime()
        if not ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
            return None
        return idle.value, kernel.value + user.value          # kernel time includes idle time

    def read(self) -> dict:
        now, cpu = self._times(), None
        if now and self._last and now[1] > self._last[1]:
            busy = (now[1] - self._last[1]) - (now[0] - self._last[0])
            cpu = round(max(0.0, min(100.0, 100.0 * busy / (now[1] - self._last[1]))), 1)
        self._last = now or self._last
        mem = None
        if sys.platform == "win32":
            status = _MemoryStatus()
            status.length = ctypes.sizeof(_MemoryStatus)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                mem = int(status.load)
        return {"cpu_percent": cpu, "mem_percent": mem}


class VmMeter:
    """CPU and memory of one Hyper-V compute system (Windows Sandbox or micro_VM) from HCS statistics.

    Windows returns HCS_E_ACCESS_DENIED to non-administrators; then every read is None and `reason` says
    so. CPU percent is of the whole PC: guest CPU time between two reads / (wall time x logical CPUs).
    """
    QUERY = '{"PropertyTypes":["Statistics"]}'

    def __init__(self, stats=None, cpus: int | None = None, clock=time.monotonic):
        self._stats = stats or self._hcs_statistics
        self._cpus = cpus or os.cpu_count() or 1
        self._clock = clock
        self._last: dict[str, tuple[float, int]] = {}
        self.reason: str | None = "no running VM measured yet"

    def read(self, system_id: str | None) -> tuple[float | None, int | None]:
        if not system_id:
            return None, None
        try:
            stats = self._stats(system_id)
        except PermissionError:
            self.reason = "needs administrator (HCS_E_ACCESS_DENIED)"
            return None, None
        except Exception as e:  # noqa: BLE001 - a missing number never breaks the overview
            self.reason = f"HCS statistics unavailable ({type(e).__name__})"
            return None, None
        runtime = int(stats.get("Processor", {}).get("TotalRuntime100ns", 0))
        mem = stats.get("Memory", {}).get("MemoryUsageCommitBytes")
        now, cpu = self._clock(), None
        if system_id in self._last:
            then, before = self._last[system_id]
            if now > then:
                cpu = round(max(0.0, min(100.0, (runtime - before) / ((now - then) * 1e7 * self._cpus) * 100)), 1)
        self._last[system_id] = (now, runtime)
        self.reason = None
        return cpu, int(mem) if isinstance(mem, (int, float)) else None

    def _hcs_statistics(self, system_id: str) -> dict:
        if sys.platform != "win32":
            raise OSError("not Windows")
        cc = ctypes.WinDLL("computecore.dll")
        cc.HcsCreateOperation.restype = ctypes.c_void_p
        cc.HcsCreateOperation.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        cc.HcsOpenComputeSystem.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
        cc.HcsGetComputeSystemProperties.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p]
        cc.HcsWaitForOperationResult.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
        for f in ("HcsCloseOperation", "HcsCloseComputeSystem"):
            getattr(cc, f).argtypes = [ctypes.c_void_p]
        system = ctypes.c_void_p()
        hr = cc.HcsOpenComputeSystem(system_id, 0x10000000, ctypes.byref(system)) & 0xFFFFFFFF
        if hr == 0x8037011B or hr == 0x80070005:
            raise PermissionError(hex(hr))
        if hr:
            raise OSError(hex(hr))
        op = cc.HcsCreateOperation(None, None)
        result = ctypes.c_void_p()
        try:
            cc.HcsGetComputeSystemProperties(system, op, self.QUERY)
            hr = cc.HcsWaitForOperationResult(op, 5000, ctypes.byref(result)) & 0xFFFFFFFF
            text = ctypes.wstring_at(result.value) if result.value else "{}"
            if hr == 0x8037011B or hr == 0x80070005:
                raise PermissionError(hex(hr))
            if hr:
                raise OSError(hex(hr))
            return json.loads(text).get("Statistics", {})
        finally:
            if result.value:
                ctypes.windll.kernel32.LocalFree(result)
            cc.HcsCloseOperation(op)
            cc.HcsCloseComputeSystem(system)


def wsb_running() -> int | None:
    """How many Windows Sandboxes are running (0 or 1), None when `wsb` cannot say."""
    try:
        out = subprocess.run(["wsb", "list", "--raw"], capture_output=True, text=True, timeout=10,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    try:
        return len(json.loads(out).get("WindowsSandboxEnvironments") or [])
    except ValueError:
        return None


def _pid_alive(pid) -> bool:
    if type(pid) is not int or pid <= 0:
        return False
    if sys.platform != "win32":
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)        # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return False
    code = ctypes.c_uint32()
    ok = ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
    ctypes.windll.kernel32.CloseHandle(handle)
    return bool(ok) and code.value == 259                                  # STILL_ACTIVE


# --------------------------------------------------------------------- the overview
class Collector:
    def __init__(self, roots: list[Path] | None = None, dashboard_dir: Path | None = None, *, vm_max: int = VM_MAX,
                 keep_ended_s: float = KEEP_ENDED_S, wsb=wsb_running, host_meter=None, vm_meter=None,
                 clock=time.time, pid_alive=_pid_alive):
        self.roots = [Path(r) for r in (roots or [default_manager_root()])]
        self.dashboard_dir = Path(dashboard_dir or default_dashboard_dir())
        self.vm_max, self.keep_ended_s = vm_max, keep_ended_s
        self.wsb, self.clock, self.pid_alive = wsb, clock, pid_alive
        self.host_meter = host_meter or HostMeter()
        self.vm_meter = vm_meter or VmMeter()

    def host_status(self) -> dict[str, dict]:
        found = {}
        for path in sorted((self.dashboard_dir / "hosts").glob("*.json")):
            data = _read_json(path)
            if data and isinstance(data.get("session_id"), str):
                found[data["session_id"]] = data
        return found

    def _sessions(self, hosts: dict[str, dict]) -> list[dict]:
        roots = list(self.roots)
        for h in hosts.values():
            if h.get("sandbox_root") and Path(h["sandbox_root"]) not in roots:
                roots.append(Path(h["sandbox_root"]))
        seen, out = set(), []
        for root in roots:
            for path in sorted((root / "sessions").glob("*/state.json")) if (root / "sessions").is_dir() else ():
                s = _read_json(path)
                if s and isinstance(s.get("session_id"), str) and s["session_id"] not in seen:
                    seen.add(s["session_id"])
                    out.append(s)
        return out

    def overview(self) -> dict:
        now = self.clock()
        hosts = self.host_status()
        rows = []
        for s in self._sessions(hosts):
            events = [e for e in s.get("events") or [] if isinstance(e, dict)]
            started = next((_ts(e.get("at")) for e in events if e.get("kind") == "PREPARED"), None)
            ended = next((_ts(e.get("at")) for e in reversed(events)
                          if e.get("kind") == "STATE" and e.get("to") in ("TERMINATED", "FAILED")), None)
            state = s.get("state")
            if state not in ACTIVE and (ended is None or now - ended > self.keep_ended_s):
                continue
            rows.append((started or 0.0, s, events, ended))
        rows.sort(key=lambda r: r[0])
        sessions, counters = [], {WSB: 0, MICRO: 0}
        for started, s, events, ended in rows:
            kind = s.get("runtime_type")
            counters[kind] = counters.get(kind, 0) + 1
            h = hosts.get(s["session_id"], {})
            micro = kind == MICRO
            binding = s.get("micro_vm") if isinstance(s.get("micro_vm"), dict) else {}
            cpu = mem = None
            if s.get("state") in UP:
                cpu, mem = self.vm_meter.read(binding.get("container_id") if micro else s.get("sandbox_id"))
            reason = s.get("termination_reason")
            owner = s.get("owner") if isinstance(s.get("owner"), dict) else {}
            image = self.dashboard_dir / "hosts" / f"{s['session_id']}.png"
            sessions.append({
                "id": s["session_id"],
                "label": f"{'VM' if micro else 'GUI'}-{counters[kind]:02d}",
                "runtime": "micro_vm" if micro else "windows_sandbox",
                "state": s.get("state"),
                "display_state": "VIOLATION" if reason == "SECURITY_VIOLATION" else s.get("state"),
                "termination_reason": reason,
                "risk_type": risk_type(_user_files(events), h.get("last_tool")),
                "task": h.get("task"),
                "last_activity": {"tool": h.get("last_tool"), "file": h.get("last_file"), "ok": h.get("last_ok"),
                                  "at": h.get("last_activity_at")} if h.get("last_tool") else None,
                "cpu_percent": cpu,
                "mem_bytes": mem,
                "started_at": _iso(started or None),
                "ended_at": _iso(ended),
                "network": "blocked" if micro else "enabled",
                "window_state": None if micro else h.get("window_state"),
                "host_alive": self.pid_alive(owner.get("pid")) if s.get("state") in ACTIVE else None,
                "screenshot": {"available": image.is_file(), "captured_at": h.get("screen_captured_at")},
            })
        wsb_sessions = [x for x in sessions if x["runtime"] == "windows_sandbox"]
        live_wsb = next((x for x in reversed(wsb_sessions) if x["state"] in ACTIVE), None)
        running = self.wsb()
        if running is None:
            running = 1 if live_wsb and live_wsb["state"] in UP else 0
        micro = [x for x in sessions if x["runtime"] == "micro_vm"]
        up = sum(x["state"] in UP for x in micro)
        starting = sum(x["state"] in ("PREPARED", "STARTING") for x in micro)
        # The limit a micro_VM Host was started with (--micro-vm-max-active), else the Manager's default.
        vm_max = max((h["vm_max"] for h in hosts.values() if type(h.get("vm_max")) is int and h.get("ended_at") is None),
                     default=self.vm_max)
        return {
            "updated_at": _iso(now),
            "runtimes": {
                "windows_sandbox": {
                    "running": running,
                    "state": live_wsb["state"] if live_wsb else ("RUNNING" if running else "STOPPED"),
                    "window_state": (live_wsb or {}).get("window_state") or "UNAVAILABLE",
                },
                "micro_vm": {"running": up, "max": vm_max, "starting": starting,
                             "failed": sum(x["state"] == "FAILED" for x in micro),
                             "free_slots": max(0, vm_max - up - starting)},
            },
            "host_resources": self.host_meter.read(),
            "metrics": {"per_session": "hcs" if self.vm_meter.reason is None else "unavailable",
                        "reason": self.vm_meter.reason},
            "sessions": sessions,
        }

    def screenshot(self, session_id: str) -> Path | None:
        """The last screen the Agent saw in that session, if its Host left one."""
        if not session_id or any(c in session_id for c in "/\\:.") or len(session_id) > 128:
            return None
        path = self.dashboard_dir / "hosts" / f"{session_id}.png"
        return path if path.is_file() else None
