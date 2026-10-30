"""Wiring of the scanner's parts, shared by the Windows service and the console `debug` mode.

    start: logging → quarantine root check → recovery (discard leftovers) → Defender check
           → publisher → job manager → Named Pipe server → periodic sweep
    stop:  no new jobs → cancel running ones (bounded wait) → pipe closed → run marker "stopped"
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
import threading
import time
from pathlib import Path

from scanner_service import __version__
from scanner_service.artifact_publisher import ArtifactPublisher, HostAssertedApproval, NoApproval
from scanner_service.config import SERVICE_NAME, ScannerConfig
from scanner_service.defender_scanner import DefenderScanner
from scanner_service.ipc_server import NamedPipeServer, RequestHandler, current_user_sid, pipe_sddl
from scanner_service.quarantine_manager import QuarantineManager
from scanner_service.recovery_manager import RecoveryManager
from scanner_service.scan_job_manager import ScanJobManager

log = logging.getLogger("scanner.runtime")


class _UtcFormatter(logging.Formatter):
    converter = time.gmtime


def setup_logging(log_dir: Path | None, level: str = "INFO", console: bool = False) -> None:
    root = logging.getLogger()
    root.setLevel(level)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = _UtcFormatter("%(asctime)sZ %(levelname)s %(name)s [%(threadName)s] %(message)s")
    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(log_dir / "scanner.log", maxBytes=5 * 1024 * 1024, backupCount=5,
                                                  encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
    if console:
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(fmt)
        root.addHandler(sh)


def harden_sys_path() -> None:
    """Frozen build: import only from the install directory (never CWD, TEMP or a user's Python)."""
    if getattr(sys, "frozen", False):
        base = os.path.normcase(os.path.abspath(getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))))
        sys.path[:] = [p for p in sys.path if p and os.path.normcase(os.path.abspath(p)).startswith(base)]


def _sys_path_inside_bundle() -> bool | None:
    if not getattr(sys, "frozen", False):
        return None
    base = os.path.normcase(os.path.abspath(getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))))
    return all(os.path.normcase(os.path.abspath(p)).startswith(base) for p in sys.path if p)


def token_info() -> dict:
    """Who this process really runs as, read from its own token."""
    import win32api
    import win32security
    tok = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    try:
        user = win32security.GetTokenInformation(tok, win32security.TokenUser)[0]
        try:
            name, domain, _ = win32security.LookupAccountSid(None, user)
            account = f"{domain}\\{name}"
        except Exception:  # noqa: BLE001
            account = None
        admins = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid)
        system = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid)
        groups = win32security.GetTokenInformation(tok, win32security.TokenGroups)
        in_admins = any(g == admins for g, _attrs in groups)     # also a UAC-filtered (deny-only) member
        privs = []
        for luid, attrs in win32security.GetTokenInformation(tok, win32security.TokenPrivileges):
            privs.append(win32security.LookupPrivilegeName(None, luid) + ("" if attrs & 2 else " (disabled)"))
        il_sid, _ = win32security.GetTokenInformation(tok, win32security.TokenIntegrityLevel)
        il = il_sid.GetSubAuthority(il_sid.GetSubAuthorityCount() - 1)
        return {"account": account, "sid": win32security.ConvertSidToStringSid(user),
                "is_admin": bool(win32security.CheckTokenMembership(None, admins)),
                "administrators_group": in_admins,
                "is_local_system": user == system,
                "elevated": bool(win32security.GetTokenInformation(tok, win32security.TokenElevation)),
                "integrity_rid": f"0x{il:04X}", "privileges": sorted(privs)}
    finally:
        tok.Close()


class ScannerRuntime:
    def __init__(self, config: ScannerConfig, *, scanner=None, dev_mode: bool = False):
        self.config = config
        self.dev_mode = dev_mode           # console/tests: create missing directories, allow the current user
        self._scanner = scanner
        self.started_at = time.monotonic()
        self.quarantine = self.recovery = self.scanner = self.publisher = self.manager = self.server = None
        self._sweep_stop = threading.Event()
        self._sweeper: threading.Thread | None = None

    def start(self) -> None:
        c = self.config
        me = token_info()
        log.info("starting %s %s (pid %d) as %s admin=%s system=%s, frozen=%s", SERVICE_NAME, __version__,
                 os.getpid(), me["account"], me["is_admin"], me["is_local_system"], getattr(sys, "frozen", False))
        if (me["is_admin"] or me["is_local_system"]) and not self.dev_mode:
            log.warning("running with administrator or LocalSystem rights: the service is meant to run as "
                        "NT SERVICE\\%s", SERVICE_NAME)
        c.work_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine = QuarantineManager(c.quarantine_root, max_file_bytes=c.max_file_bytes,
                                            store_limit_bytes=c.store_limit_bytes, min_free_bytes=c.min_free_bytes,
                                            max_jobs=c.max_active_jobs, create_root=self.dev_mode)
        self.quarantine.ensure_root()
        self.recovery = RecoveryManager(self.quarantine, c.work_dir, c.export_root)
        self.recovery.recover_on_start()
        self.scanner = self._scanner or DefenderScanner(
            work_dir=c.work_dir, scan_timeout_s=c.scan_timeout_s, require_detection_log=c.require_detection_log,
            event_settle_s=c.event_settle_s, selftest_enabled=c.selftest_enabled,
            selftest_interval_s=c.selftest_interval_s, selftest_retry_s=c.selftest_retry_s,
            selftest_dirs=(self.quarantine.new_selftest_dir, self.quarantine.remove_selftest_dir))
        h = self.scanner.health()
        if h.get("available"):
            log.info("Defender ready: %s (platform %s, sig %s)", h.get("mpcmdrun"), h.get("platform_version"),
                     h.get("signature_version"))
        else:
            log.error("Defender NOT available (%s): every scan will be blocked", h.get("problem"))
        approval = HostAssertedApproval() if c.approval_mode == "host_asserted" else NoApproval()
        self.publisher = ArtifactPublisher(c.export_root, approval, max_file_bytes=c.max_file_bytes)
        self.publisher.ensure_root()
        self.manager = ScanJobManager(c, self.quarantine, self.scanner, self.publisher)
        handler = RequestHandler(self.manager, self.health, max_chunk_bytes=c.max_chunk_bytes,
                                 max_response_bytes=c.max_response_bytes)
        clients = tuple(c.pipe_client_sids) + ((current_user_sid(),) if self.dev_mode else ())
        self.server = NamedPipeServer(c.pipe_name, handler, sddl=pipe_sddl(me["sid"], clients),
                                      max_instances=c.pipe_max_instances, max_request_bytes=c.max_request_bytes,
                                      idle_timeout_s=c.pipe_idle_timeout_s)
        self.server.start()
        self._sweeper = threading.Thread(target=self._sweep_loop, name="sweep", daemon=True)
        self._sweeper.start()
        log.info("%s started", SERVICE_NAME)

    def _sweep_loop(self) -> None:
        while not self._sweep_stop.wait(self.config.cleanup_interval_s):
            try:
                self.manager.sweep()
            except Exception:  # noqa: BLE001 - keep sweeping
                log.exception("sweep failed")

    def health(self, payload: dict | None = None) -> dict:
        if payload and payload.get("selftest") is True:
            self.scanner.ensure_selftest(force=True)
        c = self.config
        return {
            "service": SERVICE_NAME, "version": __version__, "pid": os.getpid(),
            "uptime_s": round(time.monotonic() - self.started_at, 1),
            "accepting": self.manager.accepting if self.manager else False,
            "token": token_info(),
            "defender": self.scanner.health(),
            "publish": {"enabled": self.publisher.enabled, "approval_mode": self.publisher.approval.mode,
                        "export_root": str(self.publisher.export_root) if self.publisher.export_root else None,
                        "problem": self.publisher.problem},
            "jobs": self.manager.counts(),
            "quarantine": {"reserved_bytes": self.quarantine.reserved},
            "recovery": self.recovery.last.view() if self.recovery and self.recovery.last else None,
            "limits": {"max_file_bytes": c.max_file_bytes, "max_chunk_bytes": c.max_chunk_bytes,
                       "max_request_bytes": c.max_request_bytes, "max_active_jobs": c.max_active_jobs,
                       "scan_timeout_s": c.scan_timeout_s},
            "python": {"version": sys.version.split()[0], "frozen": bool(getattr(sys, "frozen", False)),
                       "executable": sys.executable, "sys_path_ok": _sys_path_inside_bundle()},
        }

    def stop(self, timeout_s: float = 20.0) -> None:
        log.info("%s stopping", SERVICE_NAME)
        self._sweep_stop.set()
        if self.manager is not None:
            self.manager.shutdown(max(1.0, timeout_s - 5.0))
        if self.server is not None:
            self.server.stop(3.0)
        if self.recovery is not None:
            self.recovery.mark_stopped()
        log.info("%s stopped", SERVICE_NAME)
