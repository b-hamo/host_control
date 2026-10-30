"""SecureArtifactScanner Windows service (pywin32) and the executable's command line.

    SecureArtifactScanner.exe                       started by the SCM: service dispatcher
    SecureArtifactScanner.exe version
    SecureArtifactScanner.exe debug [--config F] [--data-root D]   run in this console (Ctrl+C stops)
    SecureArtifactScanner.exe client health [--selftest]
    SecureArtifactScanner.exe client roundtrip --content benign|eicar [--publish]

The SCM registration (account NT SERVICE\\SecureArtifactScanner, auto start, restart on
failure) is done by installer/install.ps1, not by this program.

Service status: START_PENDING while the runtime starts (with a wait hint), RUNNING once the
pipe is listening, STOP_PENDING while it stops. SvcStop only signals; the stop itself (no
new jobs, running scans cancelled, bounded waits) happens on the service thread.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import replace
from pathlib import Path

if __package__ in (None, ""):                         # run as a script: make the package importable
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import servicemanager
import win32event
import win32service
import win32serviceutil

from scanner_service import __version__
from scanner_service.config import SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME, SERVICE_NAME, load_config
from scanner_service.runtime import ScannerRuntime, harden_sys_path, setup_logging

log = logging.getLogger("scanner.service")
STOP_TIMEOUT_S = 25.0
START_WAIT_HINT_MS = 60_000


class SecureArtifactScannerService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY_NAME
    _svc_description_ = SERVICE_DESCRIPTION

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, True, False, None)
        self.runtime: ScannerRuntime | None = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING, waitHint=int(STOP_TIMEOUT_S * 1000) + 5000)
        win32event.SetEvent(self.stop_event)

    def SvcShutdown(self):                              # Windows is shutting down
        self.SvcStop()

    def SvcRun(self):
        self.ReportServiceStatus(win32service.SERVICE_START_PENDING, waitHint=START_WAIT_HINT_MS)
        try:
            harden_sys_path()
            config = load_config()
            setup_logging(config.log_dir, config.log_level)
            self.runtime = ScannerRuntime(config)
            self.runtime.start()
        except Exception as e:
            log.exception("%s failed to start", SERVICE_NAME)
            servicemanager.LogErrorMsg(f"{SERVICE_NAME} failed to start: {type(e).__name__}: {e}")
            if self.runtime is not None:
                try:
                    self.runtime.stop(5.0)
                except Exception:  # noqa: BLE001
                    pass
            raise                                         # pywin32 reports SERVICE_STOPPED with an error code
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        servicemanager.LogInfoMsg(f"{SERVICE_NAME} {__version__} running")
        win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING, waitHint=int(STOP_TIMEOUT_S * 1000) + 5000)
        try:
            self.runtime.stop(STOP_TIMEOUT_S)
        except Exception:  # noqa: BLE001
            log.exception("error while stopping")
        servicemanager.LogInfoMsg(f"{SERVICE_NAME} stopped")


# ----------------------------------------------------------------------------- command line
def _debug(args) -> int:
    config = load_config(args.config) if args.config else load_config()
    if args.data_root:
        config = replace(config, quarantine_root=args.data_root / "Quarantine",
                         state_dir=args.data_root / "ScannerService")
    if args.pipe:
        config = replace(config, pipe_name=args.pipe)
    setup_logging(config.log_dir, config.log_level, console=True)
    rt = ScannerRuntime(config, dev_mode=True)
    rt.start()
    print(f"{SERVICE_NAME} running in this console on {config.pipe_name}; Ctrl+C stops", file=sys.stderr)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        rt.stop(STOP_TIMEOUT_S)
    return 0


def _client(args) -> int:
    from scanner_service.client_checks import run_client
    return run_client(args)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        try:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(SecureArtifactScannerService)
            servicemanager.StartServiceCtrlDispatcher()
            return 0
        except Exception as e:  # noqa: BLE001 - started by hand, not by the SCM
            if getattr(e, "winerror", None) == 1063:     # ERROR_FAILED_SERVICE_CONTROLLER_CONNECT
                print(f"{SERVICE_NAME} is a Windows service; install it with installer/install.ps1. "
                      "Commands: version, debug, client", file=sys.stderr)
                return 2
            raise
    ap = argparse.ArgumentParser(prog="SecureArtifactScanner")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("version")
    d = sub.add_parser("debug", help="run in this console instead of as a service (development)")
    d.add_argument("--config", type=Path)
    d.add_argument("--data-root", type=Path, help="use <dir>\\Quarantine and <dir>\\ScannerService (created)")
    d.add_argument("--pipe", help="pipe name (default \\\\.\\pipe\\SecureArtifactScanner)")
    c = sub.add_parser("client", help="talk to the running service (test client)")
    c.add_argument("action", choices=("health", "roundtrip"))
    c.add_argument("--pipe", default=None)
    c.add_argument("--selftest", action="store_true", help="health: run the EICAR self-test now")
    c.add_argument("--content", choices=("benign", "eicar"), default="benign")
    c.add_argument("--publish", action="store_true", help="roundtrip: publish with a test approval")
    c.add_argument("--keep", action="store_true", help="roundtrip: leave the scanned job (no ABORT)")
    c.add_argument("--no-verify-server", action="store_true", help="do not check the pipe server is the service")
    c.add_argument("--timeout", type=float, default=240.0)
    args = ap.parse_args(argv)
    if args.cmd == "version":
        print(f"{SERVICE_NAME} {__version__} (Python {sys.version.split()[0]}, "
              f"frozen={bool(getattr(sys, 'frozen', False))})")
        return 0
    if args.cmd == "debug":
        return _debug(args)
    return _client(args)


if __name__ == "__main__":
    sys.exit(main())
