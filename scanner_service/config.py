"""Fixed names and the settings file (config.json, written by installer/install.ps1).

    C:\\Program Files\\SecureRuntime\\ScannerService\\        executable (admins write, service reads)
    C:\\ProgramData\\SecureRuntime\\ScannerService\\config.json  this file (admins write, service reads)
    C:\\ProgramData\\SecureRuntime\\ScannerService\\logs\\       service log (service writes, Users nothing)
    C:\\ProgramData\\SecureRuntime\\ScannerService\\work\\       MpCmdRun TEMP, run marker
    C:\\ProgramData\\SecureRuntime\\Quarantine\\                one directory per job

Unknown keys are refused, so a typo cannot silently fall back to a default.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, fields, replace
from pathlib import Path

SERVICE_NAME = "SecureArtifactScanner"
SERVICE_DISPLAY_NAME = "Secure Artifact Scanner"
SERVICE_DESCRIPTION = ("Receives Sandbox artifact candidates into a private quarantine, scans them with "
                       "Microsoft Defender (MpCmdRun.exe) and discards them; never runs them.")
SERVICE_ACCOUNT = "NT SERVICE\\" + SERVICE_NAME
PIPE_NAME = "\\\\.\\pipe\\" + SERVICE_NAME

MAX_BYTES_LIMIT = 52_428_800            # artifact-export-v1 ceiling (50 MiB)


def _program_data() -> Path:
    if os.name == "nt":
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList") as k:
                value, _ = winreg.QueryValueEx(k, "ProgramData")
                return Path(os.path.expandvars(value))
        except OSError:
            pass
    return Path(os.environ.get("ProgramData", r"C:\ProgramData"))


def default_data_root() -> Path:
    return _program_data() / "SecureRuntime"


def default_config_path() -> Path:
    return default_data_root() / "ScannerService" / "config.json"


@dataclass(frozen=True)
class ScannerConfig:
    quarantine_root: Path
    state_dir: Path
    export_root: Path | None = None          # None: PUBLISH is refused
    pipe_name: str = PIPE_NAME
    pipe_client_sids: tuple[str, ...] = ()   # besides SYSTEM, Administrators and the service itself
    pipe_max_instances: int = 4
    max_request_bytes: int = 512 * 1024
    max_response_bytes: int = 64 * 1024
    pipe_idle_timeout_s: float = 60.0
    max_file_bytes: int = 1024 * 1024        # same demo policy as host/artifacts.py DEFAULT_MAX_BYTES
    shared_scan_enabled: bool = False      # opt-in: binary Shared files, scan only (never PUBLISH)
    shared_max_file_bytes: int = MAX_BYTES_LIMIT
    max_chunk_bytes: int = 256 * 1024
    store_limit_bytes: int = 200 * 1024 * 1024
    min_free_bytes: int = 512 * 1024 * 1024
    max_active_jobs: int = 8
    max_concurrent_scans: int = 2
    upload_idle_timeout_s: float = 120.0
    job_ttl_s: float = 900.0
    final_retention_s: float = 300.0
    scan_timeout_s: float = 120.0
    cleanup_interval_s: float = 30.0
    require_detection_log: bool = True
    event_settle_s: float = 2.0
    selftest_enabled: bool = True
    selftest_interval_s: float = 6 * 3600.0
    selftest_retry_s: float = 300.0
    approval_mode: str = "host_asserted"     # interim, until the Artifact Broker integration
    log_level: str = "INFO"

    @property
    def log_dir(self) -> Path:
        return self.state_dir / "logs"

    @property
    def work_dir(self) -> Path:
        return self.state_dir / "work"

    def validate(self) -> "ScannerConfig":
        if type(self.shared_scan_enabled) is not bool:
            raise ValueError("shared_scan_enabled must be a boolean")
        if type(self.shared_max_file_bytes) is not int or not 1 <= self.shared_max_file_bytes <= MAX_BYTES_LIMIT:
            raise ValueError(f"shared_max_file_bytes must be 1..{MAX_BYTES_LIMIT}")
        if not 1 <= self.max_file_bytes <= MAX_BYTES_LIMIT:
            raise ValueError(f"max_file_bytes must be 1..{MAX_BYTES_LIMIT}")
        if not 1024 <= self.max_chunk_bytes <= 1024 * 1024:
            raise ValueError("max_chunk_bytes must be 1 KiB..1 MiB")
        if self.max_request_bytes < self.max_chunk_bytes * 4 // 3 + 4096:
            raise ValueError("max_request_bytes is too small for one base64 chunk")
        for name in ("pipe_max_instances", "max_active_jobs", "max_concurrent_scans"):
            if not 1 <= getattr(self, name) <= 64:
                raise ValueError(f"{name} must be 1..64")
        for name in ("scan_timeout_s", "upload_idle_timeout_s", "job_ttl_s", "cleanup_interval_s"):
            if not getattr(self, name) > 0:
                raise ValueError(f"{name} must be > 0")
        if self.approval_mode not in ("host_asserted", "disabled"):
            raise ValueError("approval_mode must be host_asserted or disabled")
        for sid in self.pipe_client_sids:
            if not isinstance(sid, str) or not sid.startswith("S-1-"):
                raise ValueError(f"pipe_client_sids: {sid!r} is not a SID string")
        return self

    @property
    def storage_file_limit(self) -> int:
        return max(self.max_file_bytes, self.shared_max_file_bytes if self.shared_scan_enabled else 0)


_PATHS = {"quarantine_root", "state_dir", "export_root"}
_TUPLES = {"pipe_client_sids"}


def load_config(path: Path | None = None) -> ScannerConfig:
    """config.json → ScannerConfig. A missing file gives the installed defaults."""
    path = Path(path) if path else default_config_path()
    root = default_data_root()
    base = ScannerConfig(quarantine_root=root / "Quarantine", state_dir=root / "ScannerService")
    if not path.exists():
        return base.validate()
    raw = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: expected a JSON object")
    known = {f.name for f in fields(ScannerConfig)}
    unknown = sorted(set(raw) - known - {"$comment"})
    if unknown:
        raise ValueError(f"{path}: unknown setting(s) {', '.join(unknown)}")
    values = {}
    for k, v in raw.items():
        if k == "$comment":
            continue
        if k in _PATHS:
            v = Path(v) if v else None
        elif k in _TUPLES:
            v = tuple(v)
        values[k] = v
    return replace(base, **values).validate()
