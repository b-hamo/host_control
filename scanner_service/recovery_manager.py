"""What a start does about the previous run: discard, never resume.

A crash, a forced stop, a reboot or a Defender failure can leave job directories in
the quarantine and `.job-*.partial` files in the export root. Nothing of that is
trusted after a restart: no job is resumed, marked scanned or published. Each leftover
is logged (from its job.json, best effort) and deleted; a directory that cannot be
deleted yet stays in the ACL-protected quarantine and is retried by every sweep.

The run marker (work\\service-run.json) says whether the previous run stopped cleanly.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from scanner_service import winfile
from scanner_service.quarantine_manager import QuarantineManager

log = logging.getLogger("scanner.recovery")

MARKER = "service-run.json"
PARTIAL_RE = re.compile(r"\.job-[0-9a-f]{32}\.partial")


@dataclass
class RecoveryReport:
    previous_run_unclean: bool = False
    previous_run: dict | None = None
    discarded_jobs: list[dict] = field(default_factory=list)
    cleanup_failed: dict[str, str] = field(default_factory=dict)
    partial_exports_removed: int = 0

    def view(self) -> dict:
        return {"previous_run_unclean": self.previous_run_unclean, "discarded_jobs": len(self.discarded_jobs),
                "cleanup_failed": len(self.cleanup_failed), "partial_exports_removed": self.partial_exports_removed}


class RecoveryManager:
    def __init__(self, quarantine: QuarantineManager, work_dir: Path, export_root: Path | None = None):
        self.quarantine = quarantine
        self.work_dir = Path(work_dir)
        self.export_root = Path(export_root) if export_root else None
        self.last: RecoveryReport | None = None

    @property
    def marker(self) -> Path:
        return self.work_dir / MARKER

    def recover_on_start(self) -> RecoveryReport:
        r = RecoveryReport()
        prev = self._read_marker()
        if prev is not None:
            r.previous_run = prev
            r.previous_run_unclean = bool(prev.get("running"))
            if r.previous_run_unclean:
                log.warning("RECOVERY previous run (pid %s, started %s) did not stop cleanly",
                            prev.get("pid"), prev.get("started_utc"))
        for job_dir in self.quarantine.list_job_dirs():
            meta = self.quarantine.read_meta(job_dir) or {}
            info = {"job_id": job_dir.name, "session_dir": job_dir.parent.name,
                    "artifact_id": meta.get("artifact_id"), "last_state": meta.get("state")}
            r.discarded_jobs.append(info)
            log.warning("RECOVERY discarding unfinished job %s (%s, artifact %s, last state %s): "
                        "not resumed, not published", info["job_id"], info["session_dir"], info["artifact_id"],
                        info["last_state"])
        report = self.quarantine.cleanup_expired_jobs(set())
        r.cleanup_failed = dict(report.failed)
        r.partial_exports_removed = self._remove_partial_exports()
        self._write_marker(running=True)
        self.last = r
        log.info("RECOVERY done: %s", json.dumps(r.view()))
        return r

    def mark_stopped(self) -> None:
        self._write_marker(running=False)

    def _remove_partial_exports(self) -> int:
        """Hidden `.job-<id>.partial` copies a crash left in <export_root>\\<session>\\<artifact>\\."""
        root = self.export_root
        if root is None or winfile.attributes(root) is None or winfile.is_reparse(root):
            return 0
        n = 0
        try:
            for s in root.iterdir():
                if winfile.is_reparse(s) or not s.is_dir():
                    continue
                for a in s.iterdir():
                    if winfile.is_reparse(a) or not a.is_dir():
                        continue
                    for f in a.iterdir():
                        if PARTIAL_RE.fullmatch(f.name) and not winfile.is_reparse(f):
                            try:
                                winfile.delete_file(f)
                                n += 1
                            except OSError as e:
                                log.warning("RECOVERY partial export %s not removed: %s", f.name, e)
        except OSError as e:
            log.warning("RECOVERY export root not fully checked: %s", e)
        return n

    def _read_marker(self) -> dict | None:
        try:
            if self.marker.stat().st_size > 4096:
                return None
            data = json.loads(self.marker.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None
        except (OSError, ValueError):
            return None

    def _write_marker(self, *, running: bool) -> None:
        data = {"running": running, "pid": os.getpid(),
                "started_utc" if running else "stopped_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        try:
            self.work_dir.mkdir(parents=True, exist_ok=True)
            tmp = self.marker.with_suffix(".tmp")
            tmp.write_text(json.dumps(data), encoding="utf-8")
            os.replace(tmp, self.marker)
        except OSError as e:
            log.warning("run marker not written: %s", e)
