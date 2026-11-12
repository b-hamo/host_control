"""What this Host is doing, written down for the local dashboard (`--dashboard-dir`, dashboard/).

The dashboard is its own read-only process: a Host lives only as long as one Agent conversation and
several can run at once, so each Host leaves a small file the dashboard reads. Per session:

  <dir>/hosts/<session_id>.json   pid, sandbox root, task (the task_submit goal), last tool and file,
                                  window_state of the Sandbox window, when the screen was last captured
  <dir>/hosts/<session_id>.png    the last screen the Agent observed; removed when the Host ends

Only tool names and file names are written. Typed text, URLs' queries and other arguments are not.
Files are replaced atomically, so a reader never sees half a file.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

TASK_MAX = 200
REFRESH_S = 2.0


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def default_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(base) / "SecureCUA" / "dashboard"


def _file_of(tool: str, args: dict) -> str | None:
    """The file a call works on, by name only."""
    if tool == "sandbox_run" and isinstance(args.get("file"), str):
        return Path(args["file"]).name
    if tool == "inbox_import" and isinstance(args.get("name"), str):
        return Path(args["name"]).name
    if tool == "inbox_download" and isinstance(args.get("url"), str):
        from urllib.parse import urlsplit
        try:
            return Path(urlsplit(args["url"]).path).name or None
        except ValueError:
            return None
    return None


class DashboardStatus:
    def __init__(self, directory: Path, session_id: str, *, sandbox_root: Path | None = None, vm_max: int | None = None,
                 window_state: Callable[[], str | None] | None = None, refresh_s: float = REFRESH_S):
        self.dir = Path(directory) / "hosts"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / f"{session_id}.json"
        self.image = self.dir / f"{session_id}.png"
        self._window_state = window_state
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.data = {"session_id": session_id, "pid": os.getpid(), "started_at": _now(), "ended_at": None,
                     "sandbox_root": str(sandbox_root) if sandbox_root else None, "vm_max": vm_max, "task": None,
                     "last_tool": None, "last_file": None, "last_ok": None, "last_activity_at": None,
                     "window_state": None, "screen_captured_at": None}
        self._write()
        if window_state is not None:
            threading.Thread(target=self._refresh, args=(refresh_s,), name="dashboard-status", daemon=True).start()

    def record(self, tool: str, arguments: dict, ok: bool, image: bytes | None = None) -> None:
        args = arguments if isinstance(arguments, dict) else {}
        with self._lock:
            d = self.data
            if tool == "task_submit" and isinstance(args.get("goal"), str):
                d["task"] = " ".join(args["goal"].split())[:TASK_MAX]
            d.update(last_tool=tool, last_ok=bool(ok), last_activity_at=_now())
            d["last_file"] = _file_of(tool, args) or d["last_file"]
            if image:
                self._replace(self.image, image)
                d["screen_captured_at"] = _now()
            self._write()

    def close(self) -> None:
        self._stop.set()
        with self._lock:
            self.data["ended_at"] = _now()
            self.data["screen_captured_at"] = None
            try:
                self.image.unlink(missing_ok=True)       # a screen of the user's work does not outlive the Host
            except OSError:
                pass
            self._write()

    def _refresh(self, every: float) -> None:
        while not self._stop.wait(every):
            try:
                state = self._window_state()
            except Exception:  # noqa: BLE001 - the dashboard never takes the Host down
                state = None
            with self._lock:
                if state != self.data["window_state"] and not self._stop.is_set():
                    self.data["window_state"] = state
                    self._write()

    def _write(self) -> None:
        self._replace(self.path, json.dumps(self.data, ensure_ascii=False).encode("utf-8"))

    @staticmethod
    def _replace(path: Path, data: bytes) -> None:
        tmp = path.with_name(path.name + ".tmp")
        try:
            tmp.write_bytes(data)
            os.replace(tmp, path)
        except OSError:
            pass
