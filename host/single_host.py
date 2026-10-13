"""One GUI MCP Host at a time on this PC, started when it is needed (--agent-guard, 2026-10-13).

The Codex app starts one MCP server (this Host) per conversation and keeps every one of them running
while the app is open, even after its window is closed. Each Host opened ports 17443/17444 at
"initialize", so the first conversation held them and every later one failed with WinError 10048
(seen on the JH PC on 2026-10-12 with three Hosts running).

With --agent-guard:
- "initialize" does not start the Host backend; the first tools/call does (lazy start), so a
  conversation that is only open holds no port;
- right before that start, an older Host OF OURS still listening on our ports is ended (the newest
  conversation that starts working wins). A process is ours only if its command line runs
  host/mcp_server.py (or the Lifecycle demo wrapper tools/host_with_inputs.py); anything else on the
  port is left alone and the start fails as before. Its Sandbox, if any, is reclaimed by the Sandbox
  Manager on the next start (its owner is gone).

The Router's task Host has its own retirement (#45/#46); this is only for the GUI MCP Host.
"""

from __future__ import annotations

import logging
import os
import subprocess
import time
from typing import Callable

log = logging.getLogger("host-single")

OUR_HOST_MARKERS = ("host\\mcp_server.py", "host/mcp_server.py", "host_with_inputs.py")


def listening_pids(port: int) -> set[int]:
    out = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True, text=True, errors="replace").stdout
    pids = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[1].endswith(f":{port}") and parts[3].upper() == "LISTENING":
            pids.add(int(parts[4]))
    return pids


def process_info(pid: int) -> tuple[str, int]:
    """(command line, parent pid); ("", 0) if unknown."""
    ps = (f"$p = Get-CimInstance Win32_Process -Filter 'ProcessId={int(pid)}'; "
          "if ($p) { \"$($p.ParentProcessId)`t$($p.CommandLine)\" }")
    out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True,
                         errors="replace").stdout.strip()
    if "\t" not in out:
        return "", 0
    parent, cmd = out.split("\t", 1)
    return cmd, int(parent or 0)


def reclaim_sandboxes(root=None) -> list[str]:
    """Stop the Sandbox an ended Host left behind (Sandbox Manager: only ones whose owner is gone)."""
    try:
        from sandbox_manager import SandboxManager
        done = SandboxManager(root).reclaim_orphans()
        if done:
            log.info("reclaimed the Sandbox of the ended Host: %s", done)
        return done
    except Exception as e:  # noqa: BLE001 - the start reports what is still wrong
        log.warning("could not reclaim the ended Host's Sandbox: %s", e)
        return []


def _ours(cmd: str) -> bool:
    return any(m in cmd for m in OUR_HOST_MARKERS)


def take_over(ports: tuple[int, ...], *, me: int | None = None, wait_s: float = 8.0,
              listening: Callable[[int], set[int]] = listening_pids,
              info: Callable[[int], tuple[str, int]] = process_info,
              kill: Callable[[int], None] | None = None) -> list[int]:
    """End OUR older Hosts holding these ports (and their venv launcher). Returns the pids ended."""
    me = me or os.getpid()
    mine = {me, info(me)[1]}                               # this Host and its own launcher
    kill = kill or (lambda pid: os.kill(pid, 9))
    ended: list[int] = []
    for port in [p for p in ports if p]:                   # port 0 (tests): nothing fixed to take over
        for pid in listening(port):
            if pid in mine or pid in ended:
                continue
            cmd, parent = info(pid)
            if not _ours(cmd):
                continue                                   # someone else's program: never touched
            victims = [pid]
            if parent and parent not in mine and _ours(info(parent)[0]):
                victims.append(parent)                     # that Host's venv launcher
            for v in victims:
                try:
                    kill(v)
                    ended.append(v)
                except OSError:
                    pass
    end = time.monotonic() + wait_s
    while ended and time.monotonic() < end and any(listening(p) for p in ports if p):
        time.sleep(0.2)
    if ended:
        log.warning("took over ports %s from an older conversation's Host (pids %s)", list(ports), ended)
    return ended
