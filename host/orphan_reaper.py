"""A batch runtime's last resort: stop the runtime of a Host that was ended before it could.

Found 2026-11-26: when the Agent's app closes, its MCP servers and everything they started end in
one stroke. A batch_run's child Hosts vanished within 0.1 s, before they could stop anything, and
their Windows Sandbox and micro_VMs kept running with no Host watching them.

So a batch child Host (host/batch_run.py) starts this watcher outside its own process tree
(Win32_Process.Create: the new process belongs to WMI's host process, not to the Agent's app). The
watcher waits for that one Host to end and then runs the Sandbox Manager's reclaim_orphans() on
that Host's own Manager folder: only sessions recorded there, and only when their owner is surely
gone. After a normal end the session is already TERMINATED and there is nothing to do.

It stops and cleans up; it does not export Output files or ask the person anything (the Host that
would have done that is gone). It never touches another Host's sessions.

    pythonw host/orphan_reaper.py <Manager folder>/reaper.json
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

log = logging.getLogger("host-reaper")

PLAN = "reaper.json"
POLL_S = 1.0
SETTLE_S = 2.0                  # after the Host is gone: let a stop it had already begun finish


def plan_for(args, pid: int, started) -> dict:
    """What the watcher needs: which Host to wait for and how that Host built its Sandbox Manager."""
    micro = None
    if getattr(args, "micro_vm_package", None):
        micro = {"package": str(args.micro_vm_package), "vm_root": str(args.micro_vm_root),
                 "relay": str(args.micro_vm_relay), "max_active": getattr(args, "micro_vm_max_active", 8),
                 "automatic": bool(getattr(args, "auto_vm_app_window", False))}
    return {"pid": pid, "started": started, "root": str(args.sandbox_root), "micro_vm": micro,
            "sys_path": [p for p in sys.path if p], "log": str(Path(args.sandbox_root) / "reaper.log")}


def start(args, *, launch=None) -> bool:
    """Called by a batch child Host before it starts its runtime. Never raises: the Host works without it."""
    try:
        from sandbox_manager.process import process_started
        root = Path(args.sandbox_root)
        root.mkdir(parents=True, exist_ok=True)
        pid = os.getpid()
        plan = root / PLAN
        plan.write_text(json.dumps(plan_for(args, pid, process_started(pid))), encoding="utf-8")
        python = Path(sys.executable).with_name("pythonw.exe")
        if not python.is_file():
            python = Path(sys.executable)
        command = subprocess.list2cmdline([str(python), str(Path(__file__).resolve()), str(plan)])
        (launch or _launch_outside)(command)
        log.info("orphan watcher started for this Host (pid %s)", pid)
        return True
    except Exception as e:  # noqa: BLE001 - last resort only
        log.warning("orphan watcher not started (%s: %s)", type(e).__name__, e)
        return False


def _launch_outside(command: str) -> None:
    """Win32_Process.Create: the watcher is not a child of this Host, so it outlives the Agent's app."""
    script = ("$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
              "-Arguments @{CommandLine = $env:SCRP_REAPER_COMMAND}; exit [int]$r.ReturnValue")
    done = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                          env=os.environ | {"SCRP_REAPER_COMMAND": command}, stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    if done.returncode != 0:
        raise OSError(f"Win32_Process.Create returned {done.returncode}")


def build_manager(plan: dict, on_event):
    """The same Manager class and folders the Host used (host/mcp_server.py _real_sandbox_manager)."""
    micro = plan.get("micro_vm")
    if not micro:
        from sandbox_manager import SandboxManager
        return SandboxManager(Path(plan["root"]), log=on_event)
    if micro.get("automatic"):
        from sandbox_manager.automatic import AutomaticVmManager
        return AutomaticVmManager(Path(plan["root"]), package=Path(micro["package"]), vm_root=Path(micro["vm_root"]),
                                  relay=Path(micro["relay"]), max_active=micro.get("max_active", 8),
                                  allow_app_window=True, log=on_event)
    from sandbox_manager.micro_vm import MicroVmManager
    return MicroVmManager(Path(plan["root"]), package=Path(micro["package"]), vm_root=Path(micro["vm_root"]),
                          relay=Path(micro["relay"]), max_active=micro.get("max_active", 8), log=on_event)


def watch(plan: dict, *, alive=None, manager=None, sleep=time.sleep, on_event=lambda m: None) -> list[str]:
    """Wait until the Host is gone, then reclaim what it left. Returns the reclaimed session ids."""
    if alive is None:
        from sandbox_manager.process import process_started

        def alive() -> bool:
            try:
                now = process_started(plan["pid"])
            except OSError:
                return True                              # cannot tell: never act on a Host that may be alive
            return now is not None and (plan.get("started") is None or now == plan["started"])
    while alive():
        sleep(POLL_S)
    sleep(SETTLE_S)
    on_event(f"Host pid {plan['pid']} is gone; checking its sessions")
    reclaimed = (manager or build_manager(plan, on_event)).reclaim_orphans()
    on_event(f"reclaimed {reclaimed}" if reclaimed else "nothing left to stop")
    return reclaimed


def main(argv: list[str] | None = None) -> int:
    path = Path((argv if argv is not None else sys.argv[1:])[0])
    plan = json.loads(path.read_text(encoding="utf-8"))
    for entry in reversed(plan.get("sys_path", [])):
        if entry not in sys.path:
            sys.path.insert(0, entry)                    # the Host's own modules (its Sandbox Manager source)
    logging.basicConfig(filename=plan["log"], level=logging.INFO, format="%(asctime)s %(message)s", encoding="utf-8")
    log.info("watching Host pid %s (%s)", plan["pid"], plan["root"])
    try:
        watch(plan, on_event=log.info)
    except Exception:  # noqa: BLE001 - recorded: the next start of that folder refuses a live leftover
        log.exception("could not reclaim")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
