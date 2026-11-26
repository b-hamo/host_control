"""A stand-in for one child Host of batch_run (tests/test_batch_run.py). Standard library only.

    python batch_child.py <state dir> [slow]

It answers the MCP calls host/batch_run.py makes and writes each one to <state dir>/calls-<pid>.jsonl.
The first child to take <state dir>/wsb says it runs in Windows Sandbox, the others in a micro_VM.
A program whose name has "gui" stays RUNNING; the others end with exit code 0. With "slow", the first
two task_submit calls say the Host is still starting.
"""
import json
import os
import sys
import time
from pathlib import Path

state = Path(sys.argv[1])
slow = "slow" in sys.argv[2:]
log = (state / f"calls-{os.getpid()}.jsonl").open("a", encoding="utf-8")
seen = {"submit": 0, "state": 0, "status": 0, "entry": None, "ended": False, "kind": None}


def note(tool, arguments):
    log.write(json.dumps({"t": time.time(), "tool": tool, "arguments": arguments,
                          "child": os.environ.get("SCRP_BATCH_CHILD")}) + "\n")
    log.flush()


def ok(**body):
    return {"content": [{"type": "text", "text": json.dumps({"ok": True, **body})}], "isError": False}


def error(code, message, retryable):
    body = {"ok": False, "error": code, "message": message, "retryable": retryable}
    return {"content": [{"type": "text", "text": json.dumps(body)}], "isError": True}


def call(tool, a):
    note(tool, a)
    if tool == "task_submit":
        seen["submit"] += 1
        if slow and seen["submit"] <= 2:
            return error("RUNTIME_UNAVAILABLE", "Host is still starting", True)
        try:
            (state / "wsb").open("x").close()
            seen["kind"] = "WINDOWS_SANDBOX"
        except FileExistsError:
            seen["kind"] = "MICRO_VM_APP_WINDOW"
        return ok(task_id="TASK-000001", runtime_state="PREPARING", sandbox={"state": "LAUNCHING"})
    if tool == "inbox_import":
        return ok(file={"name": a["name"], "sha256": "0" * 64, "size": 1})
    if tool == "runtime_get_state":
        if seen["ended"] or (state / "closed").exists():
            return ok(runtime_state="TERMINATED", host_released=True, end_reason="USER_STOP")
        seen["state"] += 1
        ready = seen["state"] > 2 and not (state / "never-ready").exists()
        return ok(runtime_state="READY" if ready else "PREPARING",
                  sandbox={"state": "READY" if ready else "LAUNCHING", "runtime_type": seen["kind"],
                           "output": {"session_id": f"SES-{os.getpid()}"}})
    if tool == "sandbox_run":
        if seen["entry"] is not None:
            return error("INTERNAL", "sandbox_run was sent twice", False)
        seen["entry"] = a["entry"]
        return ok(run_id="RUN-0001", file=a["file"], state="ACCEPTED", reason="LAUNCHING")
    if tool == "sandbox_run_status":
        seen["status"] += 1
        if seen["status"] < 2 or "gui" in seen["entry"]:
            return ok(run_id="RUN-0001", state="RUNNING", reason="INPUT_DELIVERED_AWAITING_PROCESS_RESULT")
        return ok(run_id="RUN-0001", state="SUCCEEDED", reason="EXITED", exit_code=0,
                  stdout=f"hello from {seen['entry']}")
    if tool == "computer_observe":
        return ok(screen=f"screen of {seen['entry']}", wait_ms=a.get("wait_ms"))
    if tool == "session_stop":
        seen["ended"] = True
        return ok(stopped=True, reason=a["reason"])
    return error("INVALID_ARGUMENT", f"unknown tool {tool}", False)


for line in sys.stdin.buffer:
    msg = json.loads(line)
    if msg["method"] == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name": "child"}}
    else:
        result = call(msg["params"]["name"], msg["params"].get("arguments") or {})
    sys.stdout.buffer.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}).encode() + b"\n")
    sys.stdout.buffer.flush()
note("stdin-closed", {})
