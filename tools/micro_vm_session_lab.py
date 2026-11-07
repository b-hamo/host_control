"""Real B/C MCP harness. No mock Runner/scanner and no automatic input retries.

The reviewable launch configuration pins source directories and executable
hashes in versions.json. Requests are consumed once from this test's private
queue; image evidence is decoded directly from the existing MCP result.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
import uuid

HOST = Path(__file__).resolve().parents[1]
MANAGER = Path(os.environ["SCRP_LAB_MANAGER"])
RUNNER = Path(os.environ["SCRP_LAB_RUNNER"])
PACKAGE = Path(os.environ["SCRP_LAB_PACKAGE"])
VM_ROOT = Path(os.environ["SCRP_LAB_VM_ROOT"])
RELAY = Path(os.environ["SCRP_LAB_RELAY"])
EXPORT = Path(os.environ["SCRP_LAB_EXPORT"])
ROOT = Path(os.environ.get("SCRP_APP_LAB_ROOT", r"C:\SCRPAppLab\run-20261107"))
ALLOWED = {"task_submit", "runtime_get_state", "computer_observe", "computer_click", "computer_type",
           "computer_keypress", "computer_hotkey", "artifact_list", "artifact_export", "inbox_import",
           "sandbox_run", "sandbox_run_status", "router_capture", "router_execute", "router_result", "session_stop"}


def save(path, data):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


class Slot:
    def __init__(self, slot):
        self.root = ROOT / slot
        self.root.mkdir(parents=True, exist_ok=True)
        self.pending = queue.Queue()
        self.counter = 0
        self.session = "SES-" + uuid.uuid4().hex
        work = self.root / "work"
        # Use the official inbox ACL initializer, including its system-binary
        # deny-execute probe. No application/test payload is run on the Host.
        subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                        str(MANAGER / "tools/setup_inbox.ps1"), "-Work", str(work)], check=True)
        (work / "output").mkdir(exist_ok=True)
        command = [sys.executable, "-m", "host.mcp_server", "--host", "127.0.0.1", "--port", "0",
                   "--upload-port", "0", "--session", self.session, "--startup-timeout", "240",
                   "--runner-exe", str(RUNNER), "--sandbox-root", str(self.root / "manager"),
                   "--micro-vm-package", str(PACKAGE), "--micro-vm-root", str(VM_ROOT), "--micro-vm-relay", str(RELAY),
                   "--cert-dir", str(self.root / "certs"), "--audit-dir", str(self.root / "audit"),
                   "--artifact-dir", str(self.root / "artifacts"), "--export-dir", str(EXPORT),
                   "--output-root", str(work / "output"),
                   "--log-file", str(self.root / "host.log"), "--inbox", str(work / "inbox"),
                   "--artifact-export", "--artifact-scanner", "defender-service", "--artifact-max-bytes", "8388608",
                   "--sandbox-run", "--router-capture", "--approval", "dialog", "--no-auto-restart"]
        environment = os.environ | {"PYTHONPATH": str(HOST) + os.pathsep + str(MANAGER),
                                    "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"}
        self.stderr = (self.root / "stderr.log").open("w", encoding="utf-8")
        self.process = subprocess.Popen(command, cwd=HOST, env=environment, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=self.stderr, text=True, encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW)
        save(self.root / "launch.json", {"command": command, "pid": self.process.pid, "session_id": self.session})
        threading.Thread(target=self.read, daemon=True).start()
        self.rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                               "clientInfo": {"name": "micro-vm-real-integration", "version": "1"}})

    def read(self):
        for line in self.process.stdout:
            try: self.pending.put(json.loads(line))
            except ValueError: self.pending.put({"error": "non-JSON stdout"})
        self.pending.put({"error": "MCP Host exited"})

    def rpc(self, method, parameters):
        self.counter += 1
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.counter,
            "method": method, "params": parameters}) + "\n")
        self.process.stdin.flush()
        response = self.pending.get(timeout=300)
        if response.get("id") != self.counter:
            raise RuntimeError(f"MCP reply mismatch; never replay: {response}")
        return response


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(MANAGER))
    import sandbox_manager
    versions = {"manager_path": sandbox_manager.__file__, "python": sys.executable,
        "host_commit": subprocess.check_output(["git", "-C", str(HOST), "rev-parse", "HEAD"], text=True).strip(),
        "runner": str(RUNNER), "runner_sha256": hashlib.sha256(RUNNER.read_bytes()).hexdigest(),
        "relay": str(RELAY), "relay_sha256": hashlib.sha256(RELAY.read_bytes()).hexdigest(),
        "micro_vm_package": str(PACKAGE), "micro_vm_sha256": hashlib.sha256((PACKAGE / "dbictl.exe").read_bytes()).hexdigest(),
        "working_tree_changes": True}
    save(ROOT / "versions.json", versions)
    slots = {name: Slot(name) for name in ("B", "C")}
    save(ROOT / "ready.json", {"pid": os.getpid(), "status": "MCP_CLIENTS_READY_NOT_VM_READY"})
    requests = ROOT / "requests"
    requests.mkdir(exist_ok=True)
    while True:
        for path in sorted(requests.glob("*.json")):
            claimed = path.with_suffix(".claimed")
            path.replace(claimed)
            response = {"error": "request not executed"}
            try:
                request = json.loads(claimed.read_text(encoding="utf-8-sig"))
                if request["slot"] not in slots or request["tool"] not in ALLOWED:
                    raise ValueError("unapproved slot or tool")
                response = slots[request["slot"]].rpc("tools/call", {"name": request["tool"], "arguments": request.get("arguments", {})})
                for index, item in enumerate(response.get("result", {}).get("content", [])):
                    if item.get("type") == "image":
                        image = ROOT / (path.stem + f"-{index}.png")
                        image.write_bytes(base64.b64decode(item.pop("data")))
                        item["evidence_path"] = str(image)
            except Exception as error:
                response = {"error": repr(error), "input_not_retried": True}
            save(ROOT / (path.stem + ".result.json"), response)
        time.sleep(.2)


if __name__ == "__main__": main()
