"""Real WSB A / micro_VM B/C MCP harness, with no automatic input retries.

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
import re
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

HOST = Path(__file__).resolve().parents[1]
MANAGER = Path(os.environ["SCRP_LAB_MANAGER"])
RUNNER = Path(os.environ["SCRP_LAB_RUNNER"])
PACKAGE = Path(os.environ["SCRP_LAB_PACKAGE"])
VM_ROOT = Path(os.environ["SCRP_LAB_VM_ROOT"])
RELAY = Path(os.environ["SCRP_LAB_RELAY"])
EXPORT = Path(os.environ["SCRP_LAB_EXPORT"])
ROOT = Path(os.environ.get("SCRP_APP_LAB_ROOT", r"C:\SCRPAppLab\run-20261107"))
SLOTS = tuple(os.environ.get("SCRP_LAB_SLOTS", "B,C").split(","))
if not SLOTS or len(set(SLOTS)) != len(SLOTS) or any(s not in ("A", "B", "C") for s in SLOTS):
    raise ValueError("SCRP_LAB_SLOTS must contain unique A/B/C slots")
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
        self.rpc_lock = threading.Lock()
        self.session = "SES-" + uuid.uuid4().hex
        work = self.root / "work"
        # Use the official inbox ACL initializer, including its system-binary
        # deny-execute probe. No application/test payload is run on the Host.
        subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                        str(MANAGER / "tools/setup_inbox.ps1"), "-Work", str(work)], check=True)
        (work / "output").mkdir(exist_ok=True)
        command = [sys.executable, "-m", "host.mcp_server", "--host", "0.0.0.0" if slot == "A" else "127.0.0.1",
                   "--port", "17443" if slot == "A" else "0", "--upload-port", "17444" if slot == "A" else "0",
                   "--session", self.session, "--startup-timeout", os.environ.get("SCRP_LAB_STARTUP_TIMEOUT", "240"),
                   "--runner-exe", str(RUNNER), "--sandbox-root", str(self.root / "manager"),
                   "--cert-dir", str(self.root / "certs"), "--audit-dir", str(self.root / "audit"),
                   "--artifact-dir", str(self.root / "artifacts"), "--export-dir", str(EXPORT),
                   "--output-root", str(work / "output"),
                   "--log-file", str(self.root / "host.log"), "--inbox", str(work / "inbox"),
                   "--artifact-export", "--artifact-scanner", "defender-service", "--artifact-max-bytes", "8388608",
                   "--sandbox-run", "--router-capture", "--approval", "dialog"]
        if os.environ.get("SCRP_LAB_AUTO_RESTART") != "1":
            command += ["--no-auto-restart"]
        if slot != "A" or os.environ.get("SCRP_LAB_AUTO") == "1":
            command += ["--micro-vm-package", str(PACKAGE), "--micro-vm-root", str(VM_ROOT),
                        "--micro-vm-relay", str(RELAY), "--micro-vm-max-active", os.environ.get("SCRP_LAB_MAX_ACTIVE", "8")]
            if os.environ.get("SCRP_LAB_AUTO") == "1":
                command += ["--auto-vm-app-window"]
        installed = os.environ.get("SCRP_LAB_INSTALLED_MANAGER") == "1"
        environment = os.environ | {"PYTHONPATH": str(HOST) if installed else str(HOST) + os.pathsep + str(MANAGER),
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
        with self.rpc_lock:
            return self._rpc(method, parameters)

    def _rpc(self, method, parameters):
        self.counter += 1
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.counter,
            "method": method, "params": parameters}) + "\n")
        self.process.stdin.flush()
        response = self.pending.get(timeout=300)
        if response.get("id") != self.counter:
            raise RuntimeError(f"MCP reply mismatch; never replay: {response}")
        return response


def main():
    if (ROOT / "ready.json").exists():
        raise RuntimeError("Use a new evidence root; never replace existing session clients")
    ROOT.mkdir(parents=True, exist_ok=True)
    if os.environ.get("SCRP_LAB_INSTALLED_MANAGER") != "1":
        sys.path.insert(0, str(MANAGER))
    import sandbox_manager
    import tomllib
    def source_version(repo):
        tracked = subprocess.check_output(["git", "-C", str(repo), "ls-files", "-z", "--cached", "--others", "--exclude-standard"])
        hashes = {}
        for name in tracked.decode("utf-8").split("\0"):
            path = repo / name
            if name and path.is_file() and (path.suffix in {".py", ".cpp", ".h", ".hpp", ".ps1", ".toml", ".json"}
                                            or path.name in {"CMakeLists.txt", "requirements.txt", "requirements-base.txt"}):
                hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        return {"commit": subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip(),
                "source_sha256": hashes}
    loaded_manager = Path(sandbox_manager.__file__).resolve().parent
    versions = {"manager_path": sandbox_manager.__file__, "python": sys.executable,
        "manager_loaded_file_sha256": {str(path.relative_to(loaded_manager)): hashlib.sha256(path.read_bytes()).hexdigest()
                                       for path in sorted(loaded_manager.rglob("*.py"))},
        "manager_version": tomllib.loads((MANAGER / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"],
        "manager_source": source_version(MANAGER), "host_source": source_version(HOST),
        "host_commit": subprocess.check_output(["git", "-C", str(HOST), "rev-parse", "HEAD"], text=True).strip(),
        "runner": str(RUNNER), "runner_sha256": hashlib.sha256(RUNNER.read_bytes()).hexdigest(),
        "relay": str(RELAY), "relay_sha256": hashlib.sha256(RELAY.read_bytes()).hexdigest(),
        "micro_vm_package": str(PACKAGE), "micro_vm_sha256": hashlib.sha256((PACKAGE / "dbictl.exe").read_bytes()).hexdigest(),
        "working_tree_changes": True}
    # Record the actual launcher token, not an inference from how it was started.
    groups = subprocess.check_output([str(Path(os.environ["SystemRoot"]) / "System32/whoami.exe"),
                                      "/groups", "/fo", "csv", "/nh"])
    versions["host_integrity_sids"] = [s.decode("ascii") for s in re.findall(rb"S-1-16-[0-9]+", groups)]
    service = PACKAGE / "MinoVmService.exe"
    if service.is_file() and (PACKAGE / "management.json").is_file():
        versions["management_service_sha256"] = hashlib.sha256(service.read_bytes()).hexdigest()
        versions["management_configuration"] = json.loads((PACKAGE / "management.json").read_text(encoding="utf-8-sig"))
    save(ROOT / "versions.json", versions)
    slots = {name: Slot(name) for name in SLOTS}
    save(ROOT / "ready.json", {"pid": os.getpid(), "status": "MCP_CLIENTS_READY_NOT_VM_READY"})
    requests = ROOT / "requests"
    requests.mkdir(exist_ok=True)
    executor = ThreadPoolExecutor(max_workers=len(slots), thread_name_prefix="scrp-slot")

    def execute(path, request, barrier=None):
        started = None
        try:
            if request["slot"] not in slots or request["tool"] not in ALLOWED:
                raise ValueError("unapproved slot or tool")
            if barrier is not None:
                barrier.wait(timeout=10)
            started = time.time_ns()
            response = slots[request["slot"]].rpc("tools/call", {"name": request["tool"], "arguments": request.get("arguments", {})})
            for index, item in enumerate(response.get("result", {}).get("content", [])):
                if item.get("type") == "image":
                    image = ROOT / (path.stem + f"-{index}.png")
                    image.write_bytes(base64.b64decode(item.pop("data")))
                    item["evidence_path"] = str(image)
        except Exception as error:
            response = {"error": repr(error), "input_not_retried": True}
        response["lab_timing"] = {"started_ns": started, "finished_ns": time.time_ns()}
        save(ROOT / (path.stem + ".result.json"), response)

    while True:
        for path in sorted(requests.glob("*.json")):
            claimed = path.with_suffix(".claimed")
            path.replace(claimed)
            try:
                request = json.loads(claimed.read_text(encoding="utf-8-sig"))
                if "batch" in request:
                    batch = request["batch"]
                    names = [item["slot"] for item in batch]
                    if not batch or len(set(names)) != len(batch) or any(name not in slots for name in names):
                        raise ValueError("a concurrent batch requires distinct configured slots")
                    if any(item["tool"] not in ALLOWED for item in batch):
                        raise ValueError("unapproved batch tool")
                    barrier = threading.Barrier(len(batch))
                    futures = [executor.submit(execute, ROOT / (path.stem + "-" + item["slot"] + ".json"), item, barrier)
                               for item in batch]
                    # Each batch is consumed once and finishes before another is admitted.
                    for future in futures:
                        future.result()
                    save(ROOT / (path.stem + ".result.json"), {"batch_complete": True, "slots": names})
                else:
                    execute(path, request)
            except Exception as error:
                save(ROOT / (path.stem + ".result.json"), {"error": repr(error), "input_not_retried": True})
        time.sleep(.2)


if __name__ == "__main__": main()
