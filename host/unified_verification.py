"""Interactive verification with real MCP, Manager, Runner, scanner and human dialogs.

Run after closing other test Sandboxes. This never answers a dialog or terminates
the VM. Failures keep the MCP connection alive until the person closes the VM.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys
import time
import uuid

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from host.solution_config import read_profile
from host.solution_session import Client
from host.router_command_bundle import output_directory


class EvidenceClient(Client):
    """Retain the actual Guest observations for diagnosing input failures."""
    def __init__(self, config, profile):
        super().__init__(config, profile)
        self.evidence_dir = Path(profile["state"]) / ("verification-" + uuid.uuid4().hex)
        self.evidence_dir.mkdir()

    def rpc(self, method, params, timeout=950):
        response = super().rpc(method, params, timeout)
        if method == "tools/call" and params.get("name") == "computer_observe":
            for item in response.get("content", []):
                if item.get("type") == "image" and item.get("mimeType") == "image/png":
                    (self.evidence_dir / f"observe-{self.seq:04d}.png").write_bytes(base64.b64decode(item["data"]))
        return response


def sample_command(identity, name, data):
    payload = base64.b64encode(data).decode()
    if not name or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-.' for c in name):
        raise ValueError('verification filename must be a simple lowercase basename')
    command = ("powershell -NoP -C \"$p=(New-Object -Com WScript.Shell).CreateShortcut("
               "$env:USERPROFILE+'\\Desktop\\Output.lnk').TargetPath;"
               f"[IO.File]::WriteAllBytes(($p+'\\{name}'),[Convert]::FromBase64String('{payload}'))\"")
    # The Run dialog can truncate long input even if SendInput reports success.
    if len(command) > 259:
        raise ValueError("verification command exceeds the Run dialog input limit")
    return command


def listed(client, status="ANY"):
    files, cursor = [], None
    while True:
        page = client.call("artifact_list", status=status, limit=200, cursor=cursor)
        files.extend(page["artifacts"])
        cursor = page["next_cursor"]
        if cursor is None:
            return files


def runtime_state(client):
    """A pending shutdown/approval is not a failed or stopped VM."""
    while True:
        try:
            return client.call("runtime_get_state")
        except RuntimeError as exc:
            if "CLEANUP_UNCONFIRMED" not in str(exc):
                raise
            time.sleep(2)


def verify_file(item, expected, root):
    if item["status"] != "EXPORTED" or not item.get("export_path"):
        raise RuntimeError(f"not EXPORTED: {item}")
    path = Path(item["export_path"])
    if not path.is_relative_to(root) or path.read_bytes() != expected:
        raise RuntimeError("published path or bytes differ")
    sha = hashlib.sha256(expected).hexdigest()
    if item["sha256"] != sha or "ZoneId=3" not in Path(str(path) + ":Zone.Identifier").read_text():
        raise RuntimeError("published SHA-256 or MOTW differs")
    return dict(path=str(path), sha256=sha, size=len(expected), artifact_id=item["artifact_id"], source=item["source"])


def wait_for_final_output(client):
    """Runner termination precedes scanner/dialog completion on the Host."""
    while True:
        runtime = runtime_state(client)
        sandbox = runtime.get("sandbox", {})
        if sandbox.get("state") == "FAILED":
            raise RuntimeError(f"Output cleanup/export failed: {sandbox.get('error')}")
        result = sandbox.get("output", {}).get("at_end")
        if runtime.get("runtime_state") == "TERMINATED" and result is not None:
            if not result.get("acquisition", {}).get("complete"):
                raise RuntimeError("final Output acquisition was not complete")
            return result
        time.sleep(2)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--await-review", action="store_true",
                        help="pause before opening dialogs so an operator can review the report first")
    args = parser.parse_args(argv)
    profile = read_profile(args.config)
    report_path = Path(profile["state"]) / "unified-export-verification.json"
    report = {"status": "STARTING", "exports": []}
    def save(status):
        report["status"] = status
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(status, flush=True)
    save("STARTING")
    client = EvidenceClient(args.config, profile)
    report["observations"] = str(client.evidence_dir)
    try:
        client.rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                  "clientInfo": {"name": "unified-export-verifier", "version": "1"}})
        submitted = client.call("task_submit", goal="Verify Output binary export and automatic Output acquisition/export on user closure.",
                                required_capabilities=["gui.observe", "gui.input", "filesystem.workspace", "process.execute"],
                                artifact_expected=True)
        deadline = time.monotonic() + 210
        while True:
            runtime = runtime_state(client)
            if runtime.get("runtime_state") == "READY":
                break
            if runtime.get("runtime_state") in ("FAILED", "TERMINATED") or time.monotonic() > deadline:
                raise RuntimeError(f"not READY: {runtime}")
            time.sleep(2)
        session_id = runtime["sandbox"]["output"]["session_id"]
        identity = (session_id, submitted["runtime_id"], runtime["sandbox"]["generation"])
        report["session_id"] = session_id
        from sandbox_manager.importer import downloads_folder
        destination = downloads_folder() / "SandboxOutput" / session_id
        nonce = uuid.uuid4().hex[:6]
        samples = {f"o-{nonce}.bin": b"O\x00\xff" + nonce.encode(),
                   f"p-{nonce}.zip": b"PK\x00" + nonce.encode(),
                   f"c-{nonce}.txt": b"close " + nonce.encode()}
        commands = [sample_command(identity, name, data) for name, data in samples.items()]
        report["destination_root"] = str(destination)
        report["samples"] = [{"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                             for name, data in samples.items()]
        save("PREPARING_GUEST_FILES")
        # Keep each Unicode-input action below the runner's action deadline.
        # A failed input raises immediately; never press Enter or replay it.
        for command in commands:
            client.call("computer_observe")
            client.call("computer_hotkey", keys=["win", "r"])
            client.call("computer_observe")
            client.call("computer_type", text=command)
            client.call("computer_observe")
            client.call("computer_keypress", key="enter")
            time.sleep(2)
        deadline = time.monotonic() + 45
        while True:
            candidates = listed(client)
            own = {a["path"]: a for a in candidates if a["path"] in samples}
            if len(own) == len(samples):
                break
            if time.monotonic() > deadline:
                report["candidates"] = candidates
                client.call("computer_observe")
                raise RuntimeError("Guest files did not all become export candidates")
            time.sleep(1)
        report["candidates"] = candidates
        if args.await_review:
            signal = Path(profile["state"]) / f"unified-review-{nonce}.json"
            report["review_signal"] = str(signal)
            report["destination_root"] = str(destination)
            report["samples"] = [{"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                                 for name, data in samples.items()]
            save("WAITING_FOR_OPERATOR_REVIEW")
            # This gate never answers either product dialog. It only allows the
            # operator to prepare before their existing 45-second UI deadlines.
            while not signal.exists():
                if runtime_state(client).get("runtime_state") != "READY":
                    raise RuntimeError("session ended while awaiting operator review")
                time.sleep(1)
            decision = json.loads(signal.read_text(encoding="utf-8-sig"))
            if decision != {"session_id": session_id, "reviewed": True}:
                raise RuntimeError("operator review signal does not match this session")
        save("WAITING_FOR_MANUAL_EXPORT_REVIEW_AND_APPROVAL")
        for name in list(samples)[:2]:
            candidate = own[name]
            print(f"Confirm list then final approval in the real Host dialogs: {name}", flush=True)
            response = client.call("artifact_export", artifact_id=candidate["artifact_id"], reason="Interactive unified export verification")
            if not response.get("accepted"):
                raise RuntimeError(f"export was not accepted: {response}")
            deadline = time.monotonic() + 180
            while True:
                result = next(a for a in listed(client) if a["artifact_id"] == candidate["artifact_id"])
                if result["status"] in ("EXPORTED", "BLOCKED"):
                    break
                if time.monotonic() > deadline:
                    raise RuntimeError("export outcome not confirmed")
                time.sleep(1)
            report["exports"].append(verify_file(result, samples[name], destination))
            save("MANUAL_EXPORT_VERIFIED")
        save("WAITING_FOR_USER_CLOSE_REVIEW_AND_KEEP")
        print("Close this Sandbox window, confirm the remaining file list, then approve final Keep.", flush=True)
        wait_for_final_output(client)
        completed = listed(client, "EXPORTED")
        name = list(samples)[2]
        matches = [a for a in completed if a["path"] == name]
        if len(matches) != 1:
            raise RuntimeError("automatic export was not recorded exactly once")
        report["exports"].append(verify_file(matches[0], samples[name], destination))
        for name in samples:
            copies = list(destination.rglob(name))
            if len(copies) != 1:
                raise RuntimeError(f"expected one final file, found {len(copies)} for {name}")
        save("EXPORTED_ALL_THREE")
        client.process.stdin.close()
        client.process.wait(timeout=30)
        return 0
    except (Exception, KeyboardInterrupt) as exc:
        report["error"] = str(exc)
        save("FAILED")
        print(f"Verification failed: {exc}. The existing Sandbox is not stopped automatically.", flush=True)
        while client.process.poll() is None:
            try:
                if client.call("runtime_get_state").get("runtime_state") in ("TERMINATED", "NOT_STARTED"):
                    client.process.stdin.close()
                    client.process.wait(timeout=30)
                    break
            except Exception:
                pass
            time.sleep(2)
        return 1
    finally:
        client.log.close()


if __name__ == "__main__":
    raise SystemExit(main())
