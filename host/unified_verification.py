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


def listed(client, status="ANY"):
    files, cursor = [], None
    while True:
        page = client.call("artifact_list", status=status, limit=200, cursor=cursor)
        files.extend(page["artifacts"])
        cursor = page["next_cursor"]
        if cursor is None:
            return files


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    profile = read_profile(args.config)
    report_path = Path(profile["state"]) / "unified-export-verification.json"
    report = {"status": "STARTING", "exports": []}
    def save(status):
        report["status"] = status
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(status, flush=True)
    client = Client(args.config, profile)
    try:
        client.rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                  "clientInfo": {"name": "unified-export-verifier", "version": "1"}})
        submitted = client.call("task_submit", goal="Verify unified export of benign Shared and Output files, then automatic Shared export on user closure.",
                                required_capabilities=["gui.observe", "gui.input", "filesystem.workspace", "process.execute"],
                                artifact_expected=True)
        deadline = time.monotonic() + 210
        while True:
            runtime = client.call("runtime_get_state")
            if runtime.get("runtime_state") == "READY":
                break
            if runtime.get("runtime_state") in ("FAILED", "TERMINATED") or time.monotonic() > deadline:
                raise RuntimeError(f"not READY: {runtime}")
            time.sleep(2)
        share = Path(runtime["sandbox"]["shared"]["host_folder"])
        identity = (share.name, submitted["runtime_id"], runtime["sandbox"]["generation"])
        report["session_id"] = share.name
        from sandbox_manager.importer import downloads_folder
        destination = downloads_folder() / "SandboxShared" / share.name
        nonce = uuid.uuid4().hex[:10]
        samples = {f"unified-shared-{nonce}.bin": b"Shared binary\x00\xff " + nonce.encode(),
                   f"unified-output-{nonce}.bin": b"Output binary\x00\xfe " + nonce.encode(),
                   f"unified-close-{nonce}.txt": b"automatic closure " + nonce.encode()}
        commands = []
        for name, data in samples.items():
            parent = ("'" + output_directory(identity) + "'" if "-output-" in name else
                      "(Join-Path ([Environment]::GetFolderPath('Desktop')) 'Shared')")
            commands.append(f"[IO.File]::WriteAllBytes((Join-Path {parent} '{name}'),[Convert]::FromBase64String('{base64.b64encode(data).decode()}'))")
        encoded = base64.b64encode((";".join(commands)).encode("utf-16le")).decode()
        command = "powershell -NoProfile -EncodedCommand " + encoded
        client.call("computer_observe")
        client.call("computer_hotkey", keys=["win", "r"])
        client.call("computer_observe")
        client.call("computer_type", text=command)
        client.call("computer_observe")
        client.call("computer_keypress", key="enter")
        deadline = time.monotonic() + 45
        while True:
            candidates = listed(client)
            own = {a["path"]: a for a in candidates if a["path"] in samples}
            if len(own) == len(samples):
                break
            if time.monotonic() > deadline:
                raise RuntimeError("Guest files did not all become export candidates")
            time.sleep(1)
        report["candidates"] = candidates
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
        while True:
            runtime = client.call("runtime_get_state")
            if runtime.get("runtime_state") == "TERMINATED":
                break
            time.sleep(2)
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
