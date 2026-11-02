"""Persistent, ordinary-user MCP diagnostic client for one owned Output session.

Reads JSON {tool, arguments} from stdin and records responses/screenshots.
Commands execute through the Host's regular MCP tools and approval dialogs.
EOF leaves the owned Host alive; closing it is an explicit separate operation.
"""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from host.solution_config import read_profile
from host.solution_session import Client


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=True)
    client = Client(args.config, read_profile(args.config))
    client.rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                              "clientInfo": {"name": "output-verification", "version": "1"}})
    print(json.dumps({"client_ready": True, "host_pid": client.process.pid}), flush=True)
    serial = 0
    while True:
        line = sys.stdin.readline()
        if not line:
            # Keep a diagnosable live session if the caller loses its pipe.
            if client.process.poll() is not None:
                return
            time.sleep(1)
            continue
        serial += 1
        try:
            command = json.loads(line)
            result = client.rpc("tools/call", {"name": command["tool"],
                                "arguments": command.get("arguments", {})}, timeout=950)
            for index, block in enumerate(result.get("content", [])):
                if block.get("type") == "image":
                    path = args.evidence / f"{serial:04d}-{index}.png"
                    path.write_bytes(base64.b64decode(block.pop("data"), validate=True))
                    block["path"] = str(path)
            (args.evidence / f"{serial:04d}.json").write_text(
                json.dumps({"request": command, "response": result}, ensure_ascii=False, indent=2), encoding="utf-8")
            print(json.dumps({"sequence": serial, "response": result}, ensure_ascii=False), flush=True)
        except Exception as exc:
            print(json.dumps({"sequence": serial, "error": str(exc)}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
