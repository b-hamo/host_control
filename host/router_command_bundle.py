"""Render an exact Windows process request as inert Manager input files.

No Host subprocess is created. list2cmdline only serializes Windows argv for
ProcessStartInfo (UseShellExecute=false); there is no cmd/PowerShell interpolation
of submitted arguments. The fixed helper itself runs through Guest PowerShell.
"""

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PureWindowsPath
from subprocess import list2cmdline
from uuid import uuid4

from router.models import digest, identifier
from router.ports import Request


@dataclass(frozen=True)
class TransportInput:
    path: Path
    sha256: str


def output_directory(identity):
    session, runtime, generation = identity
    identifier(session)
    identifier(runtime)
    if type(generation) is not int or generation < 1:
        raise ValueError("invalid runtime generation")
    return str(PureWindowsPath(r"C:\RunnerWorkspace\Sessions") / ("session-" + session)
               / ("runtime-" + runtime) / ("generation-" + str(generation)) / "output")


class CommandBundle:
    def __init__(self, request: Request, identity, bindings, directory: Path):
        identifier(request.request_id)
        action = request.action
        command = action.command
        if command is None or not PureWindowsPath(command.executable).is_absolute():
            raise ValueError("absolute Guest executable required; no PATH lookup")
        if not PureWindowsPath(command.cwd).is_absolute():
            raise ValueError("absolute Guest working directory required")
        if len(action.outputs) > 1:
            raise ValueError("this driver exports one stdout output per command")
        output = output_directory(identity)
        if output not in action.scope.writes:
            raise ValueError("Runner output directory is not in the delegated write scope")
        self.request, self.identity = request, identity
        self.nonce = uuid4().hex
        self.evidence_name = f"router-{self.nonce}-receipt.txt"
        self.stdout_name = f"router-{self.nonce}-stdout.txt"
        sources = {s.source_id: s for s in action.sources}
        self.expected = {
            "contract": "router-guest-v1", "request_id": request.request_id,
            "fingerprint": action.fingerprint, "nonce": self.nonce,
            "runtime_id": identity[1], "generation": identity[2],
            "command_sha256": digest(command),
            "sources": {s.source_id: s.sha256 for s in action.sources},
        }
        manifest = {**self.expected, "executable": command.executable,
                    "argument_line": list2cmdline(command.argv), "cwd": command.cwd,
                    "output_dir": output,
                    "inputs": [{"path": b.guest_path, "sha256": sources[b.source_id].sha256}
                               for b in bindings]}
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=False)
        helper = directory / f"router-guest-{self.nonce}.ps1"
        manifest_path = directory / f"router-request-{self.nonce}.json"
        helper.write_bytes(Path(__file__).with_name("router_guest.ps1").read_bytes())
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
        self.inputs = tuple(TransportInput(p, hashlib.sha256(p.read_bytes()).hexdigest())
                            for p in (helper, manifest_path))
        # Only generated filenames go through this shell boundary. Request text
        # stays in JSON and the child process's separate executable/argument fields.
        self.launch_line = (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                            " -NoLogo -NoProfile -ExecutionPolicy Bypass -File "
                            + str(PureWindowsPath(r"C:\UserFiles") / helper.name)
                            + " -Manifest " + str(PureWindowsPath(r"C:\UserFiles") / manifest_path.name))

    def verify_files(self):
        for item in self.inputs:
            if hashlib.sha256(item.path.read_bytes()).hexdigest() != item.sha256:
                raise ValueError("command transport changed; reassessment required")

    def validate_evidence(self, data: bytes):
        if len(data) > 65536:
            raise ValueError("execution evidence exceeds its limit")
        evidence = json.loads(data.decode("utf-8-sig"))
        if not isinstance(evidence, dict) or any(evidence.get(k) != v for k, v in self.expected.items()):
            raise ValueError("execution evidence does not match this request")
        if (type(evidence.get("execution_count")) is not int or evidence["execution_count"] != 1
                or type(evidence.get("process_id")) is not int or evidence["process_id"] <= 0
                or type(evidence.get("exit_code")) is not int):
            raise ValueError("process completion evidence missing")
        digest_value = evidence.get("stdout_sha256")
        if not isinstance(digest_value, str) or len(digest_value) != 64 \
                or any(c not in "0123456789abcdef" for c in digest_value):
            raise ValueError("stdout digest missing")
        return evidence
