"""Host-only JSON provisioning. Never accept this document through an Agent tool.

Keep config/private directories outside LocalTools' data root and deny the Agent
direct filesystem access to them. This module is not an OS permission boundary.
"""

import argparse
import asyncio
import hashlib
import json
from pathlib import Path

from host.approval import DialogApprover
from host.router_authority import Authority, Delegation
from host.router_codec import action, exact, scope, source, strings
from host.router_inputs import InputBinding, InputBoundManager
from router.models import Location, Operation, identifier


class ExecutionApprover(DialogApprover):
    async def __call__(self, request):
        from dataclasses import asdict
        # No truncation: an incomplete command must never be presented for approval.
        description = json.dumps(asdict(request.action), ensure_ascii=True, indent=2)
        if len(description) > 12000:
            return False
        async with self._lock:
            self._seq += 1
            title = f"Router Sandbox execution #{self._seq}"
            text = ("Approve this exact Sandbox action? Agent claims below are untrusted; "
                    "Host has checked their registered sources and delegation.\n"
                    "No response means deny.\n\n" + description)
            try:
                return await asyncio.to_thread(self._ask, text, title)
            except asyncio.CancelledError:
                self._dismiss(title)
                raise


def load(path: Path):
    path = path.absolute()
    InputBoundManager._plain_file(path)
    raw = path.read_bytes()
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("Host configuration too large")
    doc = json.loads(raw)
    exact(doc, {"version", "plan_id", "data_directory", "private_directory", "sources", "delegations",
                "execution_action", "bindings", "host", "command_launch_enabled", "execution_approval"},
          ("version", "plan_id", "data_directory", "private_directory", "sources", "delegations",
           "execution_action", "bindings", "host"))
    if doc["version"] != 1:
        raise ValueError("unsupported Host configuration")
    identifier(doc["plan_id"])

    def absolute(value):
        p = Path(value)
        if not p.is_absolute():
            raise ValueError("absolute Host path required")
        return p

    data, private = absolute(doc["data_directory"]), absolute(doc["private_directory"])
    data = data.resolve(strict=True)
    if path.resolve().is_relative_to(data) or private.resolve().is_relative_to(data):
        raise ValueError("Host authority/private state must be outside the writable data root")
    private.mkdir(parents=True, exist_ok=True)
    records, paths = [], {}
    for entry in doc["sources"]:
        exact(entry, ("source", "path"), ("source", "path"))
        record = source(entry["source"])
        if record.source_id in paths:
            raise ValueError("duplicate trusted source")
        records.append(record)
        paths[record.source_id] = absolute(entry["path"])

    def verify(record):
        target = paths[record.source_id]
        InputBoundManager._plain_file(target)
        with target.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest() == record.sha256

    grants = []
    for entry in doc["delegations"]:
        exact(entry, ("reference", "operations", "locations", "scope", "expires_at",
                      "execution_fingerprints", "approval_required"),
              ("reference", "operations", "locations", "scope", "expires_at"))
        identifier(entry["reference"])
        if type(entry.get("approval_required", False)) is not bool or type(entry["expires_at"]) not in (int, float):
            raise ValueError("invalid grant")
        grants.append(Delegation(entry["reference"], frozenset(Operation(x) for x in strings(entry["operations"])),
            frozenset(Location(x) for x in strings(entry["locations"])), scope(entry["scope"]), entry["expires_at"],
            frozenset(strings(entry.get("execution_fingerprints", []))), entry.get("approval_required", False)))
    if len({g.reference for g in grants}) != len(grants):
        raise ValueError("duplicate trusted delegation")
    authority = Authority(sources=tuple(records), delegations=tuple(grants), verify_source=verify)
    execution = action(doc["execution_action"])
    bindings = tuple(InputBinding(exact(b, ("source_id", "host_path"), ("source_id", "host_path"))["source_id"],
                                  absolute(b["host_path"])) for b in doc["bindings"])
    host = exact(doc["host"], ("host", "port", "upload_port", "session", "runtime", "generation",
                  "startup_timeout", "runner_exe", "sandbox_root", "cert_dir", "audit_dir",
                  "artifact_dir", "export_dir", "artifact_scanner", "artifact_max_bytes"),
                 ("session", "runtime", "runner_exe"))
    identifier(host["session"])
    identifier(host["runtime"])
    args = argparse.Namespace(host="0.0.0.0", port=17443, upload_port=17444,
        generation=1, startup_timeout=180, advertise_address=None, bootstrap_out=None,
        sandbox_root=private / "sandboxes", cert_dir=private / "certs", audit_dir=private / "audit",
        no_auto_restart=True, artifact_export=True, approval="deny", artifact_scanner="amsi",
        artifact_max_bytes=1048576, artifact_dir=private / "quarantine", export_dir=data / "exports")
    for key, value in host.items():
        if key in {"runner_exe", "sandbox_root", "cert_dir", "audit_dir", "artifact_dir", "export_dir"}:
            value = absolute(value)
            if key != "export_dir" and value.resolve().is_relative_to(data):
                raise ValueError("Host runtime resources must be outside the writable data root")
        setattr(args, key, value)
    approval = doc.get("execution_approval", "deny")
    if approval not in {"deny", "dialog"} or type(doc.get("command_launch_enabled", False)) is not bool:
        raise ValueError("invalid Host activation/approval mode")
    return dict(args=args, authority=authority, execution_action=execution, bindings=bindings,
                data_directory=data, private_directory=private, plan_id=doc["plan_id"],
                command_launch_enabled=doc.get("command_launch_enabled", False),
                execution_approver=ExecutionApprover() if approval == "dialog" else None)
