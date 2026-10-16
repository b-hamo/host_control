"""Long-lived Router connection with Host-owned profiles and durable start IDs.

Agent requests select a profile name, never a configuration path or authority.
Retired plans remain query-only. Unclean process loss is fail-closed: it cannot
prove Guest cleanup and must not start a replacement automatically.
"""
import asyncio
import copy
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import sqlite3
from uuid import uuid4

from host.router_command_bundle import output_directory
from host.router_inputs import InputBoundManager
from host.router_mcp_service import RouterService
from host.router_provisioning import load
from router.models import identifier


def catalog(path):
    InputBoundManager._plain_file(path)
    raw = path.read_bytes()
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("catalog too large")
    doc = json.loads(raw)
    if set(doc) != {"version", "private_directory", "profiles"} or doc["version"] != 1:
        raise ValueError("invalid Router catalog")
    root = Path(doc["private_directory"])
    if not root.is_absolute() or not isinstance(doc["profiles"], dict) or not doc["profiles"]:
        raise ValueError("absolute private root and profiles required")
    profiles = {}
    for name, value in doc["profiles"].items():
        identifier(name)
        config = Path(value)
        if not config.is_absolute():
            raise ValueError("absolute configuration required")
        provision = load(config)
        data = provision["data_directory"].resolve()
        if root.resolve().is_relative_to(data) or path.resolve().is_relative_to(data):
            raise ValueError("connection state and catalog must be outside Agent data")
        profiles[name] = config
    root.mkdir(parents=True, exist_ok=True)
    return root, profiles


class RouterConnection:
    def __init__(self, directory, profiles, open_runtime, *, initial=None, initial_directory=None, initial_action=None):
        self.directory, self.profiles, self.open_runtime = directory, profiles, open_runtime
        self.default_plan = initial.plan_id if initial is not None else None
        directory.mkdir(parents=True, exist_ok=True)
        self.lock = asyncio.Lock()
        self.closed = False
        self.services = {}
        self.db = sqlite3.connect(directory / "connection.sqlite")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS plans "
                        "(start_key TEXT PRIMARY KEY, plan_id TEXT UNIQUE, profile TEXT, execution TEXT, directory TEXT)")
        self.db.commit()
        if initial is not None:
            with self.db:
                self.db.execute("INSERT OR IGNORE INTO plans VALUES (?,?,?,?,?)",
                                ("legacy-initial", initial.plan_id, "default", json.dumps(asdict(initial_action)), str(initial_directory)))
        for pid, plan_directory in self.db.execute("SELECT plan_id,directory FROM plans"):
            if initial is not None and pid == initial.plan_id:
                self.services[pid] = initial
                continue
            service = RouterService(None, pid, Path(plan_directory) / "mcp-requests.sqlite")
            # No automatic Host restart or execution replay after process loss.
            with service.db:
                service.db.execute("INSERT OR IGNORE INTO control VALUES ('stopped')")
            service.stopped = True
            self.services[pid] = service

    def _directory(self, pid):
        return self.directory / pid

    @staticmethod
    def _cleaned(service):
        return service.db.execute("SELECT 1 FROM control WHERE key='cleaned'").fetchone() is not None

    def _started(self, pid):
        service = self.services[pid]
        cleaned = self._cleaned(service)
        if service.stopped and not cleaned:
            return {"ok": False, "error": "CLEANUP_UNCONFIRMED", "plan_id": pid,
                    "stopped": True, "cleanup_confirmed": False}
        execution = self.db.execute("SELECT execution FROM plans WHERE plan_id=?", (pid,)).fetchone()[0]
        return {"ok": True, "plan_id": pid, "stopped": service.stopped,
                "cleanup_confirmed": cleaned, "execution_action": json.loads(execution)}

    async def call(self, name, args):
        async with self.lock:
            if self.closed:
                return {"ok": False, "error": "CONNECTION_CLOSED"}
            if name == "router_list":
                return {"ok": True, "profiles": sorted(self.profiles),
                        "plans": [{"plan_id": pid, "stopped": service.stopped,
                                   "cleanup_confirmed": self._cleaned(service)}
                                  for pid, service in self.services.items()]}
            if name == "router_start":
                return await self._start(args)
            if name not in {"router_plan", "router_submit", "router_status", "router_result", "router_stop"}:
                return {"ok": False, "error": "TOOL_NOT_EXPOSED"}
            service = self.services.get(args.get("plan_id", self.default_plan))
            if service is None:
                return {"ok": False, "error": "PLAN_NOT_FOUND"}
            result = await service.call(name, args)
            if result.get("error") == "PLAN_STOPPED":
                result.update(plan_id=service.plan_id, recommended_next_step="router_start",
                              new_start_request_required=True)
            return result

    async def _start(self, args):
        key = hashlib.sha256(args["request_id"].encode()).hexdigest()
        old = self.db.execute("SELECT plan_id,profile FROM plans WHERE start_key=?", (key,)).fetchone()
        if old:
            if old[1] != args["profile"]:
                return {"ok": False, "error": "IDEMPOTENCY_CONFLICT"}
            return self._started(old[0])
        config = self.profiles.get(args["profile"])
        if config is None:
            return {"ok": False, "error": "PROFILE_NOT_FOUND"}
        for pid, service in self.services.items():
            if not service.stopped:
                return {"ok": False, "error": "PLAN_ACTIVE", "plan_id": pid,
                        "recommended_next_step": "router_stop"}
            if not self._cleaned(service):
                return {"ok": False, "error": "CLEANUP_UNCONFIRMED", "plan_id": pid,
                        "recommended_next_step": "router_stop"}
        if len(self.services) >= 1024:
            return {"ok": False, "error": "PLAN_LIMIT_REACHED"}
        provision = load(config)  # re-read Host grants and source registrations for each new plan
        if self.directory.resolve().is_relative_to(provision["data_directory"].resolve()):
            raise ValueError("private state inside data root")
        pid = "PLAN-" + uuid4().hex
        private = self._directory(pid)
        private.mkdir()
        provision.pop("plan_id")
        provision["private_directory"] = private
        host = provision["args"] = copy.copy(provision["args"])
        old_output = output_directory((host.session, host.runtime, host.generation))
        host.session, host.runtime = "SES-" + uuid4().hex, "RT-" + uuid4().hex
        new_output = output_directory((host.session, host.runtime, host.generation))
        def rebind(scope):
            return replace(scope, writes=tuple(new_output if p == old_output else p for p in scope.writes))
        original = provision["execution_action"]
        execution = provision["execution_action"] = replace(original, scope=rebind(original.scope))
        authority = provision["authority"]
        # Host-owned profile authorizes the command; only its generated output location changes.
        # Never mint a new permission or add a fingerprint to a grant that lacked the original.
        for reference, grant in authority.delegations.items():
            authority.delegations[reference] = replace(grant, scope=rebind(grant.scope),
                execution_fingerprints=frozenset(execution.fingerprint if f == original.fingerprint else f
                                                for f in grant.execution_fingerprints))
        for field, folder in (("sandbox_root", "sandboxes"), ("cert_dir", "certs"),
                              ("audit_dir", "audit"), ("artifact_dir", "quarantine")):
            setattr(host, field, private / folder)
        host.export_dir = host.export_dir / pid
        # Reserve durably before opening any listeners or creating a Guest.
        service = RouterService(None, pid, private / "mcp-requests.sqlite")
        with self.db:
            self.db.execute("INSERT INTO plans VALUES (?,?,?,?,?)", (key, pid, args["profile"], json.dumps(asdict(execution)), str(private)))
        self.services[pid] = service
        runtime = None
        try:
            runtime = await self.open_runtime(provision)
            active = RouterService(runtime, pid, private / "mcp-requests.sqlite")
            service.db.close()
            self.services[pid] = active
            return self._started(pid)
        except Exception:
            with service.db:
                service.db.execute("INSERT OR IGNORE INTO control VALUES ('stopped')")
            service.stopped = True
            if runtime is not None:
                await runtime.close()
            # Failed startup may have left resources: do not claim successful cleanup.
            return {"ok": False, "error": "START_UNCONFIRMED", "plan_id": pid,
                    "recommended_next_step": "router_start", "reuse_request_id": True}

    async def close(self):
        # A timed-out start may still own the lock. Wait for it before retiring
        # its runtime; EOF must not close the DB while that start is in flight.
        async with self.lock:
            if self.closed:
                return
            self.closed = True
            errors = []
            for service in self.services.values():
                try:
                    await service.close()
                except Exception as exc:
                    errors.append(exc)
            self.db.close()
            if errors:
                raise RuntimeError("Router cleanup unconfirmed")
