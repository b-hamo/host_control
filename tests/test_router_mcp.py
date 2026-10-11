"""MCP service tests and real stdio Host tests; inert fixtures never execute."""

import asyncio
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import sys
import time

import pytest

from host.router_mcp_service import RouterService
from host.router_provisioning import load
from host.mcp_server import McpServer
from host.router_mcp_server import tool_list
from router import Action, Command, Location, Operation, Scope, Source, Task
from test_mcp_server import Client, stop
from test_router import setup  # noqa: F401


ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "host" / "router_mcp_server.py"


def local_action(tmp_path, name="write"):
    return Action(name, name, Operation.WRITE_TEXT, Scope(writes=(str(tmp_path / (name + ".txt")),)),
                  "user-grant", locator=str(tmp_path / (name + ".txt")), text="inert text")


def definitions(actions, dependencies=None):
    return json.loads(json.dumps({"plan_id": "PLAN-TEST",
        "tasks": [asdict(Task(a.task_id, a.location, (dependencies or {}).get(a.task_id, ()))) for a in actions],
        "actions": [asdict(a) for a in actions]}))


class Port:
    def __init__(self, gateway):
        self.gateway = gateway
        self.submits = 0

    def __getattr__(self, name):
        return getattr(self.gateway, name)

    async def submit(self, request):
        self.submits += 1
        return await self.gateway.submit(request)

    async def close(self):
        pass  # fixture owns the Gateway ledger

    async def stop_sandbox(self):
        pass  # no Guest exists in these service doubles


def test_atomic_plan_and_concurrent_idempotency(setup, tmp_path):
    async def check():
        a = local_action(tmp_path)
        port = Port(setup((a,)))
        service = RouterService(port, "PLAN-TEST", tmp_path / "protocol.sqlite")
        try:
            await service.call("router_plan", definitions([a]))
            bad = definitions([replace(a, action_id="bad", task_id="unknown")])
            bad["tasks"] = []
            with pytest.raises(KeyError):
                await service.call("router_plan", bad)
            assert "bad" not in service.actions
            args = {"request_id": "REQ-ONE", "action_id": a.action_id}
            await asyncio.gather(*(service.call("router_submit", args) for _ in range(8)))
            await asyncio.gather(*service.jobs.values())
            result = await service.call("router_result", {"request_id": "REQ-ONE"})
            assert result["receipt"]["state"] == "SUCCEEDED"
            assert result["text"] == "inert text"
            await service.call("router_submit", {**args, "request_id": "REQ-ALIAS"})
            assert port.submits == 1
            assert (await service.call("computer_type", {"text": "do not dispatch"}))["error"] == "TOOL_NOT_EXPOSED"
        finally:
            await service.close()
    asyncio.run(check())


def test_dependency_and_request_id_conflict(setup, tmp_path):
    async def check():
        first, second = local_action(tmp_path, "first"), local_action(tmp_path, "second")
        service = RouterService(Port(setup((first, second))), "PLAN-TEST", tmp_path / "protocol.sqlite")
        try:
            await service.call("router_plan", definitions([second, first], {"second": ("first",)}))
            result = await service.call("router_submit", {"request_id": "REQ-2", "action_id": "second"})
            assert result["error"] == "DEPENDENCIES_UNCONFIRMED"
            await service.call("router_submit", {"request_id": "REQ-1", "action_id": "first"})
            await asyncio.gather(*service.jobs.values())
            await service.call("router_status", {"request_id": "REQ-1"})
            assert (await service.call("router_submit", {"request_id": "REQ-1", "action_id": "second"}))["error"] == "IDEMPOTENCY_CONFLICT"
            await service.call("router_submit", {"request_id": "REQ-2", "action_id": "second"})
            await asyncio.gather(*service.jobs.values())
            assert (await service.call("router_status", {"request_id": "REQ-2"}))["receipt"]["state"] == "SUCCEEDED"
        finally:
            await service.close()
    asyncio.run(check())


def test_durable_protocol_reservation_never_replays(setup, tmp_path):
    async def check():
        a = local_action(tmp_path)
        port = Port(setup((a,)))
        db = tmp_path / "protocol.sqlite"
        service = RouterService(port, "PLAN-TEST", db)
        await service.call("router_plan", definitions([a]))
        await service.call("router_submit", {"request_id": "REQ-ONE", "action_id": a.action_id})
        await asyncio.gather(*service.jobs.values())
        await service.close()
        # Simulate lost Host memory while preserving the protocol reservation.
        other = Port(setup((a,)))
        service = RouterService(other, "PLAN-TEST", db)
        try:
            await service.call("router_plan", definitions([a]))
            result = await service.call("router_submit", {"request_id": "REQ-ONE", "action_id": a.action_id})
            assert result["receipt"]["state"] == "UNKNOWN"
            assert other.submits == 0
        finally:
            await service.close()
    asyncio.run(check())


def test_explicit_stop_durably_retires_submissions(setup, tmp_path):
    async def check():
        a = local_action(tmp_path)
        port = Port(setup((a,)))
        db = tmp_path / "protocol.sqlite"
        service = RouterService(port, "PLAN-TEST", db)
        await service.call("router_plan", definitions([a]))
        assert (await service.call("router_stop", {}))["stopped"]
        assert (await service.call("router_submit", {"request_id": "REQ-1", "action_id": a.action_id}))["error"] == "PLAN_STOPPED"
        await service.close()
        service = RouterService(port, "PLAN-TEST", db)
        try:
            assert (await service.call("router_stop", {}))["stopped"]
            assert (await service.call("router_submit", {"request_id": "REQ-NEW", "action_id": a.action_id}))["error"] == "PLAN_STOPPED"
            assert port.submits == 0
        finally:
            await service.close()
    asyncio.run(check())


def configuration(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    payload = tmp_path / "inert.ps1"
    payload.write_text("inert fixture, never run", encoding="utf-8")
    runner = tmp_path / "runner.exe"
    runner.write_bytes(b"inert package; never run")
    src = Source("payload", "mock:payload", hashlib.sha256(payload.read_bytes()).hexdigest(), "generated")
    execution = Action("execute", "guest", Operation.EXECUTE,
        Scope(reads=(r"C:\UserFiles\inert.ps1",), capabilities=("process.execute",)), "user-grant",
        sources=(src,), command=Command(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                        ("-File", r"C:\UserFiles\inert.ps1"), r"C:\UserFiles", "payload"))
    a = local_action(data)
    config = {"version": 1, "plan_id": "PLAN-TEST", "data_directory": str(data),
        "private_directory": str(tmp_path / "private"),
        "sources": [{"source": asdict(src), "path": str(payload)}],
        "bindings": [{"source_id": "payload", "host_path": str(payload)}],
        "execution_action": asdict(execution),
        "delegations": [{"reference": "user-grant", "operations": ["write_text"], "locations": ["LOCAL"],
                         "scope": asdict(a.scope), "expires_at": time.time()+120}],
        "host": {"session": "SES-MCP-TEST", "runtime": "RT-MCP-TEST", "runner_exe": str(runner),
                 "port": 0, "upload_port": 0}}
    path = tmp_path / "host.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path, config, a, execution


async def start(config):
    proc = await asyncio.create_subprocess_exec(sys.executable, str(SERVER), "--config", str(config),
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    client = Client(proc)
    await client.rpc("initialize")
    return proc, client


def test_real_stdio_allowlist_local_result_and_restart(tmp_path):
    pytest.importorskip("sandbox_manager")
    async def check():
        path, config, a, execute = configuration(tmp_path)
        proc, client = await start(path)
        try:
            names = {t["name"] for t in (await client.rpc("tools/list"))["result"]["tools"]}
            assert names == {"router_plan", "router_submit", "router_status", "router_result", "router_stop"}
            for name in ("computer_type", "task_submit", "exec_command", "write_stdin", "artifact_export", "approve"):
                assert (await client.call(name, {}))["error"] == "TOOL_NOT_EXPOSED"
            await client.call("router_plan", definitions([a, execute]))
            invalid = {"request_id": "REQ-ONE", "action_id": a.action_id, "approved": True}
            assert (await client.call("router_submit", invalid))["error"] == "INVALID_ARGUMENT"
            receipt = await client.call("router_submit", {"request_id": "REQ-ONE", "action_id": a.action_id})
            for _ in range(30):
                receipt = await client.call("router_status", {"request_id": "REQ-ONE"})
                if receipt["receipt"]["state"] != "ACCEPTED":
                    break
                await asyncio.sleep(.05)
            assert receipt["receipt"]["state"] == "SUCCEEDED"
            assert (await client.call("router_result", {"request_id": "REQ-ONE"}))["text"] == "inert text"
            await client.call("router_submit", {"request_id": "REQ-DENIED", "action_id": "execute"})
            for _ in range(30):
                denied = await client.call("router_status", {"request_id": "REQ-DENIED"})
                if denied["receipt"]["state"] != "ACCEPTED":
                    break
                await asyncio.sleep(.05)
            assert denied["receipt"]["state"] == "DENIED"
            assert not list((tmp_path / "private" / "sandboxes").glob("sessions/*/sandbox.wsb"))
            before = Path(a.locator).stat().st_mtime_ns
        finally:
            await stop(proc)
        proc, client = await start(path)
        try:
            await client.call("router_plan", definitions([a, execute]))
            result = await client.call("router_submit", {"request_id": "REQ-ONE", "action_id": a.action_id})
            assert result["receipt"]["state"] == "UNKNOWN"
            assert Path(a.locator).stat().st_mtime_ns == before
            assert not (await client.call("router_result", {"request_id": "REQ-ONE"}))["ok"]
        finally:
            await stop(proc)
    asyncio.run(check())


@pytest.mark.parametrize("field", ["private_directory", "config"])
def test_host_authority_cannot_live_in_writable_data_root(tmp_path, field):
    path, config, _, _ = configuration(tmp_path)
    if field == "config":
        path = Path(config["data_directory"]) / "policy.txt"
    else:
        config[field] = str(Path(config["data_directory"]) / "private")
    path.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(ValueError, match="outside"):
        load(path)


@pytest.mark.parametrize("name", ["PRIVATE-TOKEN-MUST-NOT-LOG", ["computer_type"], None])
def test_hidden_direct_calls_never_reach_backend_or_leak_name(name, caplog):
    class NeverDispatch:
        def call(self, *args):
            raise AssertionError("hidden call reached backend")
    server = McpServer(NeverDispatch(), tool_list(), strict_tools=True)
    with caplog.at_level("INFO"):
        reply = server.handle({"id": 1, "method": "tools/call", "params": {"name": name}})
    assert reply["result"]["isError"]
    assert "PRIVATE-TOKEN-MUST-NOT-LOG" not in caplog.text
    assert "UNEXPOSED" in caplog.text


def test_execution_approval_is_bound_and_rechecks_changed_bytes(tmp_path):
    path, config, local, execution = configuration(tmp_path)
    grant = config["delegations"][0]
    grant.update(operations=["execute"], locations=["SANDBOX"], scope=asdict(execution.scope),
                 execution_fingerprints=[execution.fingerprint], approval_required=True)
    path.write_text(json.dumps(config), encoding="utf-8")
    provision = load(path)
    authority = provision["authority"]
    assert authority.check(execution) == "ALLOW"
    assert authority.delegations["user-grant"].approval_required
    Path(config["sources"][0]["path"]).write_text("changed", encoding="utf-8")
    assert authority.check(execution) == "PROVENANCE_UNVERIFIED"


def test_two_stdio_processes_cannot_own_same_private_state(tmp_path):
    pytest.importorskip("sandbox_manager")
    async def check():
        config, _, a, _ = configuration(tmp_path)
        first, client = await start(config)
        second = None
        try:
            assert (await client.call("router_plan", definitions([a])))["ok"]
            second, other = await start(config)
            assert (await other.call("router_plan", definitions([a])))["error"] == "ROUTER_UNAVAILABLE"
        finally:
            if second is not None:
                await stop(second)
            await stop(first)
    asyncio.run(check())
