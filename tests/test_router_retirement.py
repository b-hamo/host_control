"""Retirement tests: real TLS listeners/stdio, with inert inputs and injected lifecycle faults."""
import asyncio
import hashlib
import json
import socket
from pathlib import Path

import pytest

from host.mcp_server import HostBackend
from host.router_mcp_service import RouterService
from host.router_runtime import RouterRuntime
from host.router_provisioning import load
from router.ports import Receipt, State
from router.models import Artifact
from test_mcp_server import stop
from test_router_mcp import configuration, start, definitions, local_action, Port
from test_router import setup  # noqa: F401


def free_ports():
    with socket.socket() as first, socket.socket() as second:
        first.bind(("127.0.0.1", 0))
        second.bind(("127.0.0.1", 0))
        return first.getsockname()[1], second.getsockname()[1]


def assert_rebind(ports):
    sockets = []
    try:
        for port in ports:
            sock = socket.socket()
            sockets.append(sock)
            sock.bind(("127.0.0.1", port))
            sock.listen()
    finally:
        for sock in sockets:
            sock.close()


async def assert_rebind_after_exit(ports, within=5.0):
    """Windows frees a killed process's sockets shortly after its exit is reported."""
    deadline = asyncio.get_running_loop().time() + within
    while True:
        try:
            return assert_rebind(ports)
        except OSError:
            if asyncio.get_running_loop().time() >= deadline:
                raise
            await asyncio.sleep(.05)


def configured(tmp_path, ports):
    tmp_path.mkdir(exist_ok=True)
    path, config, action, execution = configuration(tmp_path)
    config["host"].update(host="127.0.0.1", port=ports[0], upload_port=ports[1])
    path.write_text(json.dumps(config))
    return path, config, action, execution


def test_live_stdio_stop_releases_both_ports_before_mcp_eof(tmp_path):
    async def run():
        ports = free_ports()
        path, config, action, _ = configured(tmp_path / "first", ports)
        proc, client = await start(path)
        other = reopened = None
        try:
            assert (await client.call("router_plan", definitions([action])))["ok"]
            await client.call("router_submit", {"request_id": "REQ-one", "action_id": action.action_id})
            for _ in range(60):
                state = await client.call("router_status", {"request_id": "REQ-one"})
                if state["receipt"]["state"] == "SUCCEEDED":
                    break
                await asyncio.sleep(.05)
            assert state["receipt"]["state"] == "SUCCEEDED"
            assert (await client.call("router_stop"))["stopped"]
            assert proc.returncode is None  # stdio remains available for queries
            assert_rebind(ports)
            assert (await client.call("router_result", {"request_id": "REQ-one"}))["text"] == "inert text"
            assert (await client.call("router_stop"))["stopped"]
            other_path, _, other_action, _ = configured(tmp_path / "second", ports)
            other, second = await start(other_path)
            assert (await second.call("router_plan", definitions([other_action])))["ok"]
            await stop(proc)
            reopened, saved = await start(path)
            # Old query-only plan must not bind/terminate the new task's occupied ports.
            assert (await saved.call("router_result", {"request_id": "REQ-one"}))["text"] == "inert text"
            assert (await saved.call("router_plan", definitions([action])))["error"] == "PLAN_STOPPED"
            assert (await second.call("router_submit", {"request_id": "REQ-two", "action_id": other_action.action_id}))["ok"]
            assert (await saved.call("router_stop"))["stopped"]
        finally:
            for child in (proc, other, reopened):
                if child is not None and child.returncode is None:
                    await stop(child)
        assert_rebind(ports)
    asyncio.run(run())


def test_partial_bind_failure_releases_upload_and_preserves_foreign_listener(tmp_path):
    ports = free_ports()
    path, _, _, _ = configured(tmp_path, ports)
    provision = load(path)
    with socket.socket() as foreign:
        foreign.bind(("127.0.0.1", ports[0]))
        foreign.listen()
        backend = HostBackend(provision["args"], sandbox_manager=object())
        backend.start()
        assert backend.ready.wait(10)
        backend.join(10)
        assert backend.error and not backend.is_alive()
        assert_rebind([ports[1]])
        assert foreign.getsockname()[1] == ports[0]


def test_zero_ports_publish_actual_bound_endpoints_and_release_them(tmp_path):
    async def run():
        path, _, _, _ = configured(tmp_path, (0, 0))
        provision = load(path)
        provision.pop("plan_id")
        runtime = await RouterRuntime.open(manager=object(), **provision)
        try:
            bootstrap = tmp_path / "bootstrap.json"
            async def publish():
                runtime.backend.launcher.publish("127.0.0.1", bootstrap, runtime.backend.session.identity)
            await runtime._on_host(publish())
            doc = json.loads(bootstrap.read_text())
            ports = [doc["port"], doc["observation_upload"]["port"]]
            assert all(0 < port < 65536 for port in ports) and ports[0] != ports[1]
            assert doc["artifact_upload"]["port"] == ports[1]
            for port in ports:
                with socket.socket() as occupied:
                    with pytest.raises(OSError):
                        occupied.bind(("127.0.0.1", port))
        finally:
            await runtime.stop_sandbox()
        assert_rebind(ports)
    asyncio.run(run())


def test_guest_disappearance_retires_real_host_without_replaying(tmp_path):
    async def run():
        ports = free_ports()
        path, config, action, _ = configured(tmp_path, ports)
        provision = load(path)
        provision.pop("plan_id")
        class Manager:
            def __init__(self):
                self.stops = self.cleanups = 0
                self.owned = object()
            def is_running(self, sandbox):
                assert sandbox is self.owned
                return False
            def stop(self, sandbox, reason, emergency=False):
                assert sandbox is self.owned
                self.stops += 1
            def cleanup(self, sandbox):
                assert sandbox is self.owned
                self.cleanups += 1
                return {"failed": []}
        manager = Manager()
        runtime = await RouterRuntime.open(manager=manager, **provision)
        service = RouterService(runtime, "PLAN-TEST", Path(config["private_directory"]) / "protocol.sqlite")
        try:
            await service.call("router_plan", definitions([action]))
            async def vanished():
                launcher = runtime.backend.launcher
                launcher.sandbox = manager.owned
                launcher.state = "READY"
                launcher._launch = asyncio.create_task(asyncio.sleep(0))
                await launcher._launch
            await runtime._on_host(vanished())
            for _ in range(100):
                if service.stopped and not runtime.backend.is_alive():
                    break
                await asyncio.sleep(.05)
            assert service.stopped and not runtime.backend.is_alive()
            assert_rebind(ports)
            assert manager.stops == manager.cleanups == 1
            assert (await service.call("router_submit", {"request_id":"REQ-new", "action_id":action.action_id}))["error"] == "PLAN_STOPPED"
            assert not Path(action.locator).exists()
            assert (await service.call("router_stop", {}))["stopped"]
        finally:
            await service.close()
    asyncio.run(run())


def test_simultaneous_stop_cancels_pending_and_never_replays(tmp_path):
    async def run():
        class Pending:
            def __init__(self):
                self.submits = self.stops = 0
            async def submit(self, request):
                self.submits += 1
                self.request = request
                await asyncio.Future()
            async def status(self, rid):
                return Receipt(rid, self.request.action.fingerprint, State.ACCEPTED, "HOST_VALIDATED")
            async def stop_sandbox(self):
                self.stops += 1
            async def close(self):
                pass
        host = Pending()
        service = RouterService(host, "PLAN-TEST", tmp_path / "requests.sqlite")
        action = local_action(tmp_path)
        await service.call("router_plan", definitions([action]))
        await service.call("router_submit", {"request_id":"REQ-one", "action_id":action.action_id})
        await asyncio.sleep(0)
        replies = await asyncio.gather(*(service.call("router_stop", {}) for _ in range(5)))
        assert all(r["stopped"] for r in replies)
        assert host.submits == host.stops == 1
        assert (await service.call("router_status", {"request_id":"REQ-one"}))["receipt"]["state"] == "UNKNOWN"
        await service.close()
        recovered = RouterService(None, "PLAN-TEST", tmp_path / "requests.sqlite")
        assert (await recovered.call("router_status", {"request_id":"REQ-one"}))["receipt"]["state"] == "UNKNOWN"
        assert (await recovered.call("router_submit", {"request_id":"REQ-new", "action_id":action.action_id}))["error"] == "PLAN_STOPPED"
        await recovered.close()
    asyncio.run(run())


def test_cleanup_timeout_never_reports_success_or_reopens_plan(setup, tmp_path):
    async def run():
        action = local_action(tmp_path)
        class Failing(Port):
            async def stop_sandbox(self):
                raise TimeoutError("private detail must not leak")
        service = RouterService(Failing(setup((action,))), "PLAN-TEST", tmp_path / "protocol.sqlite")
        await service.call("router_plan", definitions([action]))
        reply = await service.call("router_stop", {})
        assert reply["stopped"] is False and reply["error"] == "CLEANUP_UNCONFIRMED"
        assert "private detail" not in json.dumps(reply)
        assert (await service.call("router_plan", definitions([action])))["error"] == "PLAN_STOPPED"
        with pytest.raises(RuntimeError, match="cleanup unconfirmed"):
            await service.close()
        reopened = RouterService(None, "PLAN-TEST", tmp_path / "protocol.sqlite")
        assert not (await reopened.call("router_stop", {}))["stopped"]
        with pytest.raises(RuntimeError):
            await reopened.close()
    asyncio.run(run())


def test_retired_export_rechecks_bytes_and_preserves_aliases(tmp_path):
    async def run():
        output = tmp_path / "output.txt"
        output.write_bytes(b"verified")
        artifact = Artifact("ART-1", "EXPORTED", str(output), hashlib.sha256(b"verified").hexdigest(), (), "stdout")
        action = local_action(tmp_path)
        class Exported:
            async def submit(self, request):
                self.receipt = Receipt(request.request_id, action.fingerprint, State.SUCCEEDED,
                                       "VERIFIED", "EXEC-one", "ART-1", (artifact,), "RT-one", 1)
                return self.receipt
            async def status(self, rid):
                return self.receipt
            async def verify(self, receipt):
                return receipt == self.receipt
            async def artifact(self, ref):
                return artifact
            async def stop_sandbox(self):
                pass
            async def close(self):
                pass
        service = RouterService(Exported(), "PLAN-TEST", tmp_path / "protocol.sqlite")
        await service.call("router_plan", definitions([action]))
        for rid in ("REQ-one", "REQ-alias"):
            await service.call("router_submit", {"request_id":rid, "action_id":action.action_id})
        await asyncio.gather(*service.jobs.values())
        assert (await service.call("router_stop", {}))["stopped"]
        await service.close()
        service = RouterService(None, "PLAN-TEST", tmp_path / "protocol.sqlite")
        try:
            result = await service.call("router_result", {"request_id":"REQ-alias"})
            assert result["receipt"]["request_id"] == "REQ-alias"
            assert result["outputs"][0]["text"] == "verified"
            assert result["stopped"] is True
            assert result["progress"]["actions"][action.action_id]["state"] == "SUCCEEDED"
            assert result["progress"]["tasks"][action.task_id]["complete"] is True
            output.write_bytes(b"changed")
            assert (await service.call("router_result", {"request_id":"REQ-one"}))["error"] == "RESULT_NOT_VERIFIED"
        finally:
            await service.close()
    asyncio.run(run())


def test_host_thread_timeout_is_not_success():
    class StillRunning:
        loop = _stop = None
        def is_alive(self):
            return True
        def join(self, timeout):
            assert timeout == .01
    with pytest.raises(TimeoutError, match="Host shutdown unconfirmed"):
        HostBackend.shutdown(StillRunning(), timeout=.01)


def test_stalled_evidence_does_not_hold_execution_host(setup, tmp_path, monkeypatch):
    monkeypatch.setattr("host.router_mcp_service.SNAPSHOT_WAIT_S", .02)
    async def run():
        action = local_action(tmp_path)
        class Stalled(Port):
            stops = 0
            async def status(self, rid):
                await asyncio.Future()
            async def stop_sandbox(self):
                self.stops += 1
        host = Stalled(setup((action,)))
        service = RouterService(host, "PLAN-TEST", tmp_path / "protocol.sqlite")
        await service.call("router_plan", definitions([action]))
        await service.call("router_submit", {"request_id": "REQ-one", "action_id": action.action_id})
        await asyncio.gather(*service.jobs.values())
        try:
            assert (await asyncio.wait_for(service.call("router_stop", {}), 1))["stopped"]
            assert host.stops == 1
            assert (await service.call("router_status", {"request_id": "REQ-one"}))["receipt"]["state"] == "UNKNOWN"
        finally:
            await service.close()
    asyncio.run(run())


def test_failed_guest_cleanup_still_releases_owned_listeners(tmp_path, monkeypatch):
    async def run():
        ports = free_ports()
        path, config, _, _ = configured(tmp_path, ports)
        provision = load(path)
        provision.pop("plan_id")
        runtime = await RouterRuntime.open(manager=object(), **provision)
        async def fail():
            raise RuntimeError("injected cleanup failure")
        monkeypatch.setattr(runtime.backend.launcher, "shutdown", fail)
        service = RouterService(runtime, "PLAN-TEST", Path(config["private_directory"]) / "protocol.sqlite")
        try:
            reply = await service.call("router_stop", {})
            assert reply["error"] == "CLEANUP_UNCONFIRMED"
            assert not runtime.backend.is_alive()
            assert_rebind(ports)
        finally:
            with pytest.raises(RuntimeError, match="cleanup unconfirmed"):
                await service.close()
    asyncio.run(run())


def test_launcher_deadline_includes_terminate_request():
    from host.lifecycle import SandboxLauncher
    class Session:
        identity = ("SES-test", "RT-test", 1)
        terminated = False
        ready = asyncio.Event()
        async def terminate(self, reason):
            await asyncio.Future()
    async def run():
        session = Session()
        session.ready.set()
        launcher = SandboxLauncher(object(), Path("unused.exe"), session, lambda *args: None)
        with pytest.raises(TimeoutError, match="Sandbox shutdown unconfirmed"):
            await asyncio.wait_for(launcher.shutdown(timeout=.02), 1)
    asyncio.run(run())


def test_startup_failure_automatically_retires_real_host(tmp_path):
    async def run():
        ports = free_ports()
        path, config, _, _ = configured(tmp_path, ports)
        provision = load(path)
        provision.pop("plan_id")
        runtime = await RouterRuntime.open(manager=object(), **provision)
        service = RouterService(runtime, "PLAN-TEST", Path(config["private_directory"]) / "protocol.sqlite")
        try:
            await runtime._on_host(runtime.backend.session.fail_startup("injected failure"))
            for _ in range(100):
                if service.stopped and not runtime.backend.is_alive():
                    break
                await asyncio.sleep(.05)
            assert service.stopped and not runtime.backend.is_alive()
            assert_rebind(ports)
        finally:
            await service.close()
    asyncio.run(run())


def test_killed_stdio_keeps_reservation_without_replaying(tmp_path):
    async def run():
        ports = free_ports()
        path, _, action, _ = configured(tmp_path, ports)
        proc, client = await start(path)
        try:
            await client.call("router_plan", definitions([action]))
            await client.call("router_submit", {"request_id": "REQ-one", "action_id": action.action_id})
            for _ in range(60):
                state = await client.call("router_status", {"request_id": "REQ-one"})
                if state["receipt"]["state"] == "SUCCEEDED":
                    break
                await asyncio.sleep(.05)
            assert state["receipt"]["state"] == "SUCCEEDED"
            output = Path(action.locator)
            before = output.stat().st_mtime_ns
            proc.kill()  # Only this test's child, without graceful EOF/finally.
            await asyncio.wait_for(proc.wait(), 10)
            await assert_rebind_after_exit(ports)
            proc, client = await start(path)
            assert (await client.call("router_plan", definitions([action])))["ok"]
            result = await client.call("router_submit", {"request_id": "REQ-one", "action_id": action.action_id})
            assert result["receipt"]["state"] == "UNKNOWN"
            assert output.stat().st_mtime_ns == before
            assert (await client.call("router_result", {"request_id": "REQ-one"}))["error"] == "RESULT_NOT_VERIFIED"
        finally:
            if proc.returncode is None:
                await stop(proc)
    asyncio.run(run())
