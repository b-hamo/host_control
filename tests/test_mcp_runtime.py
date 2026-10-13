"""General MCP lifetime: real sockets and stdio; fake Guests are explicitly injected."""
import asyncio
import json
import socket
import sys
import time

import pytest

from host.mcp_runtime import McpRuntime
from host.mcp_server import HostBackend, McpServer, guard_descriptions, load_tool_list
from test_mcp_server import Client, SERVER, stop
from test_router_retirement import assert_rebind, free_ports
from test_sandbox_launch import args, FakeError
from test_sandbox_recovery import RecoveringManager


def body(result):
    return json.loads(result["content"][-1]["text"])


async def spawn(root, ports, *, guard=False):
    root.mkdir()
    proc = await asyncio.create_subprocess_exec(
        sys.executable, str(SERVER), "--host", "127.0.0.1", "--port", str(ports[0]),
        "--upload-port", str(ports[1]), "--startup-timeout", "60",
        "--bootstrap-out", str(root / "bootstrap.json"), "--cert-dir", str(root / "certs"),
        "--audit-dir", str(root / "audit"), "--log-file", str(root / "host.log"),
        *(["--agent-guard"] if guard else []),
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    return proc, Client(proc)


@pytest.mark.parametrize("guard", [False, True])
def test_two_stdio_conversations_release_reuse_and_preserve_active_owner(tmp_path, guard):
    async def run():
        ports = free_ports()
        p, a = await spawn(tmp_path / "a", ports, guard=guard)
        q, b = await spawn(tmp_path / "b", ports, guard=guard)
        try:
            for client in (a, b):
                await client.rpc("initialize")
                await client.rpc("initialize")
                await client.rpc("tools/list")
                assert (await client.call("runtime_get_state"))["runtime_state"] == "NOT_STARTED"
            assert_rebind(ports)
            assert (await a.call("task_submit", {"goal": "inert first task"}))["ok"]
            boot1 = json.loads((tmp_path / "a" / "bootstrap.json").read_text())
            # A live owner must survive B's bind failure.
            failed = await b.call("task_submit", {"goal": "inert second task"})
            assert failed["error"] == "RUNTIME_UNAVAILABLE"
            assert p.returncode is None
            assert (await a.call("runtime_get_state"))["ok"]
            assert (await a.call("session_stop", {"reason": "USER_STOP"}))["host_released"]
            assert_rebind(ports)
            assert (await a.call("session_stop", {"reason": "USER_STOP"}))["host_released"]
            assert (await a.call("runtime_get_state"))["host_released"]
            assert (await a.call("computer_type", {"text": "must not replay"}))["error"] == "SESSION_TERMINATED"
            assert_rebind(ports)
            # A new explicit submission may retry a failed bind after its owner released the ports.
            assert (await b.call("task_submit", {"goal": "explicit new task"}))["ok"]
            assert (await b.call("session_stop", {"reason": "USER_STOP"}))["host_released"]
            # The original MCP connection can also start a fresh session, with a new identity.
            assert (await a.call("task_submit", {"goal": "explicit third task"}))["ok"]
            boot2 = json.loads((tmp_path / "a" / "bootstrap.json").read_text())
            assert boot1["session_id"] != boot2["session_id"]
            assert (await a.call("session_stop", {"reason": "USER_STOP"}))["host_released"]
            assert_rebind(ports)
        finally:
            await stop(p)
            await stop(q)
    asyncio.run(run())


@pytest.mark.parametrize("occupied", [0, 1])
def test_bind_failure_preserves_unrelated_listener_and_releases_partial_start(tmp_path, occupied):
    async def run():
        ports = free_ports()
        with socket.socket() as owner:
            owner.bind(("127.0.0.1", ports[occupied]))
            owner.listen()
            p, c = await spawn(tmp_path / "client", ports)
            try:
                await c.rpc("initialize")
                assert (await c.call("task_submit", {"goal": "inert"}))["error"] == "RUNTIME_UNAVAILABLE"
                # Original listener is still accepting connections; the other port was not leaked.
                with socket.create_connection(("127.0.0.1", ports[occupied]), timeout=2):
                    pass
                assert_rebind([ports[1 - occupied]])
                state = await c.call("runtime_get_state")
                assert state["host_released"] and state["runtime_state"] == "START_FAILED"
            finally:
                await stop(p)
    asyncio.run(run())


def runtime(root, manager, timeout=20):
    config = args(root, startup_timeout=timeout)
    config.session = None
    config.port, config.upload_port = free_ports()
    config.no_auto_restart = True
    controller = McpRuntime(config, lambda a: HostBackend(a, sandbox_manager=manager))
    return controller, (config.port, config.upload_port)


def wait_until(predicate, seconds=12):
    deadline = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < deadline, "lifetime transition timed out"
        time.sleep(.05)


@pytest.mark.parametrize("mode", ["gone", "start_failure", "startup_timeout"])
def test_guest_end_releases_ports_without_another_tool_call(tmp_path, mode):
    manager = RecoveringManager(tmp_path / "guest", start_delay_s=0,
                                start_error=FakeError("START_FAILED", "injected") if mode == "start_failure" else None)
    controller, ports = runtime(tmp_path, manager, timeout=.4 if mode == "startup_timeout" else 20)
    try:
        assert body(controller.call("task_submit", {"goal": "inert"}))["ok"]
        backend = controller.backend
        if mode == "gone":
            wait_until(lambda: backend.launcher.state == "PUBLISHED")
            manager.sandbox_up = False
        wait_until(lambda: not backend.is_alive())
        assert_rebind(ports)
        assert backend.cleanup_confirmed
        assert manager.names().count("cleanup") == 1
        assert "reset_sandbox" not in manager.names() and "restart_runner" not in manager.names()
        assert body(controller.call("runtime_get_state", {}))["host_released"]
    finally:
        controller.shutdown()


def test_cleanup_failure_blocks_replacement_and_reports_uncertainty(tmp_path):
    class Failing(RecoveringManager):
        def cleanup(self, s):
            super().cleanup(s)
            return {"failed": ["injected"]}
    manager = Failing(tmp_path / "guest", start_delay_s=0)
    controller, ports = runtime(tmp_path, manager)
    try:
        assert body(controller.call("task_submit", {"goal": "inert"}))["ok"]
        wait_until(lambda: controller.backend.launcher.state == "PUBLISHED")
        result = body(controller.call("session_stop", {"reason": "USER_STOP"}))
        assert result["error"] == "CLEANUP_UNCONFIRMED"
        assert_rebind(ports)
        assert body(controller.call("task_submit", {"goal": "must not execute"}))["error"] == "CLEANUP_UNCONFIRMED"
        assert manager.names().count("start") == 1
    finally:
        controller.shutdown()


def test_invalid_and_readonly_cold_calls_do_not_start_host(tmp_path):
    def forbidden(_):
        raise AssertionError("must not construct backend")
    controller = McpRuntime(args(tmp_path), forbidden)
    assert body(controller.call("runtime_get_state", {}))["runtime_state"] == "NOT_STARTED"
    assert body(controller.call("runtime_get_state", {"action_id": "unknown"}))["error"] == "INVALID_ARGUMENT"
    assert body(controller.call("task_submit", {}))["error"] == "INVALID_ARGUMENT"
    assert body(controller.call("computer_click", {"x": "wrong"}))["error"] == "INVALID_ARGUMENT"
    assert body(controller.call("session_stop", {"reason": "USER_STOP"}))["host_released"]


def test_guarded_runtime_keeps_approval_without_taking_over_other_hosts(tmp_path, monkeypatch):
    def forbidden(*_):
        raise AssertionError("managed runtime must not reclaim another conversation")
    monkeypatch.setattr("host.single_host.take_over", forbidden)
    monkeypatch.setattr("host.single_host.reclaim_sandboxes", forbidden)
    manager = RecoveringManager(tmp_path / "guest", start_delay_s=0)
    controller, ports = runtime(tmp_path, manager)
    controller.args.agent_guard = True
    answers, asked = [False, True], []

    async def approver(summary):
        asked.append(summary["tool"])
        return answers.pop(0)

    controller.factory = lambda config: HostBackend(config, sandbox_manager=manager, approver=approver)
    tools = load_tool_list()
    guard_descriptions(tools)
    server = McpServer(controller, tools, strict_tools=True)

    def call(name, arguments):
        return body(server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                   "params": {"name": name, "arguments": arguments}})["result"])

    try:
        server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        listed = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]
        assert "only when the user says" in next(t["description"] for t in listed if t["name"] == "session_stop")
        assert call("runtime_get_state", {})["runtime_state"] == "NOT_STARTED"
        assert call("task_submit", {})["error"] == "INVALID_ARGUMENT"
        assert controller.backend is None
        assert_rebind(ports)
        assert call("task_submit", {"goal": "inert guarded task"})["ok"]
        wait_until(lambda: controller.backend.launcher.state == "PUBLISHED")
        assert call("session_stop", {"reason": "USER_STOP"})["error"] == "POLICY_DENIED"
        assert controller.backend.is_alive() and not controller.backend.session.terminated
        assert not set(manager.names()) & {"stop", "cleanup"}
        assert call("session_stop", {"reason": "USER_STOP"})["host_released"]
        assert_rebind(ports)
        assert asked == ["session_stop", "session_stop"]
    finally:
        controller.shutdown()


def test_eof_during_backend_start_remembers_shutdown(tmp_path):
    class SlowBackend(HostBackend):
        async def _main(self):
            await asyncio.sleep(.3)
            await super()._main()
    manager = RecoveringManager(tmp_path / "guest")
    backend = SlowBackend(args(tmp_path), sandbox_manager=manager)
    backend.start()
    backend.shutdown(timeout=5)
    assert not backend.is_alive() and backend.cleanup_confirmed
    assert not manager.calls


def test_unresolved_action_stays_unknown_after_retirement_without_replay(tmp_path):
    manager = RecoveringManager(tmp_path / "guest", start_delay_s=0)
    controller, ports = runtime(tmp_path, manager)
    try:
        assert body(controller.call("task_submit", {"goal": "inert"}))["ok"]
        backend = controller.backend
        wait_until(lambda: backend.launcher.state == "PUBLISHED")
        async def inject_unresolved():
            backend.session.actions["ACT-inflight"] = "SENT"
        asyncio.run_coroutine_threadsafe(inject_unresolved(), backend.loop).result(2)
        assert body(controller.call("session_stop", {"reason": "USER_STOP"}))["host_released"]
        for _ in range(2):
            state = body(controller.call("runtime_get_state", {"action_id": "ACT-inflight"}))
            assert state["action"] == {"action_id": "ACT-inflight", "status": "UNKNOWN"}
        assert manager.names().count("start") == 1
        assert_rebind(ports)
    finally:
        controller.shutdown()


def test_uncertain_guest_probe_does_not_stop_or_restart_live_guest(tmp_path):
    class Uncertain(RecoveringManager):
        def is_running(self, s):
            self.calls.append(("is_running",))
            raise OSError("injected observation outage")
    manager = Uncertain(tmp_path / "guest", start_delay_s=0)
    controller, ports = runtime(tmp_path, manager)
    try:
        assert body(controller.call("task_submit", {"goal": "inert"}))["ok"]
        wait_until(lambda: "is_running" in manager.names())
        assert controller.backend.is_alive() and not controller.backend.session.terminated
        assert not set(manager.names()) & {"stop", "cleanup", "restart_runner", "reset_sandbox"}
    finally:
        controller.shutdown()
    assert_rebind(ports)


def test_session_private_files_do_not_touch_another_hosts_upload(tmp_path):
    def capture(config):
        assert config.cert_dir.parent == tmp_path / "certs"
        assert config.artifact_dir.parent == tmp_path / "artifacts"
        assert config.cert_dir.name == config.artifact_dir.name == config.session
        raise RuntimeError("captured before launch")
    config = args(tmp_path)
    config.artifact_dir = tmp_path / "artifacts"
    controller = McpRuntime(config, capture)
    with pytest.raises(RuntimeError, match="captured before launch"):
        controller.call("task_submit", {"goal": "inert"})
