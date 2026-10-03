"""Recovery while the Host is alive (host/lifecycle.py + sandbox_manager restart_runner / reset_sandbox).

    lost, not back within the grace period, Sandbox there   → restart_runner, generation 2
    lost, not back, Sandbox gone (the user closed it)        → no restart, session ends
    connected but heartbeats unanswered                      → reset_sandbox, generation 2
    restart_runner fails                                     → reset_sandbox (generation 3)
    reset fails / restarts off                               → session ends, Sandbox stopped

Timing is shortened (grace 1 s, heartbeat 0.5 s) through the test-only session_tuning.
"""

import asyncio
import time

from websockets.exceptions import InvalidStatus

from host.mcp_server import HostBackend
from host.runtime_session import RuntimeSession
from test_sandbox_launch import FakeError, FakeManager, Host, args, guest, paths, run

TUNING = {"reconnect_grace_s": 1.0, "heartbeat_interval_s": 0.5, "alive_timeout_s": 0.3}


class RecoveringManager(FakeManager):
    """FakeManager plus the recovery calls, shaped like sandbox_manager ac56d7c."""

    def __init__(self, *a, restart_error=None, reset_error=None, **kw):
        super().__init__(*a, **kw)
        self.restart_error, self.reset_error = restart_error, reset_error
        self.sandbox_up = True

    def prepare(self, session_id, runtime_id, generation, runner_exe):
        s = super().prepare(session_id, runtime_id, generation, runner_exe)
        s.generation = generation
        return s

    def is_running(self, s):
        self.calls.append(("is_running",))
        return self.sandbox_up

    def restart_runner(self, s, generation):
        assert generation > s.generation
        self.calls.append(("restart_runner", generation))
        s.ready_path.unlink(missing_ok=True)
        s.bootstrap_path.unlink(missing_ok=True)
        s.generation, s.state = generation, "RESTARTING"     # like the real one, before the Guest command
        if self.restart_error:
            raise self.restart_error

    def reset_sandbox(self, s, generation):
        assert generation > s.generation
        self.calls.append(("reset_sandbox", generation))
        if self.reset_error:
            raise self.reset_error
        s.ready_path.unlink(missing_ok=True)
        s.bootstrap_path.unlink(missing_ok=True)
        s.generation, s.state = generation, "STARTED"
        return "127.0.0.1"

    def publish_bootstrap(self, s, cert_pem):
        if s.state == "RESTARTING":
            s.state = "STARTED"                              # the real one accepts RESTARTING too
        super().publish_bootstrap(s, cert_pem)


class RecoveringHost(Host):
    def __init__(self, tmp_path, manager, no_auto_restart=False):
        a = args(tmp_path)
        a.session_tuning = TUNING
        a.no_auto_restart = no_auto_restart
        self.backend = HostBackend(a, sandbox_manager=manager)
        self.backend.start()
        assert self.backend.ready.wait(20) and not self.backend.error, self.backend.error


async def start_ready(host, fake, tmp_path):
    await host.call("task_submit", {"goal": "g"})
    r, boot, serving = await guest(*paths(tmp_path / "sbx"))
    await host.wait_state("READY")
    return r, boot, serving


async def wait_republished(tmp_path, timeout=15):
    """The Guest side: a new ready marker means a new generation's bootstrap is there."""
    ready, _ = paths(tmp_path / "sbx")
    deadline = time.monotonic() + timeout
    while not ready.exists():
        assert time.monotonic() < deadline, "no new bootstrap"
        await asyncio.sleep(0.05)


# --------------------------------------------------------------------- tests
def test_runner_lost_with_the_sandbox_up_is_restarted_in_the_same_sandbox(tmp_path):
    fake = RecoveringManager(tmp_path / "sbx")

    async def body():
        host = RecoveringHost(tmp_path, fake)
        r1, boot1, serving1 = await start_ready(host, fake, tmp_path)
        first = await host.call("computer_observe")
        r1.drop()                                            # the Runner process dies
        await serving1
        waiting = await host.call("computer_observe")        # during the grace period / restart
        await wait_republished(tmp_path)
        r2, boot2, serving2 = await guest(*paths(tmp_path / "sbx"))
        again = await host.call("computer_observe", {"wait_ms": 10000})
        state = await host.call("runtime_get_state")
        # the old generation's credentials are dead
        try:
            await r1.connect(r1.reconnect_token)
            old_refused = False
        except InvalidStatus:
            old_refused = True
        stopped = await host.call("session_stop", {"reason": "TASK_COMPLETE"})
        await serving2
        await asyncio.to_thread(host.backend.shutdown)
        return first, waiting, boot1, boot2, again, state, old_refused, stopped

    first, waiting, boot1, boot2, again, state, old_refused, stopped = run(body())
    assert waiting["error"] == "RUNTIME_UNAVAILABLE" and waiting["retryable"]
    assert (boot1["generation"], boot2["generation"]) == (1, 2)
    assert boot1["session_id"] == boot2["session_id"] and boot1["token"] != boot2["token"]
    assert again["ok"] and "restarted" in again["notice"] and "computer_observe" in again["notice"]
    assert int(again["action_id"][4:]) > int(first["action_id"][4:])      # ids keep counting
    assert state["sandbox"]["generation"] == 2 and state["sandbox"]["recoveries"] == ["restart_runner"]
    assert "notice" not in state                                          # told once
    assert old_refused
    assert stopped["ok"]
    names = fake.names()
    assert names.count("start") == 1 and "reset_sandbox" not in names    # same Sandbox
    assert names.count("publish_bootstrap") == 2 and names.count("mark_ready") == 2
    assert ("stop", "TASK_COMPLETE", False) in fake.calls and names[-1] == "cleanup"


def test_sandbox_gone_means_closed_by_the_user_and_is_not_restarted(tmp_path):
    fake = RecoveringManager(tmp_path / "sbx")

    async def body():
        host = RecoveringHost(tmp_path, fake)
        r, _, serving = await start_ready(host, fake, tmp_path)
        fake.sandbox_up = False                              # the window was closed
        r.drop()
        await serving
        ended = await host.wait_state("SESSION_TERMINATED")
        await asyncio.sleep(0.3)
        status = host.backend.launcher.status()
        await asyncio.to_thread(host.backend.shutdown)
        return ended, status

    ended, status = run(body())
    assert "RUNTIME_GONE" in ended["message"]
    assert "restart_runner" not in fake.names() and "reset_sandbox" not in fake.names()
    assert ("stop", "USER_STOP", True) in fake.calls and fake.names()[-1] == "cleanup"
    assert status["recoveries"] == []


def test_connected_but_silent_sandbox_is_reset(tmp_path):
    fake = RecoveringManager(tmp_path / "sbx")

    async def body():
        host = RecoveringHost(tmp_path, fake)
        r1, _, serving1 = await start_ready(host, fake, tmp_path)
        r1.answer_heartbeats = False                         # hung: connected, never answers
        await asyncio.wait_for(serving1, 15)                 # the Host closes it when replacing it
        await wait_republished(tmp_path)
        r2, boot2, serving2 = await guest(*paths(tmp_path / "sbx"))
        again = await host.call("computer_observe", {"wait_ms": 10000})
        await asyncio.to_thread(host.backend.shutdown)
        await serving2
        return boot2, again, host.backend.launcher.status()

    boot2, again, status = run(body())
    assert boot2["generation"] == 2 and again["ok"] and "notice" in again
    assert ("reset_sandbox", 2) in fake.calls and "restart_runner" not in fake.names()
    assert status["recoveries"] == ["reset_sandbox"]


def test_failed_runner_restart_falls_back_to_a_new_sandbox(tmp_path):
    fake = RecoveringManager(tmp_path / "sbx", restart_error=FakeError(
        "RUNTIME_START_FAILED", "Guest restart script exit 3 (3: old Runner would not end)"))

    async def body():
        host = RecoveringHost(tmp_path, fake)
        r1, _, serving1 = await start_ready(host, fake, tmp_path)
        r1.drop()
        await serving1
        await wait_republished(tmp_path)
        r2, boot2, serving2 = await guest(*paths(tmp_path / "sbx"))
        again = await host.call("computer_observe", {"wait_ms": 10000})
        await asyncio.to_thread(host.backend.shutdown)
        await serving2
        return boot2, again, host.backend.launcher.status()

    boot2, again, status = run(body())
    # restart_runner had already taken generation 2, so the reset uses 3
    assert ("restart_runner", 2) in fake.calls and ("reset_sandbox", 3) in fake.calls
    assert boot2["generation"] == 3 and again["ok"]
    assert status["recoveries"] == ["reset_sandbox"] and status["generation"] == 3


def test_failed_recovery_ends_the_session_and_stops_the_sandbox(tmp_path):
    fake = RecoveringManager(tmp_path / "sbx",
                             restart_error=FakeError("RUNTIME_START_FAILED", "exit 3"),
                             reset_error=FakeError("RUNTIME_UNAVAILABLE", "restart limit reached (3/3); stop the session"))

    async def body():
        host = RecoveringHost(tmp_path, fake)
        r, _, serving = await start_ready(host, fake, tmp_path)
        r.drop()
        await serving
        ended = await host.wait_state("SESSION_TERMINATED")
        await asyncio.sleep(0.3)
        status = host.backend.launcher.status()
        await asyncio.to_thread(host.backend.shutdown)
        return ended, status

    ended, status = run(body())
    assert "recovery" in ended["message"] and "restart limit" in ended["message"]
    assert status["state"] == "FAILED"
    assert ("stop", "RUNTIME_ERROR", True) in fake.calls and fake.names()[-1] == "cleanup"


def test_with_restarts_off_a_lost_runtime_ends_the_session(tmp_path):
    fake = RecoveringManager(tmp_path / "sbx")

    async def body():
        host = RecoveringHost(tmp_path, fake, no_auto_restart=True)
        r, _, serving = await start_ready(host, fake, tmp_path)
        r.drop()
        await serving
        ended = await host.wait_state("SESSION_TERMINATED")
        await asyncio.sleep(0.3)
        await asyncio.to_thread(host.backend.shutdown)
        return ended

    ended = run(body())
    assert "RUNTIME_LOST" in ended["message"]
    assert "restart_runner" not in fake.names() and "reset_sandbox" not in fake.names()
    assert ("stop", "RUNTIME_ERROR", True) in fake.calls


def test_a_new_generation_keeps_ids_and_marks_unfinished_actions_unknown():
    old = RuntimeSession(("SES-1", "RT-1", 1))
    old._task_seq, old._action_seq = 1, 7
    old.actions = {"ACT-000005": "SUCCESS", "ACT-000006": "UNKNOWN", "ACT-000007": "SENT"}
    new = RuntimeSession(("SES-1", "RT-1", 2))
    unresolved = new.inherit(old)
    assert unresolved == ["ACT-000006", "ACT-000007"]
    assert new.actions == {"ACT-000005": "SUCCESS", "ACT-000006": "UNKNOWN", "ACT-000007": "UNKNOWN"}
    assert new.next_action() == "ACT-000008" and new.next_task() == "TASK-000002"
    assert new.last_observation is None                      # look at the screen again


# --------------------------------------------------------------------- with the real Sandbox Manager
def test_runner_restart_with_the_lifecycle_sandbox_manager(tmp_path):
    """Their restart_runner / publish_bootstrap / mark_ready with only `wsb` and the network replaced."""
    import json
    from types import SimpleNamespace

    import pytest
    sm = pytest.importorskip("sandbox_manager")
    if not hasattr(sm.SandboxManager, "restart_runner"):
        pytest.skip("sandbox_manager without restart_runner")
    from sandbox_manager import config

    class Wsb:
        def __init__(self):
            self.live, self.execs = set(), []
        def running(self):
            return set(self.live)
        def start(self, xml):
            self.live.add("sbx-1")
            return "sbx-1"
        def connect(self, sandbox_id):
            pass
        def ip(self, sandbox_id):
            return "127.0.0.2"
        def exec(self, sandbox_id, command, **kw):
            self.execs.append(command)                       # the one fixed restart command
            return 0
        def stop(self, sandbox_id):
            self.live.discard(sandbox_id)

    wsb = Wsb()
    exe = tmp_path / "runner.exe"
    exe.write_bytes(b"MZ fake runner")
    manager = sm.SandboxManager(tmp_path / "sm", wsb=wsb, network=SimpleNamespace(
        toward=lambda ip: "127.0.0.1", switch_ipv4=lambda: "127.0.0.1"),
        firewall=SimpleNamespace(problems=lambda: []), sleep=lambda s: None)
    d = tmp_path / "sm" / "sessions" / "SES-TEST-001" / "bootstrap"
    marker, boot_file = d / config.READY_NAME, d / config.BOOTSTRAP_NAME

    async def body():
        a = args(tmp_path)
        a.runner_exe, a.session_tuning = exe, TUNING
        host = Host.__new__(Host)
        host.backend = HostBackend(a, sandbox_manager=manager)
        host.backend.start()
        assert host.backend.ready.wait(20) and not host.backend.error, host.backend.error
        await host.call("task_submit", {"goal": "g"})
        r1, _, serving1 = await guest(marker, boot_file)
        await host.wait_state("READY")
        r1.drop()
        await serving1
        r2, boot2, serving2 = await guest(marker, boot_file)    # the restart script waits for this
        again = await host.call("computer_observe", {"wait_ms": 10000})
        await asyncio.sleep(0.3)
        token_left = boot_file.exists()
        await host.call("session_stop", {"reason": "TASK_COMPLETE"})
        await serving2
        await asyncio.to_thread(host.backend.shutdown)
        return boot2, again, token_left

    boot2, again, token_left = run(body())
    assert boot2["generation"] == 2 and again["ok"] and "notice" in again
    assert wsb.execs == [config.restart_command()] and not token_left
    state = json.loads((tmp_path / "sm" / "sessions" / "SES-TEST-001" / "state.json").read_text(encoding="utf-8"))
    kinds = [e["kind"] for e in state["events"]]
    assert "RUNNER_RESTARTED" in kinds and state["generation"] == 2 and state["restarts"] == 1
    assert state["state"] == "TERMINATED" and kinds[-1] == "CLEANUP" and not wsb.live
