"""The Sandbox starts at task_submit and is stopped when the session ends (host/lifecycle.py).

The Host backend runs as in mcp_server.py, with a Sandbox Manager that does not
start Windows Sandbox. A "Guest" coroutine plays the Lifecycle start script:
it waits for the ready marker, reads bootstrap.json and connects MiniRunner.

The last test uses the Lifecycle team's real SandboxManager with only wsb,
the network lookup and the firewall check replaced, so the file hand-over
(bootstrap path, ready marker, token file removal, cleanup) is theirs.
"""

import argparse
import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509

from host import tls
from host.mcp_server import HostBackend
from mini_runner import MiniRunner

SES = "SES-TEST-001"


# --------------------------------------------------------------------- fakes
class FakeError(Exception):
    """Shaped like sandbox_manager.SandboxManagerError."""
    def __init__(self, code, message):
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


class FakeManager:
    def __init__(self, root: Path, *, start_error=None, start_delay_s=0.3):
        self.root, self.start_error, self.start_delay_s = root, start_error, start_delay_s
        self.calls: list[tuple] = []

    def prepare(self, session_id, runtime_id, generation, runner_exe):
        self.calls.append(("prepare", session_id, runtime_id, generation))
        d = self.root / session_id / "bootstrap"
        d.mkdir(parents=True)
        return SimpleNamespace(session_id=session_id, state="PREPARED", bootstrap_path=d / "bootstrap.json",
                               ready_path=d / "bootstrap.ready")

    def start(self, s):
        time.sleep(self.start_delay_s)                      # wsb start takes a while
        self.calls.append(("start",))
        if self.start_error:
            s.state = "FAILED"                              # the real one stops its own Sandbox first
            raise self.start_error
        s.state = "STARTED"
        return "127.0.0.1"

    def publish_bootstrap(self, s, cert_pem):
        assert s.state == "STARTED" and "PRIVATE KEY" not in cert_pem
        json.loads(s.bootstrap_path.read_text(encoding="utf-8"))   # the Host wrote it first
        self.calls.append(("publish_bootstrap",))
        s.ready_path.write_text("")
        s.state = "RUNNING"

    def mark_ready(self, s):
        self.calls.append(("mark_ready",))
        s.bootstrap_path.unlink()

    def stop(self, s, reason, *, emergency=False):
        self.calls.append(("stop", reason, emergency))
        s.state = "TERMINATED" if s.state != "FAILED" else "FAILED"
        return s

    def cleanup(self, s):
        self.calls.append(("cleanup",))
        return {"removed": ["bootstrap"], "failed": []}

    def names(self):
        return [c[0] for c in self.calls]


def args(tmp_path, startup_timeout=20.0):
    return argparse.Namespace(
        host="127.0.0.1", port=0, upload_port=0, session=SES, runtime="RT-SBX-001", generation=1,
        startup_timeout=startup_timeout, advertise_address=None, bootstrap_out=None, runner_exe=None,
        sandbox_root=None, cert_dir=tmp_path / "certs", audit_dir=tmp_path / "audit")


class Host:
    def __init__(self, tmp_path, manager, **kw):
        self.backend = HostBackend(args(tmp_path, **kw), sandbox_manager=manager)
        self.backend.start()
        assert self.backend.ready.wait(20) and not self.backend.error, self.backend.error

    async def call(self, tool, arguments=None):
        r = await asyncio.to_thread(self.backend.call, tool, arguments or {})
        return json.loads(r["content"][-1]["text"])

    async def wait_state(self, want, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            st = await self.call("runtime_get_state")
            if st.get("runtime_state") == want or st.get("error") == want:
                return st
            await asyncio.sleep(0.3)                             # stay under 5 control calls/s
        raise AssertionError(f"never {want}: {st}")


async def guest(ready_path: Path, bootstrap_path: Path, timeout=15):
    """What the Lifecycle start script does in the Sandbox: wait for the marker, start the Runner."""
    deadline = time.monotonic() + timeout
    while not ready_path.exists():
        assert time.monotonic() < deadline, "no ready marker"
        await asyncio.sleep(0.05)
    boot = json.loads(bootstrap_path.read_text(encoding="utf-8"))
    r = MiniRunner(boot["port"], boot["host_certificate_pem"],
                   (boot["session_id"], boot["runtime_id"], boot["generation"]))
    await r.connect(boot["token"])
    return r, boot, asyncio.create_task(r.serve())


def paths(root: Path):
    d = root / SES / "bootstrap"
    return d / "bootstrap.ready", d / "bootstrap.json"


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 90))


# --------------------------------------------------------------------- tests
def test_task_submit_starts_the_sandbox_and_session_stop_removes_it(tmp_path):
    fake = FakeManager(tmp_path / "sbx", start_delay_s=1.0)

    async def body():
        host = Host(tmp_path, fake)
        assert fake.calls == []                                  # nothing starts before the task
        t0 = time.monotonic()
        submitted = await host.call("task_submit", {"goal": "메모장 열기"})
        took = time.monotonic() - t0
        r, boot, serving = await guest(*paths(tmp_path / "sbx"))
        await host.wait_state("READY")
        obs = await host.call("computer_observe")
        stopped = await host.call("session_stop", {"reason": "TASK_COMPLETE"})
        assert await asyncio.wait_for(serving, 10) == "terminated"
        host.backend.shutdown()
        return submitted, took, boot, obs, stopped

    submitted, took, boot, obs, stopped = run(body())
    assert took < 0.9                                            # did not wait for wsb start
    assert submitted["runtime_state"] == "PREPARING" and "wait_ms" in submitted["message"]
    assert submitted["sandbox"]["state"] == "LAUNCHING"
    assert boot["host"] == "127.0.0.1" and boot["session_id"] == SES
    san = x509.load_pem_x509_certificate(boot["host_certificate_pem"].encode()) \
        .extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "127.0.0.1" in {str(ip) for ip in san.get_values_for_type(x509.IPAddress)}
    assert obs["ok"] and stopped["ok"]
    assert fake.names() == ["prepare", "start", "publish_bootstrap", "mark_ready", "stop", "cleanup"]
    assert ("stop", "TASK_COMPLETE", False) in fake.calls        # TERMINATE went first: not an emergency
    assert not paths(tmp_path / "sbx")[1].exists()               # the token file is gone after READY


def test_observe_with_wait_ms_waits_for_the_sandbox(tmp_path):
    fake = FakeManager(tmp_path / "sbx", start_delay_s=1.0)

    async def body():
        host = Host(tmp_path, fake)
        await host.call("task_submit", {"goal": "g"})
        early = await host.call("computer_observe")              # no wait: fails at once
        runner = asyncio.create_task(guest(*paths(tmp_path / "sbx")))
        t0 = time.monotonic()
        waited = await host.call("computer_observe", {"wait_ms": 10000})
        took = time.monotonic() - t0
        await host.call("session_stop", {"reason": "TASK_COMPLETE"})
        await (await runner)[2]
        host.backend.shutdown()
        return early, waited, took

    early, waited, took = run(body())
    assert early["error"] == "RUNTIME_UNAVAILABLE" and early["retryable"]
    assert waited["ok"] and waited["observation_id"]
    assert took < 9.5                                            # returned soon after READY, not after 10 s


def test_start_failure_ends_the_session_and_cleans_up(tmp_path):
    fake = FakeManager(tmp_path / "sbx", start_error=FakeError(
        "RUNTIME_UNAVAILABLE", "firewall not ready: no active allow rule for TCP 17443"))

    async def body():
        host = Host(tmp_path, fake)
        submitted = await host.call("task_submit", {"goal": "g"})
        ended = await host.wait_state("SESSION_TERMINATED")
        await asyncio.sleep(0.3)
        host.backend.shutdown()
        return submitted, ended, host.backend.launcher.status()

    submitted, ended, status = run(body())
    assert submitted["ok"]
    assert "firewall not ready" in ended["message"] and "RUNTIME_START_FAILED" in ended["message"]
    assert status["state"] == "FAILED" and status["error"].startswith("RUNTIME_UNAVAILABLE")
    assert "publish_bootstrap" not in fake.names()
    assert fake.names()[-2:] == ["stop", "cleanup"]
    assert fake.calls[-2] == ("stop", "RUNTIME_ERROR", True)


def test_runner_that_never_connects_times_out_and_the_sandbox_is_stopped(tmp_path):
    fake = FakeManager(tmp_path / "sbx", start_delay_s=0.1)

    async def body():
        host = Host(tmp_path, fake, startup_timeout=1.5)
        await host.call("task_submit", {"goal": "g"})
        ended = await host.wait_state("SESSION_TERMINATED")
        await asyncio.sleep(0.3)
        host.backend.shutdown()
        return ended

    ended = run(body())
    assert "timeout" in ended["message"]
    assert ("stop", "TIMEOUT", True) in fake.calls and fake.names()[-1] == "cleanup"


def test_codex_closing_the_server_terminates_the_runner_and_stops_the_sandbox(tmp_path):
    fake = FakeManager(tmp_path / "sbx")

    async def body():
        host = Host(tmp_path, fake)
        await host.call("task_submit", {"goal": "g"})
        r, _, serving = await guest(*paths(tmp_path / "sbx"))
        await host.wait_state("READY")
        await asyncio.to_thread(host.backend.shutdown)           # what main() does when stdin closes
        return await asyncio.wait_for(serving, 10)

    assert run(body()) == "terminated"
    assert ("stop", "USER_STOP", False) in fake.calls and fake.names()[-1] == "cleanup"


def test_only_the_first_task_submit_starts_a_sandbox(tmp_path):
    fake = FakeManager(tmp_path / "sbx")

    async def body():
        host = Host(tmp_path, fake)
        await host.call("task_submit", {"goal": "a"})
        await host.call("task_submit", {"goal": "b"})
        r, _, serving = await guest(*paths(tmp_path / "sbx"))
        await host.wait_state("READY")
        await asyncio.to_thread(host.backend.shutdown)
        await serving

    run(body())
    assert fake.names().count("prepare") == 1 and fake.names().count("start") == 1


def test_before_task_submit_nothing_is_started_and_exit_is_quiet(tmp_path):
    fake = FakeManager(tmp_path / "sbx")
    host = Host(tmp_path, fake)
    host.backend.shutdown()
    assert fake.calls == [] and not host.backend.is_alive()


# --------------------------------------------------------------------- with the real Sandbox Manager
def test_with_the_lifecycle_sandbox_manager(tmp_path):
    sm = pytest.importorskip("sandbox_manager")
    from sandbox_manager import config

    class Wsb:                                   # Windows Sandbox CLI, minus the Sandbox
        def __init__(self):
            self.live: set[str] = set()
        def running(self):
            return set(self.live)
        def start(self, xml):
            assert config.GUEST_BOOTSTRAP in xml and config.GUEST_PACKAGE in xml
            self.live.add("sbx-1")
            return "sbx-1"
        def connect(self, sandbox_id):
            pass
        def ip(self, sandbox_id):
            return "127.0.0.2"
        def stop(self, sandbox_id):
            self.live.discard(sandbox_id)

    net = SimpleNamespace(toward=lambda ip: "127.0.0.1", switch_ipv4=lambda: "127.0.0.1")
    firewall = SimpleNamespace(problems=lambda: [])
    exe = tmp_path / "runner.exe"
    exe.write_bytes(b"MZ fake runner")
    wsb = Wsb()
    manager = sm.SandboxManager(tmp_path / "sm", wsb=wsb, network=net, firewall=firewall,
                                sleep=lambda s: None)

    async def body():
        a = args(tmp_path)
        a.runner_exe = exe
        backend = HostBackend(a, sandbox_manager=manager)
        backend.start()
        assert backend.ready.wait(20) and not backend.error, backend.error
        host = Host.__new__(Host)
        host.backend = backend
        await host.call("task_submit", {"goal": "g"})
        d = tmp_path / "sm" / "sessions" / SES / "bootstrap"
        r, boot, serving = await guest(d / config.READY_NAME, d / config.BOOTSTRAP_NAME)
        # What the Guest script reads next to bootstrap.json:
        address = (d / config.ADDRESS_NAME).read_text(encoding="ascii")
        cert_der = (d / config.CERT_NAME).read_bytes()
        await host.wait_state("READY")
        await asyncio.sleep(0.3)                                 # mark_ready runs in a worker thread
        token_file_left = (d / config.BOOTSTRAP_NAME).exists()
        await host.call("session_stop", {"reason": "TASK_COMPLETE"})
        await asyncio.wait_for(serving, 10)
        await asyncio.to_thread(backend.shutdown)
        return boot, address, cert_der, token_file_left

    boot, address, cert_der, token_file_left = run(body())
    assert address == "127.0.0.1" == boot["host"]
    import hashlib
    assert hashlib.sha256(cert_der).hexdigest() == boot["host_certificate_sha256"] == \
        tls.fingerprint(boot["host_certificate_pem"])
    assert not token_file_left                                   # mark_ready deleted it
    state = json.loads((tmp_path / "sm" / "sessions" / SES / "state.json").read_text(encoding="utf-8"))
    assert state["state"] == "TERMINATED" and state["termination_reason"] == "TASK_COMPLETE"
    assert not wsb.live                                          # stopped
    assert not (tmp_path / "sm" / "sessions" / SES / "package").exists()   # cleaned up
    assert [e["kind"] for e in state["events"]][-1] == "CLEANUP"
