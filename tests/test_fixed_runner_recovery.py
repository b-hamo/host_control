"""Fixed VM recovery: exact process exit proof precedes a fresh SCRP generation."""
import asyncio

from websockets.exceptions import InvalidStatus

from test_sandbox_recovery import RecoveringHost, RecoveringManager, start_ready, wait_republished
from test_sandbox_launch import guest, paths, run


class FixedManager(RecoveringManager):
    fixed_vm_binding = True

    def prepare(self, *args):
        session = super().prepare(*args)
        session.micro_vm = {"output_storage_generation": 1}
        return session

    def runner_exited(self, session):
        self.calls.append(("runner_exited",))
        return True


def test_confirmed_exit_restarts_same_vm_with_new_credentials_and_stable_output(tmp_path):
    manager = FixedManager(tmp_path / "sbx")

    async def body():
        host = RecoveringHost(tmp_path, manager)
        first, boot1, serving1 = await start_ready(host, manager, tmp_path)
        first.drop()
        await serving1
        await wait_republished(tmp_path)
        second, boot2, serving2 = await guest(*paths(tmp_path / "sbx"))
        await host.wait_state("READY")
        assert boot2["generation"] == 2 and boot1["token"] != boot2["token"]
        assert boot1["output_storage_generation"] == boot2["output_storage_generation"] == 1
        assert host.backend.launcher.recoveries == ["restart_runner_same_vm"]
        assert manager.names().count("start") == 1 and "reset_sandbox" not in manager.names()
        try:
            await first.connect(first.reconnect_token)
            raise AssertionError("retired credential accepted")
        except InvalidStatus:
            pass
        assert (await host.call("computer_observe"))["ok"]
        await host.call("session_stop", {"reason": "USER_STOP"})
        await serving2
        await asyncio.to_thread(host.backend.shutdown)

    run(body())
    assert manager.names().index("runner_exited") < manager.names().index("restart_runner")


def test_failed_new_startup_preserves_vm_until_explicit_stop(tmp_path):
    manager = FixedManager(tmp_path / "sbx")

    async def body():
        host = RecoveringHost(tmp_path, manager)
        first, _, serving = await start_ready(host, manager, tmp_path)
        first.drop()
        await serving
        await wait_republished(tmp_path)
        future = asyncio.run_coroutine_threadsafe(
            host.backend.launcher.session.fail_startup("fixture: new Runner did not verify"), host.backend.loop)
        await asyncio.wrap_future(future)
        assert not {"stop", "cleanup", "reset_sandbox"}.intersection(manager.names())
        assert host.backend.launcher.state == "FAILED"
        assert "preserved" in host.backend.launcher.error
        await host.call("session_stop", {"reason": "USER_STOP"})
        await asyncio.to_thread(host.backend.shutdown)

    run(body())
    assert "stop" in manager.names() and "cleanup" in manager.names()


def test_output_scope_retains_storage_but_not_execution_generation(tmp_path):
    import pytest
    from host.sandbox_run import SandboxRunner
    from host.router_command_bundle import output_directory
    runner = SandboxRunner(tmp_path)
    runner.bind_output_storage(1)
    assert runner.output_directory(("SES-proof", "RT-proof", 2)) == output_directory(("SES-proof", "RT-proof", 1))
    with pytest.raises(ValueError): output_directory(("SES-proof", "RT-proof", 1), 2)
    runner.runs["RUN-proof"] = object()
    with pytest.raises(RuntimeError): runner.bind_output_storage(2)
