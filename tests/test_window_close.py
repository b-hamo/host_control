"""Real Host/MiniRunner protocol; only the Windows VM/window backend is faked."""
import asyncio

import pytest

from host.lifecycle import FAILED, STOPPED
from test_sandbox_launch import Host, FakeError, run
from test_sandbox_recovery import RecoveringHost, RecoveringManager, start_ready


class WindowManager(RecoveringManager):
    window = "OPEN"

    def window_state(self, sandbox):
        return self.window


async def finished(host):
    for _ in range(150):
        task = host.backend.launcher._finish
        if task is not None and task.done():
            return host.backend.launcher
        await asyncio.sleep(0.1)
    raise AssertionError("window close did not finish cleanup")


@pytest.mark.parametrize('window_state', ['OPEN', 'UNSEEN', 'UNKNOWN', 'MISSING'])
def test_nonclosed_window_keeps_session_running(tmp_path, window_state):
    manager = WindowManager(tmp_path / 'sbx')

    async def body():
        host = Host(tmp_path, manager)
        runner, boot, serving = await start_ready(host, manager, tmp_path)
        manager.window = window_state
        await asyncio.sleep(0.7)
        assert not host.backend.session.terminated
        assert 'stop' not in manager.names()
        manager.window = 'CLOSED'
        assert await asyncio.wait_for(serving, 10) == 'terminated'
        launcher = await finished(host)
        assert launcher.state == STOPPED
        assert host.backend.session.end_reason == 'USER_STOP'
        assert manager.calls.count(('stop', 'USER_STOP', False)) == 1
        assert manager.names().count('cleanup') == 1
        await asyncio.to_thread(host.backend.shutdown)
    run(body())


def test_close_before_runner_connects_stops_vm(tmp_path):
    manager = WindowManager(tmp_path / 'sbx')
    manager.window = 'CLOSED'

    async def body():
        host = Host(tmp_path, manager)
        await host.call('task_submit', {'goal': 'g'})
        launcher = await finished(host)
        assert launcher.state == STOPPED
        assert ('stop', 'USER_STOP', True) in manager.calls
        assert not launcher.recoveries
        await asyncio.to_thread(host.backend.shutdown)
    run(body())


@pytest.mark.parametrize('no_auto_restart', [False, True])
def test_close_wins_over_disconnected_runner_recovery(tmp_path, no_auto_restart):
    manager = WindowManager(tmp_path / 'sbx')

    async def body():
        host = RecoveringHost(tmp_path, manager, no_auto_restart=no_auto_restart)
        runner, boot, serving = await start_ready(host, manager, tmp_path)
        manager.window = 'MISSING'
        runner.drop()
        await serving
        await asyncio.sleep(1.4)  # recovery grace expired; window absence is not yet confirmed
        assert not {'restart_runner', 'reset_sandbox'} & set(manager.names())
        manager.window = 'CLOSED'
        launcher = await finished(host)
        assert launcher.state == STOPPED
        assert not launcher.recoveries
        assert ('stop', 'USER_STOP', True) in manager.calls
        assert not {'restart_runner', 'reset_sandbox'} & set(manager.names())
        await asyncio.to_thread(host.backend.shutdown)
    run(body())


def test_stop_failure_is_reported_and_does_not_export(tmp_path):
    class BrokenStop(WindowManager):
        def stop(self, s, reason, *, emergency=False):
            self.calls.append(('stop', reason, emergency))
            raise FakeError('RUNTIME_UNAVAILABLE', 'VM still listed')
    manager = BrokenStop(tmp_path / 'sbx')

    async def body():
        host = Host(tmp_path, manager)
        runner, boot, serving = await start_ready(host, manager, tmp_path)
        manager.window = 'CLOSED'
        await asyncio.wait_for(serving, 10)
        launcher = await finished(host)
        assert launcher.state == FAILED
        assert 'VM still listed' in launcher.error
        assert 'cleanup' not in manager.names()
        await asyncio.to_thread(host.backend.shutdown)
        assert not host.backend.cleanup_confirmed
        assert 'cleanup unconfirmed' in host.backend.error
    run(body())


def test_terminate_failure_still_stops_owned_vm(tmp_path):
    manager = WindowManager(tmp_path / 'sbx')

    async def body():
        host = Host(tmp_path, manager)
        runner, boot, serving = await start_ready(host, manager, tmp_path)

        async def fail(reason):
            raise TimeoutError('TERMINATE transport unavailable')

        host.backend.session.terminate = fail
        manager.window = 'CLOSED'
        launcher = await finished(host)
        await asyncio.wait_for(serving, 10)
        assert launcher.state == STOPPED
        assert ('stop', 'USER_STOP', True) in manager.calls
        await asyncio.to_thread(host.backend.shutdown)
    run(body())


def test_output_capture_precedes_terminate_and_finish_follows_vm_cleanup(tmp_path):
    manager, events = WindowManager(tmp_path / 'sbx'), []
    async def body():
        host = Host(tmp_path, manager)
        _, _, serving = await start_ready(host, manager, tmp_path)
        launcher = host.backend.launcher
        async def capture(session, reason):
            assert not session.terminated and 'stop' not in manager.names()
            events.append('capture')
        class Output:
            acquisition = {}
            async def finish_closed(self):
                assert 'cleanup' in manager.names() and host.backend.session.terminated
                events.append('finish')
                return {'held': 0}
        launcher.output = Output()
        host.backend.session.before_terminate = capture
        manager.window = 'CLOSED'
        await asyncio.wait_for(serving, 10)
        await finished(host)
        assert events == ['capture', 'finish'] and launcher.output_result == {'held': 0}
        await asyncio.to_thread(host.backend.shutdown)
    run(body())


def test_failed_output_capture_preserves_vm_until_explicit_retry(tmp_path):
    from scrp.validate import ProtocolError
    manager = WindowManager(tmp_path / 'sbx')
    async def body():
        host = Host(tmp_path, manager)
        _, _, serving = await start_ready(host, manager, tmp_path)
        async def capture(session, reason):
            raise ProtocolError('ARTIFACT_BLOCKED', 'unfinished file')
        host.backend.session.before_terminate = capture
        manager.window = 'CLOSED'
        await asyncio.sleep(1)
        assert not host.backend.session.terminated and 'stop' not in manager.names()
        assert 'unfinished file' in host.backend.launcher.error
        host.backend.session.before_terminate = None
        await host.call('session_stop', {'reason': 'TASK_COMPLETE'})
        await asyncio.wait_for(serving, 10)
        await finished(host)
        await asyncio.to_thread(host.backend.shutdown)
    run(body())
