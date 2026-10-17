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


@pytest.mark.parametrize('choice,status', [('keep', 'EXPORTED'), ('delete', 'DELETED'), ('hold', 'HELD')])
def test_close_asks_first_and_applies_the_choice_only_after_vm_stop_and_scan(tmp_path, choice, status):
    # 배주한 요청 2026-10-17: the question appears right after the window closes (about 1.5 s), while the
    # VM stops and the scan runs; the answer is applied only after both (a scan problem overrides "keep").
    from sandbox_manager.shared import finish_shared
    manager = WindowManager(tmp_path / 'sbx')
    share = tmp_path / 'share'
    share.mkdir()
    (share / 'result.txt').write_text('saved in Shared', encoding='utf-8')
    events = []

    def scan(folder):
        assert ('stop', 'USER_STOP', False) in manager.calls
        events.append('scan')
        return 'clean', 'test scanner'

    async def choose(summary):
        assert events == [] and summary['before_scan'] is True
        assert not any(c[0] == 'stop' for c in manager.calls)      # asked before the VM is stopped
        events.append('choose')
        return choice

    async def body():
        host = Host(tmp_path, manager)
        runner, boot, serving = await start_ready(host, manager, tmp_path)
        launcher = host.backend.launcher
        launcher.shared = share
        launcher._choose_shared = choose
        launcher._finish_shared = lambda folder, decide: finish_shared(
            folder, dest=tmp_path / 'downloads', scan=scan, decide=decide)
        manager.window = 'CLOSED'
        await asyncio.wait_for(serving, 10)
        await finished(host)
        assert launcher.shared_result['status'] == status
        assert events == ['choose', 'scan']
        assert (tmp_path / 'downloads' / 'share' / 'result.txt').exists() == (choice == 'keep')
        assert share.exists() == (choice == 'hold')
        await asyncio.to_thread(host.backend.shutdown)
    run(body())


def test_keep_answered_early_is_not_honoured_when_the_scan_fails(tmp_path):
    from sandbox_manager.shared import finish_shared
    manager = WindowManager(tmp_path / 'sbx')
    share = tmp_path / 'share'
    share.mkdir()
    (share / 'bad.exe').write_bytes(b'MZ')
    told = []

    async def choose(summary):
        return 'keep'

    async def notify(result):
        told.append(result['status'])

    async def body():
        host = Host(tmp_path, manager)
        runner, boot, serving = await start_ready(host, manager, tmp_path)
        launcher = host.backend.launcher
        launcher.shared = share
        launcher._choose_shared, launcher._notify_shared = choose, notify
        launcher._finish_shared = lambda folder, decide: finish_shared(
            folder, dest=tmp_path / 'downloads', scan=lambda f: ('threat', 'test'), decide=decide)
        manager.window = 'CLOSED'
        await asyncio.wait_for(serving, 10)
        await finished(host)
        assert launcher.shared_result['status'] == 'BLOCKED'
        assert told == ['BLOCKED']
        assert not (tmp_path / 'downloads').exists() and (share / 'bad.exe').exists()
        await asyncio.to_thread(host.backend.shutdown)
    run(body())
