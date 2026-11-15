import json
import os

import pytest

from dashboard.liveness import owner_alive, process_started, wsb_ids
from test_dashboard import board, session, at


def test_pid_reuse_is_not_the_same_host():
    assert owner_alive({'pid': 12, 'started': 100}, lambda pid: 100) is True
    assert owner_alive({'pid': 12, 'started': 100}, lambda pid: 101) is False
    assert owner_alive({'pid': 12, 'started': 100}, lambda pid: None) is False
    assert owner_alive({'pid': 12}, lambda pid: 100) is None
    def denied(pid):
        raise PermissionError('access denied')
    assert owner_alive({'pid': 12, 'started': 100}, denied) is None


@pytest.mark.skipif(os.name != 'nt', reason='Windows identity')
def test_current_process_identity_is_checked_on_windows():
    stamp = process_started(os.getpid())
    assert isinstance(stamp, int)
    assert owner_alive({'pid': os.getpid(), 'started': stamp}) is True
    assert owner_alive({'pid': os.getpid(), 'started': stamp - 1}) is False


def test_stale_sessions_are_hidden_without_changing_records_or_exports(board, tmp_path):
    c, _ = board
    c.owner_check = lambda o: False
    c.sandbox_inventory = lambda: {'wsb-1'}
    before = {p: p.read_bytes() for p in tmp_path.rglob('state.json')}
    o = c.overview()
    assert [s['id'] for s in o['sessions']] == ['SES-wsb', 'SES-bad']
    assert o['sessions'][0]['host_alive'] is False  # real Sandbox survives its Host
    assert o['runtimes']['micro_vm']['running'] == 0
    assert before == {p: p.read_bytes() for p in before}
    assert c._exports({'old': {'exports': [{'artifact_id': 'ART-1', 'session_id': 'SES-vm1',
                         'stage': 'BLOCKED', 'observed_at': at(5)}]}}, {}, c.clock())[0]['stage'] == 'BLOCKED'


def test_runtime_inventory_overrules_old_records_and_preserves_orphan_vm(board):
    c, _ = board
    c.owner_check = lambda o: False
    c.vm_inventory = lambda: {'c-1'}
    c.sandbox_inventory = lambda: set()
    o = c.overview()
    assert [s['id'] for s in o['sessions']] == ['SES-vm1', 'SES-bad']
    assert o['runtimes']['micro_vm']['running'] == 1
    assert o['runtimes']['micro_vm']['count_source'] == 'hcs'
    assert o['runtimes']['windows_sandbox']['state'] == 'STOPPED'


def test_permission_failure_is_unknown_not_stopped_or_free_capacity(board):
    c, _ = board
    c.owner_check = lambda o: None
    c.wsb = lambda: None
    o = c.overview()
    vm = o['runtimes']['micro_vm']
    assert (vm['running'], vm['starting'], vm['unknown'], vm['free_slots']) == (0, 0, 3, None)
    assert o['runtimes']['windows_sandbox']['running'] is None
    assert o['runtimes']['windows_sandbox']['state'] == 'UNKNOWN'
    assert all(s['display_state'] == 'UNKNOWN' for s in o['sessions'] if s['state'] == 'RUNNING')


def test_starting_host_without_a_container_is_retained(board):
    c, _ = board
    c.vm_inventory = lambda: set()
    o = c.overview()
    assert [s['id'] for s in o['sessions'] if s['runtime'] == 'micro_vm'] == ['SES-bad', 'SES-vm2']
    assert o['runtimes']['micro_vm']['starting'] == 1


def test_same_physical_vm_is_counted_once(board, tmp_path):
    c, _ = board
    session(tmp_path / 'manager', 'SES-copy', 'MICRO_VM_APP_WINDOW', 'RUNNING', started=50, container='c-1')
    o = c.overview()
    ids = [s['id'] for s in o['sessions']]
    assert 'SES-copy' in ids and 'SES-vm1' not in ids
    assert o['runtimes']['micro_vm']['running'] == 2


def test_host_advertised_root_wins_over_stale_duplicate(board, tmp_path):
    c, _ = board
    session(tmp_path / 'manager', 'SES-vm3', 'MICRO_VM_APP_WINDOW', 'TERMINATED', ended=8000, container='c-3')
    assert next(s for s in c.overview()['sessions'] if s['id'] == 'SES-vm3')['state'] == 'RUNNING'


def test_wsb_query_failure_and_malformed_response_are_not_zero(monkeypatch):
    from types import SimpleNamespace
    import dashboard.liveness as live
    for code, text in ((1, '{}'), (0, '{}'), (0, 'null'), (0, '{"WindowsSandboxEnvironments":null}')):
        monkeypatch.setattr(live.subprocess, 'run', lambda *a, **kw: SimpleNamespace(returncode=code, stdout=text))
        assert wsb_ids() is None
    monkeypatch.setattr(live.subprocess, 'run', lambda *a, **kw: SimpleNamespace(returncode=0, stdout='{"WindowsSandboxEnvironments":[]}'))
    assert wsb_ids() == set()
