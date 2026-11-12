"""Integrated launch contract and fail-closed setup; no VM is launched here."""
import asyncio
from pathlib import Path
import sys
import tomllib

import pytest

from host import solution


def test_profile_always_connects_all_three_components_and_service(tmp_path):
    runner, work, state = tmp_path / 'runner.exe', tmp_path / 'work', tmp_path / 'state'
    args = solution.host_arguments(runner, work, state)
    for flag, value in {'--runner-exe': runner, '--output-root': work / 'output',
                        '--inbox': work / 'inbox', '--sandbox-root': state / 'sandbox',
                        '--export-dir': state / 'exports', '--artifact-scanner': 'defender-service',
                        '--approval': 'dialog'}.items():
        assert args[args.index(flag) + 1] == str(value)
    assert {'--artifact-export', '--sandbox-run', '--agent-guard'} <= set(args)
    # 2026-11-03 멘토링: only a publicly trusted signed program also goes to Downloads
    assert '--signed-downloads' in args and '--save-downloads' not in args
    assert '--shared' not in args and '--unified-export' not in args
    assert args[args.index('--artifact-max-bytes') + 1] == '52428800'
    runner = tmp_path / "한글 dir's" / 'runner.exe'
    config = tomllib.loads(solution.render_config(runner, work, state))['mcp_servers']['scrp_sandbox']
    assert config['command'] == sys.executable
    assert config['args'][2] == str(runner)
    assert config['args'][0].endswith('solution.py')


def test_paths_refuse_code_or_state_inside_writable_mapping(tmp_path):
    runner = tmp_path / 'runner.exe'
    runner.touch()
    work, state = tmp_path / 'work', tmp_path / 'state'
    solution.validate_paths(runner, work, state)
    for bad_work, bad_state in [(tmp_path, state), (work, work / 'state'),
                                (Path.home() / 'Downloads' / 'work', state),
                                (Path.home(), state), (Path(work.anchor), state)]:
        with pytest.raises(ValueError):
            solution.validate_paths(runner, bad_work, bad_state)


@pytest.mark.skipif(sys.platform != 'win32', reason='Windows scanner')
@pytest.mark.parametrize('failure', ['missing-service', 'shared-disabled', 'wrong-export-root'])
def test_service_preflight_refuses_unusable_service(tmp_path, monkeypatch, failure):
    from host.shared_scanner import ServiceSharedFinisher, SharedScanError
    from host.artifact_scan import DefenderServiceScanner
    async def shared(_):
        if failure != 'wrong-export-root':
            raise SharedScanError('SCANNER_UNAVAILABLE', failure)
    async def artifact(*_):
        return False, 'wrong-export-root'
    monkeypatch.setattr(ServiceSharedFinisher, 'check_available', shared)
    monkeypatch.setattr(DefenderServiceScanner, 'refresh', artifact)
    with pytest.raises((SharedScanError, RuntimeError), match=failure):
        asyncio.run(solution.check_service(tmp_path))


@pytest.mark.parametrize('mode', ['run', 'config'])
def test_failed_preflight_never_starts_host_or_replaces_config(tmp_path, monkeypatch, mode):
    from host import inbox_download, mcp_server
    from sandbox_manager import inbox
    runner, work, state = tmp_path / 'runner.exe', tmp_path / 'work', tmp_path / 'state'
    runner.touch()
    config = tmp_path / 'mcp.toml'
    config.write_text('existing configuration', encoding='utf-8')
    monkeypatch.setattr(inbox, 'check_inbox_root', lambda p: p)
    monkeypatch.setattr(inbox_download, 'check_no_execute', lambda p: (True, 'denied'))
    async def unavailable(_):
        raise RuntimeError('service stopped')
    monkeypatch.setattr(solution, 'check_service', unavailable)
    monkeypatch.setattr(mcp_server, 'main', lambda _: pytest.fail('started without scanner'))
    args = ['--runner-exe', str(runner), '--work', str(work), '--state', str(state)]
    if mode == 'config':
        args += ['--write-config', str(config)]
    with pytest.raises(SystemExit) as e:
        solution.main(args)
    assert e.value.code == 1
    assert config.read_text(encoding='utf-8') == 'existing configuration'


def test_successful_preflight_publishes_config_and_launches_profile(tmp_path, monkeypatch):
    from host import inbox_download, mcp_server
    from sandbox_manager import inbox
    runner, work, state = tmp_path / 'runner.exe', tmp_path / 'work', tmp_path / 'state'
    runner.touch()
    checked, launched = [], []
    monkeypatch.setattr(inbox, 'check_inbox_root', lambda p: p)
    monkeypatch.setattr(inbox_download, 'check_no_execute', lambda p: (checked.append(p) is None, 'denied'))
    async def ready(path):
        checked.append(path)
    monkeypatch.setattr(solution, 'check_service', ready)
    monkeypatch.setattr(mcp_server, 'main', launched.append)
    args = ['--runner-exe', str(runner), '--work', str(work), '--state', str(state)]
    config = tmp_path / 'mcp.toml'
    solution.main(args + ['--write-config', str(config)])
    assert tomllib.loads(config.read_text(encoding='utf-8'))['mcp_servers']['scrp_sandbox']
    assert not launched
    solution.main(args)
    assert launched == [solution.host_arguments(runner, work, state)]
    assert checked == [work / 'inbox', work / 'output', state] * 2


@pytest.mark.parametrize('failure', [None, 'inbox', 'output', 'service'])
def test_auto_chat_preflight_uses_own_mappings_before_host_start(tmp_path, monkeypatch, failure):
    """An occupied legacy mapping must not prevent a second chat's handshake."""
    from host import inbox_download, mcp_server, solution_config
    from sandbox_manager import inbox
    runner, work, state = tmp_path / 'runner.exe', tmp_path / 'work', tmp_path / 'state'
    runner.touch()
    profile = dict(host_repo=str(solution.REPO), runner_exe=str(runner),
                   work=str(work), state=str(state), micro_vm=dict(mode='AutoAppWindow',
                   package=str(tmp_path / 'package'), root=str(tmp_path / 'vm-root'),
                   relay=str(tmp_path / 'relay.exe')))
    monkeypatch.setattr(solution_config, 'read_profile', lambda _: profile)
    monkeypatch.setattr(solution_config, 'validate_micro_vm', lambda _: None)
    checked, launched, services = [], [], []
    monkeypatch.setattr(inbox, 'check_inbox_root', lambda p: p)
    def check(path):
        assert path.parent.parent == work / 'clients', 'touched another chat mapping'
        assert path.is_dir()
        checked.append(path)
        return path.name != failure, 'deny-execute missing'
    async def service(path):
        services.append(path)
        if failure == 'service':
            raise RuntimeError('scanner unavailable')
    monkeypatch.setattr(inbox_download, 'check_no_execute', check)
    monkeypatch.setattr(solution, 'check_service', service)
    monkeypatch.setattr(mcp_server, 'main', launched.append)
    args = ['--config', str(tmp_path / 'solution.json')]
    if failure:
        with pytest.raises(SystemExit) as error:
            solution.main(args)
        assert error.value.code == 1
        assert not launched
        assert len(checked) == (1 if failure == 'inbox' else 2)
        assert services == ([state] if failure == 'service' else [])
    else:
        solution.main(args)
        solution.main(args)
        mappings = [[Path(argv[argv.index(flag) + 1]) for flag in ('--inbox', '--output-root')]
                    for argv in launched]
        assert checked == mappings[0] + mappings[1]
        assert len(set(checked)) == 4
        assert services == [state, state]  # Scanner keeps its installed export root.
    assert not (work / 'inbox').exists()
    assert not (work / 'output').exists()
