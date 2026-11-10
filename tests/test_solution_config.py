import hashlib
import json
from pathlib import Path
import tomllib

import pytest

from host.solution_config import merge_mcp, read_profile, register_mcp, render_profile_mcp


def profile(tmp_path):
    runner = tmp_path / '한글 runner.exe'
    runner.write_bytes(b'fixture')
    result = {key: str(tmp_path / key) for key in
              ('host_repo', 'manager_repo', 'runner_repo', 'python', 'work', 'state')}
    result.update(schema_version=1, mode='Dev', runner_exe=str(runner),
                  runner_sha256=hashlib.sha256(b'fixture').hexdigest())
    return result


def test_profile_accepts_powershell_bom_and_checks_runner_bytes(tmp_path):
    p = profile(tmp_path)
    path = tmp_path / 'solution.json'
    path.write_text(json.dumps(p), encoding='utf-8-sig')
    assert read_profile(path) == p
    Path(p['runner_exe']).write_bytes(b'different build')
    with pytest.raises(ValueError, match='Runner changed'):
        read_profile(path)


def test_micro_vm_profile_pins_binaries_and_explicit_surface(tmp_path):
    from host.solution_config import validate_micro_vm
    from host.solution import host_arguments
    package = tmp_path / 'micro'
    package.mkdir()
    (package / 'dbictl.exe').write_bytes(b'broker')
    relay = package / 'ScrpRelay.exe'
    relay.write_bytes(b'relay')
    micro = dict(mode='AutoAppWindow', package=str(package), root=str(tmp_path / 'vm-root'), relay=str(relay),
                 dbictl_sha256=hashlib.sha256(b'broker').hexdigest(), relay_sha256=hashlib.sha256(b'relay').hexdigest())
    validate_micro_vm(micro)
    clients = ['12345678-1234-4234-8234-123456789abc', '12345678-1234-4234-8234-123456789abd']
    arguments = [host_arguments(tmp_path/'runner.exe', tmp_path/'work', tmp_path/'state',
                               micro_vm=micro, client_id=client) for client in clients]
    for flag in ('--inbox', '--output-root', '--sandbox-root', '--cert-dir', '--log-file'):
        assert arguments[0][arguments[0].index(flag)+1] != arguments[1][arguments[1].index(flag)+1]
    for args in arguments:
        assert '--auto-vm-app-window' in args
        assert '--no-auto-restart' not in args  # Same-VM verified Runner recovery is enabled in deployment too.
        assert args[args.index('--startup-timeout')+1] == '1200'
        assert args[args.index('--export-dir')+1] == str(tmp_path/'state'/'exports')
    relay.write_bytes(b'replaced')
    with pytest.raises(ValueError, match='changed since installation'):
        validate_micro_vm(micro)
    with pytest.raises(ValueError, match='explicitly accept'):
        validate_micro_vm(dict(micro, mode='Desktop'))


def test_installed_management_profile_pins_service_and_configuration(tmp_path):
    from host.solution_config import validate_micro_vm
    package = tmp_path / 'package'
    package.mkdir()
    micro = dict(mode='AutoAppWindow', package=str(package), root=str(tmp_path/'root'),
                 relay=str(package/'ScrpRelay.exe'), max_active=8)
    for key, name in [('dbictl_sha256', 'dbictl.exe'), ('relay_sha256', 'ScrpRelay.exe'),
                      ('management_service_sha256', 'MinoVmService.exe')]:
        (package/name).write_bytes(name.encode())
        micro[key] = hashlib.sha256(name.encode()).hexdigest()
    config = package/'management.json'
    config.write_text(json.dumps(dict(schema_version=1, root=micro['root'], max_active=8)), encoding='utf-8')
    micro['management_config_sha256'] = hashlib.sha256(config.read_bytes()).hexdigest()
    validate_micro_vm(micro)
    with pytest.raises(ValueError, match='capacity differs'):
        validate_micro_vm(dict(micro, max_active=9))
    with pytest.raises(ValueError, match='root differs'):
        validate_micro_vm(dict(micro, root=str(tmp_path/'other')))
    unpinned = dict(micro)
    del unpinned['management_service_sha256']
    with pytest.raises(ValueError, match='changed since installation'):
        validate_micro_vm(unpinned)
    config.write_text(config.read_text() + ' ', encoding='utf-8')
    with pytest.raises(ValueError, match='changed since installation'):
        validate_micro_vm(micro)


@pytest.mark.parametrize('change', [{'schema_version': 2}, {'mode': 'unknown'}, {'work': 'relative'}])
def test_invalid_profiles_refused(tmp_path, change):
    path = tmp_path / 'solution.json'
    path.write_text(json.dumps(profile(tmp_path) | change), encoding='utf-8')
    with pytest.raises(ValueError):
        read_profile(path)


def test_registration_preserves_unrelated_settings_and_is_idempotent(tmp_path):
    original = '''# user comment
model = "user-choice"
[mcp_servers.scrp_sandbox]
command = "old"
[mcp_servers.scrp_sandbox.env]
OLD = "yes"
[mcp_servers.other]
command = "keep"
[[projects.list]]
path = "user-work"
'''
    fragment = render_profile_mcp(tmp_path / 'solution.json', profile(tmp_path))
    config = tmp_path / 'config.toml'
    config.write_text(original, encoding='utf-8')
    backup = register_mcp(config, fragment)
    assert backup.read_text(encoding='utf-8') == original
    updated = config.read_text(encoding='utf-8')
    assert '# user comment' in updated
    data = tomllib.loads(updated)
    assert data['model'] == 'user-choice'
    assert data['mcp_servers']['other']['command'] == 'keep'
    assert data['projects']['list'] == [{'path': 'user-work'}]
    assert data['mcp_servers']['scrp_sandbox']['args'][-2:] == ['-State', str(tmp_path)]
    assert data['mcp_servers']['scrp_sandbox']['command'] == 'powershell.exe'
    assert register_mcp(config, fragment) is None
    assert config.read_text(encoding='utf-8') == updated


@pytest.mark.parametrize('original', [
    '[mcp_servers.scrp]\ncommand="legacy"\n',
    'not valid TOML',
    'description = """\n[mcp_servers.scrp_sandbox]\nimportant text\n"""\n',
    '[mcp_servers."scrp_sandbox"]\ncommand="quoted"\n',
])
def test_ambiguous_or_invalid_config_never_overwritten(tmp_path, original):
    config = tmp_path / 'config.toml'
    config.write_text(original, encoding='utf-8')
    with pytest.raises(ValueError):
        register_mcp(config, render_profile_mcp(tmp_path/'solution.json', profile(tmp_path)))
    assert config.read_text(encoding='utf-8') == original
    assert not list(tmp_path.glob('*.before-solution-*'))


def test_new_config_registration(tmp_path):
    config = tmp_path/'new'/'config.toml'
    fragment = render_profile_mcp(tmp_path/'solution.json', profile(tmp_path))
    register_mcp(config, fragment)
    assert tomllib.loads(config.read_text()) == tomllib.loads(fragment)


def test_full_update_does_not_pin_mcp_to_previous_environment(tmp_path):
    p = profile(tmp_path)
    initial = render_profile_mcp(tmp_path/'solution.json', p)
    p['python'] = str(tmp_path/'envs'/'new'/'python.exe')
    assert render_profile_mcp(tmp_path/'solution.json', p) == initial
