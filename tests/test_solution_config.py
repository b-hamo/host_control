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
