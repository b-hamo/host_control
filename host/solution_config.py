"""Portable installation profile and loss-checked MCP registration (stdlib only)."""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import tomllib


def read_profile(path: Path, *, verify_runner: bool = True) -> dict:
    profile = json.loads(path.read_text(encoding='utf-8-sig'))
    if profile.get('schema_version') != 1 or profile.get('mode') not in ('Dev', 'Deploy'):
        raise ValueError('unsupported solution profile')
    for name in ('host_repo', 'manager_repo', 'runner_repo', 'python', 'runner_exe', 'work', 'state'):
        value = profile.get(name)
        if not isinstance(value, str) or not Path(value).is_absolute():
            raise ValueError(f'profile requires an absolute {name}')
    if verify_runner:
        with Path(profile['runner_exe']).open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual != profile.get('runner_sha256'):
            raise ValueError('Runner changed since installation; run update_solution.ps1 -Component Runner')
    micro = profile.get('micro_vm')
    if micro is not None:
        validate_micro_vm(micro)
    return profile


def validate_micro_vm(micro: dict) -> None:
    """An opt-in backend is pinned like the Runner, not discovered from PATH."""
    if not isinstance(micro, dict) or micro.get('mode') not in ('AutoAppWindow', 'AppWindow'):
        raise ValueError('micro_VM mode must explicitly accept app-window capabilities')
    limit = micro.get('max_active', 8)
    if type(limit) is not int or not 1 <= limit <= 64:
        raise ValueError('micro_VM max_active must be 1..64')
    for key in ('package', 'root', 'relay'):
        value = micro.get(key)
        if not isinstance(value, str) or not Path(value).is_absolute() or Path(value).resolve() != Path(value):
            raise ValueError(f'micro_VM requires an absolute, non-linked {key}')
    for key, path in (('dbictl_sha256', Path(micro['package']) / 'dbictl.exe'),
                      ('relay_sha256', Path(micro['relay']))):
        with path.open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual != micro.get(key):
            raise ValueError(f'micro_VM {key} changed since installation')
    service_config = Path(micro['package']) / 'management.json'
    service_pins = ('management_service_sha256', 'management_config_sha256')
    if service_config.exists() or any(key in micro for key in service_pins):
        for key, path in zip(service_pins, (Path(micro['package']) / 'MinoVmService.exe', service_config)):
            with path.open('rb') as stream:
                actual = hashlib.file_digest(stream, 'sha256').hexdigest()
            if actual != micro.get(key):
                raise ValueError(f'micro_VM {key} changed since installation')
        installed = json.loads(service_config.read_text(encoding='utf-8-sig'))
        if installed.get('schema_version') != 1 or Path(installed.get('root', '')).resolve() != Path(micro['root']):
            raise ValueError('micro_VM management root differs from installed service')
        if installed.get('max_active') != limit:
            raise ValueError('micro_VM capacity differs from installed service')


def render_profile_mcp(profile_path: Path, profile: dict) -> str:
    q = lambda value: json.dumps(str(value), ensure_ascii=False)
    # Resolve Python from the current profile on every connection: a full update
    # publishes a fresh environment without rewriting the user's MCP registration.
    args = ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
            str(Path(profile['host_repo']) / 'scripts' / 'start_solution.ps1'),
            '-Stdio', '-State', str(profile_path.parent)]
    return ('[mcp_servers.scrp_sandbox]\n'
            f'command = "powershell.exe"\nargs = {json.dumps(args, ensure_ascii=False)}\n'
            f'cwd = {q(profile["host_repo"])}\nenabled = true\n'
            'startup_timeout_sec = 60\ntool_timeout_sec = 120\n'
            '[mcp_servers.scrp_sandbox.env]\nPYTHONIOENCODING = "utf-8"\n'
            'PYTHONDONTWRITEBYTECODE = "1"\n')


def merge_mcp(original: str, fragment: str) -> str:
    """Preserve unrelated bytes, then parse/compare to catch unusual TOML layouts.

    A multiline string may look like a section header. Never trust the text
    splice alone: refuse it if the parsed result changes any unrelated value.
    """
    before = tomllib.loads(original)
    addition = tomllib.loads(fragment)['mcp_servers']['scrp_sandbox']
    servers = before.get('mcp_servers', {})
    if 'scrp' in servers:
        raise ValueError('legacy MCP name scrp exists; remove/rename it explicitly to avoid two Hosts')
    if servers.get('scrp_sandbox') == addition:
        return original
    expected = copy.deepcopy(before)
    expected.setdefault('mcp_servers', {})['scrp_sandbox'] = addition
    kept, dropping = [], False
    header = re.compile(r'^\s*\[([^\[\]]+)\]\s*(?:#.*)?$')
    for line in original.splitlines(keepends=True):
        match = header.match(line.rstrip('\r\n'))
        if match:
            table = match.group(1).strip()
            dropping = table == 'mcp_servers.scrp_sandbox' or table.startswith('mcp_servers.scrp_sandbox.')
        elif line.lstrip().startswith('[['):
            dropping = False
        if not dropping:
            kept.append(line)
    candidate = ''.join(kept).rstrip() + '\n\n' + fragment
    if tomllib.loads(candidate) != expected:
        raise ValueError('MCP registration would alter unrelated TOML; use the generated mcp.toml manually')
    return candidate


def register_mcp(config: Path, fragment: str) -> Path | None:
    original = config.read_text(encoding='utf-8-sig') if config.exists() else ''
    candidate = merge_mcp(original, fragment)
    if candidate == original:
        return None
    config.parent.mkdir(parents=True, exist_ok=True)
    backup = None
    if config.exists():
        backup = config.with_name(config.name + '.before-solution-' + datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f'))
        backup.write_bytes(config.read_bytes())
    fd, name = tempfile.mkstemp(prefix=config.name + '.', suffix='.tmp', dir=config.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='') as stream:
            stream.write(candidate)
        # Do not overwrite an edit made after we read the user's config.
        now = config.read_text(encoding='utf-8-sig') if config.exists() else ''
        if now != original:
            raise ValueError('Codex configuration changed during registration; retry')
        os.replace(name, config)
    finally:
        Path(name).unlink(missing_ok=True)
    return backup
