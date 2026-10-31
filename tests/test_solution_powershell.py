"""Exercise PowerShell failure/locking paths without altering services or launching VMs."""
from pathlib import Path
import json
import os
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(sys.platform != 'win32', reason='Windows PowerShell')


def ps(code):
    # Explicit success prevents a deliberately caught native failure from becoming
    # PowerShell -Command's implicit process exit status.
    return subprocess.run(['powershell.exe', '-NoProfile', '-Command', "$ErrorActionPreference='Stop'\n" + code + '\nexit 0'], capture_output=True, text=True)


def quoted(path):
    return "'" + str(path).replace("'", "''") + "'"


def test_all_solution_scripts_parse_in_windows_powershell():
    paths = list((ROOT/'installer').glob('*solution*.ps1'))
    paths += [ROOT/'installer/register_codex.ps1', ROOT/'installer/build.ps1'] + list((ROOT/'scripts').glob('*solution.ps1'))
    for path in paths:
        result = ps(f'$t=$null; $e=$null; [void][Management.Automation.Language.Parser]::ParseFile({quoted(path)},[ref]$t,[ref]$e); if($e.Count){{$e; exit 1}}')
        assert result.returncode == 0, (path, result.stdout, result.stderr)


def test_setup_lock_prevents_parallel_updates_and_releases(tmp_path):
    common = quoted(ROOT/'installer/solution_common.ps1')
    state = quoted(tmp_path)
    result = ps(f'''. {common}
$first = Enter-SolutionUpdate {state}
try {{
  try {{ $second=Enter-SolutionUpdate {state}; throw 'accepted parallel update' }}
  catch {{ if ($_.Exception.Message -notmatch 'Another solution') {{ throw }} }}
}} finally {{ $first.Dispose() }}
$third=Enter-SolutionUpdate {state}; $third.Dispose()
''')
    assert result.returncode == 0, result.stderr


def test_existing_sandbox_refuses_mutation_without_stopping_it():
    result = ps(f'''. {quoted(ROOT/'installer/solution_common.ps1')}
function Get-Process {{ param($Name,$ErrorAction); [pscustomobject]@{{Id=123}} }}
function Stop-Process {{ throw 'must not stop an existing session' }}
try {{ Assert-SolutionIdle; throw 'accepted active session' }}
catch {{ if ($_.Exception.Message -notmatch 'A Windows Sandbox is open') {{ throw }} }}
''')
    assert result.returncode == 0, result.stderr


def test_failed_external_command_propagates():
    result = ps(f'''. {quoted(ROOT/'installer/solution_common.ps1')}
try {{ Invoke-SolutionCommand powershell.exe @('-NoProfile','-Command','exit 7'); throw 'failure swallowed' }}
catch {{ if ($_.Exception.Message -notmatch 'exit 7') {{ throw }} }}
''')
    assert result.returncode == 0, result.stderr


def test_connected_python_environment_cannot_be_updated():
    result = ps(f'''. {quoted(ROOT/'installer/solution_common.ps1')}
function Get-CimInstance {{ param($ClassName,$Filter); [pscustomobject]@{{ExecutablePath='C:\\solution\\python.exe'}} }}
try {{ Assert-SolutionEnvironmentUnused 'C:\\solution\\python.exe'; throw 'accepted connected Host' }}
catch {{ if ($_.Exception.Message -notmatch 'environment is in use') {{ throw }} }}
''')
    assert result.returncode == 0, result.stderr


def test_base_interpreter_with_venv_command_cannot_be_updated():
    result = ps(f'''. {quoted(ROOT/'installer/solution_common.ps1')}
function Get-CimInstance {{ param($ClassName,$Filter); [pscustomobject]@{{ExecutablePath='C:\\Python313\\python.exe'; CommandLine='"C:\\solution\\python.exe" host/solution.py'}} }}
try {{ Assert-SolutionEnvironmentUnused 'C:\\solution\\python.exe'; throw 'accepted connected redirector' }}
catch {{ if ($_.Exception.Message -notmatch 'environment is in use') {{ throw }} }}
''')
    assert result.returncode == 0, result.stderr


def test_stdio_launcher_reads_profile_and_preserves_rpc_stream(tmp_path):
    # Exercise the real PowerShell/native-process boundary without starting Host,
    # service, or VM. The stand-in only echoes one JSON-RPC request.
    host = tmp_path/'host'
    host.mkdir()
    (host/'solution.py').write_text(
        'import sys\nsys.stdout.write(sys.stdin.readline())\nsys.stdout.flush()\n', encoding='utf-8')
    (tmp_path/'solution.json').write_text(json.dumps({
        'schema_version': 1, 'python': sys.executable, 'host_repo': str(tmp_path),
    }), encoding='utf-8')
    request = '{"jsonrpc":"2.0","id":1,"method":"initialize"}\n'
    result = subprocess.run([
        'powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        str(ROOT/'scripts/start_solution.ps1'), '-State', str(tmp_path), '-Stdio',
    ], input=request, capture_output=True, text=True, encoding='utf-8', timeout=15,
       env=os.environ | {'PYTHONIOENCODING': 'utf-8'})
    assert result.returncode == 0, result.stderr
    assert result.stdout == request
