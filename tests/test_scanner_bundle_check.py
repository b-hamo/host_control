"""Installer scan decisions, with AV mocked and no executable/service started."""
from pathlib import Path
import os
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(sys.platform != 'win32', reason='Windows PowerShell')


def literal(path):
    return "'" + str(path).replace("'", "''") + "'"


@pytest.mark.parametrize('case, expected', [
    ('clean', None), ('removed', 'changed or was quarantined'),
    ('detected', 'reported a detection'), ('failed', 'scan failed'),
    ('disabled', 'real-time protection is required'),
])
def test_bundle_scan_fails_closed_even_after_exit_zero(tmp_path, case, expected):
    bundle = tmp_path/'bundle'
    bundle.mkdir()
    (bundle/'SecureArtifactScanner.exe').write_bytes(b'non-executable test fixture')
    script = f'''
$ErrorActionPreference='Stop'
. {literal(ROOT/'installer/scanner_bundle_check.ps1')}
$case='{case}'
function Get-MpComputerStatus {{
  [pscustomobject]@{{AntivirusEnabled=$true;RealTimeProtectionEnabled=($case -ne 'disabled');
  AMRunningMode='Normal';AMProductVersion='test';AntivirusSignatureVersion='test';AMEngineVersion='test'}}
}}
function Get-ScannerDefenderCommand {{ 'C:\\Defender\\MpCmdRun.exe' }}
function Invoke-ScannerBundleScan {{ param($Program,$Root)
  if($case -eq 'removed') {{ Remove-Item -LiteralPath (Join-Path $Root 'SecureArtifactScanner.exe') }}
  @{{exit_code=$(if($case -eq 'failed'){{2}}else{{0}});output='scan fixture'}}
}}
function Get-WinEvent {{
  if($case -eq 'detected') {{ [pscustomobject]@{{Message={literal(bundle)}+' threat'}} }}
}}
try {{
  $result=Assert-ScannerBundleClean {literal(bundle)}
  if($case -ne 'clean') {{ throw 'unexpected success' }}
  if($result.files -ne 1 -or $result.exe_sha256.Length -ne 64) {{throw 'missing scan evidence'}}
}} catch {{
  if($case -eq 'clean' -or $_.Exception.Message -notlike '*{expected or "unexpected"}*') {{throw}}
}}
exit 0
'''
    # Python started by pwsh can inherit its incompatible PS7 module search path.
    # Let Windows PowerShell initialize its own built-in modules, as a normal launch does.
    env = {key: value for key, value in os.environ.items() if key.upper() != 'PSMODULEPATH'}
    result = subprocess.run(['powershell.exe', '-NoProfile', '-Command', script],
                            capture_output=True, text=True, timeout=20, env=env)
    assert result.returncode == 0, (result.stdout, result.stderr)
