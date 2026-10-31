#Requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$RequestPath)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'solution_common.ps1')
$r = Get-Content -LiteralPath $RequestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$me = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($me.User.Value -ne $r.sid -or -not ([Security.Principal.WindowsPrincipal]$me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Elevation must use the same Windows account as the ordinary Host user.'
}
$repo = Split-Path $PSScriptRoot -Parent
Start-Transcript -Path (Join-Path $r.state 'setup-elevated.log') -Append | Out-Null
try {
    Assert-SolutionIdle
    Invoke-SolutionCommand $r.python @((Join-Path $repo 'host/solution.py'),'--runner-exe',$r.runner,'--work',$r.work,'--state',$r.state,'--validate-paths')
    foreach ($folder in @($r.work,(Join-Path $r.work 'inbox'),(Join-Path $r.work 'shared'),$r.state)) {
        New-Item -ItemType Directory -Force -Path $folder | Out-Null
    }
    Invoke-SolutionCommand icacls.exe @($r.work,'/deny','*S-1-1-0:(OI)(IO)(X)','/Q')
    Invoke-SolutionCommand icacls.exe @($r.work,'/grant','*S-1-3-4:(OI)(CI)(R,W,D)','/Q')
    Invoke-SolutionCommand powershell.exe @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'install.ps1'),
        '-SourceDir',$r.scanner_source,'-ClientUser',$r.user,'-ExportRoot',(Join-Path $r.state 'exports'),'-EnableSharedScan')
    # Windows venv's redirector runs the base interpreter; bind the existing
    # Manager firewall rules to that process image, not the venv redirector.
    $basePython = (& $r.python -c 'import sys; print(sys._base_executable)') -join ''
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $basePython -PathType Leaf)) { throw 'Cannot resolve the Host base Python for firewall rules.' }
    Invoke-SolutionCommand powershell.exe @('-NoProfile','-ExecutionPolicy','Bypass','-File',
        (Join-Path $r.manager_repo 'tools/install_firewall.ps1'),'-PythonExe',$basePython)
    @{ok=$true} | ConvertTo-Json | Set-Content -LiteralPath $r.result -Encoding UTF8
} catch {
    @{ok=$false; error=$_.Exception.Message} | ConvertTo-Json | Set-Content -LiteralPath $r.result -Encoding UTF8
    throw
} finally { Stop-Transcript | Out-Null }
