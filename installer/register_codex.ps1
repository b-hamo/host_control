#Requires -Version 5.1
param([string]$State = '', [string]$ConfigPath = '')
. (Join-Path $PSScriptRoot 'solution_common.ps1')
Assert-SolutionUser
$State = Get-SolutionStatePath $State
$p = Read-SolutionProfile $State
if (-not $ConfigPath) {
    $base = $env:CODEX_HOME
    if (-not $base) { $base = Join-Path $env:USERPROFILE '.codex' }
    $ConfigPath = Join-Path $base 'config.toml'
}
Invoke-SolutionCommand $p.python @((Join-Path $p.host_repo 'host/solution.py'),'--config',(Join-Path $State 'solution.json'),'--register-codex',$ConfigPath)
