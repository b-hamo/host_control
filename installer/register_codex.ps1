#Requires -Version 5.1
param([string]$State = '', [string]$ConfigPath = '', [switch]$NoGuard)
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
# Team Skill + exec guard hook (PreToolUse checks, PostToolUse origin marks). -NoGuard skips both.
if (-not $NoGuard) {
    Install-SolutionAgentGuard $p 'Codex'
    Write-Host 'Codex runs a new hook only after you trust it: Codex app Settings > Hooks (or CLI /hooks).'
}
