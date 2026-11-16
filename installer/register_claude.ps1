#Requires -Version 5.1
# Register the installed Host with Claude Code (user scope). Run again after moving the State folder.
param([string]$State = '', [switch]$NoGuard)
. (Join-Path $PSScriptRoot 'solution_common.ps1')
Assert-SolutionUser
$State = Get-SolutionStatePath $State
$p = Read-SolutionProfile $State
Invoke-SolutionCommand $p.python @((Join-Path $p.host_repo 'host/solution.py'),'--config',(Join-Path $State 'solution.json'),'--register-claude')
# Team Skill + exec guard hook (PreToolUse checks, PostToolUse origin marks). -NoGuard skips both.
if (-not $NoGuard) { Install-SolutionAgentGuard $p 'Claude' }
