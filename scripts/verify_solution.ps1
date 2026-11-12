#Requires -Version 5.1
param([string]$State = '')
. (Join-Path $PSScriptRoot '../installer/solution_common.ps1')
Assert-SolutionUser
Assert-SolutionIdle
$State = Get-SolutionStatePath $State
$p = Read-SolutionProfile $State
Write-Host 'This starts a real Sandbox and creates a benign Shared file. Close its window and select Keep to complete verification.'
Invoke-SolutionCommand $p.python @('-u',(Join-Path $p.host_repo 'host/solution_session.py'),'--config',(Join-Path $State 'solution.json'),'--verify')
