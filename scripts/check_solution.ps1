#Requires -Version 5.1
param([string]$State = '')
. (Join-Path $PSScriptRoot '../installer/solution_common.ps1')
Assert-SolutionUser
$State = Get-SolutionStatePath $State
$p = Read-SolutionProfile $State
Invoke-SolutionCommand $p.python @((Join-Path $p.host_repo 'host/solution.py'),'--config',(Join-Path $State 'solution.json'),'--check')
Write-Host "Mode: $($p.mode); Manager: $($p.manager_repo); Runner: $($p.runner_exe)"
