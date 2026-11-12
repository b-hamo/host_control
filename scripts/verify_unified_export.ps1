#Requires -Version 5.1
param([string]$State = '')
. (Join-Path $PSScriptRoot '../installer/solution_common.ps1')
Assert-SolutionUser
Assert-SolutionIdle
$State = Get-SolutionStatePath $State
$solutionProfile = Read-SolutionProfile $State
Write-Host 'Creates three benign Guest files. Confirm real list/final dialogs for Shared and Output, then close the Sandbox and confirm automatic Shared export.'
Invoke-SolutionCommand $solutionProfile.python @('-u',(Join-Path $solutionProfile.host_repo 'host/unified_verification.py'),'--config',(Join-Path $State 'solution.json'))
