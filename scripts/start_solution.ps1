#Requires -Version 5.1
param([string]$State = '', [switch]$Stdio)
. (Join-Path $PSScriptRoot '../installer/solution_common.ps1')
Assert-SolutionUser
$State = Get-SolutionStatePath $State
$p = Read-SolutionProfile $State
if ($Stdio) {
    # For MCP clients: preserve stdout exactly as the JSON-RPC stream.
    & $p.python (Join-Path $p.host_repo 'host/solution.py') --config (Join-Path $State 'solution.json')
    exit $LASTEXITCODE
}
Assert-SolutionIdle
Invoke-SolutionCommand $p.python @('-u',(Join-Path $p.host_repo 'host/solution_session.py'),'--config',(Join-Path $State 'solution.json'))
