#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('Host','Manager','Runner','Scanner','All')][string]$Component,
      [string]$State = '')
. (Join-Path $PSScriptRoot 'solution_common.ps1')
Assert-SolutionUser
Assert-SolutionIdle
$State = Get-SolutionStatePath $State
$p = Read-SolutionProfile $State
Assert-SolutionEnvironmentUnused $p.python
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ($p.host_repo -ne $repo) { throw 'Use the Host repository recorded in solution.json.' }
if ($Component -eq 'All') {
    & (Join-Path $PSScriptRoot 'install_solution.ps1') -Mode $p.mode -ManagerRepo $p.manager_repo -RunnerRepo $p.runner_repo `
        -UcrtRoot $p.ucrt_root -PythonExe $p.python -Work $p.work -State $State
    return
}
$lock = Enter-SolutionUpdate $State
Start-Transcript -Path (Join-Path $State 'update.log') -Append | Out-Null
try {
    switch ($Component) {
        'Host' { Invoke-SolutionCommand $p.python @('-m','pip','install','-r',(Join-Path $repo 'requirements-base.txt')) }
        'Manager' { Install-SolutionManager $p.python $p.manager_repo $p.mode }
        'Runner' {
            $runner = Build-SolutionRunner $p.runner_repo $p.ucrt_root
            $p.runner_exe = $runner.executable
            $p.runner_sha256 = $runner.sha256
        }
        'Scanner' {
            $output = Join-Path $repo ('build/solution-scanner/'+[Guid]::NewGuid().ToString('N'))
            Invoke-SolutionCommand powershell.exe @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'build.ps1'),'-OutDir',$output,'-PythonExe',$p.python)
            Install-SolutionPrivileged $repo $p.python $p.work $State $p.runner_exe (Join-Path $output 'SecureArtifactScanner') $p.manager_repo
        }
    }
    Invoke-SolutionCommand $p.python @((Join-Path $repo 'host/solution.py'),'--runner-exe',$p.runner_exe,'--work',$p.work,'--state',$State,'--check')
    $p.sources = @{host=(Get-SolutionSource $repo); manager=(Get-SolutionSource $p.manager_repo); runner=(Get-SolutionSource $p.runner_repo)}
    $p.installed_at = [DateTime]::UtcNow.ToString('o')
    Save-SolutionProfile $p $State
    Write-Host "SOLUTION_UPDATED: $Component. Reconnect the MCP Host to load changed modules."
} finally { Stop-Transcript | Out-Null; $lock.Dispose() }
