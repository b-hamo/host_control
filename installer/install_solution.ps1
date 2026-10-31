#Requires -Version 5.1
<# Run in ordinary PowerShell. Only service installation requests UAC.
   Requires Windows Sandbox, Defender, Python 3.13 x64, Git, MSYS2 UCRT64.
   Never checks out code, reboots, or terminates an existing VM. #>
[CmdletBinding()]
param(
    [ValidateSet('Dev','Deploy')][string]$Mode = 'Dev',
    [string]$ManagerRepo = '', [string]$RunnerRepo = '', [string]$UcrtRoot = '',
    [string]$PythonExe = '', [string]$Work = '', [string]$State = '',
    [switch]$RegisterCodex, [string]$CodexConfig = '', [switch]$Start,
    [switch]$CheckOnly
)
. (Join-Path $PSScriptRoot 'solution_common.ps1')
Assert-SolutionUser
Assert-SolutionIdle
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$parent = Split-Path $repo -Parent
if (-not $ManagerRepo) { $ManagerRepo = Join-Path $parent 'sandbox_manager' }
if (-not $RunnerRepo) { $RunnerRepo = Join-Path $parent 'sandbox_runner' }
$ManagerRepo = Resolve-SolutionRepo $ManagerRepo 'pyproject.toml'
[void](Resolve-SolutionRepo $ManagerRepo 'tools/install_firewall.ps1')
$RunnerRepo = Resolve-SolutionRepo $RunnerRepo 'scripts/build.ps1'
$State = Get-SolutionStatePath $State
if (-not $Work) { $Work = Join-Path $env:USERPROFILE 'SecureCUA/solution' }
$Work = [IO.Path]::GetFullPath($Work)
foreach ($name in @('git.exe','WindowsSandbox.exe','wsb.exe')) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) { throw "$name is required. Enable Windows Sandbox and reboot if Windows requests it." }
}
if (-not $PythonExe) {
    if (-not (Get-Command py.exe -ErrorAction SilentlyContinue)) { throw 'Install Python 3.13 x64 with its py launcher, or pass -PythonExe.' }
    $PythonExe = (& py -3.13 -c 'import sys; print(sys.executable)') -join ''
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.13 x64 is required.' }
}
$PythonExe = (Resolve-Path -LiteralPath $PythonExe).Path
Invoke-SolutionCommand $PythonExe @('-c',"import sys,struct; assert sys.version_info[:2]==(3,13) and struct.calcsize('P')==8")
$buildArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $RunnerRepo 'scripts/build.ps1'),'-CheckOnly')
if ($UcrtRoot) { $buildArgs += @('-UcrtRoot',$UcrtRoot) }
Invoke-SolutionCommand powershell.exe $buildArgs
if ($CheckOnly) { Write-Host 'SETUP_PREREQUISITES_READY (service/Defender/ACL checks run during installation).'; return }
$lock = Enter-SolutionUpdate $State
Start-Transcript -Path (Join-Path $State 'setup.log') -Append | Out-Null
try {
    # Never uninstall a package beneath a connected MCP process. Publish the new
    # environment only after all installation checks succeed; keep the previous one.
    $environment = Join-Path $State ('envs/'+[Guid]::NewGuid().ToString('N'))
    $python = Join-Path $environment 'Scripts/python.exe'
    Invoke-SolutionCommand $PythonExe @('-m','venv',$environment)
    Invoke-SolutionCommand $python @('-c',"import sys,struct; assert sys.version_info[:2]==(3,13) and struct.calcsize('P')==8")
    Invoke-SolutionCommand $python @('-m','pip','install','-r',(Join-Path $repo 'requirements-base.txt'))
    Install-SolutionManager $python $ManagerRepo $Mode
    $runner = Build-SolutionRunner $RunnerRepo $UcrtRoot
    Invoke-SolutionCommand $python @((Join-Path $repo 'host/solution.py'),'--runner-exe',$runner.executable,'--work',$Work,'--state',$State,'--validate-paths')
    $scannerOut = Join-Path $repo ('build/solution-scanner/'+[Guid]::NewGuid().ToString('N'))
    Invoke-SolutionCommand powershell.exe @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'build.ps1'),'-OutDir',$scannerOut,'-PythonExe',$PythonExe)
    Install-SolutionPrivileged $repo $python $Work $State $runner.executable (Join-Path $scannerOut 'SecureArtifactScanner') $ManagerRepo
    Invoke-SolutionCommand $python @((Join-Path $repo 'host/solution.py'),'--runner-exe',$runner.executable,'--work',$Work,'--state',$State,'--check')
    $profile = [ordered]@{schema_version=1; mode=$Mode; host_repo=$repo; manager_repo=$ManagerRepo; runner_repo=$RunnerRepo;
        python=$python; runner_exe=$runner.executable; runner_sha256=$runner.sha256; ucrt_root=$runner.ucrt_root;
        work=$Work; state=$State; installed_at=[DateTime]::UtcNow.ToString('o');
        sources=@{host=(Get-SolutionSource $repo); manager=(Get-SolutionSource $ManagerRepo); runner=(Get-SolutionSource $RunnerRepo)}}
    Save-SolutionProfile $profile $State
    Invoke-SolutionCommand $python @((Join-Path $repo 'host/solution.py'),'--config',(Join-Path $State 'solution.json'),'--write-config',(Join-Path $State 'mcp.toml'))
    if ($RegisterCodex) { & (Join-Path $PSScriptRoot 'register_codex.ps1') -State $State -ConfigPath $CodexConfig }
    Write-Host "SOLUTION_INSTALLED: $(Join-Path $State 'solution.json')"
} finally { Stop-Transcript | Out-Null; $lock.Dispose() }
if ($Start) { & (Join-Path $repo 'scripts/start_solution.ps1') -State $State }
