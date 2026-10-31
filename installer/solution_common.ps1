# Shared by the solution commands. Dot-sourcing performs no installation.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-SolutionCommand {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "$Program failed (exit $LASTEXITCODE)." }
}
function Get-SolutionStatePath {
    param([string]$State)
    if (-not $State) { $State = Join-Path $env:USERPROFILE 'SecureCUAState/solution' }
    [IO.Path]::GetFullPath($State)
}
function Assert-SolutionIdle {
    # Never terminate another session as a side effect of installing/updating.
    $active = Get-Process -Name WindowsSandbox,WindowsSandboxClient,WindowsSandboxRemoteSession,vmmemWindowsSandbox -ErrorAction SilentlyContinue
    if ($active) { throw 'A Windows Sandbox is open. Finish it yourself before installing/updating/starting another session.' }
}
function Assert-SolutionUser {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Start this command in an ordinary PowerShell. Only the service/ACL step requests elevation.'
    }
}
function Assert-SolutionEnvironmentUnused {
    param([string]$Python)
    $active = Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" |
        Where-Object {
            ($_.ExecutablePath -and $_.ExecutablePath -eq $Python) -or
            ($_.PSObject.Properties['CommandLine'] -and $_.CommandLine -and
             $_.CommandLine -match ('(?i)(?:^|["\s])' + [regex]::Escape($Python) + '(?:["\s]|$)'))
        }
    if ($active) { throw 'The installed Python environment is in use. Disconnect its MCP/client before updating it.' }
}
function Resolve-SolutionRepo {
    param([string]$Path, [string]$Marker)
    if (-not (Test-Path -LiteralPath (Join-Path $Path $Marker) -PathType Leaf)) {
        throw "Repository is missing $Marker at $Path. Supply -ManagerRepo / -RunnerRepo for a non-sibling layout."
    }
    (Resolve-Path -LiteralPath $Path).Path
}
function Read-SolutionProfile {
    param([string]$State)
    $file = Join-Path (Get-SolutionStatePath $State) 'solution.json'
    $profile = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($profile.schema_version -ne 1) { throw "Unsupported solution profile: $file" }
    $profile
}
function Get-SolutionSource {
    param([string]$Repo)
    $commit = (& git -C $Repo rev-parse HEAD) -join ''
    if ($LASTEXITCODE -ne 0) { throw "Not a Git checkout: $Repo" }
    $dirty = [bool]((& git -C $Repo status --porcelain --untracked-files=normal) -join '')
    if ($LASTEXITCODE -ne 0) { throw "Cannot read Git state: $Repo" }
    @{path=$Repo; commit=$commit; dirty=$dirty}
}
function Enter-SolutionUpdate {
    param([string]$State)
    New-Item -ItemType Directory -Force -Path $State | Out-Null
    try { [IO.File]::Open((Join-Path $State 'setup.lock'), 'OpenOrCreate', 'ReadWrite', 'None') }
    catch { throw 'Another solution installation/update is running.' }
}
function Install-SolutionManager {
    param([string]$Python, [string]$ManagerRepo, [string]$Mode)
    if ($Mode -eq 'Dev') { Invoke-SolutionCommand $Python @('-m','pip','install','-e',$ManagerRepo) }
    else { Invoke-SolutionCommand $Python @('-m','pip','install','--upgrade','--force-reinstall','--no-deps',$ManagerRepo) }
    # These APIs are actually used by solution.py and the Host lifecycle.
    Invoke-SolutionCommand $Python @('-c', "from sandbox_manager.inbox import USER_FOLDERS,check_inbox_root; from sandbox_manager import SandboxManager,make_share,SharedWatcher,finish_shared,clear_inbox; assert hasattr(SandboxManager,'window_state'), 'Manager window_state API is required'; import sandbox_manager; print('MANAGER_SOURCE:', sandbox_manager.__file__)")
}
function Build-SolutionRunner {
    param([string]$RunnerRepo, [string]$UcrtRoot)
    $script = Join-Path $RunnerRepo 'scripts/build.ps1'
    if (-not (Test-Path -LiteralPath $script)) { throw 'Runner scripts/build.ps1 is required (sandbox_runner issue #33).' }
    $argsForBuild = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$script)
    if ($UcrtRoot) { $argsForBuild += @('-UcrtRoot',$UcrtRoot) }
    Invoke-SolutionCommand powershell.exe $argsForBuild
    $info = Get-Content -LiteralPath (Join-Path $RunnerRepo 'build/solution/build-info.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $expected = [IO.Path]::GetFullPath((Join-Path $RunnerRepo 'build/solution/sandbox_runner.exe'))
    if ($info.schema_version -ne 1 -or $info.executable -ne $expected -or
        (Get-FileHash -LiteralPath $expected -Algorithm SHA256).Hash -ne $info.sha256) { throw 'Runner build receipt mismatch.' }
    $info
}
function Install-SolutionPrivileged {
    param([string]$HostRepo, [string]$Python, [string]$Work, [string]$State, [string]$RunnerExe, [string]$ScannerSourceDir, [string]$ManagerRepo)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $id = [Guid]::NewGuid().ToString('N')
    $requestPath = Join-Path $State "install-$id.json"
    $resultPath = Join-Path $State "install-$id.result.json"
    @{sid=$identity.User.Value; user=$identity.Name; python=$Python; work=$Work; state=$State;
      runner=$RunnerExe; scanner_source=$ScannerSourceDir; manager_repo=$ManagerRepo; result=$resultPath} |
        ConvertTo-Json | Set-Content -LiteralPath $requestPath -Encoding UTF8
    # Encode a literal command; no path is reinterpreted as shell syntax.
    $script = (Join-Path $HostRepo 'installer/solution_elevated.ps1').Replace("'", "''")
    $literal = $requestPath.Replace("'", "''")
    $command = "& '$script' -RequestPath '$literal'"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $process = Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -PassThru -Wait `
        -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded)
    if ($process.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $resultPath)) {
        throw "Privileged setup failed/cancelled. Inspect $State/setup-elevated.log and $resultPath."
    }
    $result = Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $result.ok) { throw "Service installation failed: $($result.error)" }
}
function Save-SolutionProfile {
    param($Profile, [string]$State)
    $path = Join-Path $State 'solution.json'
    $temp = $path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    $Profile | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $temp -Encoding UTF8
    if (Test-Path -LiteralPath $path) {
        Copy-Item -LiteralPath $path -Destination ($path+'.backup-'+[DateTime]::UtcNow.ToString('yyyyMMddHHmmssfff'))
    }
    Move-Item -LiteralPath $temp -Destination $path -Force
}
