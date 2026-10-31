#Requires -Version 5.1
<#
.SYNOPSIS
    Installs the integrated Host + pinned Sandbox Manager + Runner configuration.
.DESCRIPTION
    Run elevated as the SAME Windows user who will run the Host. Requires Python
    3.13 x64, Git and a built sandbox_runner.exe. Installs Python dependencies,
    builds/installs the scanner service, prepares deny-execute inbox/Shared roots,
    and writes an MCP fragment only after the complete service preflight passes.
    Does not close an existing Sandbox or rewrite the user's Codex configuration.
    -SkipDependencyInstall and -ScannerSourceDir support a prepared offline bundle.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$RunnerExe,
    [string]$PythonExe = '',
    [string]$Work = '',
    [string]$State = '',
    [string]$ConfigOut = '',
    [string]$ScannerSourceDir = '',
    [switch]$SkipDependencyInstall
)
$ErrorActionPreference = 'Stop'
$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $Work) { $Work = Join-Path $env:USERPROFILE 'SecureCUA\solution' }
if (-not $State) { $State = Join-Path $env:USERPROFILE 'SecureCUAState\solution' }
if (-not $ConfigOut) { $ConfigOut = Join-Path $State 'mcp.toml' }
$me = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run elevated as the Host user (do not use a different administrator account).'
}
if (-not $PythonExe) {
    $PythonExe = Join-Path $Repo '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $PythonExe)) {
        & py -3.13 -m venv (Join-Path $Repo '.venv')
        if ($LASTEXITCODE -ne 0) { throw 'Python 3.13 x64 is required.' }
    }
}
& $PythonExe -c "import sys,struct; assert sys.version_info[:2] == (3,13) and struct.calcsize('P') == 8"
if ($LASTEXITCODE -ne 0) { throw 'Python 3.13 x64 is required.' }
if (-not $SkipDependencyInstall) {
    & $PythonExe -m pip install -r (Join-Path $Repo 'requirements.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Host / pinned sandbox_manager dependency install failed.' }
}
$Entry = Join-Path $Repo 'host\solution.py'
$ProfileArgs = @('--runner-exe', $RunnerExe, '--work', $Work, '--state', $State)
& $PythonExe $Entry @ProfileArgs --validate-paths
if ($LASTEXITCODE -ne 0) { throw 'Invalid solution paths; no ACL or service changes made.' }

# Only the dedicated work root receives execute-deny permissions. State and code
# must be outside it; solution.py validates this before anything is created.
foreach ($folder in @($Work, (Join-Path $Work 'inbox'), (Join-Path $Work 'shared'), $State)) {
    New-Item -ItemType Directory -Force -Path $folder | Out-Null
}
& icacls.exe $Work /deny '*S-1-1-0:(OI)(IO)(X)' /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot apply execute-deny ACL.' }
& icacls.exe $Work /grant '*S-1-3-4:(OI)(CI)(R,W,D)' /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot apply owner-rights ACL.' }

if (-not $ScannerSourceDir) {
    # A child PowerShell isolates the build/install scripts' exit statements.
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'build.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'Scanner build failed.' }
    $ScannerSourceDir = Join-Path $Repo 'dist\SecureArtifactScanner'
}
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'install.ps1') `
    -SourceDir $ScannerSourceDir -ClientUser $me.Name -ExportRoot (Join-Path $State 'exports') -EnableSharedScan
if ($LASTEXITCODE -ne 0) { throw 'Scanner service install/verification failed; MCP config not published.' }

& $PythonExe $Entry @ProfileArgs --write-config $ConfigOut
if ($LASTEXITCODE -ne 0) { throw 'Solution preflight failed; MCP config not published.' }
Write-Host "Installed and verified. MCP fragment: $ConfigOut"
Write-Host 'Replace the existing scrp_sandbox MCP block with this fragment, then reconnect after finishing the current Sandbox.'
Write-Host 'Start the Host as your ordinary user. Shared export: Downloads\SandboxShared\<session>.'
