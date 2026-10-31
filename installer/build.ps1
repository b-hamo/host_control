#Requires -Version 5.1
<#
.SYNOPSIS
    Builds SecureArtifactScanner.exe (PyInstaller --onedir) into dist\SecureArtifactScanner\.

.DESCRIPTION
    - Uses its own virtual environment (build\scanner\venv) with pinned versions from
      installer\requirements-build.txt, so the result does not depend on the developer's Python.
    - --onedir, not --onefile: --onefile unpacks the Python runtime into a TEMP directory at every
      start, which a service must not load code from. --onedir runs from the install directory only.
    - The output needs no Python on the target PC (python313.dll, pywin32 DLLs and modules are inside).
    - A smoke test runs the built exe ("version") and records build-info.json.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File installer\build.ps1
#>
[CmdletBinding()]
param(
    [string]$PythonLauncherVersion = "3.13",
    [string]$PythonExe = "",
    [string]$OutDir = "",
    [switch]$Clean
)
$ErrorActionPreference = "Stop"
if (-not $OutDir) { $OutDir = Join-Path $PSScriptRoot "..\dist" }      # $PSScriptRoot is empty in param defaults on 5.1
$Name = "SecureArtifactScanner"
$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BuildRoot = Join-Path $Repo "build\scanner"
$Venv = Join-Path $BuildRoot "venv"
$Py = Join-Path $Venv "Scripts\python.exe"
New-Item -ItemType Directory -Force $BuildRoot | Out-Null
New-Item -ItemType Directory -Force $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

if ($Clean -and (Test-Path $Venv)) {
    $resolved = (Resolve-Path -LiteralPath $Venv).Path
    if (-not $resolved.StartsWith($Repo + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Build venv is outside the repository.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
if (-not (Test-Path $Py)) {
    Write-Host "Creating build venv (Python $PythonLauncherVersion) in $Venv"
    if ($PythonExe) { & $PythonExe -m venv $Venv }
    else { & py "-$PythonLauncherVersion" -m venv $Venv }
    if ($LASTEXITCODE -ne 0) { throw "py -$PythonLauncherVersion -m venv failed (is Python $PythonLauncherVersion x64 installed?)" }
}
& $Py -c "import sys, struct; assert sys.version_info[:2] == (3, 13), sys.version; assert struct.calcsize('P') == 8, '64-bit Python required'"
if ($LASTEXITCODE -ne 0) { throw "build venv must be 64-bit Python 3.13" }
& $Py -m pip install --disable-pip-version-check -q -r (Join-Path $PSScriptRoot "requirements-build.txt")
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

$Dist = Join-Path $OutDir $Name
if (Test-Path $Dist) {
    $resolved = (Resolve-Path -LiteralPath $Dist).Path
    if (-not $resolved.StartsWith($OutDir.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Scanner output is outside OutDir.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
Write-Host "Running PyInstaller (--onedir)"
& $Py -m PyInstaller --noconfirm --clean --onedir --console --name $Name `
    --distpath $OutDir --workpath (Join-Path $BuildRoot "work") --specpath $BuildRoot `
    --paths $Repo `
    --hidden-import win32timezone --hidden-import servicemanager `
    --exclude-module tkinter --exclude-module pytest `
    (Join-Path $PSScriptRoot "scanner_entry.py")
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

$Exe = Join-Path $Dist "$Name.exe"
$Version = (& $Exe version) -join "`n"
if ($LASTEXITCODE -ne 0 -or $Version -notmatch "frozen=True") { throw "smoke test failed: $Version" }
$Hash = (Get-FileHash $Exe -Algorithm SHA256).Hash.ToLower()
$Info = [ordered]@{
    name = $Name; version_line = $Version; built_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    python = (& $Py -c "import sys; print(sys.version.split()[0])")
    pyinstaller = (& $Py -c "import PyInstaller; print(PyInstaller.__version__)")
    pywin32 = (& $Py -c "import importlib.metadata as m; print(m.version('pywin32'))")
    exe_sha256 = $Hash
    files = (Get-ChildItem $Dist -Recurse -File).Count
}
$Info | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $Dist "build-info.json")
Write-Host "Built $Exe"
Write-Host "  $Version"
Write-Host "  sha256 $Hash, $($Info.files) files"
Write-Host "Next (elevated PowerShell): installer\install.ps1"
