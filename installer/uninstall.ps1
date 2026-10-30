#Requires -Version 5.1
<#
.SYNOPSIS
    Removes the SecureArtifactScanner service. Run elevated.

.DESCRIPTION
    Stops and deletes the service, removes the program files, the quarantine (all pending scan
    jobs), the work directory, config.json, the event log source and the service's grant on the
    export root. Exported files in the export root are NOT touched.

    Folders are deleted with "rmdir /s /q", which removes a junction itself instead of following
    it (Windows PowerShell 5.1 Remove-Item -Recurse can follow junctions into their targets).

.PARAMETER KeepLogs
    Keep ProgramData\SecureRuntime\ScannerService\logs for later inspection.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "",
    [string]$DataRoot = "",
    [switch]$KeepLogs
)
$ErrorActionPreference = "Stop"
$Name = "SecureArtifactScanner"
$Account = "NT SERVICE\$Name"
if (-not $InstallDir) { $InstallDir = Join-Path $env:ProgramFiles "SecureRuntime\ScannerService" }
if (-not $DataRoot) { $DataRoot = Join-Path $env:ProgramData "SecureRuntime" }
$StateDir = Join-Path $DataRoot "ScannerService"
$Quarantine = Join-Path $DataRoot "Quarantine"

function Remove-Tree([string]$path) {
    if (Test-Path -LiteralPath $path) {
        & cmd.exe /d /c rmdir /s /q $path
        if (Test-Path -LiteralPath $path) { Write-Warning "could not remove $path completely" }
    }
}
function Remove-IfEmpty([string]$path) {
    if ((Test-Path -LiteralPath $path) -and -not (Get-ChildItem -LiteralPath $path -Force)) {
        & cmd.exe /d /c rmdir $path
    }
}

$me = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell (Run as administrator)."
}

$svc = Get-Service $Name -ErrorAction SilentlyContinue
$SvcSid = $null
if ($svc) {
    try { $SvcSid = (New-Object Security.Principal.NTAccount $Account).Translate([Security.Principal.SecurityIdentifier]).Value } catch {}
}

# export root grant (read the config before it is deleted)
$cfgPath = Join-Path $StateDir "config.json"
$exportRoot = $null
if (Test-Path $cfgPath) {
    try { $exportRoot = (Get-Content -Raw $cfgPath | ConvertFrom-Json).export_root } catch {}
}

Write-Host "[1/6] stop and delete the service"
if ($svc) {
    if ($svc.Status -ne "Stopped") {
        Stop-Service $Name -Force -ErrorAction SilentlyContinue
        try { $svc.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(60)) } catch {
            $procId = (Get-CimInstance Win32_Service -Filter "Name='$Name'").ProcessId
            if ($procId) { Write-Warning "service did not stop; ending process $procId"; Stop-Process -Id $procId -Force }
        }
    }
    & sc.exe delete $Name | Out-Null
    for ($i = 0; $i -lt 30 -and (Get-Service $Name -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Milliseconds 500 }
    if (Get-Service $Name -ErrorAction SilentlyContinue) { Write-Warning "service is marked for deletion (close Services/Event Viewer windows or reboot)" }
} else {
    Write-Host "        not installed"
}

Write-Host "[2/6] export root: remove the service's grant (exported files are kept)"
if ($exportRoot -and (Test-Path -LiteralPath $exportRoot) -and $SvcSid) {
    & icacls.exe $exportRoot /remove:g "*$SvcSid" /Q | Out-Null
    Write-Host "        $exportRoot"
}

Write-Host "[3/6] program files"
Remove-Tree $InstallDir
Remove-IfEmpty (Split-Path $InstallDir -Parent)

Write-Host "[4/6] quarantine and pending scan jobs"
Remove-Tree $Quarantine

Write-Host "[5/6] service state (config, work$(if (-not $KeepLogs) { ', logs' }))"
Remove-Tree (Join-Path $StateDir "work")
if (Test-Path $cfgPath) { Remove-Item -LiteralPath $cfgPath -Force }
if (-not $KeepLogs) { Remove-Tree (Join-Path $StateDir "logs") }
Remove-IfEmpty $StateDir
Remove-IfEmpty $DataRoot

Write-Host "[6/6] event log source"
$evt = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$Name"
if (Test-Path $evt) { Remove-Item $evt -Recurse -Force }
Write-Host "SecureArtifactScanner removed."
