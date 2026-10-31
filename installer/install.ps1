#Requires -Version 5.1
<#
.SYNOPSIS
    Installs (or repairs/updates) the SecureArtifactScanner Windows service. Run elevated.

.DESCRIPTION
    1  administrator check            7  account NT SERVICE\SecureArtifactScanner, SID type, privileges
    2  build output check             8  install directory ACL
    3  Windows / Defender check       9  data directories (Quarantine, logs, work) and their ACLs
    4  stop an existing service       10 config.json (pipe clients, export root), event log source
    5  copy the executable            11 start the service
    6  register the service           12 verify (installer\verify.ps1)

    Safe to run again: it stops the service, replaces the files, re-applies the same settings and
    ACLs and keeps config.json values that are not given on the command line.

    ACLs are written in one operation per directory (owner, protection from inheritance and all
    grants together, via .NET DirectorySecurity), parent before child. That avoids the earlier
    "icacls /inheritance:r first, grants afterwards" order problem, where the service lost its
    access between the two commands (or for good, if the second one failed).

    The service account is a virtual account: its SID (S-1-5-80-...) exists only once the service
    is registered, so registration comes before the ACLs.

.PARAMETER ClientUser
    Accounts allowed to use the Named Pipe besides SYSTEM and Administrators (the Host user).
    Default: the account running this script, or what config.json already has.
.PARAMETER ExportRoot
    Folder that published (approved and clean) artifacts go to. Without it PUBLISH is disabled.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File installer\install.ps1 -ExportRoot "$env:USERPROFILE\SecureExports"
#>
[CmdletBinding()]
param(
    [string]$SourceDir = "",
    [string]$InstallDir = "",
    [string]$DataRoot = "",
    [string[]]$ClientUser = @(),
    [string]$ExportRoot = "",
    [switch]$EnableSharedScan,
    [switch]$NoStart,
    [switch]$SkipVerify
)
$ErrorActionPreference = "Stop"
$Name = "SecureArtifactScanner"
$Account = "NT SERVICE\$Name"
if (-not $SourceDir) { $SourceDir = Join-Path $PSScriptRoot "..\dist\$Name" }
if (-not $InstallDir) { $InstallDir = Join-Path $env:ProgramFiles "SecureRuntime\ScannerService" }
if (-not $DataRoot) { $DataRoot = Join-Path $env:ProgramData "SecureRuntime" }
$StateDir = Join-Path $DataRoot "ScannerService"
$Quarantine = Join-Path $DataRoot "Quarantine"
$ConfigPath = Join-Path $StateDir "config.json"
$TrustedOwners = @("S-1-5-32-544", "S-1-5-18", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")

function Step([int]$n, [string]$text) { Write-Host ("[{0,2}/12] {1}" -f $n, $text) }
function Sid([string]$name) { (New-Object Security.Principal.NTAccount $name).Translate([Security.Principal.SecurityIdentifier]).Value }
function Invoke-Sc {
    $out = & sc.exe @args 2>&1
    if ($LASTEXITCODE -ne 0) { throw "sc.exe $($args -join ' ') failed ($LASTEXITCODE): $out" }
}
function Test-Reparse([string]$path) {
    (Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)
}
function Assert-SafeExisting([string]$path) {
    # A folder someone else made before the install (ProgramData lets users create folders) is not reused.
    if (-not (Test-Path -LiteralPath $path)) { return }
    if (Test-Reparse $path) { throw "$path is a junction or link; remove it and run the installer again" }
    $owner = (Get-Acl -LiteralPath $path).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($TrustedOwners -notcontains $owner) {
        throw "$path already exists and is owned by $owner, not Administrators/SYSTEM; remove it and run again"
    }
}
function New-Rule([string]$sid, [string]$rights, [bool]$inherit = $true) {
    $flags = if ($inherit) { "ContainerInherit,ObjectInherit" } else { "None" }
    New-Object Security.AccessControl.FileSystemAccessRule(
        (New-Object Security.Principal.SecurityIdentifier $sid), [Security.AccessControl.FileSystemRights]$rights,
        [Security.AccessControl.InheritanceFlags]$flags, [Security.AccessControl.PropagationFlags]"None", "Allow")
}
function Set-ProtectedAcl([string]$path, $rules) {
    # Owner, "no inheritance" and every grant in ONE write; then children are reset to inherit it.
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier "S-1-5-32-544"))
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($r in $rules) { $acl.AddAccessRule($r) }
    Set-Acl -LiteralPath $path -AclObject $acl
    if (Get-ChildItem -LiteralPath $path -Force -ErrorAction SilentlyContinue) {
        & icacls.exe (Join-Path $path "*") /reset /T /C /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "icacls /reset under $path failed ($LASTEXITCODE)" }
    }
}

# 1 --------------------------------------------------------------------------------------------
Step 1 "administrator check"
$me = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell (Run as administrator)."
}

# 2 --------------------------------------------------------------------------------------------
Step 2 "build output: $SourceDir"
$SrcExe = Join-Path $SourceDir "$Name.exe"
if (-not (Test-Path $SrcExe) -or -not (Test-Path (Join-Path $SourceDir "_internal"))) {
    throw "$SrcExe not found; build it first: installer\build.ps1"
}
$ver = (& $SrcExe version) -join " "
if ($LASTEXITCODE -ne 0 -or $ver -notmatch "frozen=True") { throw "the build output does not run: $ver" }
Write-Host "        $ver"

# 3 --------------------------------------------------------------------------------------------
Step 3 "Windows and Defender"
if (-not [Environment]::Is64BitOperatingSystem) { throw "64-bit Windows required" }
$os = Get-CimInstance Win32_OperatingSystem
if ([int]$os.BuildNumber -lt 22000) { Write-Warning "tested on Windows 11 (build 22000+); this is $($os.Caption) build $($os.BuildNumber)" }
$wd = Get-Service WinDefend -ErrorAction SilentlyContinue
if (-not $wd -or $wd.Status -ne "Running") {
    Write-Warning "Microsoft Defender Antivirus (WinDefend) is not running: the service will install, but block every scan"
}

# 4 --------------------------------------------------------------------------------------------
Step 4 "existing service"
$svc = Get-Service $Name -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne "Stopped") {
    Stop-Service $Name -Force
    $svc.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(60))
}
Write-Host ("        " + $(if ($svc) { "found, stopped (update)" } else { "none (new install)" }))

# 5 --------------------------------------------------------------------------------------------
Step 5 "copy files to $InstallDir"
Assert-SafeExisting (Split-Path $InstallDir -Parent)
Assert-SafeExisting $InstallDir
New-Item -ItemType Directory -Force $InstallDir | Out-Null
& robocopy.exe $SourceDir $InstallDir /MIR /NFL /NDL /NJH /NJS /NP /R:2 /W:1 | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy failed ($LASTEXITCODE)" }
$Exe = Join-Path $InstallDir "$Name.exe"

# 6 --------------------------------------------------------------------------------------------
Step 6 "register the service"
$bin = "`"$Exe`""
if (-not $svc) {
    New-Service -Name $Name -BinaryPathName $bin -DisplayName "Secure Artifact Scanner" -StartupType Automatic `
        -Description "Scans Sandbox artifact candidates with Microsoft Defender in a private quarantine; never runs them." | Out-Null
} else {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    if ((Get-ItemProperty $key).ImagePath -ne $bin) { Set-ItemProperty $key -Name ImagePath -Value $bin -Type ExpandString }
    Invoke-Sc config $Name start= auto
}

# 7 --------------------------------------------------------------------------------------------
Step 7 "service account $Account"
Invoke-Sc config $Name obj= $Account
Invoke-Sc sidtype $Name unrestricted
Invoke-Sc privs $Name "SeChangeNotifyPrivilege/SeImpersonatePrivilege"
Invoke-Sc failure $Name reset= 86400 actions= restart/5000/restart/30000/restart/120000
Invoke-Sc failureflag $Name 1
$SvcSid = Sid $Account
Write-Host "        SID $SvcSid"

# 8 --------------------------------------------------------------------------------------------
Step 8 "install directory ACL (admins write, service and users read/execute)"
Set-ProtectedAcl $InstallDir @(
    (New-Rule "S-1-5-18" "FullControl"), (New-Rule "S-1-5-32-544" "FullControl"),
    (New-Rule $SvcSid "ReadAndExecute"), (New-Rule "S-1-5-32-545" "ReadAndExecute"))

# 9 --------------------------------------------------------------------------------------------
Step 9 "data directories and ACLs under $DataRoot"
foreach ($d in @($DataRoot, $StateDir, (Join-Path $StateDir "logs"), (Join-Path $StateDir "work"), $Quarantine)) {
    Assert-SafeExisting $d
    New-Item -ItemType Directory -Force $d | Out-Null
}
# parent first, each in one write
Set-ProtectedAcl $DataRoot @((New-Rule "S-1-5-18" "FullControl"), (New-Rule "S-1-5-32-544" "FullControl"),
                             (New-Rule $SvcSid "ReadAndExecute" $false))
Set-ProtectedAcl $StateDir @((New-Rule "S-1-5-18" "FullControl"), (New-Rule "S-1-5-32-544" "FullControl"),
                             (New-Rule $SvcSid "ReadAndExecute"))
foreach ($d in @((Join-Path $StateDir "logs"), (Join-Path $StateDir "work"), $Quarantine)) {
    Set-ProtectedAcl $d @((New-Rule "S-1-5-18" "FullControl"), (New-Rule "S-1-5-32-544" "FullControl"),
                          (New-Rule $SvcSid "Modify"))
}
$q = Get-Item -LiteralPath $Quarantine -Force
$q.Attributes = $q.Attributes -bor [IO.FileAttributes]::NotContentIndexed      # no indexing / previews

# 10 -------------------------------------------------------------------------------------------
Step 10 "config.json and event log source"
$cfg = [ordered]@{}
if (Test-Path $ConfigPath) {
    $old = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json
    foreach ($p in $old.PSObject.Properties) { $cfg[$p.Name] = $p.Value }
}
$cfg["quarantine_root"] = $Quarantine
$cfg["state_dir"] = $StateDir
if ($PSBoundParameters.ContainsKey("EnableSharedScan")) {
    $cfg["shared_scan_enabled"] = [bool]$EnableSharedScan
}
if ($ClientUser.Count -gt 0) {
    $cfg["pipe_client_sids"] = @($ClientUser | ForEach-Object { Sid $_ })
} elseif (-not $cfg.Contains("pipe_client_sids") -or @($cfg["pipe_client_sids"]).Count -eq 0) {
    $cfg["pipe_client_sids"] = @($me.User.Value)
}
if ($ExportRoot) {
    New-Item -ItemType Directory -Force $ExportRoot | Out-Null
    $ExportRoot = (Resolve-Path -LiteralPath $ExportRoot).Path
    if (Test-Reparse $ExportRoot) { throw "export root $ExportRoot is a junction or link" }
    & icacls.exe $ExportRoot /grant "*${SvcSid}:(OI)(CI)M" /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "could not grant the service access to $ExportRoot" }
    $cfg["export_root"] = $ExportRoot
}
$cfg["`$comment"] = "Written by installer\install.ps1. Settings: scanner_service\config.py."
$json = $cfg | ConvertTo-Json -Depth 4
[IO.File]::WriteAllText($ConfigPath, $json, (New-Object Text.UTF8Encoding $false))
Write-Host ("        pipe clients: " + (@($cfg["pipe_client_sids"]) -join ", "))
Write-Host ("        export root: " + $(if ($cfg.Contains("export_root") -and $cfg["export_root"]) { $cfg["export_root"] } else { "(none: PUBLISH disabled)" }))
$evt = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$Name"
$msgDll = Get-ChildItem -LiteralPath $InstallDir -Recurse -Filter "servicemanager*.pyd" | Select-Object -First 1
if ($msgDll) {
    New-Item -Path $evt -Force | Out-Null
    Set-ItemProperty $evt -Name EventMessageFile -Value $msgDll.FullName -Type ExpandString
    Set-ItemProperty $evt -Name TypesSupported -Value 7 -Type DWord
}

# 11 -------------------------------------------------------------------------------------------
if ($NoStart) { Write-Host "[11/12] not started (-NoStart)"; return }
Step 11 "start"
try {
    Start-Service $Name
    (Get-Service $Name).WaitForStatus("Running", [TimeSpan]::FromSeconds(90))
} catch {
    Write-Warning "service did not start: $_"
    & sc.exe query $Name
    $log = Join-Path $StateDir "logs\scanner.log"
    if (Test-Path $log) { Get-Content $log -Tail 30 }
    throw
}

# 12 -------------------------------------------------------------------------------------------
Step 12 "verify"
$qc = (& sc.exe qc $Name) -join "`n"
if ($qc -notmatch [regex]::Escape("SERVICE_START_NAME : $Account")) { throw "service account is not $Account`n$qc" }
if ($SkipVerify) { Write-Host "        sc qc: account OK (full checks skipped: -SkipVerify)"; return }
& (Join-Path $PSScriptRoot "verify.ps1") -InstallDir $InstallDir -DataRoot $DataRoot
exit $LASTEXITCODE
