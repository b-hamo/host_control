#Requires -Version 5.1
<#
.SYNOPSIS
    Checks an installed SecureArtifactScanner: account, token, ACLs, pipe, Defender, cleanup. Run elevated.

.DESCRIPTION
    Account   sc.exe qc / qsidtype / qprivs, Win32_Service.StartName and the running process's user
    Token     HEALTH_CHECK over the pipe: the service reads its own token (admin? LocalSystem? privileges)
    ACLs      install dir: nobody but SYSTEM/Administrators/TrustedInstaller may write;
              data, logs, work, quarantine: only SYSTEM, Administrators and the service, inheritance cut
    Function  benign text: upload -> Defender CLEAN -> SCANNED -> abort -> DISPOSED, quarantine empty
              EICAR (unless -SkipEicar): BLOCKED / MALWARE_DETECTED (raises a Defender alert, expected)
              -Publish: benign -> EXPORTED into the configured export root
              -Restart: Restart-Service, then the same checks again on the new process
              -CrashTest: kill the service process; the SCM restarts it and it reports the unclean stop
    A report is written to -ReportPath (default build\verify-report.txt). Exit code 1 if anything failed.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "",
    [string]$DataRoot = "",
    [string]$ReportPath = "",
    [switch]$SkipEicar,
    [switch]$Publish,
    [switch]$Restart,
    [switch]$CrashTest
)
$ErrorActionPreference = "Stop"
$Name = "SecureArtifactScanner"
$Account = "NT SERVICE\$Name"
if (-not $InstallDir) { $InstallDir = Join-Path $env:ProgramFiles "SecureRuntime\ScannerService" }
if (-not $DataRoot) { $DataRoot = Join-Path $env:ProgramData "SecureRuntime" }
if (-not $ReportPath) { $ReportPath = Join-Path $PSScriptRoot "..\build\verify-report.txt" }
$Exe = Join-Path $InstallDir "$Name.exe"
$StateDir = Join-Path $DataRoot "ScannerService"
$Quarantine = Join-Path $DataRoot "Quarantine"
$Trusted = @("S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
$WriteMask = 0x500D0156          # write/append data, EA, delete child, attributes, DELETE, DAC, owner, GENERIC_ALL/WRITE
$results = New-Object System.Collections.Generic.List[object]

function Add-Result([string]$check, [string]$result, [string]$detail) {
    $results.Add([pscustomobject]@{ Check = $check; Result = $result; Detail = $detail })
    $color = @{ PASS = "Green"; FAIL = "Red"; WARN = "Yellow"; INFO = "Gray" }[$result]
    Write-Host ("{0,-5} {1,-34} {2}" -f $result, $check, $detail) -ForegroundColor $color
}
function Check([string]$check, [bool]$ok, [string]$detail) { Add-Result $check $(if ($ok) { "PASS" } else { "FAIL" }) $detail }
function Sid($identity) {
    try { $identity.Translate([Security.Principal.SecurityIdentifier]).Value } catch { "$identity" }
}
function Client([string[]]$a) {
    $out = (& $Exe client @a) | Out-String
    $code = $LASTEXITCODE
    try { $obj = $out | ConvertFrom-Json } catch { $obj = $null }
    [pscustomobject]@{ Code = $code; Json = $obj; Text = $out.Trim() }
}
function Acl-Writers([string]$path, [string[]]$allowed) {
    $acl = Get-Acl -LiteralPath $path
    $bad = @()
    foreach ($r in $acl.Access) {
        if ($r.AccessControlType -ne "Allow") { continue }
        $sid = Sid $r.IdentityReference
        if (([int64]$r.FileSystemRights -band $WriteMask) -and ($allowed -notcontains $sid)) { $bad += "$($r.IdentityReference):$($r.FileSystemRights)" }
    }
    [pscustomobject]@{ Bad = $bad; Protected = $acl.AreAccessRulesProtected; Owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value; Acl = $acl }
}
function Quarantine-Entries { @(Get-ChildItem -LiteralPath $Quarantine -Recurse -Force -ErrorAction SilentlyContinue) }

function Check-Service([string]$label) {
    $w = Get-CimInstance Win32_Service -Filter "Name='$Name'"
    if (-not $w) { Check "$label service registered" $false "not installed"; return $null }
    Check "$label service state" ($w.State -eq "Running") "$($w.State), start mode $($w.StartMode), pid $($w.ProcessId)"
    Check "$label Win32_Service.StartName" ($w.StartName -eq $Account) $w.StartName
    Check "$label binary path" ($w.PathName -eq "`"$Exe`"") $w.PathName
    $qc = (& sc.exe qc $Name) -join "`n"
    Check "$label sc qc SERVICE_START_NAME" ($qc -match [regex]::Escape("SERVICE_START_NAME : $Account")) (($qc -split "`n" | Where-Object { $_ -match "START_NAME" }) -join "").Trim()
    $sidtype = (& sc.exe qsidtype $Name) -join " "
    Check "$label sc qsidtype" ($sidtype -match "UNRESTRICTED") ($sidtype -replace "\s+", " ").Trim()
    $privs = ((& sc.exe qprivs $Name) -join " ") -replace "\s+", " "
    Add-Result "INFO" "INFO" "required privileges: $($privs.Trim())"
    if ($w.ProcessId) {
        $p = Get-Process -Id $w.ProcessId -IncludeUserName
        Check "$label process user (outside view)" ($p.UserName -eq $Account) "$($p.UserName), $($p.Path)"
    }
    return $w
}

function Check-Health([string]$label) {
    $h = Client @("health")
    if (-not $h.Json -or -not $h.Json.token) { Check "$label pipe HEALTH_CHECK" $false $h.Text; return $null }
    $t = $h.Json.token
    Check "$label pipe HEALTH_CHECK" $true "pid $($h.Json.pid), version $($h.Json.version)"
    Check "$label token account" ($t.account -eq $Account) "$($t.account) $($t.sid)"
    Check "$label token not administrator" ((-not $t.is_admin) -and (-not $t.administrators_group)) "is_admin=$($t.is_admin) administrators_group=$($t.administrators_group)"
    Check "$label token not LocalSystem" (-not $t.is_local_system) "integrity $($t.integrity_rid), elevated=$($t.elevated)"
    Add-Result "INFO" "INFO" ("token privileges: " + (@($t.privileges) -join ", "))
    $py = $h.Json.python
    Check "$label runs frozen from install dir" ($py.frozen -and $py.executable -like "$InstallDir*") "$($py.executable) (Python $($py.version), sys.path inside bundle: $($py.sys_path_ok))"
    $d = $h.Json.defender
    Check "$label Defender usable" ([bool]$d.available) $(if ($d.available) { "$($d.mpcmdrun); platform $($d.platform_version), sig $($d.signature_version)" } else { $d.problem })
    Add-Result "INFO" "INFO" ("publish: enabled=$($h.Json.publish.enabled) mode=$($h.Json.publish.approval_mode) $($h.Json.publish.problem)")
    return $h.Json
}

function Check-Functions([string]$label) {
    $b = Client @("roundtrip", "--content", "benign")
    $bs = if ($b.Json) { "$($b.Json.steps.uploaded) -> $($b.Json.steps.scanned) -> $($b.Json.final_state); $($b.Json.scan.detail)" } else { $b.Text }
    Check "$label benign file scanned clean" ($b.Code -eq 0) $bs
    if (-not $SkipEicar) {
        $e = Client @("roundtrip", "--content", "eicar")
        $es = if ($e.Json) { "$($e.Json.steps.uploaded) -> $($e.Json.steps.scanned); $($e.Json.error.code): $($e.Json.error.message)" } else { $e.Text }
        Check "$label EICAR blocked" ($e.Code -eq 0) $es
    }
    if ($Publish) {
        $p = Client @("roundtrip", "--content", "benign", "--publish")
        $ps = if ($p.Json -and $p.Json.published) { "$($p.Json.published.outcome) $($p.Json.published.export_path)" } else { $p.Text }
        Check "$label publish to export root" ($p.Code -eq 0) $ps
    }
    Start-Sleep -Seconds 1
    $left = Quarantine-Entries
    Check "$label quarantine empty afterwards" ($left.Count -eq 0) ("{0} entr{1}" -f $left.Count, $(if ($left.Count -eq 1) { "y" } else { "ies" }))
}

# ------------------------------------------------------------------------------------------------
$me = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell (Run as administrator)."
}
Write-Host "SecureArtifactScanner verification $(Get-Date -Format s)"
$w = Check-Service "1."
if (-not $w) { exit 1 }
$SvcSid = Sid (New-Object Security.Principal.NTAccount $Account)

$a = Acl-Writers $InstallDir $Trusted
Check "2. install dir: only admins write" ($a.Bad.Count -eq 0) $(if ($a.Bad) { $a.Bad -join "; " } else { "owner $($a.Owner), protected=$($a.Protected)" })
$a = Acl-Writers $Exe $Trusted
Check "2. executable: only admins write" ($a.Bad.Count -eq 0) $(if ($a.Bad) { $a.Bad -join "; " } else { "ok" })
foreach ($d in @($DataRoot, $StateDir, (Join-Path $StateDir "logs"), (Join-Path $StateDir "work"), $Quarantine)) {
    $a = Acl-Writers $d ($Trusted + $SvcSid)
    $others = @($a.Acl.Access | Where-Object { $_.AccessControlType -eq "Allow" -and (@($Trusted + $SvcSid) -notcontains (Sid $_.IdentityReference)) } |
                ForEach-Object { "$($_.IdentityReference)" })
    $ok = ($a.Bad.Count -eq 0) -and ($others.Count -eq 0) -and $a.Protected
    Check ("2. ACL " + (Split-Path $d -Leaf)) $ok $(if ($ok) { "SYSTEM, Administrators, service only; inheritance cut" } else { "others: $($others -join ', '); protected=$($a.Protected)" })
}
$qa = (Get-Acl -LiteralPath $Quarantine).Access | Where-Object { (Sid $_.IdentityReference) -eq $SvcSid }
Check "2. service may modify quarantine" ([bool]($qa | Where-Object { $_.FileSystemRights -match "Modify|FullControl" })) (($qa | ForEach-Object { "$($_.FileSystemRights)" }) -join ", ")
$cfg = Join-Path $StateDir "config.json"
$ca = Acl-Writers $cfg $Trusted
Check "2. config.json: only admins write" ($ca.Bad.Count -eq 0) $(if ($ca.Bad) { $ca.Bad -join "; " } else { "ok" })

$h = Check-Health "3."
Check-Functions "4."

if ($Restart) {
    $oldPid = $w.ProcessId
    Restart-Service $Name -Force
    (Get-Service $Name).WaitForStatus("Running", [TimeSpan]::FromSeconds(90))
    $w2 = Check-Service "5. after restart:"
    Check "5. new process after restart" ($w2.ProcessId -ne $oldPid) "pid $oldPid -> $($w2.ProcessId)"
    $h2 = Check-Health "5."
    if ($h2) { Check "5. clean stop recorded" (-not $h2.recovery.previous_run_unclean) "previous_run_unclean=$($h2.recovery.previous_run_unclean)" }
    Check-Functions "5."
}

if ($CrashTest) {
    $w = Get-CimInstance Win32_Service -Filter "Name='$Name'"
    Stop-Process -Id $w.ProcessId -Force
    Add-Result "INFO" "INFO" "killed pid $($w.ProcessId); waiting for the SCM to restart the service (failure action: 5 s)"
    $deadline = (Get-Date).AddSeconds(90)
    do { Start-Sleep -Seconds 2; $w3 = Get-CimInstance Win32_Service -Filter "Name='$Name'" } while (
        ($w3.State -ne "Running" -or $w3.ProcessId -eq $w.ProcessId -or -not $w3.ProcessId) -and (Get-Date) -lt $deadline)
    Check "6. restarted by the SCM after a kill" ($w3.State -eq "Running" -and $w3.ProcessId -ne $w.ProcessId) "$($w3.State), pid $($w3.ProcessId)"
    Start-Sleep -Seconds 2
    $h3 = Check-Health "6."
    if ($h3) { Check "6. unclean stop detected, leftovers discarded" ([bool]$h3.recovery.previous_run_unclean) "recovery: $($h3.recovery | ConvertTo-Json -Compress)" }
    Check-Functions "6."
}

$fails = @($results | Where-Object { $_.Result -eq "FAIL" })
New-Item -ItemType Directory -Force (Split-Path $ReportPath -Parent) | Out-Null
$header = "SecureArtifactScanner verify $(Get-Date -Format s) on $env:COMPUTERNAME ($((Get-CimInstance Win32_OperatingSystem).Caption) $([Environment]::OSVersion.Version))"
($header, ($results | Format-Table -AutoSize -Wrap | Out-String -Width 220), "FAILED: $($fails.Count)") | Set-Content -Encoding UTF8 $ReportPath
Write-Host ""
Write-Host "Report: $((Resolve-Path $ReportPath).Path)"
if ($fails.Count) { Write-Host "$($fails.Count) check(s) FAILED" -ForegroundColor Red; exit 1 }
Write-Host "All checks passed" -ForegroundColor Green
exit 0
