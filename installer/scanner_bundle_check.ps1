# Defender checks run before any bundled executable and before replacing a service.
# Dot-sourcing defines functions only, so failure paths can be tested without AV/SCM changes.
function Get-ScannerBundleInventory {
    param([string]$Root)
    $items = @(Get-Item -LiteralPath $Root -Force) + @(Get-ChildItem -LiteralPath $Root -Recurse -Force)
    if ($items | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) {
        throw 'Scanner bundle must not contain links or junctions.'
    }
    $inventory = [ordered]@{}
    foreach ($file in @($items | Where-Object { -not $_.PSIsContainer } | Sort-Object FullName)) {
        $relative = $file.FullName.Substring($Root.Length).TrimStart('\')
        $inventory[$relative] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLower()
    }
    $inventory
}

function Invoke-ScannerBundleScan {
    param([string]$Program, [string]$Root)
    $output = (& $Program -Scan -ScanType 3 -File $Root 2>&1 | Out-String)
    @{exit_code=$LASTEXITCODE; output=$output}
}

function Get-ScannerDefenderCommand {
    # AMProductVersion omits the platform directory's revision suffix (e.g. -0).
    $install = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Defender' -Name InstallLocation -ErrorAction Stop).InstallLocation
    $mp = [IO.Path]::GetFullPath((Join-Path $install 'MpCmdRun.exe'))
    $root = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'Microsoft/Windows Defender/Platform'))
    $legacy = Join-Path $env:ProgramFiles 'Windows Defender/MpCmdRun.exe'
    if (-not $mp.StartsWith($root+'\', [StringComparison]::OrdinalIgnoreCase) -and $mp -ne $legacy) {
        throw 'Defender command is outside the Windows Defender installation directories.'
    }
    if ((Get-AuthenticodeSignature -LiteralPath $mp).Status -ne 'Valid') {
        throw 'Microsoft Defender command signature could not be verified.'
    }
    $mp
}

function Assert-ScannerBundleClean {
    param([Parameter(Mandatory=$true)][string]$Bundle)
    $root = (Resolve-Path -LiteralPath $Bundle).Path.TrimEnd('\')
    if (-not (Test-Path -LiteralPath (Join-Path $root 'SecureArtifactScanner.exe') -PathType Leaf)) {
        throw 'Scanner executable is missing; do not restore or replace a service without a verified bundle.'
    }
    $status = Get-MpComputerStatus -ErrorAction Stop
    if (-not $status.AntivirusEnabled -or -not $status.RealTimeProtectionEnabled -or $status.AMRunningMode -ne 'Normal') {
        throw 'Active Microsoft Defender with real-time protection is required to verify the scanner bundle.'
    }
    $mp = Get-ScannerDefenderCommand
    $before = Get-ScannerBundleInventory $root
    $started = Get-Date
    $scan = Invoke-ScannerBundleScan $mp $root
    if ($scan.exit_code -ne 0) { throw "Scanner bundle scan failed (exit $($scan.exit_code)): $($scan.output)" }
    # MpCmdRun may return 0 after removing malware. Exit code alone is insufficient.
    try {
        $events = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';
            Id=1116,1117; StartTime=$started.AddSeconds(-1)} -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { throw }
        $events = @()
    }
    if ($events | Where-Object { $_.Message.IndexOf($root, [StringComparison]::OrdinalIgnoreCase) -ge 0 }) {
        throw 'Defender reported a detection in the scanner bundle. Existing service was not replaced.'
    }
    $after = Get-ScannerBundleInventory $root
    if (($before | ConvertTo-Json -Compress) -ne ($after | ConvertTo-Json -Compress)) {
        throw 'Scanner bundle changed or was quarantined during scanning. Existing service was not replaced.'
    }
    Write-Host "SCANNER_BUNDLE_CLEAN: $root; signature=$($status.AntivirusSignatureVersion); files=$($before.Count)"
    [ordered]@{ scanned_at=$started.ToUniversalTime().ToString('o');
        signature=$status.AntivirusSignatureVersion; engine=$status.AMEngineVersion;
        platform=$status.AMProductVersion; exe_sha256=$before['SecureArtifactScanner.exe']; files=$before.Count }
}
