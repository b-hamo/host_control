# This script only unpacks and runs Host-built output. It never compiles.
param([string]$Runtime = '')
$ErrorActionPreference = 'Stop'
# BUILD_PACKAGE_DATA
$package = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encodedPackage)) | ConvertFrom-Json
$deadline = [DateTime]::UtcNow.AddSeconds(120)
$stream = $null
try {
    while ($null -eq $stream) {
        try {
            $stream = [IO.File]::Open($package.package, 'Open', 'Read', 'Read')
            $hasher = [Security.Cryptography.SHA256]::Create()
            try { $actual = [BitConverter]::ToString($hasher.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() }
            finally { $hasher.Dispose() }
            if ($actual -ne $package.sha256) { throw 'build package hash mismatch' }
        } catch {
            if ($stream) { $stream.Dispose(); $stream = $null }
            if ([DateTime]::UtcNow -ge $deadline) { throw }
            Start-Sleep -Milliseconds 500
        }
    }
    $root = Join-Path $env:TEMP ('RouterOutput-' + $package.nonce)
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    & (Join-Path $env:SystemRoot 'System32\tar.exe') -xf $package.package -C $root
    if ($LASTEXITCODE -ne 0) { throw ('build package extraction failed: ' + $LASTEXITCODE) }
} finally { if ($stream) { $stream.Dispose() } }
$entry = Join-Path $root $package.entry
$argv = @($package.arguments | ForEach-Object { $_.Replace('{entry}', $entry).Replace('{root}', $root) })
if ($Runtime) { $exe = $Runtime } else { $exe = $entry }
# Quote each argument for Windows CreateProcess, including empty strings,
# embedded quotes and trailing backslashes. No shell expansion is performed.
function Quote-Argument([string]$value) {
    $value = [regex]::Replace($value, '(\\*)"', { param($m) ($m.Groups[1].Value + $m.Groups[1].Value + '\"') })
    $value = [regex]::Replace($value, '(\\+)$', { param($m) ($m.Value + $m.Value) })
    return '"' + $value + '"'
}
$info = New-Object Diagnostics.ProcessStartInfo
$info.FileName = $exe
$info.Arguments = (@($argv | ForEach-Object { Quote-Argument $_ }) -join ' ')
$info.WorkingDirectory = Split-Path -Parent $entry
$info.UseShellExecute = $false
$info.CreateNoWindow = $true
# Inherit the helper's output handles so its existing receipt records the result.
$process = [Diagnostics.Process]::Start($info)
$process.WaitForExit()
$code = $process.ExitCode
$process.Dispose()
exit $code
