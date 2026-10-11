# sandbox_run helper (host/sandbox_run.py). Written into the inbox as data; runs only in the Guest.
# Based on router_guest.ps1. Difference: the file to run arrives through the live inbox, and the
# Guest watcher copies it to Desktop\Input a moment later, so wait for that copy (hash checked)
# instead of failing at once. Without a good copy no process starts and a failure receipt says why.
param([Parameter(Mandatory=$true)][string]$Manifest)
$ErrorActionPreference = 'Stop'
if ([Environment]::UserName -ne 'WDAGUtilityAccount') { throw 'Windows Sandbox only' }
$request = Get-Content -LiteralPath $Manifest -Raw -Encoding UTF8 | ConvertFrom-Json
if ($request.contract -ne 'sandbox-run-v1') { throw 'Unsupported request contract' }
$work = Join-Path $env:TEMP ('SandboxRun-' + $request.nonce)
New-Item -ItemType Directory -Path $work -Force | Out-Null
# CreateNew is a per-request execution reservation, never removed or reused.
$lock = [IO.File]::Open((Join-Path $work 'dispatched'), [IO.FileMode]::CreateNew,
                       [IO.FileAccess]::Write, [IO.FileShare]::None)
$utf8 = New-Object Text.UTF8Encoding($false)
$receipt = [ordered]@{
    contract = 'sandbox-run-v1'
    run_id = $request.run_id
    fingerprint = $request.fingerprint
    nonce = $request.nonce
    runtime_id = $request.runtime_id
    generation = $request.generation
    command_sha256 = $request.command_sha256
    sources = $request.sources
}
function Write-Receipt {
    $evidence = Join-Path $request.output_dir ('run-' + $request.nonce + '-receipt.txt')
    [IO.File]::WriteAllText($evidence, ($receipt | ConvertTo-Json -Depth 8 -Compress), $utf8)
}
try {
    $deadline = (Get-Date).AddSeconds([int]$request.wait_inputs_s)
    foreach ($inputFile in $request.inputs) {
        while ($true) {
            $actual = $null
            if (Test-Path -LiteralPath $inputFile.path) {
                try { $actual = (Get-FileHash -LiteralPath $inputFile.path -Algorithm SHA256).Hash.ToLowerInvariant() }
                catch { $actual = $null }      # still being copied
            }
            if ($actual -eq $inputFile.sha256) { break }
            if ((Get-Date) -gt $deadline) {
                $receipt.execution_count = 0
                $receipt.failure = 'INPUT_NOT_READY'
                Write-Receipt
                exit 3
            }
            Start-Sleep -Milliseconds 500
        }
    }
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $request.executable
    $info.Arguments = $request.argument_line
    $info.WorkingDirectory = $request.cwd
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'Process did not start' }
    $outTask = $process.StandardOutput.ReadToEndAsync()
    $errTask = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $stdout = $outTask.GetAwaiter().GetResult()
    # Drain stderr to avoid a pipe deadlock; raw stderr never goes into evidence.
    $null = $errTask.GetAwaiter().GetResult()
    $output = Join-Path $request.output_dir ('run-' + $request.nonce + '-stdout.txt')
    [IO.File]::WriteAllText($output, $stdout, $utf8)
    $receipt.process_id = $process.Id
    $receipt.execution_count = 1
    $receipt.exit_code = $process.ExitCode
    $receipt.stdout_sha256 = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Receipt
} finally {
    $lock.Dispose()
}
