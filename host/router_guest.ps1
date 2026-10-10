# Trusted Router transport helper. This file is copied as data and runs only in Guest.
param([Parameter(Mandatory=$true)][string]$Manifest)
$ErrorActionPreference = 'Stop'
if ([Environment]::UserName -ne 'WDAGUtilityAccount') { throw 'Windows Sandbox only' }
$request = Get-Content -LiteralPath $Manifest -Raw -Encoding UTF8 | ConvertFrom-Json
if ($request.contract -ne 'router-guest-v1') { throw 'Unsupported request contract' }
$work = Join-Path $env:TEMP ('RouterCommand-' + $request.nonce)
New-Item -ItemType Directory -Path $work -Force | Out-Null
# CreateNew is a per-request execution reservation, never removed or reused.
$lock = [IO.File]::Open((Join-Path $work 'dispatched'), [IO.FileMode]::CreateNew,
                       [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    foreach ($inputFile in $request.inputs) {
        $actual = (Get-FileHash -LiteralPath $inputFile.path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $inputFile.sha256) { throw 'Input changed before execution' }
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
    # Drain stderr to avoid a pipe deadlock; do not put raw stderr in evidence/logs.
    $null = $errTask.GetAwaiter().GetResult()
    $utf8 = New-Object Text.UTF8Encoding($false)
    $output = Join-Path $request.output_dir ('router-' + $request.nonce + '-stdout.txt')
    [IO.File]::WriteAllText($output, $stdout, $utf8)
    $receipt = [ordered]@{
        contract = 'router-guest-v1'
        request_id = $request.request_id
        fingerprint = $request.fingerprint
        nonce = $request.nonce
        runtime_id = $request.runtime_id
        generation = $request.generation
        command_sha256 = $request.command_sha256
        sources = $request.sources
        process_id = $process.Id
        execution_count = 1
        exit_code = $process.ExitCode
        stdout_sha256 = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $evidence = Join-Path $request.output_dir ('router-' + $request.nonce + '-receipt.txt')
    [IO.File]::WriteAllText($evidence, ($receipt | ConvertTo-Json -Depth 8 -Compress), $utf8)
    Write-Output ('ROUTER-COMPLETED ' + $request.nonce + ' exit=' + $process.ExitCode)
} finally {
    $lock.Dispose()
}
