param([Parameter(Mandatory=$true)][ValidatePattern('^SES-[a-f0-9]{32}$')][string]$Session,
 [Parameter(Mandatory=$true)][ValidateRange(1,65535)][int]$DataPort,
 [Parameter(Mandatory=$true)][ValidateRange(1,65535)][int]$ControlPort,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$FixtureSha256)
$ErrorActionPreference='Stop'
$ctx=Get-Content C:\RunnerPackage\guest-context.json -Raw|ConvertFrom-Json
if($ctx.session_id -ne $Session -or $DataPort -eq $ControlPort){throw 'Wrong Guest binding'}
$fixture='C:\RunnerInput\scrp-relay-fault-20261109.exe'
if((Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash -ne $FixtureSha256){throw 'Wrong fault fixture bytes'}
$ready='C:\RunnerLogs\cut-relay.ready'
$attempt='C:\RunnerLogs\cut-attempt.json'
if(Test-Path -LiteralPath $attempt){throw 'Attempt already recorded; no replay'}
$rows=@()
$handles=@{}
foreach($p in @(Get-CimInstance Win32_Process -Filter "Name='ScrpRelay.exe'")){
 $pattern='guest\s+\{'+[regex]::Escape($ctx.container_id)+'\}\s+(\{[0-9a-f-]{36}\})\s+(\d+)\s+(\d+)\s+'
 if($p.CommandLine -match $pattern){
  $row=@{pid=[int]$p.ProcessId;service=$Matches[1];port=[int]$Matches[2];parent=[int]$Matches[3]}
  $held=Get-Process -Id $row.pid
  $null=$held.Handle
  $now=Get-CimInstance Win32_Process -Filter ('ProcessId='+$row.pid)
  if($held.HasExited -or $now.CreationDate -ne $p.CreationDate -or $now.CommandLine -ne $p.CommandLine){throw 'Process identity changed'}
  $rows+=$row;$handles[$row.pid]=$held
 }
}
$data=@($rows|Where-Object {$_.port -eq $DataPort})
$control=@($rows|Where-Object {$_.port -eq $ControlPort})
if($rows.Count -ne 2 -or $data.Count -ne 1 -or $control.Count -ne 1){throw 'Ambiguous owned relay set'}
function Start-OwnedRelay($exe,$row,$marker){
 if(-not(Get-Process -Id $row.parent -ErrorAction SilentlyContinue)){throw 'Original relay parent exited'}
 $a=@('guest',('{'+$ctx.container_id+'}'),$row.service,[string]$row.port,[string]$row.parent,$marker)
 Start-Process -FilePath $exe -ArgumentList $a -WindowStyle Hidden -PassThru
}
$record=[ordered]@{session=$Session;container=$ctx.container_id;started=[DateTime]::UtcNow.ToString('o');relays=$rows;fixture_sha256=$FixtureSha256;restored=@()}
[IO.File]::WriteAllText($attempt,($record|ConvertTo-Json -Depth 6))
$stopped=@();$lab=$null
try {
 $handles[$data[0].pid].Kill();$stopped+=$data[0]
 if(-not $handles[$data[0].pid].WaitForExit(5000)){throw 'Data relay did not exit'}
 $lab=Start-OwnedRelay $fixture $data[0] $ready
 $limit=[DateTime]::UtcNow.AddSeconds(5)
 while(-not(Test-Path -LiteralPath $ready)){
  if($lab.HasExited -or [DateTime]::UtcNow -gt $limit){throw 'Fault relay failed to listen'}
  Start-Sleep -Milliseconds 20
 }
 $file=Join-Path $ctx.output_path 'cut-transfer.txt'
 if(Test-Path -LiteralPath $file){throw 'Fixture already exists'}
 [IO.File]::WriteAllText($file,($Session+'|'+('D'*7340032)),[Text.UTF8Encoding]::new($false))
 $record.expected_sha256=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
 $record.expected_size=(Get-Item -LiteralPath $file).Length
 $limit=[DateTime]::UtcNow.AddSeconds(15)
 while(-not(Test-Path -LiteralPath ($ready+'.fault'))){
  if($lab.HasExited -or [DateTime]::UtcNow -gt $limit){throw 'No bounded wire fault observed'}
  Start-Sleep -Milliseconds 10
 }
 # Get-Content's decorated PSObject string expands provider/drive metadata in
 # Windows PowerShell 5.1 ConvertTo-Json. Keep a plain bounded CLR string.
 $record.fault=[IO.File]::ReadAllText($ready+'.fault')
 $record.cut_at=[DateTime]::UtcNow.ToString('o')
 $handles[$control[0].pid].Kill();$stopped+=$control[0]
 Start-Sleep -Seconds 2
} catch { $record.error=$_.Exception.Message; throw }
finally {
 if($lab -and -not $lab.HasExited){$lab.Kill();if(-not $lab.WaitForExit(5000)){throw 'Fault relay still running'}}
 foreach($row in $stopped){
  $p=Start-OwnedRelay 'C:\RunnerPackage\ScrpRelay.exe' $row ('C:\RunnerLogs\cut-restored-'+$row.port+'.ready')
  $record.restored+=@{port=$row.port;pid=$p.Id}
 }
 $record.finished=[DateTime]::UtcNow.ToString('o')
 [IO.File]::WriteAllText((Join-Path $ctx.output_path 'cut-transfer-proof.json'),($record|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
}
$record|ConvertTo-Json -Depth 6
