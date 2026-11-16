param([Parameter(Mandatory=$true)][ValidatePattern('^SES-[a-f0-9]{32}$')][string]$Session,
 [Parameter(Mandatory=$true)][ValidateRange(1,65535)][int]$DataPort,
 [Parameter(Mandatory=$true)][ValidateRange(1,65535)][int]$ControlPort)
$ErrorActionPreference='Stop'
$ctx=Get-Content C:\RunnerPackage\guest-context.json -Raw|ConvertFrom-Json
if($ctx.session_id -ne $Session){throw 'Wrong Guest session'}
$output=$ctx.output_path
$proof=Join-Path $output 'transfer-fault-proof.json'
$attempt='C:\RunnerLogs\transfer-fault-attempt.json'
if((Test-Path -LiteralPath $proof) -or (Test-Path -LiteralPath $attempt)){throw 'Fault already attempted; never replay'}
if($DataPort -eq $ControlPort){throw 'Relay ports must differ'}
$rows=@()
foreach($p in @(Get-CimInstance Win32_Process -Filter "Name='ScrpRelay.exe'")) {
 $pattern='guest\s+\{'+[regex]::Escape($ctx.container_id)+'\}\s+(\{[0-9a-f-]{36}\})\s+(\d+)\s+(\d+)\s+'
 if($p.CommandLine -match $pattern) {
  $rows+=@{pid=[int]$p.ProcessId;service=$Matches[1];port=[int]$Matches[2];parent=[int]$Matches[3];created=$p.CreationDate;command=$p.CommandLine}
 }
}
$data=@($rows|Where-Object {$_.port -eq $DataPort})
$control=@($rows|Where-Object {$_.port -eq $ControlPort})
if($rows.Count -ne 2 -or $data.Count -ne 1 -or $control.Count -ne 1){throw 'Ambiguous owned relay set'}
# Hold process handles so a reused PID cannot select an unrelated process.
$handles=@{}
foreach($row in $rows){
 $held=Get-Process -Id $row.pid
 $null=$held.Handle
 $current=Get-CimInstance Win32_Process -Filter ('ProcessId='+$row.pid)
 if($held.HasExited -or $current.CreationDate -ne $row.created -or $current.CommandLine -ne $row.command){throw 'Relay identity changed'}
 $handles[$row.pid]=$held
}
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class OwnedTcpProbe {
 [DllImport("iphlpapi.dll")] static extern uint GetExtendedTcpTable(IntPtr p, ref int n, bool order, int family, int table, uint reserved);
 public static int Established(int pid) {
  int n=0;GetExtendedTcpTable(IntPtr.Zero,ref n,false,2,5,0);var p=Marshal.AllocHGlobal(n);
  try {var e=GetExtendedTcpTable(p,ref n,false,2,5,0);if(e!=0)throw new Exception("TCP table error "+e);
   int count=Marshal.ReadInt32(p),found=0;for(int i=0;i<count;i++){var row=IntPtr.Add(p,4+i*24);if(Marshal.ReadInt32(row)==5&&Marshal.ReadInt32(row,20)==pid)found++;}return found;
  }finally{Marshal.FreeHGlobal(p);}
 }
}
'@
$limit=[DateTime]::UtcNow.AddSeconds(10)
while([OwnedTcpProbe]::Established($data[0].pid) -ne 0) {
 if([DateTime]::UtcNow -gt $limit){throw 'Data relay not idle; fault not attempted'}
 Start-Sleep -Milliseconds 10
}
$record=[ordered]@{session=$Session;container=$ctx.container_id;relay=$rows;started=[DateTime]::UtcNow.ToString('o');restored=@()}
[IO.File]::WriteAllText($attempt,($record|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
$file=Join-Path $output 'interrupted-transfer.txt'
if(Test-Path -LiteralPath $file){throw 'Transfer fixture already exists'}
[IO.File]::WriteAllText($file,($Session+'|'+('B'*7340032)),[Text.UTF8Encoding]::new($false))
$limit=[DateTime]::UtcNow.AddSeconds(15)
while([OwnedTcpProbe]::Established($data[0].pid) -eq 0) {
 if([DateTime]::UtcNow -gt $limit){throw 'No actual data connection; no fault injected'}
 Start-Sleep -Milliseconds 1
}
$record.data_connected=[DateTime]::UtcNow.ToString('o')
Start-Sleep -Milliseconds 20
# Only the two checked relay PIDs inside this VM. The Runner/app processes live.
$stopped=@()
try {
 $handles[$data[0].pid].Kill()
 $stopped+=$data[0]
 $record.data_stopped=[DateTime]::UtcNow.ToString('o')
 Start-Sleep -Milliseconds 250
 $handles[$control[0].pid].Kill()
 $stopped+=$control[0]
 $record.control_stopped=[DateTime]::UtcNow.ToString('o')
 Start-Sleep -Seconds 2
} finally {
 foreach($row in $stopped) {
  if(-not(Get-Process -Id $row.parent -ErrorAction SilentlyContinue)){throw 'Original relay owner exited; no reparenting'}
  $args=@('guest',('{'+$ctx.container_id+'}'),$row.service,[string]$row.port,[string]$row.parent,('C:\RunnerLogs\fault-'+$row.port+'.ready'))
  $child=Start-Process C:\RunnerPackage\ScrpRelay.exe -ArgumentList $args -WindowStyle Hidden -PassThru
  $record.restored+=@{port=$row.port;pid=$child.Id}
 }
 $record.finished=[DateTime]::UtcNow.ToString('o')
 [IO.File]::WriteAllText($proof,($record|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
}
$record|ConvertTo-Json -Depth 6
