param(
    [Parameter(Mandatory=$true)][ValidatePattern('^SES-[a-f0-9]{32}$')][string]$Session,
    [DateTime]$StartUtc = [DateTime]::UtcNow.AddMinutes(-15),
    [DateTime]$EndUtc = [DateTime]::UtcNow
)
$ErrorActionPreference = 'Stop'
try {
    if ($StartUtc -ge $EndUtc -or ($EndUtc-$StartUtc).TotalHours -gt 12) { throw 'Invalid bounded event interval' }
    if (-not (Test-Path 'HKLM:\SOFTWARE\DBI\WorkspaceRuntime')) { throw 'micro_VM Guest marker missing' }
    $output = 'C:\RunnerWorkspace\Sessions\session-'+$Session+'\runtime-RT-SBX-001\generation-1\output'
    if (-not (Test-Path -LiteralPath $output -PathType Container)) { throw 'Session Output missing' }
    Add-Type @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class LogonEvidence {
 [StructLayout(LayoutKind.Sequential)] public struct WTS { public int Id; public IntPtr Name; public int State; }
 public sealed class Row { public int Id; public string Name; public int State; }
 [DllImport("wtsapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool WTSEnumerateSessions(IntPtr s,int a,int b,out IntPtr p,out int count);
 [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr p);
 [DllImport("user32.dll", SetLastError=true)] static extern IntPtr OpenInputDesktop(uint f,bool inherit,uint access);
 [DllImport("user32.dll")] static extern bool CloseDesktop(IntPtr h);
 [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool GetUserObjectInformation(IntPtr h,int i,StringBuilder p,uint n,out uint needed);
 [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern IntPtr FindWindow(string c,string t);
 public static Row[] Sessions() {
  IntPtr p; int count;
  if (!WTSEnumerateSessions(IntPtr.Zero,0,1,out p,out count)) throw new System.ComponentModel.Win32Exception();
  try { var rows=new List<Row>(); int size=Marshal.SizeOf(typeof(WTS));
   for(int i=0;i<count;i++) { var s=(WTS)Marshal.PtrToStructure(IntPtr.Add(p,i*size),typeof(WTS)); rows.Add(new Row {Id=s.Id,Name=Marshal.PtrToStringUni(s.Name),State=s.State}); }
   return rows.ToArray();
  } finally { WTSFreeMemory(p); }
 }
 public static string InputDesktop() {
  var h=OpenInputDesktop(0,false,1); if(h==IntPtr.Zero)return "OpenError:"+Marshal.GetLastWin32Error();
  try { uint needed; var text=new StringBuilder(512); return GetUserObjectInformation(h,2,text,1024,out needed)?text.ToString():"QueryError:"+Marshal.GetLastWin32Error(); }
  finally { CloseDesktop(h); }
 }
 public static bool Taskbar() { return FindWindow("Shell_TrayWnd",null)!=IntPtr.Zero; }
}
'@
    $report = [ordered]@{kind='micro-vm-readonly-logon-evidence'; time=[DateTime]::UtcNow.ToString('o'); session=$Session;
        process_session=(Get-Process -Id $PID).SessionId; identity=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
        sessions=@([LogonEvidence]::Sessions()); input_desktop=[LogonEvidence]::InputDesktop(); taskbar=[LogonEvidence]::Taskbar();
        explorer=@(Get-Process explorer -ErrorAction SilentlyContinue | Select-Object Id,SessionId);
        events=@(); log_queries=@(); logon_attempted_by_this_probe=$false;
        start_utc=$StartUtc.ToUniversalTime().ToString('o'); end_utc=$EndUtc.ToUniversalTime().ToString('o')}
    $logs = @('Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational','Microsoft-Windows-Winlogon/Operational',
        'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational','Security')
    foreach ($log in $logs) {
        try {
            $filter = @{LogName=$log;StartTime=$StartUtc;EndTime=$EndUtc}
            if ($log -eq 'Security') { $filter.Id=@(4624,4625) }
            $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 128 -ErrorAction Stop)
            foreach ($event in $events) {
                $xml = [xml]$event.ToXml()
                $fields = [ordered]@{}
                $allowed = @('Status','SubStatus','LogonType','SessionID','SessionId','Session','ErrorCode','Reason','ReasonCode',
                    'FailureReason','AuthenticationPackageName','LogonProcessName','Win32Status','MethodName','Event','SubscriberName')
                foreach ($data in @($xml.Event.EventData.Data)) {
                    if ($data.Name -in $allowed) {
                        $fields[[string]$data.Name] = [string]$data.'#text'
                    }
                }
                # LSM stores Session/Reason in UserData, not EventData. Do not silently discard it.
                foreach ($data in $xml.SelectNodes("/*[local-name()='Event']/*[local-name()='UserData']//*[not(*)]")) {
                    if ($data.LocalName -in $allowed) { $fields[$data.LocalName] = $data.InnerText }
                }
                $report.events += @{log=$log;id=$event.Id;record_id=$event.RecordId;time=$event.TimeCreated.ToUniversalTime().ToString('o');fields=$fields;
                    process_id=[string]$xml.Event.System.Execution.ProcessID;thread_id=[string]$xml.Event.System.Execution.ThreadID;
                    activity_id=[string]$xml.Event.System.Correlation.ActivityID}
            }
            $report.log_queries += @{log=$log;count=$events.Count;ok=$true}
        } catch { $report.log_queries += @{log=$log;ok=$false;error=$_.Exception.Message} }
    }
    $json = $report | ConvertTo-Json -Depth 9
    [IO.File]::WriteAllText((Join-Path $output 'logon-evidence.json'),$json,[Text.UTF8Encoding]::new($false))
    $json
    exit 0
} catch { Write-Output ($_ | Out-String); exit 1 }
