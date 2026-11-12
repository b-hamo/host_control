param([Parameter(Mandatory=$true)][ValidatePattern('^SES-[a-f0-9]{32}$')][string]$Session, [switch]$TryDefault)
$ErrorActionPreference='Stop'
$output='C:\RunnerWorkspace\Sessions\session-'+$Session+'\runtime-RT-SBX-001\generation-1\output'
if(-not(Test-Path -LiteralPath $output)){throw 'Session Output missing'}
Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class DesktopProbe {
 [DllImport("user32.dll", SetLastError=true)] public static extern IntPtr OpenInputDesktop(uint f, bool inherit, uint access);
 [DllImport("user32.dll", SetLastError=true)] public static extern bool CloseDesktop(IntPtr d);
 [DllImport("user32.dll")] public static extern IntPtr GetThreadDesktop(uint t);
 [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
 [DllImport("kernel32.dll")] static extern void SetLastError(uint error);
 [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr OpenDesktop(string name,uint flags,bool inherit,uint access);
 [DllImport("user32.dll", SetLastError=true)] static extern bool SwitchDesktop(IntPtr desktop);
 [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool GetUserObjectInformation(IntPtr h,int i,StringBuilder p,uint size,out uint needed);
 public static string Name(IntPtr h) {uint needed;var text=new StringBuilder(512);return GetUserObjectInformation(h,2,text,1024,out needed)?text.ToString():"WinError:"+Marshal.GetLastWin32Error();}
 public static string Input() {var h=OpenInputDesktop(0,false,1);if(h==IntPtr.Zero)return "WinError:"+Marshal.GetLastWin32Error();try{return Name(h);}finally{CloseDesktop(h);}}
 public static string ActivateDefault() {var h=OpenDesktop("Default",0,false,0x101);if(h==IntPtr.Zero)return "open=false; error="+Marshal.GetLastWin32Error();try{SetLastError(0);bool ok=SwitchDesktop(h);int e=Marshal.GetLastWin32Error();return "open=true; switched="+ok+"; error="+e;}finally{CloseDesktop(h);}}
}
'@
$report=[ordered]@{session=$Session;identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name;
 process_session=(Get-Process -Id $PID).SessionId; thread_desktop=[DesktopProbe]::Name([DesktopProbe]::GetThreadDesktop([DesktopProbe]::GetCurrentThreadId()));
 input_desktop=[DesktopProbe]::Input(); explorer=@(Get-Process explorer -ErrorAction SilentlyContinue|Select-Object Id,SessionId,MainWindowTitle);
 winlogon=@(Get-Process winlogon -ErrorAction SilentlyContinue|Select-Object Id,SessionId)}
if($TryDefault){$report.switch_result=[DesktopProbe]::ActivateDefault();$report.input_after=[DesktopProbe]::Input()}
try {
 Add-Type -AssemblyName System.Drawing
 $bitmap=New-Object Drawing.Bitmap(1280,720)
 $graphics=[Drawing.Graphics]::FromImage($bitmap)
 try { $graphics.CopyFromScreen(0,0,0,0,$bitmap.Size); $bitmap.Save((Join-Path $output 'desktop-probe.png'),[Drawing.Imaging.ImageFormat]::Png); $report.capture='written; requires visual inspection' }
 finally { $graphics.Dispose();$bitmap.Dispose() }
} catch { $report.capture_error=$_.Exception.Message }
$json=$report|ConvertTo-Json -Depth 5
$name=if($TryDefault){'desktop-switch-probe.json'}else{'desktop-probe.json'}
[IO.File]::WriteAllText((Join-Path $output $name),$json,[Text.UTF8Encoding]::new($false))
$json
