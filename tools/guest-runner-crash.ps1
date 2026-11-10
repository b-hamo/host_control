param(
 [Parameter(Mandatory=$true)][ValidatePattern('^SES-[a-f0-9]{32}$')][string]$Session,
 [Parameter(Mandatory=$true)][ValidateRange(1,2147483647)][int]$RunnerPid,
 [Parameter(Mandatory=$true)][ValidatePattern('^[1-9][0-9]*$')][string]$CreationTime)
$ErrorActionPreference='Stop'
$ctx=[IO.File]::ReadAllText('C:\RunnerPackage\guest-context.json')|ConvertFrom-Json
if($ctx.session_id -ne $Session -or $ctx.generation -ne 1){throw 'Wrong initial recovery test session/generation'}
$exe='C:\RunnerPackage\sandbox_runner.exe'
if((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ctx.runner_sha256){throw 'Runner binary changed'}
$attempt='C:\RunnerLogs\runner-crash-attempt.json'
$proof=Join-Path $ctx.output_path 'runner-crash-proof.json'
if((Test-Path -LiteralPath $attempt) -or (Test-Path -LiteralPath $proof)){throw 'Crash already attempted; never replay'}
Add-Type @'
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public sealed class OriginalRunner : IDisposable {
 IntPtr handle;
 [StructLayout(LayoutKind.Sequential)] struct FT {public uint low,high;}
 [StructLayout(LayoutKind.Sequential)] struct FI {public uint attributes;public FT created,accessed,written;public uint volume,sizeHigh,sizeLow,links,indexHigh,indexLow;}
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out FI info);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr h,out FT a,out FT b,out FT c,out FT d);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr h,uint flags,StringBuilder text,ref uint n);
 [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h,uint ms);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr h,uint code);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 static bool SameFile(string actual,string expected) {
  using(var a=File.OpenRead(actual)) using(var b=File.OpenRead(expected)) {
   FI x,y;
   if(!GetFileInformationByHandle(a.SafeFileHandle,out x) || !GetFileInformationByHandle(b.SafeFileHandle,out y)) throw new Exception("Image file identity unavailable");
   return (x.indexHigh!=0 || x.indexLow!=0) && x.volume==y.volume && x.indexHigh==y.indexHigh && x.indexLow==y.indexLow;
  }
 }
 public OriginalRunner(int pid,string birth,string path) {
  handle=OpenProcess(0x101001,false,(uint)pid);
  try {
   FT a,b,c,d;var text=new StringBuilder(32768);uint n=32768;
   if(handle==IntPtr.Zero || !GetProcessTimes(handle,out a,out b,out c,out d)) throw new Exception("Original process unavailable");
   if((((ulong)a.high<<32)|a.low).ToString()!=birth) throw new Exception("Process creation time mismatch");
   if(!QueryFullProcessImageName(handle,0,text,ref n) || !SameFile(text.ToString(),path)) throw new Exception("Process image file identity mismatch");
   if(WaitForSingleObject(handle,0)!=258) throw new Exception("Original Runner already exited");
  } catch {Dispose();throw;}
 }
 public void Stop() {
  if(!TerminateProcess(handle,0xDEAD))throw new Exception("Owned Runner termination failed");
  if(WaitForSingleObject(handle,5000)!=0)throw new Exception("Original Runner exit not confirmed");
 }
 public void Dispose(){if(handle!=IntPtr.Zero){CloseHandle(handle);handle=IntPtr.Zero;}}
}
'@
$held=[OriginalRunner]::new($RunnerPid,$CreationTime,$exe)
try {
 $record=[ordered]@{session=$Session;container=$ctx.container_id;generation=1;pid=$RunnerPid;creation_time=$CreationTime;execution_count=1;started=[DateTime]::UtcNow.ToString('o')}
 [IO.File]::WriteAllText($attempt,($record|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
 $held.Stop()
 $record.exited=[DateTime]::UtcNow.ToString('o')
 [IO.File]::WriteAllText($proof,($record|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
 $record|ConvertTo-Json
} finally {$held.Dispose()}
