$ErrorActionPreference='Stop'
$root='@@ROOT@@'
$nonce='@@NONCE@@'
function Publish([string]$name,$value){
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 8 -Compress))
 $file=[IO.File]::Open(($root+'\'+$name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
}
if($env:COMPUTERNAME -cne 'PASSKEYS-WORKER' -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18'){throw 'Dedicated SYSTEM worker required'}
$process=[Diagnostics.Process]::GetCurrentProcess()
if($process.SessionId -ne 0){throw 'Session zero required'}
Publish 'started.json' @{nonce=$nonce;pid=$PID;startedUtc=$process.StartTime.ToUniversalTime().ToString('o');image=$process.MainModule.FileName;sessionId=$process.SessionId;sid='S-1-5-18'}
try {
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class AiwTaskContext {
 [StructLayout(LayoutKind.Sequential)] public struct BasicLimits { public long ProcessTime, JobTime; public uint LimitFlags; public UIntPtr MinWorking, MaxWorking; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint Priority, Scheduling; }
 [StructLayout(LayoutKind.Sequential)] public struct IoCounters { public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes; }
 [StructLayout(LayoutKind.Sequential)] public struct ExtendedLimits { public BasicLimits Basic; public IoCounters Io; public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory; }
 [StructLayout(LayoutKind.Sequential)] public struct Luid { public uint Low; public int High; }
 [StructLayout(LayoutKind.Sequential)] public struct OnePrivilege { public uint Count; public Luid Id; public uint Attributes; }
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessInJob(IntPtr p,IntPtr job,out bool answer);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int kind,out ExtendedLimits info,int size,IntPtr returned);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,uint access,out IntPtr token);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenThreadToken(IntPtr p,uint access,bool self,out IntPtr token);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr data,int size,out int returned);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out Luid luid);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token,bool all,ref OnePrivilege privileges,int size,out OnePrivilege previous,out int returned);
 static void Check(bool success){if(!success)throw new Win32Exception(Marshal.GetLastWin32Error());}
 public static Dictionary<string,object> Observe(){
  bool inJob; Check(IsProcessInJob(GetCurrentProcess(),IntPtr.Zero,out inJob));
  var answer=new Dictionary<string,object>(); answer["inAnyJob"]=inJob; answer["queryScope"]="immediateJobOnly";
  if(inJob){ExtendedLimits limits; Check(QueryInformationJobObject(IntPtr.Zero,9,out limits,Marshal.SizeOf(typeof(ExtendedLimits)),IntPtr.Zero));answer["limitFlags"]=limits.Basic.LimitFlags;}
  IntPtr thread; if(OpenThreadToken(GetCurrentThread(),8,true,out thread)){CloseHandle(thread);throw new Exception("Thread is impersonating");}
  int noToken=Marshal.GetLastWin32Error(); if(noToken!=1008)throw new Win32Exception(noToken); answer["threadNotImpersonating"]=true;
  IntPtr token;Check(OpenProcessToken(GetCurrentProcess(),0x28,out token));
  try {
   int count;GetTokenInformation(token,3,IntPtr.Zero,0,out count);if(count<4||count>65536)throw new Exception("Privilege size invalid");
   IntPtr data=Marshal.AllocHGlobal(count);
   try {
    Check(GetTokenInformation(token,3,data,count,out count));int n=Marshal.ReadInt32(data);if(n<0||4+n*12>count)throw new Exception("Privilege count invalid");
    var observed=new List<object>();
    foreach(string name in new[]{"SeTcbPrivilege","SeAssignPrimaryTokenPrivilege","SeIncreaseQuotaPrivilege","SeImpersonatePrivilege","SeChangeNotifyPrivilege"}){
     Luid id;Check(LookupPrivilegeValue(null,name,out id));bool found=false;uint attrs=0;
     for(int i=0;i<n;i++){IntPtr p=IntPtr.Add(data,4+i*12);if(unchecked((uint)Marshal.ReadInt32(p))==id.Low&&Marshal.ReadInt32(p,4)==id.High){found=true;attrs=unchecked((uint)Marshal.ReadInt32(p,8));break;}}
     if(!found||(attrs&4)!=0){observed.Add(new {name=name,present=found,removed=(attrs&4)!=0,attributes=attrs,enableRestoreAttempted=false,enableAndRestorePassed=false});continue;}
     OnePrivilege request=new OnePrivilege{Count=1,Id=id,Attributes=2}, previous;int written;
     Check(AdjustTokenPrivileges(token,false,ref request,Marshal.SizeOf(typeof(OnePrivilege)),out previous,out written));int enableError=Marshal.GetLastWin32Error();
     if(enableError!=0)throw new Win32Exception(enableError);
     OnePrivilege ignored;Check(AdjustTokenPrivileges(token,false,ref previous,Marshal.SizeOf(typeof(OnePrivilege)),out ignored,out written));int restoreError=Marshal.GetLastWin32Error();
     if(restoreError!=0)throw new Win32Exception(restoreError);
     observed.Add(new {name=name,present=true,removed=false,attributes=attrs,enableRestoreAttempted=true,enableAndRestorePassed=true});
    }
    answer["privileges"]=observed;
   } finally {Marshal.FreeHGlobal(data);}
  } finally {CloseHandle(token);}
  return answer;
 }
}
'@
function Invoke-AiwPrimaryApplication {
$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ne 'PASSKEYS-WORKER' -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18' -or [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0){throw 'Pinned SYSTEM session-zero required'}
$exe='C:\AIW-Msix-Lifecycle-Input\msix_standard_user_lifecycle.exe';$prep='C:\AIW-Msix-Lifecycle-Preparation.json'
if((Get-FileHash -LiteralPath $exe).Hash.ToLowerInvariant() -cne 'd4bc21662221bd681e0ec89e691a89ff9e4f1902358fdf04975cf438aed147ee'){throw 'Reviewed driver bytes differ'}
if((Get-FileHash -LiteralPath $prep).Hash.ToLowerInvariant() -cne '@@PREP_SHA@@'){throw 'Exact prepared receipt differs'};
$prepared=Get-Content -LiteralPath $prep -Raw|ConvertFrom-Json
if($prepared.userSid -cne '@@USER_SID@@' -or $prepared.vmId -cne '7e686bee-8c05-43c7-9603-a9562ece224c' -or $prepared.runNonce -cne $nonce -or [DateTime]::UtcNow.ToFileTimeUtc() -gt $prepared.notAfterFileTime){throw 'Owned preparation differs or expired'}
$root='C:\AIW-Msix-Primary-Application-Controller-VM106-r1';if(Test-Path -LiteralPath $root){throw 'Refuse existing controller evidence'}
New-Item -ItemType Directory -Path $root|Out-Null
$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'));foreach($sid in @('S-1-5-18','S-1-5-21-3849540285-1795134874-2442050430-1006')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))};Set-Acl -LiteralPath $root -AclObject $acl
function Write-Record([string]$name,[object]$value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 5 -Compress));$stream=[IO.FileStream]::new((Join-Path $root $name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}}
Write-Record 'request.json' @{vmId=$prepared.vmId;userSid=$prepared.userSid;sessionId=$prepared.sessionId;runNonce=$prepared.runNonce;imageSha256=$prepared.sourceImageSha256;preparationSha256=(Get-FileHash -LiteralPath $prep).Hash.ToLowerInvariant();command='vm-controller';deadlineSeconds=1260;startedUtc=[DateTime]::UtcNow.ToString('o')}
$info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$exe;$info.Arguments='vm-controller';$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true;$info.WorkingDirectory='C:\AIW-Msix-Lifecycle-Input'
$process=[Diagnostics.Process]::new();$process.StartInfo=$info;$started=$false;$timedOut=$false
try{
 if(!$process.Start()){throw 'Controller did not start'};$started=$true
 Write-Record 'started.json' @{pid=$process.Id;startTimeUtc=$process.StartTime.ToUniversalTime().ToString('o');heldProcess=$true;runNonce=$prepared.runNonce}
 Start-Sleep -Seconds 4
 $stdoutTask=$process.StandardOutput.ReadToEndAsync();$stderrTask=$process.StandardError.ReadToEndAsync()
 if(!$process.WaitForExit(1260000)){$timedOut=$true;$process.Kill();if(!$process.WaitForExit(15000)){throw 'Exact controller termination unconfirmed'}}
 $stdout=$stdoutTask.GetAwaiter().GetResult();$stderr=$stderrTask.GetAwaiter().GetResult()
 [IO.File]::WriteAllText((Join-Path $root 'stdout.log'),$stdout,[Text.UTF8Encoding]::new($false));[IO.File]::WriteAllText((Join-Path $root 'stderr.log'),$stderr,[Text.UTF8Encoding]::new($false))
 $result=@{pid=$process.Id;exitCode=$process.ExitCode;timedOut=$timedOut;exited=$process.HasExited;controllerRoot=$root;lifecycleRoot='C:\AIW-Msix-Lifecycle-Output\standard-user-lifecycle';runNonce=$prepared.runNonce;stdoutLength=$stdout.Length;stderrLength=$stderr.Length;terminalReceiptPresent=(Test-Path -LiteralPath 'C:\AIW-Msix-Lifecycle-Output\standard-user-lifecycle\result.json');finishedUtc=[DateTime]::UtcNow.ToString('o')}
 Write-Record 'result.json' $result;if($result.exitCode -ne 0 -or !$result.terminalReceiptPresent -or $result.timedOut -or !$result.exited){throw 'Native application lifecycle failed; inspect retained native evidence'};return $result
}catch{
 $primaryError=$_.Exception.Message;$cleanupError=$null;$exitConfirmed=!$started
 if($started){try{if(!$process.HasExited){$process.Kill()};if(!$process.WaitForExit(15000)){throw 'Exact controller exit unconfirmed'};$exitConfirmed=$process.HasExited}catch{$cleanupError=$_.Exception.Message}}
 $combined='Controller wrapper failed: '+$primaryError+'; controller exit confirmed: '+$exitConfirmed+'; cleanup error: '+$cleanupError
 try{Write-Record 'wrapper-failure.json' @{error=$primaryError;cleanupError=$cleanupError;controllerExitConfirmed=$exitConfirmed;fatalCleanupUnconfirmed=(!$exitConfirmed);runNonce=$prepared.runNonce;restoreBoundaryRequired=$exitConfirmed}}catch{$combined+='; failure record could not be published: '+$_.Exception.Message}
 throw $combined
}finally{$process.Dispose()}
}

 $observation=[AiwTaskContext]::Observe()
 if(!$observation.inAnyJob -or ($observation.limitFlags -band 4096) -eq 0 -or !$observation.threadNotImpersonating){throw 'Reviewed default task context differs'}
 foreach($p in $observation.privileges){if(!$p.present -or $p.removed -or !$p.enableAndRestorePassed){throw 'Required privilege control failed'}}
 $native=Invoke-AiwPrimaryApplication
 $nativeRoot='C:\AIW-Msix-Lifecycle-Output\standard-user-lifecycle'
 function Read-Native([string]$name){$path=Join-Path $nativeRoot $name;$item=Get-Item -LiteralPath $path -Force;if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -gt 8192){throw 'Native record outside bound'};Get-Content -LiteralPath $path -Raw|ConvertFrom-Json}
 $context=Read-Native 'primary-context.json';$result=Read-Native 'result.json';$job=Read-Native 'controller-job.json';$bound=Get-Content -LiteralPath 'C:\AIW-Msix-Lifecycle-Preparation.json' -Raw|ConvertFrom-Json
 if($native.runNonce -cne $nonce -or $bound.runNonce -cne $nonce -or $context.runNonce -cne $nonce -or $context.prepared.userSid -cne '@@USER_SID@@' -or $context.prepared.sessionId -ne $bound.sessionId -or $context.prepared.sourceImageSha256 -cne 'd4bc21662221bd681e0ec89e691a89ff9e4f1902358fdf04975cf438aed147ee' -or $job.processId -ne $native.pid -or $job.sessionId -ne 0 -or $job.inAnyJob){throw 'Native process/session/preparation binding differs'}
 if(!$result.researchOnly -or !$result.passed -or !$result.jobEmpty -or $result.isolation -cne 'notMeasured'){throw 'Native application terminal receipt differs'}
 Publish 'native-application.json' @{nonce=$nonce;wrapper=$native;context=$context;result=$result;controllerJob=$job;applicationLaunchAttempted=$true}

 Publish 'observation.json' @{schemaVersion='aiw.dev/research-task-context/v1';nonce=$nonce;pid=$PID;sessionId=0;sid='S-1-5-18';diagnosticOnly=$true;context=$observation;observedUtc=[DateTime]::UtcNow.ToString('o')}
 # A finite binding interval lets the controller acquire this exact process handle.
 Start-Sleep -Seconds 4
 Publish 'result.json' @{nonce=$nonce;pid=$PID;contextObserved=$true;applicationLaunchAttempted=$true;completedUtc=[DateTime]::UtcNow.ToString('o')}
} catch {
 Publish 'failure.json' @{nonce=$nonce;pid=$PID;error=$_.Exception.Message;applicationLifecycleRequested=$true;applicationLaunchAttempted=$null}
 throw
}
