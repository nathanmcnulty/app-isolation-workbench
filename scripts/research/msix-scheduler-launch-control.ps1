# Closed disposable-VM research control. No caller-supplied executable or command.
function Invoke-AiwMsixSchedulerLaunchControl {
    $ErrorActionPreference = 'Stop'
    if ($env:COMPUTERNAME -cne 'aiwcleanhost' -or
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or
        [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0) {
        throw 'Dedicated SYSTEM session-zero worker required'
    }
    $meta = Invoke-RestMethod -Headers @{ Metadata = 'true' } -TimeoutSec 3 -Uri 'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01'
    if ($meta.vmId -cne 'cb7cc9f0-81f7-4326-8c52-828e42673d11') { throw 'Wrong dedicated VM' }
    foreach ($path in @('C:\Windows', 'C:\Windows\System32', 'C:\Windows\System32\cmd.exe')) {
        if (([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse control image path' }
    }
    $heldImage = [IO.File]::Open('C:\Windows\System32\cmd.exe', [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        if ($heldImage.Length -le 0 -or $heldImage.Length -gt 16777216) { throw 'Control image outside bounds' }
        $imageHash = ([BitConverter]::ToString($sha.ComputeHash($heldImage))).Replace('-', '').ToLowerInvariant()
        if ($imageHash -cne '97ac98b1a92c286054cce55239cfccdfc23a5517bd07fe693072c9ca96c7dabb') { throw 'Frozen OS control image differs' }
        if ((Get-AuthenticodeSignature -LiteralPath 'C:\Windows\System32\cmd.exe').Status -ne 'Valid') { throw 'Control image signature invalid' }
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
public static class AiwSchedulerLaunchControl {
 // Failed cleanup never releases the last exact process handle in this helper.
 // Such a failure blocks further trials and requires the cold worker boundary.
 static readonly List<IntPtr> UnconfirmedProcessHandles=new List<IntPtr>();
 [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes { public int Length; public IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] public bool Inherit; }
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct StartupInfo {
  public uint Size; public string Reserved, Desktop, Title; public uint X,Y,XSize,YSize,XCount,YCount,Fill,Flags; public ushort Show,ReservedCount; public IntPtr ReservedBytes,Input,Output,Error;
 }
 [StructLayout(LayoutKind.Sequential)] struct StartupInfoEx { public StartupInfo Startup; public IntPtr Attributes; }
 [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr Process,Thread; public uint ProcessId,ThreadId; }
 [StructLayout(LayoutKind.Sequential)] struct BasicLimits { public long ProcessTime,JobTime; public uint Flags; public UIntPtr MinWorking,MaxWorking; public uint ActiveLimit; public UIntPtr Affinity; public uint Priority,Scheduling; }
 [StructLayout(LayoutKind.Sequential)] struct IoCounters { public ulong ReadOps,WriteOps,OtherOps,ReadBytes,WriteBytes,OtherBytes; }
 [StructLayout(LayoutKind.Sequential)] struct ExtendedLimits { public BasicLimits Basic; public IoCounters Io; public UIntPtr ProcessMemory,JobMemory,PeakProcessMemory,PeakJobMemory; }
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool member);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int kind,IntPtr output,uint size,out uint returned);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int kind,ref ExtendedLimits limits,int size);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attributes,string name);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool CreatePipe(out IntPtr read,out IntPtr write,ref SecurityAttributes attributes,uint size);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetHandleInformation(IntPtr handle,uint mask,uint flags);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFile(string path,uint access,uint share,ref SecurityAttributes attributes,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,uint flags,ref IntPtr size);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,IntPtr size,IntPtr previous,IntPtr returned);
 [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string image,StringBuilder command,IntPtr processAttributes,IntPtr threadAttributes,bool inherit,uint flags,IntPtr environment,string directory,ref StartupInfoEx startup,out ProcessInfo process);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool PeekNamedPipe(IntPtr pipe,byte[] bytes,uint size,out uint read,out uint available,out uint remaining);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr process,uint flags,StringBuilder image,ref uint size);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool ProcessIdToSessionId(uint pid,out uint session);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
 static void Check(bool success,string stage){if(!success)throw new Win32Exception(Marshal.GetLastWin32Error(),stage);}
 static bool InJob(IntPtr process,IntPtr job){bool member;Check(IsProcessInJob(process,job,out member),"IsProcessInJob");return member;}
 static uint ParentLimits(){
  int size=Marshal.SizeOf(typeof(ExtendedLimits));IntPtr data=Marshal.AllocHGlobal(size);
  try{uint returned;Check(QueryInformationJobObject(IntPtr.Zero,9,data,(uint)size,out returned),"Parent limits");return ((ExtendedLimits)Marshal.PtrToStructure(data,typeof(ExtendedLimits))).Basic.Flags;}
  finally{Marshal.FreeHGlobal(data);}
 }
 static bool JobEmpty(IntPtr job){
  const int size=8+256*8;IntPtr data=Marshal.AllocHGlobal(size);
  try{uint returned;Check(QueryInformationJobObject(job,3,data,size,out returned),"Bounded job PID inventory");int assigned=Marshal.ReadInt32(data),count=Marshal.ReadInt32(data,4);if(assigned<0||count<0||count>256||count>assigned)throw new Exception("Malformed job PID inventory");return assigned==0&&count==0;}
  finally{Marshal.FreeHGlobal(data);}
 }
 static void RequireEmptyJob(IntPtr job){var timer=Stopwatch.StartNew();while(!JobEmpty(job)){if(timer.ElapsedMilliseconds>=3000)throw new Exception("Owned job not empty");System.Threading.Thread.Sleep(20);}}
 static void RequireEmptyPipe(IntPtr pipe,string name){var timer=Stopwatch.StartNew();while(true){uint count,available,remaining;bool ok=PeekNamedPipe(pipe,new byte[1],1,out count,out available,out remaining);int error=Marshal.GetLastWin32Error();if(!ok){if(error==109)return;throw new Win32Exception(error,name+" pipe observation");}if(count!=0||available!=0)throw new Exception(name+" unexpectedly contains "+available+" bytes");if(timer.ElapsedMilliseconds>=1000)throw new Exception(name+" EOF unconfirmed");System.Threading.Thread.Sleep(20);}}
 static void Close(ref IntPtr handle,List<Exception> failures){if(handle!=IntPtr.Zero&&handle!=new IntPtr(-1)){if(!CloseHandle(handle))failures.Add(new Win32Exception(Marshal.GetLastWin32Error(),"CloseHandle"));handle=IntPtr.Zero;}}
 public static Dictionary<string,object> Run(){
  IntPtr job=IntPtr.Zero,input=IntPtr.Zero,outRead=IntPtr.Zero,outWrite=IntPtr.Zero,errRead=IntPtr.Zero,errWrite=IntPtr.Zero,attributes=IntPtr.Zero,allowed=IntPtr.Zero;
  ProcessInfo child=new ProcessInfo();bool initialized=false,assigned=false;Exception operation=null;var cleanup=new List<Exception>();var result=new Dictionary<string,object>();
  try {
   if(!InJob(GetCurrentProcess(),IntPtr.Zero))throw new Exception("Expected scheduled parent job absent");uint limits=ParentLimits();if((limits&0x1000)==0)throw new Exception("Silent breakaway premise absent");
   job=CreateJobObject(IntPtr.Zero,null);if(job==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error(),"CreateJobObject");
   var ownedLimits=new ExtendedLimits();ownedLimits.Basic.Flags=0x2000;Check(SetInformationJobObject(job,9,ref ownedLimits,Marshal.SizeOf(typeof(ExtendedLimits))),"Kill-on-close owned job");
   var security=new SecurityAttributes{Length=Marshal.SizeOf(typeof(SecurityAttributes)),Inherit=true};
   Check(CreatePipe(out outRead,out outWrite,ref security,4096),"stdout pipe");Check(SetHandleInformation(outRead,1,0),"Non-inherited stdout reader");
   Check(CreatePipe(out errRead,out errWrite,ref security,4096),"stderr pipe");Check(SetHandleInformation(errRead,1,0),"Non-inherited stderr reader");
   input=CreateFile("NUL",0x80000000,3,ref security,3,0x80,IntPtr.Zero);if(input==new IntPtr(-1))throw new Win32Exception(Marshal.GetLastWin32Error(),"NUL input");
   IntPtr size=IntPtr.Zero;bool initial=InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref size);if(initial||Marshal.GetLastWin32Error()!=122||size.ToInt64()<=0||size.ToInt64()>65536)throw new Exception("Attribute-list size invalid");
   attributes=Marshal.AllocHGlobal(size);Check(InitializeProcThreadAttributeList(attributes,1,0,ref size),"Attribute list");initialized=true;
   allowed=Marshal.AllocHGlobal(3*IntPtr.Size);Marshal.WriteIntPtr(allowed,0,input);Marshal.WriteIntPtr(allowed,IntPtr.Size,outWrite);Marshal.WriteIntPtr(allowed,2*IntPtr.Size,errWrite);
   Check(UpdateProcThreadAttribute(attributes,0,new IntPtr(0x20002),allowed,new IntPtr(3*IntPtr.Size),IntPtr.Zero,IntPtr.Zero),"Exact inherited handle list");
   var startup=new StartupInfoEx();startup.Startup.Size=(uint)Marshal.SizeOf(typeof(StartupInfoEx));startup.Startup.Flags=0x100;startup.Startup.Input=input;startup.Startup.Output=outWrite;startup.Startup.Error=errWrite;startup.Attributes=attributes;
   const string image=@"C:\Windows\System32\cmd.exe";
   // Suspended, no window, Unicode environment and explicit handle list. No BREAKAWAY flag.
   Check(CreateProcess(image,new StringBuilder("\""+image+"\" /d /c \"exit 42\""),IntPtr.Zero,IntPtr.Zero,true,0x08080404,IntPtr.Zero,@"C:\Windows\System32",ref startup,out child),"Fixed suspended CreateProcessW");
   Close(ref outWrite,cleanup);Close(ref errWrite,cleanup);Close(ref input,cleanup);if(cleanup.Count!=0)throw new AggregateException(cleanup);
   if(InJob(child.Process,IntPtr.Zero))throw new Exception("Suspended child remains in an inherited job");
   Check(AssignProcessToJobObject(job,child.Process),"Owned job assignment");assigned=true;if(!InJob(child.Process,job))throw new Exception("Exact owned job membership absent");
   var childImage=new StringBuilder(32768);uint imageLength=32768;Check(QueryFullProcessImageName(child.Process,0,childImage,ref imageLength),"Suspended image");if(!String.Equals(childImage.ToString(),image,StringComparison.OrdinalIgnoreCase))throw new Exception("Suspended image differs");
   uint session;Check(ProcessIdToSessionId(child.ProcessId,out session),"Suspended session");if(session!=0)throw new Exception("Suspended session differs");
   IntPtr token;Check(OpenProcessToken(child.Process,8,out token),"Suspended token");try{using(var identity=new WindowsIdentity(token)){if(identity.User.Value!="S-1-5-18")throw new Exception("Suspended SID differs");}}finally{Close(ref token,cleanup);}
   uint previous=ResumeThread(child.Thread);if(previous!=1)throw new Exception("Unexpected resume count "+previous);
   uint wait=WaitForSingleObject(child.Process,10000);if(wait!=0)throw new Exception("Fixed control deadline/wait failed "+wait);
   uint exit;Check(GetExitCodeProcess(child.Process,out exit),"Fixed control exit");if(exit!=42)throw new Exception("Fixed control exit differs "+exit);
   RequireEmptyJob(job);RequireEmptyPipe(outRead,"stdout");RequireEmptyPipe(errRead,"stderr");
   result["parentInAnyJob"]=true;result["parentImmediateLimitFlags"]=limits;result["childInitiallyInAnyJob"]=false;result["exactOwnedJobAssigned"]=true;result["processId"]=child.ProcessId;result["initialThreadId"]=child.ThreadId;result["sessionId"]=session;result["userSid"]="S-1-5-18";result["imagePath"]=image;result["creationFlags"]=0x08080404;result["breakawayRequested"]=false;result["previousSuspendCount"]=previous;result["exitCode"]=exit;result["stdoutBytes"]=0;result["stderrBytes"]=0;result["jobEmpty"]=true;
  } catch(Exception error){operation=error;}
  finally {
   bool childExited=child.Process==IntPtr.Zero;
   if(child.Process!=IntPtr.Zero){
    bool terminationFailed=false;
    try{if(assigned)Check(TerminateJobObject(job,1),"Cleanup owned job");else if(WaitForSingleObject(child.Process,0)!=0)Check(TerminateProcess(child.Process,1),"Cleanup suspended child");}catch(Exception error){terminationFailed=true;cleanup.Add(error);}
    if(terminationFailed){try{if(WaitForSingleObject(child.Process,0)!=0)Check(TerminateProcess(child.Process,1),"Fallback exact child termination");}catch(Exception error){cleanup.Add(error);}}
    try{childExited=WaitForSingleObject(child.Process,5000)==0;if(!childExited)throw new Exception("Exact child exit unconfirmed: PID "+child.ProcessId);}catch(Exception error){cleanup.Add(error);}
    if(assigned){try{RequireEmptyJob(job);}catch(Exception error){cleanup.Add(error);Close(ref job,cleanup);}}
    // Closing a kill-on-close job is an independent fallback. Confirm exit again.
    if(!childExited){Close(ref job,cleanup);try{childExited=WaitForSingleObject(child.Process,5000)==0;if(!childExited)throw new Exception("Cold restore required; child PID "+child.ProcessId+" exit remains unconfirmed");}catch(Exception error){cleanup.Add(error);}}
   }
   Close(ref child.Thread,cleanup);if(childExited)Close(ref child.Process,cleanup);else {UnconfirmedProcessHandles.Add(child.Process);child.Process=IntPtr.Zero;}
   Close(ref outWrite,cleanup);Close(ref errWrite,cleanup);Close(ref input,cleanup);Close(ref outRead,cleanup);Close(ref errRead,cleanup);Close(ref job,cleanup);
   if(initialized)DeleteProcThreadAttributeList(attributes);if(attributes!=IntPtr.Zero)Marshal.FreeHGlobal(attributes);if(allowed!=IntPtr.Zero)Marshal.FreeHGlobal(allowed);
  }
  if(operation!=null)cleanup.Insert(0,operation);if(cleanup.Count!=0)throw new AggregateException("Fixed control operation/cleanup failed",cleanup);
  result["cleanupConfirmed"]=true;result["controlOnly"]=true;result["applicationCompatibility"]="notMeasured";result["isolation"]="notMeasured";return result;
 }
}
'@
        $result = [AiwSchedulerLaunchControl]::Run()
        $result['imageSha256'] = $imageHash
        $result['signatureValid'] = $true
        return $result
    } finally {
        $sha.Dispose()
        $heldImage.Dispose()
    }
}
