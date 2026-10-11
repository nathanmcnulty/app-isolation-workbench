using System;
using System.Text;
using System.Runtime.InteropServices;
using System.ComponentModel;
public sealed class AiwMsixObservation {
 public string PackageFullName; public bool IsElevated; public bool IsAppContainer; public string IntegritySid; public string UserSid; public uint TokenSessionId; public int ElevationType; public bool AdministratorsEnabled;
}
public sealed class AiwMsixProcess {public uint Pid;public uint SessionId;public string ImagePath;public string PackageFullName;public string PackageIdentityStatus;public int? ImageQueryError;}
public static class AiwMsixNative {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern int GetApplicationUserModelId(IntPtr process,ref uint length,StringBuilder name);
 public static string ApplicationId(IntPtr process) {
  uint length=0;int result=GetApplicationUserModelId(process,ref length,null);
  if(result!=122)throw new Win32Exception(result);
  if(length==0 || length>1024)throw new InvalidOperationException("Application identity length refused");
  var name=new StringBuilder((int)length);result=GetApplicationUserModelId(process,ref length,name);if(result!=0)throw new Win32Exception(result);return name.ToString();
 }
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool QueryFullProcessImageNameW(IntPtr process,uint flags,StringBuilder name,ref uint length);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool ProcessIdToSessionId(uint pid,out uint session);
 public static string ImagePath(IntPtr process) {uint n=32768;var name=new StringBuilder((int)n);if(!QueryFullProcessImageNameW(process,0,name,ref n))throw new Win32Exception(Marshal.GetLastWin32Error());return name.ToString();}
 public static AiwMsixProcess Inspect(uint pid) {
  IntPtr p=OpenProcess(0x1000,false,pid);if(p==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
  try{
   uint session;if(!ProcessIdToSessionId(pid,out session))throw new Win32Exception(Marshal.GetLastWin32Error());
   // Query package identity before the optional image path. Kernel pseudo-processes
   // can positively have no package identity while having no executable image.
   string package=PackageName(p);string image=null;int? imageError=null;
   try{image=ImagePath(p);}catch(Win32Exception error){if(package!=null)throw;imageError=error.NativeErrorCode;}
   return new AiwMsixProcess{Pid=pid,SessionId=session,ImagePath=image,PackageFullName=package,PackageIdentityStatus=package==null?"noPackage":"packaged",ImageQueryError=imageError};
  }finally{CloseHandle(p);}
 }
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool assigned);
 [DllImport("user32.dll",SetLastError=true)] static extern uint GetWindowThreadProcessId(IntPtr window,out uint processId);
 [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
 public static bool InJob(IntPtr process) {bool assigned;if(!IsProcessInJob(process,IntPtr.Zero,out assigned))throw new Win32Exception(Marshal.GetLastWin32Error());return assigned;}
 public static bool VisibleOwnedWindow(IntPtr window,uint expectedPid) {uint pid;return window!=IntPtr.Zero && GetWindowThreadProcessId(window,out pid)!=0 && pid==expectedPid && IsWindowVisible(window);}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern int GetPackageFullName(IntPtr process,ref uint length,StringBuilder name);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr data,uint length,out uint needed);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 static string PackageName(IntPtr process) {
  uint length=0;int result=GetPackageFullName(process,ref length,null);
  if(result==15700)return null;
  if(result!=122)throw new Win32Exception(result);
  if(length==0 || length>1024)throw new InvalidOperationException("Package identity length refused");
  var name=new StringBuilder((int)length);result=GetPackageFullName(process,ref length,name);if(result!=0)throw new Win32Exception(result);return name.ToString();
 }
 static IntPtr Information(IntPtr token,int kind) {
  uint needed; GetTokenInformation(token,kind,IntPtr.Zero,0,out needed);
  if(needed==0 || needed>65536) throw new Win32Exception(Marshal.GetLastWin32Error());
  IntPtr data=Marshal.AllocHGlobal((int)needed);
  if(!GetTokenInformation(token,kind,data,needed,out needed)){int error=Marshal.GetLastWin32Error();Marshal.FreeHGlobal(data);throw new Win32Exception(error);}
  return data;
 }
 public static AiwMsixObservation Observe(IntPtr process) {
  string package=PackageName(process);
  IntPtr token; if(!OpenProcessToken(process,8,out token))throw new Win32Exception(Marshal.GetLastWin32Error());
  try {
   bool elevated,container,admin=false;string integrity,userSid;uint session;int elevationType;
   IntPtr data=Information(token,20);try{elevated=Marshal.ReadInt32(data)!=0;}finally{Marshal.FreeHGlobal(data);}
   data=Information(token,29);try{container=Marshal.ReadInt32(data)!=0;}finally{Marshal.FreeHGlobal(data);}
   data=Information(token,25);try{integrity=new System.Security.Principal.SecurityIdentifier(Marshal.ReadIntPtr(data)).Value;}finally{Marshal.FreeHGlobal(data);}
   data=Information(token,1);try{userSid=new System.Security.Principal.SecurityIdentifier(Marshal.ReadIntPtr(data)).Value;}finally{Marshal.FreeHGlobal(data);}
   data=Information(token,12);try{session=unchecked((uint)Marshal.ReadInt32(data));}finally{Marshal.FreeHGlobal(data);}
   data=Information(token,18);try{elevationType=Marshal.ReadInt32(data);}finally{Marshal.FreeHGlobal(data);}
   data=Information(token,2);try{int count=Marshal.ReadInt32(data);if(count<0 || count>4096)throw new InvalidOperationException("Group count refused");int stride=IntPtr.Size==8?16:8;int offset=IntPtr.Size==8?8:4;for(int k=0;k<count;k++){IntPtr row=IntPtr.Add(data,offset+k*stride);string sid=new System.Security.Principal.SecurityIdentifier(Marshal.ReadIntPtr(row)).Value;int attributes=Marshal.ReadInt32(row,IntPtr.Size);if(sid=="S-1-5-32-544" && (attributes&4)!=0)admin=true;}}finally{Marshal.FreeHGlobal(data);}
   return new AiwMsixObservation{PackageFullName=package,IsElevated=elevated,IsAppContainer=container,IntegritySid=integrity,UserSid=userSid,TokenSessionId=session,ElevationType=elevationType,AdministratorsEnabled=admin};
  }finally{CloseHandle(token);}
 }
}
// Research-only fixed launch. The caller must verify the held suspended process
// before Resume; disposal kills an unresumed process, never an unrelated PID.
public sealed class AiwSuspendedNotepad : IDisposable {
 [StructLayout(LayoutKind.Sequential)] struct Startup {
  public uint cb;public IntPtr reserved,desktop,title;public uint x,y,xSize,ySize,xChars,yChars,fill,flags;public ushort show,reservedBytes;public IntPtr reservedData,input,output,error;
 }
 [StructLayout(LayoutKind.Sequential)] struct ProcessInfo {public IntPtr process,thread;public uint pid,tid;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessW(string application,StringBuilder command,IntPtr processAttributes,IntPtr threadAttributes,bool inherit,uint flags,IntPtr environment,string directory,ref Startup startup,out ProcessInfo process);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 ProcessInfo info;bool resumed,disposed;
 AiwSuspendedNotepad(ProcessInfo value){info=value;}
 public uint Pid {get{return info.pid;}}
 public IntPtr Handle {get{if(disposed)throw new ObjectDisposedException("AiwSuspendedNotepad");return info.process;}}
 public static AiwSuspendedNotepad Create() {
  const string directory=@"C:\Program Files\WindowsApps\AIWResearch.NotepadPP_8.9.8.0_x64__q1fhfzcjv9wt6\Application";
  var startup=new Startup();startup.cb=(uint)Marshal.SizeOf(typeof(Startup));ProcessInfo value;
  if(!CreateProcessW(directory+@"\notepad++.exe",null,IntPtr.Zero,IntPtr.Zero,false,4,IntPtr.Zero,directory,ref startup,out value))throw new Win32Exception(Marshal.GetLastWin32Error());
  return new AiwSuspendedNotepad(value);
 }
 public void Resume() {
  if(disposed || resumed)throw new InvalidOperationException("Single suspended resume required");
  uint previous=ResumeThread(info.thread);if(previous==0xffffffff)throw new Win32Exception(Marshal.GetLastWin32Error());
  if(previous!=1)throw new InvalidOperationException("Unexpected thread suspend count");resumed=true;
 }
 public void Dispose() {
  if(disposed)return;
  try{if(!resumed){if(!TerminateProcess(info.process,1))throw new Win32Exception(Marshal.GetLastWin32Error());if(WaitForSingleObject(info.process,5000)!=0)throw new InvalidOperationException("Suspended process cleanup not verified");}}
  finally{CloseHandle(info.thread);CloseHandle(info.process);disposed=true;}
 }
}
