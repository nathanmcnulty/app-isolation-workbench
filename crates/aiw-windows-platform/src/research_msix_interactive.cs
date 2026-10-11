// Research-only, read-only prerequisite for the real interactive-user control.
// This does not launch, authenticate, create accounts, or install applications.
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

public sealed class AiwInteractiveObservation {
 public string UserSid,UserName,LogonDomain,AuthenticationId,WtsUserName,WtsDomain;
 public uint SessionId,LogonSessionId,LogonType;
 public long LogonTimeFileTime;
 public int WtsState;
 public uint ShellPid;
 public string ShellAuthenticationId;
 public AiwMsixObservation Token,ShellToken;
}
public static class AiwInteractiveNative {
 [StructLayout(LayoutKind.Sequential)] struct Luid {public uint Low;public int High;}
 [StructLayout(LayoutKind.Sequential)] struct UnicodeString {public ushort Length,MaximumLength;public IntPtr Buffer;}
 // Prefix through LogonTime; LSA owns the full, potentially larger structure.
 [StructLayout(LayoutKind.Sequential)] struct LogonData {
  public uint Size;public Luid LogonId;public UnicodeString UserName,LogonDomain,AuthenticationPackage;
  public uint LogonType,Session;public IntPtr Sid;public long LogonTime;
 }
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr data,uint length,out uint needed);
 [DllImport("secur32.dll")] static extern uint LsaGetLogonSessionData(ref Luid id,out IntPtr data);
 [DllImport("secur32.dll")] static extern uint LsaFreeReturnBuffer(IntPtr data);
 [DllImport("advapi32.dll")] static extern uint LsaNtStatusToWinError(uint status);
 [DllImport("wtsapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool WTSQuerySessionInformationW(IntPtr server,uint session,int kind,out IntPtr buffer,out uint length);
 [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr memory);
 [DllImport("user32.dll")] static extern IntPtr GetShellWindow();
 [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window,out uint pid);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 static string Id(Luid id){return unchecked((uint)id.High).ToString("x8")+id.Low.ToString("x8");}
 static Luid Authentication(IntPtr process) {
  IntPtr token;if(!OpenProcessToken(process,8,out token))throw new Win32Exception(Marshal.GetLastWin32Error());
  try {
   // TOKEN_STATISTICS starts with TokenId and AuthenticationId (two LUIDs).
   uint needed;GetTokenInformation(token,10,IntPtr.Zero,0,out needed);
   if(needed<16 || needed>65536)throw new InvalidOperationException("Token statistics length refused");
   IntPtr data=Marshal.AllocHGlobal((int)needed);
   try{if(!GetTokenInformation(token,10,data,needed,out needed))throw new Win32Exception(Marshal.GetLastWin32Error());if(needed<16)throw new InvalidOperationException("Truncated token statistics");return (Luid)Marshal.PtrToStructure(IntPtr.Add(data,8),typeof(Luid));}
   finally{Marshal.FreeHGlobal(data);}
  }finally{CloseHandle(token);}
 }
 static string Text(UnicodeString value) {
  if(value.Length>value.MaximumLength || value.Length>4096 || (value.Length&1)!=0 || (value.Length!=0 && value.Buffer==IntPtr.Zero))throw new InvalidOperationException("LSA string refused");
  return value.Length==0?String.Empty:Marshal.PtrToStringUni(value.Buffer,value.Length/2);
 }
 static string Wts(uint session,int kind,out int state) {
  IntPtr data;uint length;if(!WTSQuerySessionInformationW(IntPtr.Zero,session,kind,out data,out length))throw new Win32Exception(Marshal.GetLastWin32Error());
  try {
   state=-1;if(data==IntPtr.Zero)throw new InvalidOperationException("Missing WTS buffer");
   if(kind==8){if(length!=4)throw new InvalidOperationException("WTS state length refused");state=Marshal.ReadInt32(data);return null;}
   if(length<2 || length>4096 || (length&1)!=0 || Marshal.ReadInt16(data,(int)length-2)!=0)throw new InvalidOperationException("WTS string length refused");
   string value=Marshal.PtrToStringUni(data,(int)length/2-1);if(value.IndexOf('\0')>=0)throw new InvalidOperationException("Embedded WTS terminator");return value;
  }finally{WTSFreeMemory(data);}
 }
 public static AiwInteractiveObservation ObserveCurrent() {
  using(var current=Process.GetCurrentProcess()) {
   var token=AiwMsixNative.Observe(current.Handle);Luid auth=Authentication(current.Handle);
   IntPtr data;uint status=LsaGetLogonSessionData(ref auth,out data);if(status!=0)throw new Win32Exception((int)LsaNtStatusToWinError(status));
   var result=new AiwInteractiveObservation();
   try {
    if(data==IntPtr.Zero || unchecked((uint)Marshal.ReadInt32(data))<(uint)Marshal.SizeOf(typeof(LogonData)))throw new InvalidOperationException("LSA data length refused");
    var logon=(LogonData)Marshal.PtrToStructure(data,typeof(LogonData));
    if(logon.Sid==IntPtr.Zero || new SecurityIdentifier(logon.Sid).Value!=token.UserSid || Id(logon.LogonId)!=Id(auth))throw new InvalidOperationException("LSA token identity mismatch");
    result.UserSid=token.UserSid;result.UserName=Text(logon.UserName);result.LogonDomain=Text(logon.LogonDomain);result.AuthenticationId=Id(auth);result.SessionId=token.TokenSessionId;result.LogonSessionId=logon.Session;result.LogonType=logon.LogonType;result.LogonTimeFileTime=logon.LogonTime;result.Token=token;
   }finally{if(data!=IntPtr.Zero)LsaFreeReturnBuffer(data);}
   int state;result.WtsUserName=Wts(result.SessionId,5,out state);result.WtsDomain=Wts(result.SessionId,7,out state);Wts(result.SessionId,8,out state);result.WtsState=state;
   IntPtr window=GetShellWindow();uint pid;
   if(window==IntPtr.Zero || GetWindowThreadProcessId(window,out pid)==0 || pid==0)throw new InvalidOperationException("Interactive shell absent");
   IntPtr shell=OpenProcess(0x1000,false,pid);if(shell==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
   try{result.ShellPid=pid;result.ShellToken=AiwMsixNative.Observe(shell);result.ShellAuthenticationId=Id(Authentication(shell));uint after;if(GetShellWindow()!=window || GetWindowThreadProcessId(window,out after)==0 || after!=pid)throw new InvalidOperationException("Interactive shell changed during observation");}
   finally{CloseHandle(shell);}
   return result;
  }
 }
 // Explicit run-owned SID/time bounds are required; observations alone accept nothing.
 public static void RequireOwnedStandardSession(AiwInteractiveObservation value,string expectedSid,long notBeforeFileTime,long notAfterFileTime) {
  if(value==null || String.IsNullOrEmpty(expectedSid) || notBeforeFileTime<=0 || notAfterFileTime<notBeforeFileTime)throw new InvalidOperationException("Run binding required");
  if(value.UserSid!=expectedSid || !String.Equals(value.UserName,"AiwStandardUser",StringComparison.OrdinalIgnoreCase) || !String.Equals(value.WtsUserName,value.UserName,StringComparison.OrdinalIgnoreCase) || !String.Equals(value.WtsDomain,value.LogonDomain,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Interactive user ownership differs");
  if(value.SessionId==0 || value.LogonSessionId!=value.SessionId || value.WtsState!=0 || (value.LogonType!=2 && value.LogonType!=10) || value.LogonTimeFileTime<notBeforeFileTime || value.LogonTimeFileTime>notAfterFileTime)throw new InvalidOperationException("Run-owned interactive logon absent");
  if(String.IsNullOrEmpty(value.AuthenticationId) || value.ShellPid==0 || value.ShellAuthenticationId!=value.AuthenticationId)throw new InvalidOperationException("Interactive shell logon differs");
  foreach(var token in new[]{value.Token,value.ShellToken}) {
   if(token==null || token.UserSid!=expectedSid || token.TokenSessionId!=value.SessionId || token.IsElevated || token.IsAppContainer || token.AdministratorsEnabled || token.IntegritySid!="S-1-16-8192")throw new InvalidOperationException("Medium standard-user process and shell required");
  }
 }
}
