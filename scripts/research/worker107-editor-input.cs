// Fixed research keyboard workflow. No file writes, process creation or
// cross-process memory writes. Every input batch requires the owned foreground.
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
public static class AiwOwnedEditorInput {
 [StructLayout(LayoutKind.Sequential)] struct Mouse { public int X,Y; public uint Data,Flags,Time; public UIntPtr Extra; }
 [StructLayout(LayoutKind.Sequential)] struct Keyboard { public ushort Key,Scan; public uint Flags,Time; public UIntPtr Extra; }
 [StructLayout(LayoutKind.Explicit)] struct Union { [FieldOffset(0)] public Mouse Mouse; [FieldOffset(0)] public Keyboard Key; }
 [StructLayout(LayoutKind.Sequential)] struct Input { public uint Type; public Union Data; }
 [DllImport("user32.dll",SetLastError=true)] static extern uint SendInput(uint count,Input[] inputs,int size);
 [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr window);
 [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
 [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window,out uint pid);
 [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr window,StringBuilder name,int size);
 [DllImport("user32.dll")] static extern short GetAsyncKeyState(int key);
 static void Own(IntPtr window,uint pid) {
  uint actual; if(window==IntPtr.Zero || !IsWindowVisible(window) || GetForegroundWindow()!=window || GetWindowThreadProcessId(window,out actual)==0 || actual!=pid)throw new Exception("Owned foreground window required; no input sent");
 }
 static Input Key(ushort key,bool up) { return new Input{Type=1,Data=new Union{Key=new Keyboard{Key=key,Flags=up?2u:0u}}}; }
 static void Send(IntPtr window,uint pid,Input[] inputs) {
  Own(window,pid); if(SendInput((uint)inputs.Length,inputs,Marshal.SizeOf(typeof(Input)))!=inputs.Length)throw new Win32Exception(Marshal.GetLastWin32Error(),"Fixed keyboard batch incomplete; no retry");
 }
 static void Chord(IntPtr window,uint pid,ushort modifier,ushort key) { Send(window,pid,new[]{Key(modifier,false),Key(key,false),Key(key,true),Key(modifier,true)}); }
 static void Text(IntPtr window,uint pid,string text) {
  var keys=new Input[text.Length*2];for(int i=0;i<text.Length;i++){keys[i*2]=new Input{Type=1,Data=new Union{Key=new Keyboard{Scan=text[i],Flags=4}}};keys[i*2+1]=new Input{Type=1,Data=new Union{Key=new Keyboard{Scan=text[i],Flags=6}}};}Send(window,pid,keys);
 }
 public static void Edit(uint pid,IntPtr main) {
  foreach(int key in new[]{0x10,0x11,0x12,0x5b,0x5c})if((GetAsyncKeyState(key)&0x8000)!=0)throw new Exception("Keyboard modifier already held");
  if(!SetForegroundWindow(main))throw new Exception("Could not foreground owned editor");Thread.Sleep(200);Own(main,pid);
  Chord(main,pid,0x11,0x4f);Thread.Sleep(700);
  IntPtr dialog=GetForegroundWindow();Own(dialog,pid);var name=new StringBuilder(256);GetClassName(dialog,name,256);
  if(dialog==main || name.ToString()!="#32770")throw new Exception("Owned Open dialog absent");
  Text(dialog,pid,@"C:\Users\AiwStandardUser\AppData\Local\AIW\msix-lifecycle\document.txt");
  Send(dialog,pid,new[]{Key(0x0d,false),Key(0x0d,true)});Thread.Sleep(700);Own(main,pid);
  Chord(main,pid,0x11,0x23);Text(main,pid,"AIW packaged validation");Send(main,pid,new[]{Key(0x0d,false),Key(0x0d,true)});
  Chord(main,pid,0x11,0x53);Thread.Sleep(500);Own(main,pid);Chord(main,pid,0x12,0x73);
 }
}
