#requires -Version 5.1
# Fixed production transport. The approved native worker owns application execution.
param(
 [Parameter(Mandatory)][ValidateSet('Clean','Stage','Enroll','Restart','Ready','Control','Run','Status','Collect')][string]$Operation,
 [Parameter(Mandatory)][ValidatePattern('\A[a-zA-Z0-9-]{1,96}\z')][string]$RunId,
 [Parameter(Mandatory)][string]$Workspace
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$ProgressPreference='SilentlyContinue'
$session=$null;$credential=$null
try {
 $tools=Join-Path $Workspace 'tools'
 $prepared=Get-Content -LiteralPath (Join-Path $tools 'msix-preparation.json') -Raw|ConvertFrom-Json
 $request=Get-Content -LiteralPath (Join-Path $tools 'request.json') -Raw|ConvertFrom-Json
 if($prepared.runId -cne $RunId -or $request.runId -cne $RunId -or $request.workerUuid -cne 'e5cecc90-35c2-4831-bf9c-424be23f7d4e'){throw 'Prepared run identity differs'}
 $trusted=Get-Item -LiteralPath 'Cert:\CurrentUser\Root\BC14DCC4E37F83161EBB55AF8624E36A79E19256'
 if($trusted.Thumbprint -cne $prepared.worker.httpsCertificateSha1 -or $trusted.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow){throw 'Enrolled worker certificate expired or differs'}
 $stored=Import-Clixml -LiteralPath (Join-Path $env:USERPROFILE '.aiw-private\worker107-winrm.xml')
 $credential=[pscredential]::new('labadmin',$stored.Password);$stored=$null
 # The actual credential-bearing channel validates chain, name and expiry normally.
 $session=New-PSSession -ComputerName '192.168.1.174' -UseSSL -Authentication Basic -Credential $credential -ConfigurationName Microsoft.PowerShell -SessionOption (New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 60000)
 $root='C:\ProgramData\AIW\MsixWorker\'+$RunId
 $identity=Invoke-Command -Session $session -ScriptBlock {
  $ErrorActionPreference='Stop'
  $uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID
  $actor=[Security.Principal.WindowsIdentity]::GetCurrent()
  if($uuid -ine 'e5cecc90-35c2-4831-bf9c-424be23f7d4e' -or $actor.User.Value -cne 'S-1-5-21-3556347314-2314855617-1438300668-1001' -or !([Security.Principal.WindowsPrincipal]::new($actor)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){return @{rejected=$true}}
  @{workerUuid=$uuid;actorSid=$actor.User.Value;rejected=$false}
 }
 if($identity.rejected){
  if($Operation -eq 'Ready'){@{fatal=$true;reason='Exact elevated VM107 operator required'}|ConvertTo-Json -Compress;return}
  throw 'Exact elevated VM107 operator required'
 }
 if($Operation -eq 'Ready'){
  Invoke-Command -Session $session -ArgumentList $root,$request.nonce,$request.workerUuid -ScriptBlock {
   param($root,$nonce,$uuid)
   $ErrorActionPreference='Stop';Set-StrictMode -Version Latest
   try {
    $account=Get-Content -LiteralPath ($root+'\account.json') -Raw|ConvertFrom-Json
    $user=Get-LocalUser -Name AiwStandardUser
    if($account.runNonce -cne $nonce -or $account.workerUuid -cne $uuid -or !$account.created -or $user.SID.Value -cne $account.userSid -or $user.SID.Value -ceq 'S-1-5-21-3556347314-2314855617-1438300668-1001'){throw 'Run-owned account differs'}
    $result=@{nonce=$nonce;workerUuid=$uuid;userSid=$account.userSid;accountBound=$true;ready=$false;active=$false;profileLoaded=$false;sessionId=0}
    $sessions=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'"|Where-Object {
     $owner=Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid
     if($owner.ReturnValue -ne 0){throw 'Explorer owner query failed'}
     $owner.Sid -ceq $account.userSid
    }|Select-Object -ExpandProperty SessionId -Unique)
    if($sessions.Count -gt 1 -or ($sessions.Count -eq 1 -and $sessions[0] -le 0)){throw 'Contradictory standard-user session'}
    if($sessions.Count -eq 0){return $result}
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class AiwReadiness {
 [DllImport("wtsapi32.dll",SetLastError=true)] static extern bool WTSQuerySessionInformationW(IntPtr server,int session,int kind,out IntPtr value,out int bytes);
 [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr value);
 public static bool Active(int session) {
  IntPtr value;int bytes;
  if(!WTSQuerySessionInformationW(IntPtr.Zero,session,8,out value,out bytes))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
  try{if(bytes!=4 || value==IntPtr.Zero)throw new InvalidOperationException("Session state buffer differs");return Marshal.ReadInt32(value)==0;}finally{WTSFreeMemory(value);}
 }
}
'@
    $profile=@(Get-CimInstance Win32_UserProfile|Where-Object SID -CEQ $account.userSid)
    if($profile.Count -gt 1){throw 'Ambiguous loaded profile'}
    $result.sessionId=[int]$sessions[0];$result.active=[AiwReadiness]::Active($result.sessionId)
    $result.profileLoaded=($profile.Count -eq 1 -and $profile[0].Loaded)
    $result.ready=($result.active -and $result.profileLoaded)
    $result
   }catch{@{fatal=$true;nonce=$nonce;workerUuid=$uuid;reason=$_.Exception.Message}}
  }|ConvertTo-Json -Depth 6 -Compress;return
 }
 if($Operation -eq 'Clean'){
  $clean=Invoke-Command -Session $session -ScriptBlock {
   $ErrorActionPreference='Stop'
   $expected=@('Administrator','CodexSandboxOffline','CodexSandboxOnline','DefaultAccount','Guest','labadmin','WDAGUtilityAccount')|Sort-Object
   if((@(Get-LocalUser|Select-Object -ExpandProperty Name|Sort-Object)-join '|') -cne ($expected -join '|')){throw 'Restored account inventory differs'}
   foreach($path in @('C:\ProgramData\AIW\MsixWorker','C:\AIW-Worker107-Research-r1','C:\AIW-Worker107-Intake-r1','C:\AIW-Msix-Lifecycle-Input','C:\Users\AiwStandardUser')){if(Test-Path -LiteralPath $path){throw 'Restored worker contains trial artifacts'}}
   if(@(Get-AppxPackage -AllUsers -Name 'AIWResearch.NotepadPP').Count -ne 0 -or @(Get-AppxProvisionedPackage -Online|Where-Object DisplayName -CEQ 'AIWResearch.NotepadPP').Count -ne 0 -or @(Get-Process -Name 'notepad++' -ErrorAction SilentlyContinue).Count -ne 0){throw 'Restored package/process inventory not empty'}
   if(@(Get-ScheduledTask|Where-Object TaskName -Match '^AIW').Count -ne 0){throw 'Restored worker has AIW tasks'}
   $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon')
   try{if($key.GetValueNames() -contains 'DefaultPassword' -or $key.GetValueNames() -contains 'AutoLogonCount' -or $key.GetValue('AutoAdminLogon') -eq '1'){throw 'Automatic sign-in remains'}}finally{$key.Dispose()}
   $listeners=@(Get-ChildItem WSMan:\localhost\Listener)
   if($listeners.Count -ne 1){throw 'Expected sole HTTPS listener'}
   $settings=Get-ChildItem $listeners[0].PSPath
   if(($settings|Where-Object Name -EQ Transport).Value -cne 'HTTPS' -or ($settings|Where-Object Name -EQ CertificateThumbprint).Value -cne 'BC14DCC4E37F83161EBB55AF8624E36A79E19256'){throw 'Listener differs'}
   @{clean=$true;workerUuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID;accounts=$expected;trialArtifactsAbsent=$true;automaticSignInDisabled=$true}
  }
  $clean|ConvertTo-Json -Depth 6 -Compress;return
 }
 if($Operation -eq 'Stage'){
  Invoke-Command -Session $session -ArgumentList $root -ScriptBlock {
   param($root)
   $ErrorActionPreference='Stop'
   $base='C:\ProgramData\AIW\MsixWorker'
   if(Test-Path -LiteralPath $base){throw 'Existing worker intake refused; cold recovery required'}
   $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-21-3556347314-2314855617-1438300668-1001'))
   foreach($sid in @('S-1-5-18','S-1-5-21-3556347314-2314855617-1438300668-1001')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
   $parent='C:\ProgramData\AIW'
   if(!(Test-Path -LiteralPath $parent)){$null=[IO.Directory]::CreateDirectory($parent,$acl)}
   $parentItem=Get-Item -LiteralPath $parent
   $parentAcl=Get-Acl -LiteralPath $parent
   if($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint -or !$parentAcl.AreAccessRulesProtected){throw 'Protected ordinary worker parent required'}
   foreach($rule in $parentAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-21-3556347314-2314855617-1438300668-1001')){throw 'Worker parent ACL differs'}}
   $null=[IO.Directory]::CreateDirectory($base,$acl);$null=[IO.Directory]::CreateDirectory($root,$acl);$null=[IO.Directory]::CreateDirectory(($root+'\input'))
  }
  Copy-Item -LiteralPath (Join-Path $tools 'agent.exe') -Destination ($root+'\agent.exe') -ToSession $session
  Copy-Item -LiteralPath (Join-Path $tools 'request.json') -Destination ($root+'\request.json') -ToSession $session
  foreach($name in @('assembly.json','signing.json')){Copy-Item -LiteralPath (Join-Path $tools $name) -Destination ($root+'\input\'+$name) -ToSession $session}
  Copy-Item -LiteralPath $prepared.packageImport.payload.finalPath -Destination ($root+'\input\application.msix') -ToSession $session
  Invoke-Command -Session $session -ArgumentList $root,$request -ScriptBlock {
   param($root,$request)
   $ErrorActionPreference='Stop'
   foreach($entry in @(@('agent.exe',$request.agentSha256),@('input\application.msix',$request.packageSha256),@('input\assembly.json',$request.assemblySha256),@('input\signing.json',$request.signingSha256))){if((Get-FileHash -LiteralPath (Join-Path $root $entry[0])).Hash.ToLowerInvariant() -cne $entry[1]){throw 'Transferred approved bytes differ'}}
   @{staged=$true;nonce=$request.nonce}
  }|ConvertTo-Json -Compress;return
 }
 if($Operation -eq 'Restart'){
  Invoke-Command -Session $session -ArgumentList $root,$request.nonce -ScriptBlock {
   param($root,$nonce)
   $enrolled=Get-Content -LiteralPath ($root+'\enroll-result.json') -Raw|ConvertFrom-Json
   if($enrolled.runNonce -cne $nonce -or !$enrolled.restartRequired){throw 'Run-owned enrollment required'}
   $marker=[IO.File]::Open(($root+'\restart-intent'),[IO.FileMode]::CreateNew);$marker.Flush($true);$marker.Dispose()
   # Schedule reboot after the successful dispatch reply has left WinRM.
   & C:\Windows\System32\shutdown.exe /r /t 5 /f | Out-Null
   if($LASTEXITCODE -ne 0){throw 'Restart dispatch failed'}
   @{restartDispatched=$true;nonce=$nonce}
  }|ConvertTo-Json -Compress;return
 }
 if($Operation -in @('Enroll','Control','Run')){
  $op=$Operation.ToLowerInvariant()
  Invoke-Command -Session $session -ArgumentList $root,$op,$RunId,$request.agentSha256,$request.nonce -ScriptBlock {
   param($root,$op,$runId,$agentSha,$nonce)
   $ErrorActionPreference='Stop'
   $marker=$root+'\'+$op+'-dispatch.json'
   if(Test-Path -LiteralPath $marker){throw 'Operation already dispatched; inspect status, never replay'}
   if((Get-FileHash -LiteralPath ($root+'\agent.exe')).Hash.ToLowerInvariant() -cne $agentSha){throw 'Approved agent differs'}
   $source=@'
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$request=Get-Content -LiteralPath ($root+'\request.json') -Raw|ConvertFrom-Json
if((Get-CimInstance Win32_ComputerSystemProduct).UUID -ine $request.workerUuid -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18'){throw 'Exact SYSTEM worker required'}
if((Get-FileHash -LiteralPath ($root+'\agent.exe')).Hash.ToLowerInvariant() -cne $request.agentSha256){throw 'Agent differs'}
$p=[Diagnostics.Process]::new();$p.StartInfo=[Diagnostics.ProcessStartInfo]::new(($root+'\agent.exe'),'@@OP@@ '+$request.runId)
$p.StartInfo.UseShellExecute=$false;$p.StartInfo.RedirectStandardOutput=$true;$p.StartInfo.RedirectStandardError=$true;$p.StartInfo.CreateNoWindow=$true
try {
 if(!$p.Start()){throw 'Native worker did not start'}
 $out=$p.StandardOutput.ReadToEndAsync();$err=$p.StandardError.ReadToEndAsync()
 if(!$p.WaitForExit(1320000)){throw 'Native worker deadline exceeded'}
 [IO.File]::WriteAllText(($root+'\@@OP@@-stdout.txt'),$out.GetAwaiter().GetResult())
 [IO.File]::WriteAllText(($root+'\@@OP@@-stderr.txt'),$err.GetAwaiter().GetResult())
 $record=@{completed=$true;exitCode=$p.ExitCode;nonce=$request.nonce;operation='@@OP@@'}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Compress))
 $path=$root+'\@@OP@@-transport.json';$pending=$path+'.pending'
 $f=[IO.File]::Open($pending,[IO.FileMode]::CreateNew)
 try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
 [IO.File]::Move($pending,$path)
}finally{$p.Dispose()}
'@
   $path=$root+'\'+$op+'-task.ps1';[IO.File]::WriteAllText($path,$source.Replace('@@OP@@',$op),[Text.UTF8Encoding]::new($false))
   $service=New-Object -ComObject Schedule.Service;$service.Connect();$folder=$service.GetFolder('\');$name='AIW-Msix-'+$op+'-'+$runId
   if(@($folder.GetTasks(1)|Where-Object Name -CEQ $name).Count -ne 0){throw 'Fresh task required'}
   $task=$service.NewTask(0);$task.Principal.UserId='S-1-5-18';$task.Principal.LogonType=5;$task.Principal.RunLevel=1;$task.Settings.ExecutionTimeLimit='PT24M'
   $task.Settings.DisallowStartIfOnBatteries=$false;$task.Settings.StopIfGoingOnBatteries=$false
   $action=$task.Actions.Create(0);$action.Path='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe';$action.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File '+$path
   $registered=$folder.RegisterTaskDefinition($name,$task,0x12,'S-1-5-18',$null,5,'O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;S-1-5-21-3556347314-2314855617-1438300668-1001)')
   $bytes=[Text.UTF8Encoding]::new($false).GetBytes((@{nonce=$nonce;operation=$op}|ConvertTo-Json -Compress));$f=[IO.File]::Open($marker,[IO.FileMode]::CreateNew)
   try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
   $null=$registered.RunEx($null,0,0,$null)
   @{dispatched=$true;nonce=$nonce;operation=$op}
  }|ConvertTo-Json -Compress;return
 }
 if($Operation -eq 'Status'){
  Invoke-Command -Session $session -ArgumentList $root,$request.nonce -ScriptBlock {
   param($root,$nonce)
   $records=[ordered]@{}
   foreach($name in @('enroll-transport','control-transport','run-transport','enroll-result','control-result','result','failure','logon-cleared')){
    $path=$root+'\'+$name+'.json';if(Test-Path -LiteralPath $path){if((Get-Item -LiteralPath $path).Length -gt 262144){throw 'Status bound exceeded'};$records[$name]=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json}
   }
   @{nonce=$nonce;records=$records}
  }|ConvertTo-Json -Depth 16 -Compress;return
 }
 if($Operation -eq 'Collect'){
  Invoke-Command -Session $session -ArgumentList $root,$request.nonce -ScriptBlock {
   param($root,$nonce)
   $ErrorActionPreference='Stop';$files=@();$total=0
   # Read-only retry is safe only after native/controller work has stopped.
   if(@(Get-ScheduledTask|Where-Object {$_.TaskName -like 'AIW-Msix-*' -and $_.State -eq 'Running'}).Count -ne 0 -or @(Get-Process -Name 'notepad++','agent' -ErrorAction SilentlyContinue).Count -ne 0){throw 'Worker still running; preserve its lease and evidence'}
   # Only receipts, raw evidence and bounded diagnostic logs; never inputs/account secrets.
   $exportFiles=@()
   if(Test-Path -LiteralPath $root){
    if((Get-Item -LiteralPath $root -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse evidence root refused'}
    $exportFiles+=@(Get-ChildItem -LiteralPath $root -File -Force -ErrorAction Stop)
    foreach($directory in @(($root+'\evidence'),($root+'\failed-evidence'))){
     if(Test-Path -LiteralPath $directory){
      if((Get-Item -LiteralPath $directory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse evidence directory refused'}
      $tree=@(Get-ChildItem -LiteralPath $directory -Recurse -Force -ErrorAction Stop)
      if(@($tree|Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count -ne 0){throw 'Reparse evidence entry refused'}
      $exportFiles+=@($tree|Where-Object {!$_.PSIsContainer})
     }
    }
   }
   foreach($file in $exportFiles){
    $name=$file.FullName.Substring($root.Length+1).Replace('\','/')
    if($name -notmatch '\A(?:evidence/|failed-evidence/|[^/]+\.(?:json|txt)\z)' -or $name -eq 'request.json'){continue}
    if($file.Attributes -band [IO.FileAttributes]::ReparsePoint -or $file.Length -gt 4MB){throw 'Evidence file bound/type rejected'}
    $total+=$file.Length;if($total -gt 16MB -or $files.Count -ge 512){throw 'Evidence export bound exceeded'}
    $bytes=[IO.File]::ReadAllBytes($file.FullName);$hash=[Security.Cryptography.SHA256]::Create()
    try{$sha=([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
    $files+=@{path=$name;sha256=$sha;bytes=$bytes.Length;base64=[Convert]::ToBase64String($bytes)}
   }
   @{nonce=$nonce;files=$files;quiescent=$true;enumerationComplete=$true}
  }|ConvertTo-Json -Depth 6 -Compress;return
 }
 throw 'Unsupported closed transport operation'
}finally{if($session){Remove-PSSession $session};$credential=$null}
