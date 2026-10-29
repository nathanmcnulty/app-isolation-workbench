#Requires -Version 7.6
#Requires -PSEdition Core
param([Parameter(Mandatory)][ValidateSet('enroll','clear-logon','prepare','before','after')][string]$Operation)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$ProgressPreference='SilentlyContinue'
$root=$PSScriptRoot
$request=Get-Content -LiteralPath (Join-Path $root 'request.json') -Raw|ConvertFrom-Json
Assert-AiwWorkerRuntimeIdentity $AiwPowerShellRuntime $request.powerShellRuntime
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID
if($identity.User.Value -cne 'S-1-5-18' -or [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0 -or $uuid -ine 'e5cecc90-35c2-4831-bf9c-424be23f7d4e' -or $uuid -ine $request.workerUuid){throw 'Exact disposable VM107 LocalSystem required'}
if($request.schemaVersion -cne 'aiw.dev/msix-worker-request/v0alpha1' -or $request.runId -cnotmatch '\A[a-zA-Z0-9-]{1,96}\z' -or $request.nonce -cnotmatch '\A[0-9a-f]{64}\z' -or $root -cne ('C:\ProgramData\AIW\MsixWorker\'+$request.runId)){throw 'Closed run-owned MSIX path required'}
if($Operation -ne 'clear-logon' -and ([DateTime]::UtcNow.ToFileTimeUtc() -lt $request.notBeforeFileTime -or [DateTime]::UtcNow.ToFileTimeUtc() -ge $request.notAfterFileTime)){throw 'Approved execution interval expired'}
$operatorSid='S-1-5-21-3556347314-2314855617-1438300668-1001'
$acl=Get-Acl -LiteralPath $root
if(!$acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18',$operatorSid)){throw 'Protected worker intake required'}
$accountPath=Join-Path $root 'account.json';$account=$null
if(Test-Path -LiteralPath $accountPath){$account=Get-Content -LiteralPath $accountPath -Raw|ConvertFrom-Json;if($account.runNonce -cne $request.nonce){throw 'Account run binding differs'}}
foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
 $sid=$rule.IdentityReference.Value
 if($rule.AccessControlType -ne 'Allow' -or $rule.IsInherited){throw 'Worker ACL form differs'}
 if($sid -notin @('S-1-5-18',$operatorSid)){
  if(!$account -or $sid -cne $account.userSid){throw 'Worker ACL principal differs'}
  $allowed=[int64][Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [int64][Security.AccessControl.FileSystemRights]::Synchronize
  if(([int64]$rule.FileSystemRights -band (-bnot $allowed)) -ne 0){throw 'Application account may write protected intake'}
 }
}
function Record([string]$Name,$Value){
 $Value['powerShellRuntime']=$AiwPowerShellRuntime
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $Value -Depth 16))
 $path=Join-Path $root ($Name+'.json');$pending=$path+'.pending'
 $file=[IO.File]::Open($pending,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
 [IO.File]::Move($pending,$path)
}
function New-AiwInputReadSecurity([string]$UserSid,[switch]$Staged) {
 if($UserSid -cnotmatch '\AS-1-5-21-3556347314-2314855617-1438300668-[0-9]+\z' -or $UserSid -ceq $operatorSid){throw 'Exact fresh application SID required'}
 $security=[Security.AccessControl.DirectorySecurity]::new()
 $security.SetAccessRuleProtection($true,$false)
 $owner=if($Staged){$operatorSid}else{'S-1-5-18'}
 $security.SetOwner([Security.Principal.SecurityIdentifier]::new($owner))
 foreach($principal in @('S-1-5-18',$operatorSid)){$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($principal),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
 if(!$Staged){$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($UserSid),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))}
 return $security
}
function Assert-AiwInputSecurity($Security,[string]$UserSid,[switch]$File,[switch]$Staged) {
 $expected=New-AiwInputReadSecurity $UserSid -Staged:$Staged
 if(!$File){
  # Windows may retain SE_DACL_AUTO_INHERITED on a protected directory after
  # its parent changes. Check owner and every ACE, not that bookkeeping flag.
  if(!$Security.AreAccessRulesProtected -or $Security.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $expected.GetOwner([Security.Principal.SecurityIdentifier]).Value){throw 'Closed protected input directory owner or protection differs'}
 }else{
  if($Security.AreAccessRulesProtected -or $Security.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544',$operatorSid)){throw 'Input file owner or inheritance differs'}
 }
 $principals=@('S-1-5-18',$operatorSid);if(!$Staged){$principals+=@($UserSid)}
 $rules=@($Security.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
 if($rules.Count -ne $principals.Count){throw 'Input file ACL principal count differs'}
 foreach($principal in $principals){
  $matching=@($rules|Where-Object {$_.IdentityReference.Value -ceq $principal})
  if($matching.Count -ne 1){throw 'Input file ACL principal differs'}
  $rule=$matching[0]
  $rights=if($principal -ceq $UserSid){[int64][Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [int64][Security.AccessControl.FileSystemRights]::Synchronize}else{[int64][Security.AccessControl.FileSystemRights]::FullControl}
  $inheritance=if($File){[Security.AccessControl.InheritanceFlags]::None}else{[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'}
  if($rule.IsInherited -ne $File.IsPresent -or $rule.AccessControlType -ne 'Allow' -or $rule.InheritanceFlags -ne $inheritance -or $rule.PropagationFlags -ne 'None' -or [int64]$rule.FileSystemRights -ne $rights){throw 'Input ACL rights or form differs'}
 }
}
function Assert-AiwInputLayout([string]$RunRoot) {
 $input=Join-Path $RunRoot 'input'
 $directory=Get-Item -LiteralPath $input -Force
 if(!$directory.PSIsContainer -or $directory.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Ordinary exact input directory required'}
 $items=@(Get-ChildItem -LiteralPath $input -Force -ErrorAction Stop)
 $names=@('application.msix','assembly.json','signing.json')
 if($items.Count -ne 3 -or @(Compare-Object -ReferenceObject $names -DifferenceObject @($items.Name) -CaseSensitive).Count){throw 'Exactly three approved input files required'}
 foreach($name in $names){
  $path=Join-Path $input $name;$item=Get-Item -LiteralPath $path -Force
  if($item.PSIsContainer -or $item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Ordinary input file required'}
 }
}
function Assert-AiwRunInputAccess([string]$RunRoot,$Request,[string]$UserSid,[switch]$Staged) {
 Assert-AiwInputLayout $RunRoot
 $input=Join-Path $RunRoot 'input'
 Assert-AiwInputSecurity (Get-Acl -LiteralPath $input) $UserSid -Staged:$Staged
 foreach($name in @('application.msix','assembly.json','signing.json')){
  $path=Join-Path $input $name
  Assert-AiwInputSecurity (Get-Acl -LiteralPath $path) $UserSid -File -Staged:$Staged
  $hash=switch($name){'application.msix'{$Request.packageSha256}'assembly.json'{$Request.assemblySha256}'signing.json'{$Request.signingSha256}}
  if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hash){throw 'Approved input bytes differ'}
 }
}
function Set-AiwRunInputReadAccess([string]$RunRoot,$Request,[string]$UserSid) {
 # Stage deliberately protects input separately. Root inheritance cannot cross
 # that boundary, so grant only this fresh account read access to exact input.
 Assert-AiwRunInputAccess $RunRoot $Request $UserSid -Staged
 # Persist only the factory's modified Owner and Access sections. Set-Acl
 # copies Audit too, which is outside this read-access transition.
 [IO.FileSystemAclExtensions]::SetAccessControl([IO.DirectoryInfo]::new((Join-Path $RunRoot 'input')),(New-AiwInputReadSecurity $UserSid))
 Assert-AiwRunInputAccess $RunRoot $Request $UserSid
}
function Clear-AiwLogon {
 if(!$account){throw 'Run-owned account required'}
 $user=Get-LocalUser -Name AiwStandardUser
 if($user.SID.Value -cne $account.userSid){throw 'Created account SID differs'}
 $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',$true)
 try{
  if($key.GetValue('DefaultUserName') -cne 'AiwStandardUser'){throw 'Automatic sign-in owner differs'}
  $key.DeleteValue('DefaultPassword',$false);$key.DeleteValue('AutoLogonCount',$false);$key.SetValue('AutoAdminLogon','0')
  if($key.GetValueNames() -contains 'DefaultPassword' -or $key.GetValueNames() -contains 'AutoLogonCount' -or $key.GetValue('AutoAdminLogon') -eq '1'){throw 'Automatic sign-in cleanup not verified'}
 }finally{$key.Dispose()}
 $path=Join-Path $root 'logon-cleared.json'
 if(!(Test-Path -LiteralPath $path)){Record 'logon-cleared' @{runNonce=$request.nonce;userSid=$account.userSid;passwordValuePresent=$false;automaticSignInDisabled=$true}}
 $cleared=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
 if($cleared.runNonce -cne $request.nonce -or $cleared.userSid -cne $account.userSid -or $cleared.passwordValuePresent -ne $false -or $cleared.automaticSignInDisabled -ne $true){throw 'Cleared sign-in receipt differs'}
 if([DateTime]::UtcNow.ToFileTimeUtc() -ge $request.notAfterFileTime){Disable-LocalUser -SID $account.userSid}
}
if($Operation -eq 'enroll'){
 if($account -or (Test-Path -LiteralPath (Join-Path $root 'enroll-started.json')) -or @(Get-LocalUser -Name AiwStandardUser -ErrorAction SilentlyContinue).Count -ne 0){throw 'Existing enrollment refused; recover before another run'}
 $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',$true)
 $password=$null;$secure=$null
 try{
  if($key.GetValueNames() -contains 'DefaultPassword' -or $key.GetValue('AutoAdminLogon') -eq '1'){throw 'Preexisting automatic sign-in refused'}
  Record 'enroll-started' @{runNonce=$request.nonce;temporaryAutomaticSignIn=$true}
  $random=[byte[]]::new(32);$rng=[Security.Cryptography.RandomNumberGenerator]::Create()
  try{$rng.GetBytes($random);$password='Aa9!'+[Convert]::ToBase64String($random)}finally{$rng.Dispose();[Array]::Clear($random,0,$random.Length)}
  $secure=ConvertTo-SecureString $password -AsPlainText -Force
  $user=New-LocalUser -Name AiwStandardUser -Password $secure -AccountExpires ([DateTime]::FromFileTimeUtc($request.notAfterFileTime)) -Description 'Disposable MSIX worker; restore after run'
  $sid=$user.SID.Value
  if($sid -cnotmatch '\AS-1-5-21-3556347314-2314855617-1438300668-[0-9]+\z' -or $sid -ceq $operatorSid){throw 'Unexpected account identity'}
  Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user
  if(@(Get-LocalGroupMember -SID 'S-1-5-32-544'|Where-Object {$_.SID.Value -ceq $sid}).Count -ne 0){throw 'Application user is an administrator'}
  $account=@{userSid=$sid;runNonce=$request.nonce;workerUuid=$request.workerUuid;created=$true}
  Record 'account' $account
  $owned=[Security.AccessControl.DirectorySecurity]::new();$owned.SetAccessRuleProtection($true,$false);$owned.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
  foreach($principal in @('S-1-5-18',$operatorSid)){$owned.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($principal),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
  $owned.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
  Set-Acl -LiteralPath $root -AclObject $owned
  Set-AiwRunInputReadAccess $root $request $sid
  $service=New-Object -ComObject Schedule.Service;$service.Connect();$folder=$service.GetFolder('\')
  $task=$service.NewTask(0);$task.Principal.UserId='S-1-5-18';$task.Principal.LogonType=5;$task.Principal.RunLevel=1
  $task.Settings.ExecutionTimeLimit='PT1M';$task.Settings.DisallowStartIfOnBatteries=$false;$task.Settings.StopIfGoingOnBatteries=$false
  $trigger=$task.Triggers.Create(9);$trigger.UserId=$sid
  $expiry=$task.Triggers.Create(1);$expiry.StartBoundary=[DateTime]::FromFileTimeUtc($request.notAfterFileTime).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
  $action=$task.Actions.Create(0);$action.Path=Join-Path $root 'agent.exe';$action.Arguments='clear-logon '+$request.runId
  $null=$folder.RegisterTaskDefinition(('AIW-Msix-ClearLogon-'+$request.runId),$task,0x12,'S-1-5-18',$null,5,'O:SYG:SYD:P(A;;FA;;;SY)')
  $key.SetValue('DefaultUserName','AiwStandardUser');$key.SetValue('DefaultDomainName',$env:COMPUTERNAME)
  $key.SetValue('DefaultPassword',$password);$key.SetValue('AutoLogonCount',1,[Microsoft.Win32.RegistryValueKind]::DWord);$key.SetValue('AutoAdminLogon','1')
  Record 'enroll-result' @{runNonce=$request.nonce;userSid=$sid;restartRequired=$true;credentialsExported=$false}
 }finally{$password=$null;if($secure){$secure.Dispose()};$key.Dispose()}
 return
}
if($Operation -eq 'clear-logon'){Clear-AiwLogon;return}
if(!$account){throw 'Run-owned application account required'}
Assert-AiwRunInputAccess $root $request $account.userSid
if($Operation -eq 'prepare'){
 Clear-AiwLogon
 $sessions=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'"|Where-Object{(Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid).Sid -ceq $account.userSid}|Select-Object -ExpandProperty SessionId -Unique)
 if($sessions.Count -ne 1 -or $sessions[0] -le 0){throw 'Actual unique standard-user Explorer session required'}
 Record 'session' @{userSid=$account.userSid;sessionId=$sessions[0];runNonce=$request.nonce}
 return
}
# C# process observer and inventory function are inserted from fixed compiled
# sources by the native agent. No script body comes from the request.
$packages=@(Get-AppxPackage -AllUsers -Name AIWResearch.NotepadPP|Select-Object PackageFullName,PackageUserInformation,InstallLocation)
$provisioned=@(Get-AppxProvisionedPackage -Online|Where-Object DisplayName -ceq AIWResearch.NotepadPP|Select-Object PackageName)
$processes=Get-AiwPackageProcessInventory
Record ('inventory-'+$Operation) @{workerUuid=$uuid;runNonce=$request.nonce;packages=$packages;provisioned=$provisioned;processes=$processes;observerSid=$identity.User.Value;observerSessionId=0}
if($packages.Count -ne 0 -or $provisioned.Count -ne 0 -or $processes.matches.Count -ne 0 -or $processes.queryErrors.Count -ne 0){throw 'Privileged package/process absence was not verified'}
