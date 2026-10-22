$ErrorActionPreference='Stop'
$nonce='@@NONCE@@'
$root='C:\AIW-Task-Primary-'+$nonce
$name='AIW-Task-Primary-'+$nonce
$operator='S-1-5-21-3849540285-1795134874-2442050430-1006'
$taskPath='\'+$name
function Publish([string]$name,$value){
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 8 -Compress))
 $file=[IO.File]::Open(($root+'\'+$name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
}
function Read-Record([string]$name){
 $path=$root+'\'+$name
 if(([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse record'}
 $held=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{if($held.Length -gt 8192){throw 'Record exceeds bound'};$reader=[IO.StreamReader]::new($held,[Text.UTF8Encoding]::new($false,$true));try{return ($reader.ReadToEnd()|ConvertFrom-Json)}finally{$reader.Dispose()}}finally{$held.Dispose()}
}
if($env:COMPUTERNAME -cne 'PASSKEYS-WORKER' -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18'){throw 'Dedicated SYSTEM worker required'}
$vm=Get-CimInstance Win32_ComputerSystemProduct
if($vm.UUID -ine '7e686bee-8c05-43c7-9603-a9562ece224c'){throw 'Wrong Proxmox worker'}
$adapters=@(Get-NetAdapter -Physical);if($adapters.Count -ne 1 -or $adapters[0].MacAddress -ine 'CC-34-21-7E-FE-59'){throw 'Wrong worker adapter'}
$meta=@{vmId=$vm.UUID.ToLowerInvariant()}

if($meta.vmId -cne '7e686bee-8c05-43c7-9603-a9562ece224c'){throw 'Wrong VM'}
if((Get-FileHash 'C:\AIW-VM106-Baseline.json').Hash.ToLowerInvariant() -cne '1e6f9990e50a90601395dc7f0e0b216481388c98a43a748962bbc92e296eb41a'){throw 'Baseline identity differs'}
if(Test-Path -LiteralPath $root){throw 'Fresh stage required'}
if(([IO.File]::GetAttributes('C:\') -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse root'}
$service=New-Object -ComObject 'Schedule.Service';$service.Connect();$folder=$service.GetFolder('\')
if(@($folder.GetTasks(1)|Where-Object {$_.Name -ceq $name}).Count -ne 0){throw 'Task already exists'}

if(Test-Path -LiteralPath 'C:\AIW-Msix-Lifecycle-Output\standard-user-lifecycle'){throw 'Fresh native evidence required'}
[IO.Directory]::CreateDirectory($root)|Out-Null
$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'));$acl.SetAccessRuleProtection($true,$false)
foreach($sid in @('S-1-5-18',$operator)){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
Set-Acl -LiteralPath $root -AclObject $acl
$workerBytes=[Convert]::FromBase64String('@@WORKER_B64@@')
$workerPath=$root+'\worker.ps1'
$f=[IO.File]::Open($workerPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($workerBytes,0,$workerBytes.Length);$f.Flush($true)}finally{$f.Dispose()}
$workerHeld=[IO.File]::Open($workerPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
$xmlHeld=$null;$registered=$null;$running=$null;$actionHeld=$null;$clean=$false;$actionVerified=$false;$nativeHeld=$null;$nativeExitConfirmed=$false
$ps='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$workerPath+'"'
$privileges=@('SeTcbPrivilege','SeAssignPrimaryTokenPrivilege','SeIncreaseQuotaPrivilege','SeImpersonatePrivilege','SeChangeNotifyPrivilege')
$xml=@"
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
 <RegistrationInfo><Description>AIW fixed context observation $nonce</Description></RegistrationInfo><Triggers />
 <Principals><Principal id="AiwSystem"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
 <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>false</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT260S</ExecutionTimeLimit><Priority>7</Priority></Settings>
 <Actions Context="AiwSystem"><Exec><Command>$ps</Command><Arguments>$arguments</Arguments><WorkingDirectory>$root</WorkingDirectory></Exec></Actions>
</Task>
"@

$definition=$service.NewTask(0);$definition.XmlText=$xml
$definition.Principal.UserId='S-1-5-18';$definition.Principal.LogonType=5;$definition.Principal.RunLevel=1;$definition.Principal.Id='AiwSystem';$definition.Actions.Context='AiwSystem'
$xml=$definition.XmlText

function Verify-Definition($definition){
 if($definition.Principal.LogonType -ne 5){throw 'Service-account COM logon differs'}
 [xml]$doc=$definition.XmlText;$ns=[Xml.XmlNamespaceManager]::new($doc.NameTable);$ns.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task')
 $expected=@{'/t:Task/t:Principals/t:Principal/t:UserId'='S-1-5-18';'/t:Task/t:Actions/t:Exec/t:Command'=$ps;'/t:Task/t:Actions/t:Exec/t:Arguments'=$arguments;'/t:Task/t:Actions/t:Exec/t:WorkingDirectory'=$root;'/t:Task/t:Settings/t:MultipleInstancesPolicy'='IgnoreNew';'/t:Task/t:Settings/t:AllowHardTerminate'='true';'/t:Task/t:Settings/t:AllowStartOnDemand'='true';'/t:Task/t:Settings/t:ExecutionTimeLimit'='PT260S';'/t:Task/t:Settings/t:StartWhenAvailable'='false';'/t:Task/t:Settings/t:WakeToRun'='false';'/t:Task/t:Settings/t:RunOnlyIfIdle'='false';'/t:Task/t:Settings/t:RunOnlyIfNetworkAvailable'='false';'/t:Task/t:Settings/t:Enabled'='true'}
 foreach($key in $expected.Keys){$node=$doc.SelectSingleNode($key,$ns);if(!$node -or $node.InnerText -cne $expected[$key]){throw ('Task field differs: '+$key)}}
 foreach($query in @('/t:Task/t:Triggers/*','/t:Task/t:Settings/t:RestartOnFailure','/t:Task/t:Principals/t:Principal/t:ProcessTokenSidType','/t:Task/t:Principals/t:Principal/t:LogonType','/t:Task/t:Principals/t:Principal/t:RequiredPrivileges')){if($doc.SelectNodes($query,$ns).Count -ne 0){throw 'Unexpected task authority'}}
 if($doc.SelectNodes('/t:Task/t:Actions/*',$ns).Count -ne 1 -or $doc.SelectNodes('/t:Task/t:Principals/*',$ns).Count -ne 1){throw 'Unexpected action/principal count'}
 $actual=@($doc.SelectNodes('/t:Task/t:Principals/t:Principal/t:RequiredPrivileges/t:Privilege',$ns)|ForEach-Object {$_.InnerText})
 if($actual.Count -ne 0){throw 'Default task privileges required for observation'}
}
function Verify-Task($task){
 if($task.Path -cne $taskPath){throw 'Task path differs'}
 Verify-Definition $task.Definition
 $sd=[Security.AccessControl.RawSecurityDescriptor]::new($task.GetSecurityDescriptor(7))
 if($sd.Owner.Value -cne 'S-1-5-18' -or $sd.DiscretionaryAcl.Count -ne 2){throw 'Task security differs'}
 $sids=@();foreach($ace in $sd.DiscretionaryAcl){if($ace.AceQualifier -ne 'AccessAllowed' -or $ace.AceFlags -ne 'None' -or $ace.AccessMask -ne 0x1f01ff){throw 'Task access differs'};$sids+=$ace.SecurityIdentifier.Value}
 if(($sids|Sort-Object) -join ',' -cne ((@('S-1-5-18',$operator)|Sort-Object) -join ',')){throw 'Task principals differ'}
}

Add-Type -TypeDefinition @'
using System;using System.ComponentModel;using System.Runtime.InteropServices;using System.Security.Principal;
public static class AiwNativeTokenIdentity {
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
 public static string Sid(IntPtr process){IntPtr token;if(!OpenProcessToken(process,8,out token))throw new Win32Exception(Marshal.GetLastWin32Error());try{using(var identity=new WindowsIdentity(token)){return identity.User.Value;}}finally{if(!CloseHandle(token))throw new Win32Exception(Marshal.GetLastWin32Error());}}
}
'@
function Bind-Native {
 if($script:nativeHeld){return}
 $path='C:\AIW-Msix-Primary-Control-Controller-VM106-r1\started.json'
 if(!(Test-Path -LiteralPath $path)){return}
 $info=Get-Item -LiteralPath $path -Force
 if($info.PSIsContainer -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $info.Length -gt 4096){throw 'Native start record outside bound'}
 $record=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
 if($record.runNonce -cne $nonce -or !$record.heldProcess -or $record.pid -le 0){throw 'Native start binding differs'}
 $candidate=[Diagnostics.Process]::GetProcessById($record.pid);$null=$candidate.Handle
 try {
  if($candidate.StartTime.ToUniversalTime().ToString('o') -cne $record.startTimeUtc -or $candidate.MainModule.FileName -ine 'C:\AIW-Msix-Lifecycle-Input\msix_standard_user_lifecycle.exe' -or $candidate.SessionId -ne 0 -or [AiwNativeTokenIdentity]::Sid($candidate.Handle) -cne 'S-1-5-18'){throw 'Native exact process identity differs'}
  $script:nativeHeld=$candidate
 } catch {$candidate.Dispose();throw}
}

try {
 Publish 'request.json' @{schemaVersion='aiw.dev/research-task-request/v1';nonce=$nonce;vmId=$meta.vmId;taskPath=$taskPath;workerSha256=(Get-FileHash $workerPath).Hash.ToLowerInvariant();observationOnly=$false;nativePrimaryControlOnly=$true;applicationLaunchAttempted=$false}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes($xml);$f=[IO.File]::Open(($root+'\task.xml'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
 $xmlHeld=[IO.File]::Open(($root+'\task.xml'),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 $sddl='O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;'+$operator+')'
 # Create only; do not let Scheduler append an unreviewed principal ACE.

 Verify-Definition $definition
 $validation=$folder.RegisterTaskDefinition($name,$definition,1,'S-1-5-18',$null,5,$sddl)
 if($validation -or @($folder.GetTasks(1)|Where-Object {$_.Name -ceq $name}).Count -ne 0){throw 'Validate-only unexpectedly registered a task'}
 $generatedBytes=[Text.UTF8Encoding]::new($false).GetBytes($definition.XmlText)
 $hash=[Security.Cryptography.SHA256]::Create();try{$generatedHash=([BitConverter]::ToString($hash.ComputeHash($generatedBytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
 if($generatedHash -cne (Get-FileHash ($root+'\task.xml')).Hash.ToLowerInvariant()){throw 'Validated definition changed'}
 Verify-Definition $definition
 Publish 'validation.json' @{nonce=$nonce;validationOnly=$true;registered=$false;generatedXmlSha256=$generatedHash}
 $registered=$folder.RegisterTaskDefinition($name,$definition,0x12,'S-1-5-18',$null,5,$sddl)

 Verify-Task $registered
 Publish 'registration.json' @{nonce=$nonce;xml=$registered.Xml;sddl=$registered.GetSecurityDescriptor(7);sourceXmlSha256=(Get-FileHash ($root+'\task.xml')).Hash.ToLowerInvariant()}
 if($registered.GetInstances(0).Count -ne 0){throw 'Unexpected existing instance'}
 Publish 'start-request.json' @{nonce=$nonce;requestedUtc=[DateTime]::UtcNow.ToString('o');parametersCount=0;flags=0}
 $running=$registered.RunEx($null,0,0,$null)
 Publish 'instance.json' @{nonce=$nonce;instanceGuid=$running.InstanceGuid;enginePid=$running.EnginePID;taskPath=$running.Path}
 $deadline=[DateTime]::UtcNow.AddSeconds(210)
 while(!(Test-Path ($root+'\started.json')) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 100}
 if(!(Test-Path ($root+'\started.json'))){throw 'Task never published start identity'}
 $started=Read-Record 'started.json'
 if($started.nonce -cne $nonce -or $started.sid -cne 'S-1-5-18' -or $started.sessionId -ne 0 -or $started.image -ine $ps){throw 'Action identity differs'}
 $actionHeld=[Diagnostics.Process]::GetProcessById($started.pid);$null=$actionHeld.Handle
 if($actionHeld.StartTime.ToUniversalTime().ToString('o') -cne $started.startedUtc -or $actionHeld.MainModule.FileName -ine $ps -or $actionHeld.SessionId -ne 0){throw 'Action generation differs'}
 $actionVerified=$true
 $instances=$registered.GetInstances(0)
 if($instances.Count -ne 1 -or $instances.Item(1).InstanceGuid -cne $running.InstanceGuid){throw 'Task instance differs'}
 while(!$actionHeld.HasExited -and [DateTime]::UtcNow -lt $deadline){Bind-Native;Start-Sleep -Milliseconds 100;$actionHeld.Refresh()}
 Bind-Native
 if(!$actionHeld.HasExited){throw 'Action deadline exceeded'}
 if(!$nativeHeld){throw 'Exact native process custody was not acquired'}
 if($actionHeld.ExitCode -ne 0){throw 'Action failed; inspect retained failure'}
 $result=Read-Record 'result.json';$observation=Read-Record 'observation.json'
 if($result.nonce -cne $nonce -or $result.pid -ne $started.pid -or !$result.contextObserved -or $result.applicationLaunchAttempted -or $observation.nonce -cne $nonce -or $observation.pid -ne $started.pid){throw 'Terminal binding differs'}
 if($observation.schemaVersion -cne 'aiw.dev/research-task-context/v1' -or $observation.context.inAnyJob -isnot [bool] -or $observation.context.threadNotImpersonating -isnot [bool] -or !$observation.context.threadNotImpersonating){throw 'Context record malformed'}
 $records=@($observation.context.privileges)
 if($records.Count -ne $privileges.Count){throw 'Privilege record count differs'}
 $eligible=!$observation.context.inAnyJob
 for($index=0;$index -lt $records.Count;$index++){
  $p=$records[$index]
  if($p.name -cne $privileges[$index]){throw 'Privilege record name differs'}
  foreach($field in @('present','removed','enableRestoreAttempted','enableAndRestorePassed')){if($p.$field -isnot [bool]){throw 'Privilege Boolean malformed'}}
  if(($p.attributes -isnot [int] -and $p.attributes -isnot [long]) -or $p.attributes -lt 0 -or $p.attributes -gt [uint32]::MaxValue){throw 'Privilege attributes malformed'}
  if($p.removed -ne (($p.attributes -band 4) -ne 0)){throw 'Privilege removed state differs'}
  $usable=$p.present -and !$p.removed
  if($p.enableRestoreAttempted -ne $usable -or $p.enableAndRestorePassed -ne $usable){throw 'Privilege operation state differs'}
  $eligible=$eligible -and $usable
 }
 while($registered.GetInstances(0).Count -ne 0 -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 100}
 if($registered.GetInstances(0).Count -ne 0){throw 'Task instance remained'}

 $native=Read-Record 'native-control.json'
 if($native.nonce -cne $nonce -or $native.applicationLaunchAttempted -or $native.wrapper.exitCode -ne 0 -or !$native.wrapper.exited -or $native.wrapper.timedOut -or !$native.result.passed -or $native.result.exitCode -ne 42 -or !$native.result.jobEmpty){throw 'Native receipt binding differs'}
 if($native.wrapper.pid -ne $nativeHeld.Id -or !$nativeHeld.HasExited -or $nativeHeld.ExitCode -ne 0){throw 'Exact native exit differs'}
 $nativeExitConfirmed=$true
 $clean=$true
 Publish 'controller-result.json' @{nonce=$nonce;observation=$observation;actionPid=$started.pid;actionExited=$true;actionExitCode=$actionHeld.ExitCode;enginePid=$running.EnginePID;instanceGuid=$running.InstanceGuid;diagnosticOnly=$false;nativePrimaryControlOnly=$true;nativeControl=$native;nativePrerequisitesMeasuredPresent=$eligible;applicationLaunchAttempted=$false}
} catch {
 $primaryError=$_.Exception.Message;$cleanupErrors=@()
 try{Bind-Native}catch{$cleanupErrors+=('Native binding failed: '+$_.Exception.Message)}
 try{if($running){$running.Stop()};if($actionHeld){$clean=$actionHeld.WaitForExit(10000)}}catch{$cleanupErrors+=('Task stop/exit failed: '+$_.Exception.Message);$clean=$false}
 if($nativeHeld){
  try{if(!$nativeHeld.HasExited){$nativeHeld.Kill()}}catch{$cleanupErrors+=('Native termination failed: '+$_.Exception.Message)}
  try{$nativeExitConfirmed=$nativeHeld.WaitForExit(15000);if(!$nativeExitConfirmed){throw 'Exact native exit unconfirmed'}}catch{$cleanupErrors+=('Native exit wait failed: '+$_.Exception.Message);$nativeExitConfirmed=$false}
 }
 # Missing custody is uncertain, even if the action has exited. Preserve the task
 # and require cold recovery rather than publishing a false native cleanup claim.
 if(!$nativeExitConfirmed){$clean=$false;$cleanupErrors+='Native custody/exit unconfirmed; cold recovery required'}
 Publish 'controller-failure.json' @{nonce=$nonce;error=$primaryError;cleanupErrors=$cleanupErrors;nativeExitConfirmed=$nativeExitConfirmed;fatalCleanupUnconfirmed=(!$nativeExitConfirmed);applicationLaunchAttempted=$false}
 throw ($primaryError+'; cleanup: '+($cleanupErrors -join '; '))
} finally {
 if($registered -and $clean){Verify-Task $registered;if($registered.GetInstances(0).Count -ne 0){throw 'Cannot remove active task'};$folder.DeleteTask($name,0);if(@($folder.GetTasks(1)|Where-Object {$_.Name -ceq $name}).Count -ne 0){throw 'Task cleanup unconfirmed'};Publish 'cleanup.json' @{nonce=$nonce;taskAbsent=$true;instanceAbsent=$true;actionExited=$true;nativeExitConfirmed=$nativeExitConfirmed;retainedStage=$root}}
 if($nativeHeld -and $nativeExitConfirmed){$nativeHeld.Dispose()};if($actionHeld){$actionHeld.Dispose()};if($xmlHeld){$xmlHeld.Dispose()};$workerHeld.Dispose()
}
$answer=@{schemaVersion='aiw.dev/research-task-context-controller/v1';nonce=$nonce;vmId=$meta.vmId;stage=$root;result=(Read-Record 'controller-result.json');cleanup=(Read-Record 'cleanup.json')}|ConvertTo-Json -Depth 9 -Compress
if([Text.Encoding]::UTF8.GetByteCount($answer) -gt 3500){throw 'Result exceeds bound'}
Write-Output $answer
