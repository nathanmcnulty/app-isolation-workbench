. 'C:\AIW-Worker-Setup\msix-vm106-staging\msix-primary-preparation.ps1'
$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ne 'PASSKEYS-WORKER' -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18' -or [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0 -or $null -ne [Security.Principal.WindowsIdentity]::GetCurrent($true)){throw 'Pinned unimpersonated SYSTEM required'}
$marker='C:\AIW-VM106-Baseline.json'
if((Get-FileHash $marker).Hash.ToLowerInvariant() -cne '1e6f9990e50a90601395dc7f0e0b216481388c98a43a748962bbc92e296eb41a'){throw 'Baseline marker differs'}
$created=Get-Content -LiteralPath 'C:\AIW-Msix-Primary-Account-VM106-r1\created.json' -Raw|ConvertFrom-Json
$ready=Get-Content -LiteralPath 'C:\AIW-Msix-Primary-Account-VM106-r1\ready.json' -Raw|ConvertFrom-Json
$sid='@@USER_SID@@'
if(!$created.accountCreated -or $created.userSid -cne $sid -or $ready.userSid -cne $sid -or $created.runNonce -cne $ready.runNonce -or $created.vmId -cne '7e686bee-8c05-43c7-9603-a9562ece224c'){throw 'Owned account receipts differ'}
$user=Get-LocalUser AiwStandardUser;if(!$user.Enabled -or $user.SID.Value -cne $sid){throw 'Owned user differs'}
$groups=@(Get-LocalGroup|Where-Object {@(Get-LocalGroupMember -Group $_ -ErrorAction Stop|Where-Object {$_.SID.Value -ceq $sid}).Count -gt 0}|ForEach-Object {$_.SID.Value}|Sort-Object)
if(($groups -join ',') -cne 'S-1-5-32-545,S-1-5-32-555'){throw 'Local membership differs'}
if(!(Test-Path -LiteralPath ('Registry::HKEY_USERS\'+$sid)) -or !(Test-Path -LiteralPath 'C:\Users\AiwStandardUser')){throw 'Actual interactive profile required'}
$shells=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'"|Where-Object {(Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid -ErrorAction Stop).Sid -ceq $sid})
if($shells.Count -ne 1 -or $shells[0].SessionId -le 0){throw 'Unique real owned shell required'}
if(@(Get-AppxPackage -AllUsers -Name AIWResearch.NotepadPP).Count -ne 0){throw 'Existing package forbidden'}
$input='C:\AIW-Msix-Lifecycle-Input';$output='C:\AIW-Msix-Lifecycle-Output';$prep='C:\AIW-Msix-Lifecycle-Preparation.json'
foreach($dir in @($input,$output)){$item=Get-Item -LiteralPath $dir -Force;if(!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Fixed directory identity differs'}}
if(Test-Path $prep){throw 'Refuse existing preparation'}
if(@(Get-ChildItem -LiteralPath $output -Force).Count -ne 0){throw 'Output not fresh'}
$expected=@{'application.msix'='2ae3a7c685e811eb34479980bff41d1442b023578074e19f4dca8fc676070437';'assembly.json'='d7eca3af76598534d29e411b4d4775d61e6ffe11174aa5a171b44bfe2a080c38';'signing.json'='670e6f9e44211848c305c61261aa2ed6e2c94fac229214ec843cd4c9afab9e80';'msix_standard_user_lifecycle.exe'='442265d9c40fefade23ccbe9db90d10058d0969643d52eb8854aa65fb921b1ca'}
$files=@(Get-ChildItem -LiteralPath $input -Force);if($files.Count -ne 4){throw 'Input inventory differs'}
foreach($file in $files){if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or !$expected.ContainsKey($file.Name) -or (Get-FileHash -LiteralPath $file.FullName).Hash.ToLowerInvariant() -cne $expected[$file.Name]){throw 'Input bytes differ'}}
foreach($dir in @($input,$output)){
 $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
 foreach($principal in @('S-1-5-18','S-1-5-21-3849540285-1795134874-2442050430-1006')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($principal),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
 $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'));Set-Acl -LiteralPath $dir -AclObject $acl
}
$now=[DateTime]::UtcNow;$before=[DateTime]::FromFileTimeUtc([int64]$created.notBeforeFileTime);$after=$before.AddMinutes(30);if($now -lt $before -or $now -gt $after){throw 'Owned creation and login window expired; restore boundary'}
$record=New-AiwMsixPrimaryPreparation -CreatedAccount $created -SessionId ([uint32]$shells[0].SessionId) -SourceImageSha256 $expected['msix_standard_user_lifecycle.exe'] -NowFileTime ($now.ToFileTimeUtc())
$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Compress));$stream=[IO.FileStream]::new($prep,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
$acl=[Security.AccessControl.FileSecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
foreach($principal in @('S-1-5-18','S-1-5-21-3849540285-1795134874-2442050430-1006')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($principal),'FullControl','Allow'))}
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'ReadAndExecute','Allow'));Set-Acl -LiteralPath $prep -AclObject $acl
@{prepared=$record;shellPid=$shells[0].ProcessId;preparationSha256=(Get-FileHash -LiteralPath $prep).Hash.ToLowerInvariant();applicationExecuted=$false}|ConvertTo-Json -Depth 5 -Compress
