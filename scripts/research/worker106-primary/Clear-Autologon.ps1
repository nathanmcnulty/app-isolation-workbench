param([ValidateSet('AfterLogin','Recovery')][string]$Mode='AfterLogin')
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if((Get-CimInstance Win32_ComputerSystemProduct).UUID -ine '7e686bee-8c05-43c7-9603-a9562ece224c' -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or (Get-Process -Id $PID).SessionId -ne 0 -or $null -ne [Security.Principal.WindowsIdentity]::GetCurrent($true)){throw 'Pinned unimpersonated SYSTEM session zero required'}
$root='C:\AIW-Msix-Primary-Account-VM106-r1'
$account=Get-Content -LiteralPath (Join-Path $root created.json) -Raw|ConvertFrom-Json
$intent=Get-Content -LiteralPath (Join-Path $root autologon-intent.json) -Raw|ConvertFrom-Json
if($intent.vmId -cne '7e686bee-8c05-43c7-9603-a9562ece224c' -or !$intent.existingSecretAbsent -or $intent.userSid -cne $account.userSid -or $intent.runNonce -cne $account.runNonce -or (Get-LocalUser AiwStandardUser).SID.Value -cne $account.userSid){throw 'Owned automatic logon intent differs'}
$path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$before=Get-Content -LiteralPath (Join-Path $root winlogon-before.json) -Raw|ConvertFrom-Json
$current=(Get-ItemProperty -LiteralPath $path).PSObject.Properties['DefaultUserName']
if($current -and $current.Value -cne 'AiwStandardUser' -and $current.Value -cne $before.DefaultUserName.value){throw 'Automatic logon identity changed'}
$errors=@();$observationError=$null;$shells=@();$interactive=$false;$secretAbsent=$false;$registryRestored=$true
if($Mode -eq 'AfterLogin'){
 try{$shells=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'"|Where-Object{(Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid).Sid -ceq $account.userSid});$interactive=($shells.Count -eq 1 -and $shells[0].SessionId -gt 0)}catch{$observationError=$_.Exception.ToString()}
}
# Disable automatic logon, delete the secret and restore every public field as
# independent operations: failure in one must not skip the remaining cleanup.
try{Set-ItemProperty -LiteralPath $path -Name AutoAdminLogon -Value '0' -ErrorAction Stop}catch{$errors += $_.Exception.ToString()}
try{. 'C:\AIW-Worker-Setup\msix-vm106-staging\Worker106-AutologonSecret.ps1';[Aiw.Research.Worker106AutologonSecret]::Delete()}catch{$errors += $_.Exception.ToString()}
foreach($entry in $before.PSObject.Properties){
 try{
 if($entry.Value.exists){New-ItemProperty -LiteralPath $path -Name $entry.Name -Value $entry.Value.value -PropertyType $entry.Value.kind -Force|Out-Null}
 elseif((Get-ItemProperty -LiteralPath $path).PSObject.Properties[$entry.Name]){Remove-ItemProperty -LiteralPath $path -Name $entry.Name -ErrorAction Stop}
 }catch{$errors += $_.Exception.ToString()}
}
foreach($entry in $before.PSObject.Properties){
 try{
 $actual=(Get-ItemProperty -LiteralPath $path).PSObject.Properties[$entry.Name]
 if($entry.Value.exists){
  if(!$actual -or (Get-Item -LiteralPath $path).GetValueKind($entry.Name).ToString() -cne $entry.Value.kind -or
     (ConvertTo-Json -InputObject $actual.Value -Compress) -cne (ConvertTo-Json -InputObject $entry.Value.value -Compress)){throw 'Restored registry value/type differs'}
 } elseif($actual){throw 'Restored registry absence differs'}
 }catch{$registryRestored=$false;$errors += $_.Exception.ToString()}
}
try{$secretAbsent=![Aiw.Research.Worker106AutologonSecret]::Exists();if(!$secretAbsent -or (Get-ItemProperty -LiteralPath $path).PSObject.Properties['DefaultPassword']){throw 'Automatic logon secret cleanup incomplete'}}catch{$errors += $_.Exception.ToString()}
$result=[ordered]@{autologonSecretAbsent=$secretAbsent;registryRestored=$registryRestored;cleanupErrors=$errors;observationError=$observationError;userSid=$account.userSid;interactiveVerified=$interactive;mode=$Mode;shellPid=if($interactive){$shells[0].ProcessId}else{$null};sessionId=if($interactive){$shells[0].SessionId}else{$null}}
$result|ConvertTo-Json -Compress
if($errors.Count){throw 'Automatic logon cleanup incomplete; inspect aggregate result and restore baseline'}
if($Mode -eq 'AfterLogin' -and (!$interactive -or $observationError)){throw 'Automatic logon cleanup completed; actual standard-user Explorer sign-in is missing'}
