$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if((Get-CimInstance Win32_ComputerSystemProduct).UUID -ine '7e686bee-8c05-43c7-9603-a9562ece224c' -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18'){throw 'Pinned SYSTEM required'}
$root='C:\AIW-Msix-Primary-Account-VM106-r1'
$account=Get-Content -LiteralPath (Join-Path $root created.json) -Raw|ConvertFrom-Json
$shells=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'"|Where-Object{(Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid).Sid -ceq $account.userSid})
if($shells.Count -ne 1 -or $shells[0].SessionId -le 0){throw 'Actual standard-user Explorer sign-in required before clearing automatic logon'}
. 'C:\AIW-Worker-Setup\msix-vm106-staging\Worker106-AutologonSecret.ps1'
$path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if((Get-ItemProperty -LiteralPath $path -Name DefaultUserName).DefaultUserName -cne 'AiwStandardUser'){throw 'Automatic logon identity changed'}
[Aiw.Research.Worker106AutologonSecret]::Delete()
$before=Get-Content -LiteralPath (Join-Path $root winlogon-before.json) -Raw|ConvertFrom-Json
foreach($entry in $before.PSObject.Properties){
 if($entry.Value.exists){New-ItemProperty -LiteralPath $path -Name $entry.Name -Value $entry.Value.value -PropertyType $entry.Value.kind -Force|Out-Null}
 else{Remove-ItemProperty -LiteralPath $path -Name $entry.Name -ErrorAction SilentlyContinue}
}
if([Aiw.Research.Worker106AutologonSecret]::Exists() -or (Get-ItemProperty -LiteralPath $path).PSObject.Properties['DefaultPassword']){throw 'Automatic logon cleanup incomplete'}
[ordered]@{autologonSecretAbsent=$true;registryRestored=$true;userSid=$account.userSid;shellPid=$shells[0].ProcessId;sessionId=$shells[0].SessionId}|ConvertTo-Json -Compress
