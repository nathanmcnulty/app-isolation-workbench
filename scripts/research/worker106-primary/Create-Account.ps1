# Fixed ephemeral standard-user account and one-time console sign-in.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if((Get-CimInstance Win32_ComputerSystemProduct).UUID -ine '7e686bee-8c05-43c7-9603-a9562ece224c' -or $env:COMPUTERNAME -cne 'PASSKEYS-WORKER' -or
   [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or (Get-Process -Id $PID).SessionId -ne 0){throw 'Pinned SYSTEM worker required'}
$staging='C:\AIW-Worker-Setup\msix-vm106-staging'
. (Join-Path $staging 'msix-primary-preparation.ps1')
. (Join-Path $staging 'Worker106-AutologonSecret.ps1')
$root='C:\AIW-Msix-Primary-Account-VM106-r1'
$winlogon='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if(Get-LocalUser AiwStandardUser -ErrorAction SilentlyContinue){throw 'Existing account; do not adopt'}
if((Test-Path C:\Users\AiwStandardUser) -or (Test-Path $root)){throw 'Existing profile/account stage; preserve it'}
if(@(Get-AppxPackage -AllUsers -Name AIWResearch.NotepadPP).Count){throw 'Existing application registration'}
if((Get-FileHash C:\AIW-VM106-Baseline.json).Hash.ToLowerInvariant() -cne '1e6f9990e50a90601395dc7f0e0b216481388c98a43a748962bbc92e296eb41a'){throw 'Baseline marker differs'}
if([Aiw.Research.Worker106AutologonSecret]::Exists()){throw 'Existing autologon secret; refuse overwrite'}
$properties=Get-ItemProperty -LiteralPath $winlogon
if($properties.PSObject.Properties['DefaultPassword'] -or ($properties.PSObject.Properties['AutoAdminLogon'] -and $properties.AutoAdminLogon -eq '1')){throw 'Existing automatic logon configuration'}
$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
foreach($sid in @('S-1-5-18','S-1-5-21-3849540285-1795134874-2442050430-1006')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
[IO.Directory]::CreateDirectory($root,$acl)|Out-Null
function Record([string]$Name,$Value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 7 -Compress));$file=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}}
$before=@{}
foreach($name in @('DefaultUserName','DefaultDomainName','AutoAdminLogon','AutoLogonCount')){
 $property=$properties.PSObject.Properties[$name]
 $before[$name]=@{exists=($null -ne $property);value=if($property){$property.Value}else{$null};kind=if($property){(Get-Item -LiteralPath $winlogon).GetValueKind($name).ToString()}else{$null}}
}
Record 'winlogon-before.json' $before
$nonce=New-AiwMsixPrimaryNonce
$account=[ordered]@{schemaVersion='aiw.dev/research-primary-account/v1';vmId='7e686bee-8c05-43c7-9603-a9562ece224c';runNonce=$nonce;accountName='AiwStandardUser';accountCreated=$false;notBeforeFileTime=[DateTime]::UtcNow.AddSeconds(-5).ToFileTimeUtc();snapshotName='aiw-vm106-baseline-20261021'}
Record 'request.json' $account
$random=[byte[]]::new(24);$rng=[Security.Cryptography.RandomNumberGenerator]::Create();$rsa=[Security.Cryptography.RSACng]::new();$plain=$null;$secure=$null;$secretStored=$false
try {
 if((Get-FileHash -LiteralPath (Join-Path $staging 'recovery-public-key.json')).Hash.ToLowerInvariant() -cne '5b72fe15997cf704ce3c52dc7b9af666f90588cd46871c795b066a02a94f1d2d'){throw 'Recovery public key differs'}
 $public=Get-Content -LiteralPath (Join-Path $staging 'recovery-public-key.json') -Raw|ConvertFrom-Json
 $parameters=[Security.Cryptography.RSAParameters]::new();$parameters.Modulus=[Convert]::FromBase64String($public.Modulus);$parameters.Exponent=[Convert]::FromBase64String($public.Exponent);$rsa.ImportParameters($parameters)
 $rng.GetBytes($random);$plain='Aiw!'+[Convert]::ToBase64String($random);$secure=ConvertTo-SecureString $plain -AsPlainText -Force
 $created=New-LocalUser -Name AiwStandardUser -Password $secure -AccountExpires ([DateTime]::FromFileTimeUtc($account.notBeforeFileTime).AddMinutes(30)) -PasswordNeverExpires -Description 'Owned VM106 primary MSIX research trial'
 $sid=$created.SID.Value
 if($sid -cnotmatch '^S-1-5-21-3849540285-1795134874-2442050430-[0-9]+$' -or $sid -ceq 'S-1-5-21-3849540285-1795134874-2442050430-1006'){throw 'Created account SID differs'}
 $account.accountCreated=$true;$account.userSid=$sid
 Record 'created.json' $account
 foreach($group in @('S-1-5-32-545','S-1-5-32-555')){if(@(Get-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new($group))|Where-Object{$_.SID.Value -ceq $sid}).Count -eq 0){Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new($group)) -Member $created}}
 $groups=@(Get-LocalGroup|Where-Object{@(Get-LocalGroupMember -Group $_|Where-Object{$_.SID.Value -ceq $sid}).Count}|ForEach-Object{$_.SID.Value}|Sort-Object)
 if(($groups -join ',') -cne 'S-1-5-32-545,S-1-5-32-555'){throw 'Standard-user memberships differ'}
 Record 'credential-recovery.json' @{userSid=$sid;algorithm='RSA-OAEP-SHA256';ciphertext=[Convert]::ToBase64String($rsa.Encrypt([Text.Encoding]::UTF8.GetBytes($plain),[Security.Cryptography.RSAEncryptionPadding]::OaepSHA256))}
 $secretStored=$true;[Aiw.Research.Worker106AutologonSecret]::Store($plain)
 New-ItemProperty -LiteralPath $winlogon -Name DefaultUserName -Value AiwStandardUser -PropertyType String -Force|Out-Null
 New-ItemProperty -LiteralPath $winlogon -Name DefaultDomainName -Value PASSKEYS-WORKER -PropertyType String -Force|Out-Null
 New-ItemProperty -LiteralPath $winlogon -Name AutoLogonCount -Value 1 -PropertyType DWord -Force|Out-Null
 New-ItemProperty -LiteralPath $winlogon -Name AutoAdminLogon -Value '1' -PropertyType String -Force|Out-Null
 Record 'ready.json' @{vmId=$account.vmId;userSid=$sid;runNonce=$nonce;accountCreated=$true;groups=$groups;autologon='one-console-logon; LSA secret; no plaintext registry value'}
 $account|ConvertTo-Json -Compress
} catch {
 if($secretStored){[Aiw.Research.Worker106AutologonSecret]::Delete();Set-ItemProperty -LiteralPath $winlogon -Name AutoAdminLogon -Value '0'}
 Record 'failure.json' @{error=$_.Exception.ToString();recovery='Retain evidence and restore VM106 baseline; do not recreate/adopt account'}
 throw
} finally {$rsa.Dispose();$rng.Dispose();[Array]::Clear($random,0,$random.Length);$plain=$null;if($secure){$secure.Dispose()}}
