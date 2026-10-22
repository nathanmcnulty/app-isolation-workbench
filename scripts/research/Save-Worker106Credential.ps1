param([ValidateSet('Prepare','State')][string]$Receipt='Prepare')
# Controller-only recovery. Never prints the generated password or private key.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Assert-Worker106CredentialReceipt([object]$State,[string]$Mode) {
    if ($Mode -notin @('Prepare','State') -or $State.VmUuid -ine '7e686bee-8c05-43c7-9603-a9562ece224c' -or $State.AdminName -cne 'AiwWorkerAdmin' -or $State.AdminSid -cnotmatch '^S-1-5-21-3849540285-1795134874-2442050430-[0-9]+$' -or [Convert]::FromBase64String($State.CredentialCiphertext).Length -ne 384) {throw 'Unexpected credential recovery identity or ciphertext'}
    if ($Mode -eq 'Prepare' -and ($State.Phase -cne 'PreparedAwaitingReboot' -or -not $State.CredentialLogonValidated)) {throw 'Preparation did not reach its successful terminal state'}
    if ($Mode -eq 'State' -and $State.Phase -notin @('AdministratorCreated','FreshAdministratorAndProfileVerified','CopiedSandboxAccountsDisabled','PreparedAwaitingReboot','SetupFailed','Finalized')) {throw 'State does not record account creation; preserve evidence'}
}
$directory='C:\passkeys\worker106-tools\worker-admin-recovery'
$receiptPath=if ($Receipt -eq 'Prepare') {'C:\passkeys\worker106-tools\preparation-result.json'} else {'C:\passkeys\worker106-tools\preparation-state-result.json'}
if ((Get-CimInstance Win32_ComputerSystemProduct).UUID -ieq '7e686bee-8c05-43c7-9603-a9562ece224c') {throw 'Run on controller only'}
$receiptRecord=Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
if ($receiptRecord.ExitCode -ne 0) {throw 'Guest receipt did not succeed; preserve output and collect the fixed State operation for partial setup recovery'}
$journal=$receiptRecord.Output[0] | ConvertFrom-Json
if ($journal.phase -cne 'finished' -or $journal.result.exitcode -ne 0 -or $journal.result.'out-truncated') {throw 'Preparation receipt incomplete'}
$state=$journal.result.'out-data' | ConvertFrom-Json
Assert-Worker106CredentialReceipt $state $Receipt
$keyPath=Join-Path $directory 'recovery-key.dpapi'
$target=Join-Path $directory $(if($Receipt -eq 'Prepare'){'worker-admin.credential.clixml'}else{'worker-admin.partial-recovery.credential.clixml'})
if (Test-Path -LiteralPath $target) {throw 'Preserve existing recovered credential'}
$private=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($keyPath),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
$rsa=[Security.Cryptography.RSA]::Create()
$plain=$null;$secure=$null
try {
    $read=0;$rsa.ImportPkcs8PrivateKey($private,[ref]$read)
    $plain=$rsa.Decrypt([Convert]::FromBase64String($state.CredentialCiphertext),[Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    $secure=ConvertTo-SecureString ([Text.Encoding]::UTF8.GetString($plain)) -AsPlainText -Force
    [Management.Automation.PSCredential]::new('PASSKEYS-WORKER\AiwWorkerAdmin',$secure) | Export-Clixml -LiteralPath $target -Encoding UTF8
    [ordered]@{CredentialStored=$true;Storage='DPAPI CurrentUser';PasswordPrinted=$false;Path=$target;Receipt=$Receipt;CredentialLogonValidated=$state.CredentialLogonValidated;SetupPhase=$state.Phase} | ConvertTo-Json
} finally {
    $rsa.Dispose()
    [Array]::Clear($private,0,$private.Length)
    if ($null -ne $plain) {[Array]::Clear($plain,0,$plain.Length)}
    if ($null -ne $secure) {$secure.Dispose()}
}
