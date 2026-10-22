# Controller-only recovery. Never prints the generated password or private key.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$directory='C:\passkeys\worker106-tools\worker-admin-recovery'
$receiptPath='C:\passkeys\worker106-tools\preparation-result.json'
if ((Get-CimInstance Win32_ComputerSystemProduct).UUID -ieq '7e686bee-8c05-43c7-9603-a9562ece224c') {throw 'Run on controller only'}
$receipt=Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
if ($receipt.ExitCode -ne 0) {throw 'Guest preparation did not succeed; use protected state recovery instead'}
$journal=$receipt.Output[0] | ConvertFrom-Json
if ($journal.phase -cne 'finished' -or $journal.result.exitcode -ne 0 -or $journal.result.'out-truncated') {throw 'Preparation receipt incomplete'}
$state=$journal.result.'out-data' | ConvertFrom-Json
if ($state.VmUuid -ine '7e686bee-8c05-43c7-9603-a9562ece224c' -or $state.AdminName -cne 'AiwWorkerAdmin' -or $state.Phase -cne 'PreparedAwaitingReboot' -or -not $state.CredentialLogonValidated) {throw 'Unexpected preparation state'}
$keyPath=Join-Path $directory 'recovery-key.dpapi'
$target=Join-Path $directory 'worker-admin.credential.clixml'
if (Test-Path -LiteralPath $target) {throw 'Preserve existing recovered credential'}
$private=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($keyPath),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
$rsa=[Security.Cryptography.RSA]::Create()
$plain=$null;$secure=$null
try {
    $read=0;$rsa.ImportPkcs8PrivateKey($private,[ref]$read)
    $plain=$rsa.Decrypt([Convert]::FromBase64String($state.CredentialCiphertext),[Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    $secure=ConvertTo-SecureString ([Text.Encoding]::UTF8.GetString($plain)) -AsPlainText -Force
    [Management.Automation.PSCredential]::new('PASSKEYS-WORKER\AiwWorkerAdmin',$secure) | Export-Clixml -LiteralPath $target -Encoding UTF8
    [ordered]@{CredentialStored=$true;Storage='DPAPI CurrentUser';PasswordPrinted=$false;Path=$target} | ConvertTo-Json
} finally {
    $rsa.Dispose()
    [Array]::Clear($private,0,$private.Length)
    if ($null -ne $plain) {[Array]::Clear($plain,0,$plain.Length)}
    if ($null -ne $secure) {$secure.Dispose()}
}
