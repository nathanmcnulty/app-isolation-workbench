# Tests only the pure receipt guard with synthetic public bytes; no secrets/files.
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot Save-Worker106Credential.ps1),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Parse failed'}
$f=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-Worker106CredentialReceipt'},$true))
if($f.Count -ne 1){throw 'Unique guard required'}
Invoke-Expression $f[0].Extent.Text
$valid=[pscustomobject]@{VmUuid='7e686bee-8c05-43c7-9603-a9562ece224c';AdminName='AiwWorkerAdmin';AdminSid='S-1-5-21-3849540285-1795134874-2442050430-1004';CredentialCiphertext=[Convert]::ToBase64String((New-Object byte[] 384));Phase='PreparedAwaitingReboot';CredentialLogonValidated=$true}
Assert-Worker106CredentialReceipt $valid Prepare
$partial=$valid | ConvertTo-Json | ConvertFrom-Json
$partial.Phase='SetupFailed';$partial.CredentialLogonValidated=$false
Assert-Worker106CredentialReceipt $partial State
$cases=@(
    {param($o)$o.VmUuid='wrong'}, {param($o)$o.AdminName='labadmin'},
    {param($o)$o.AdminSid='S-1-5-18'}, {param($o)$o.CredentialCiphertext='invalid'},
    {param($o)$o.CredentialCiphertext=[Convert]::ToBase64String((New-Object byte[] 32))},
    {param($o)$o.CredentialLogonValidated=$false}, {param($o)$o.Phase='SetupFailed'}
)
foreach($case in $cases){$o=$valid | ConvertTo-Json | ConvertFrom-Json; &$case $o; $rejected=$false;try{Assert-Worker106CredentialReceipt $o Prepare}catch{$rejected=$true};if(-not $rejected){throw 'Unsafe receipt accepted'}}
$partial.Phase='PreflightPassed';$rejected=$false
try{Assert-Worker106CredentialReceipt $partial State}catch{$rejected=$true}
if(-not $rejected){throw 'Pre-account state accepted'}
[ordered]@{Accepted=2;Rejected=8;PrivateKeyOrCredentialAccess=$false}|ConvertTo-Json
