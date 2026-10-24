#Requires -Version 7.6
#Requires -PSEdition Core
[CmdletBinding()]
param([switch]$EmitNativeFixture)
$ErrorActionPreference = 'Stop'
if ([Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString() -cne 'X64' -or $PSVersionTable.PSVersion.ToString() -match '-' -or ($PSVersionTable.ContainsKey('GitCommitId') -and $PSVersionTable.GitCommitId -match 'preview|rc')) { throw 'Stable x64 PowerShell Core >=7.6 required; prerelease runtime refused' }
$PSModuleAutoLoadingPreference = 'None'
foreach ($module in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Security')) { Import-Module $module -SkipEditionCheck -ErrorAction Stop }
if (@(Get-PSSession -ErrorAction SilentlyContinue | Where-Object Name -eq 'WinPSCompatSession').Count) { throw 'Windows compatibility session forbidden' }

Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'worker107-primary-preparation.ps1')
$account = [pscustomobject]@{
    schemaVersion = 'aiw.dev/research-primary-account/v1'
    vmId = 'e5cecc90-35c2-4831-bf9c-424be23f7d4e'
    accountName = 'AiwStandardUser'
    accountCreated = $true
    userSid = 'S-1-5-21-3556347314-2314855617-1438300668-2000'
    runNonce = New-AiwMsixPrimaryNonce
    notBeforeFileTime = [long]100
}
$hash = 'a' * 64
$record = New-AiwMsixPrimaryPreparation -CreatedAccount $account -SessionId 4 -SourceImageSha256 $hash -NowFileTime 200
if ($record.runNonce -cnotmatch '\A[0-9a-f]{64}\z' -or $record.notAfterFileTime -ne 18000000100) { throw 'Generated preparation differs' }
if ($EmitNativeFixture) { $record | ConvertTo-Json -Compress; return }
$passed = @('generated')
foreach ($case in @('shortNonce', 'uppercaseNonce', 'operatorSid', 'wrongVm', 'falseCreated', 'stringCreated', 'zeroSession', 'wrongHash', 'future', 'expired', 'overflow')) {
    $candidate = $account | ConvertTo-Json -Compress | ConvertFrom-Json
    $session = 4; $image = $hash; $now = [long]200
    switch ($case) {
        shortNonce { $candidate.runNonce = '43cd415eb41808ba1396b52a69efec17' }
        uppercaseNonce { $candidate.runNonce = 'B' * 64 }
        operatorSid { $candidate.userSid = 'S-1-5-21-3556347314-2314855617-1438300668-1001' }
        wrongVm { $candidate.vmId = 'other' }
        falseCreated { $candidate.accountCreated = $false }
        stringCreated { $candidate.accountCreated = 'true' }
        zeroSession { $session = 0 }
        wrongHash { $image = 'A' * 64 }
        future { $now = 99 }
        expired { $now = 18000000101 }
        overflow { $candidate.notBeforeFileTime = [long]::MaxValue }
    }
    $rejected = $false
    try { New-AiwMsixPrimaryPreparation -CreatedAccount $candidate -SessionId $session -SourceImageSha256 $image -NowFileTime $now | Out-Null } catch { $rejected = $true }
    if (!$rejected) { throw "Preparation accepted invalid case: $case" }
    $passed += $case
}
[pscustomobject]@{ passed = $true; powerShellVersion = $PSVersionTable.PSVersion.ToString(); cases = $passed; applicationTrialExecuted = $false } | ConvertTo-Json -Compress
