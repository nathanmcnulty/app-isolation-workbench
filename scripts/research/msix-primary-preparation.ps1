#Requires -Version 7.6
#Requires -PSEdition Core
if ([Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString() -cne 'X64' -or $PSVersionTable.PSVersion.ToString() -match '-' -or ($PSVersionTable.ContainsKey('GitCommitId') -and $PSVersionTable.GitCommitId -match 'preview|rc')) { throw 'Stable x64 PowerShell Core >=7.6 required; prerelease runtime refused' }
$PSModuleAutoLoadingPreference = 'None'
foreach ($module in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Security')) { Import-Module $module -SkipEditionCheck -ErrorAction Stop }
if (@(Get-PSSession -ErrorAction SilentlyContinue | Where-Object Name -eq 'WinPSCompatSession').Count) { throw 'Windows compatibility session forbidden' }
# Pure research record helpers. These do not create accounts, publish preparation,
# authenticate, launch a process, or establish a worker/session identity.
function New-AiwMsixPrimaryNonce {
    $bytes = [byte[]]::new(32)
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $random.GetBytes($bytes)
        return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
    } finally { $random.Dispose(); [Array]::Clear($bytes, 0, $bytes.Length) }
}

function New-AiwMsixPrimaryPreparation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$CreatedAccount,
        [Parameter(Mandatory)][uint32]$SessionId,
        [Parameter(Mandatory)][string]$SourceImageSha256,
        [Parameter(Mandatory)][long]$NowFileTime
    )
    $ErrorActionPreference = 'Stop'

    $nonce = [string]$CreatedAccount.runNonce
    if ($nonce -cnotmatch '\A[0-9a-f]{64}\z') { throw 'Primary run nonce must be exactly 64 lowercase hexadecimal characters' }
    if ($CreatedAccount.schemaVersion -cne 'aiw.dev/research-primary-account/v1' -or
        $CreatedAccount.vmId -cne '7e686bee-8c05-43c7-9603-a9562ece224c' -or
        $CreatedAccount.accountName -cne 'AiwStandardUser' -or
        $CreatedAccount.accountCreated -isnot [bool] -or !$CreatedAccount.accountCreated) {
        throw 'Owned account receipt differs'
    }
    $sid = [string]$CreatedAccount.userSid
    if ($sid -cnotmatch '\AS-1-5-21-3849540285-1795134874-2442050430-([0-9]+)\z' -or
        [long]$Matches[1] -lt 1000 -or
        $sid -ceq 'S-1-5-21-3849540285-1795134874-2442050430-1006' -or $SessionId -eq 0 -or
        $SourceImageSha256 -cnotmatch '\A[0-9a-f]{64}\z') { throw 'Primary session or image identity differs' }
    $before = [long]$CreatedAccount.notBeforeFileTime
    if ($before -le 0 -or $before -gt ([long]::MaxValue - 18000000000)) { throw 'Primary account time is invalid' }
    $after = $before + 18000000000
    if ($NowFileTime -lt $before -or $NowFileTime -gt $after) { throw 'Original primary account freshness window expired or not reached' }
    [pscustomobject][ordered]@{
        schemaVersion = 'aiw.dev/research-primary-msix/v1'
        vmId = [string]$CreatedAccount.vmId
        sourceImageSha256 = $SourceImageSha256
        userSid = $sid
        sessionId = $SessionId
        notBeforeFileTime = $before
        notAfterFileTime = $after
        runNonce = $nonce
        accountCreated = $true
        accountName = 'AiwStandardUser'
    }
}
