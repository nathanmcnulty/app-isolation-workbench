#Requires -Version 7.6
#Requires -PSEdition Core
[CmdletBinding()]
param(
    [switch]$ObserveCurrent,
    [string]$SourceRoot
)
# AIW runtime contract: stable PowerShell Core >=7.6; no compatibility session.
if ($PSVersionTable.PSEdition -cne 'Core' -or $PSVersionTable.PSVersion -lt [version]'7.6' -or $PSVersionTable.PSVersion.PreReleaseLabel -or [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne 'X64') { throw 'AIW requires stable x64 PowerShell Core 7.6 or later' }
foreach ($aiwNativeModule in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Security','Microsoft.PowerShell.Archive')) { Import-Module (Join-Path $PSHOME ('Modules\'+$aiwNativeModule+'\'+$aiwNativeModule+'.psd1')) -SkipEditionCheck -ErrorAction Stop }
$PSModuleAutoLoadingPreference = 'None'
if (@(Get-PSSession | Where-Object Name -eq 'WinPSCompatSession').Count) { throw 'AIW prohibits Windows PowerShell compatibility sessions' }
$PSNativeCommandUseErrorActionPreference = $false
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (!$SourceRoot) {
    $SourceRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'crates/aiw-windows-platform/src'
}
Add-Type -Path @((Join-Path $SourceRoot 'research_msix_native.cs'), (Join-Path $SourceRoot 'research_msix_interactive.cs'))
$sid = 'S-1-5-21-1-2-3-1000'
function New-Observation {
    $value = [AiwInteractiveObservation]::new()
    $value.UserSid = $sid
    $value.UserName = 'AiwStandardUser'
    $value.LogonDomain = 'aiwcleanhost'
    $value.WtsUserName = 'AiwStandardUser'
    $value.WtsDomain = 'AIWCLEANHOST'
    $value.AuthenticationId = '0000000000000012'
    $value.ShellAuthenticationId = $value.AuthenticationId
    $value.SessionId = 3
    $value.LogonSessionId = 3
    $value.LogonType = 10
    $value.LogonTimeFileTime = 200
    $value.WtsState = 0
    $value.ShellPid = 1234
    foreach ($name in @('Token', 'ShellToken')) {
        $token = [AiwMsixObservation]::new()
        $token.UserSid = $sid
        $token.TokenSessionId = 3
        $token.IntegritySid = 'S-1-16-8192'
        $value.$name = $token
    }
    return $value
}
$cases = @(
    @{ name = 'otherUser'; change = { param($v) $v.UserSid = 'S-1-5-21-1-2-3-1001' } },
    @{ name = 'secondaryLogonOnAnotherDesktop'; change = { param($v) $v.WtsUserName = 'WDAGUtilityAccount' } },
    @{ name = 'wrongDomain'; change = { param($v) $v.WtsDomain = 'elsewhere' } },
    @{ name = 'disconnected'; change = { param($v) $v.WtsState = 4 } },
    @{ name = 'serviceSession'; change = { param($v) $v.SessionId = 0 } },
    @{ name = 'lsaSessionMismatch'; change = { param($v) $v.LogonSessionId = 4 } },
    @{ name = 'batchLogon'; change = { param($v) $v.LogonType = 4 } },
    @{ name = 'staleLogon'; change = { param($v) $v.LogonTimeFileTime = 99 } },
    @{ name = 'futureLogon'; change = { param($v) $v.LogonTimeFileTime = 301 } },
    @{ name = 'missingAuthenticationId'; change = { param($v) $v.AuthenticationId = '' } },
    @{ name = 'shellLogonMismatch'; change = { param($v) $v.ShellAuthenticationId = '0000000000000013' } },
    @{ name = 'noShell'; change = { param($v) $v.ShellPid = 0 } },
    @{ name = 'wrongShellSid'; change = { param($v) $v.ShellToken.UserSid = 'S-1-5-21-1-2-3-1001' } },
    @{ name = 'wrongShellSession'; change = { param($v) $v.ShellToken.TokenSessionId = 4 } },
    @{ name = 'elevatedCoordinator'; change = { param($v) $v.Token.IsElevated = $true } },
    @{ name = 'enabledShellAdmin'; change = { param($v) $v.ShellToken.AdministratorsEnabled = $true } },
    @{ name = 'highShell'; change = { param($v) $v.ShellToken.IntegritySid = 'S-1-16-12288' } },
    @{ name = 'containerCoordinator'; change = { param($v) $v.Token.IsAppContainer = $true } },
    @{ name = 'missingShellToken'; change = { param($v) $v.ShellToken = $null } }
)
[AiwInteractiveNative]::RequireOwnedStandardSession((New-Observation), $sid, 100, 300)
$console = New-Observation
$console.LogonType = 2
[AiwInteractiveNative]::RequireOwnedStandardSession($console, $sid, 100, 300)
foreach ($case in $cases) {
    $value = New-Observation
    & $case.change $value
    $rejected = $false
    try { [AiwInteractiveNative]::RequireOwnedStandardSession($value, $sid, 100, 300) }
    catch { $rejected = $true }
    if (!$rejected) { throw ('Invalid observation accepted: ' + $case.name) }
}
$badBoundsRejected = $false
try { [AiwInteractiveNative]::RequireOwnedStandardSession((New-Observation), $sid, 300, 100) }
catch { $badBoundsRejected = $true }
if (!$badBoundsRejected) { throw 'Inverted run bounds accepted' }
$observation = $null
if ($ObserveCurrent) { $observation = [AiwInteractiveNative]::ObserveCurrent() }
[ordered]@{
    passed = $true
    positiveCases = 2
    rejectedCases = $cases.Count + 1
    powershellVersion = $PSVersionTable.PSVersion.ToString()
    applicationExecuted = $false
    currentObservation = $observation
    currentObservationAcceptedForTrial = $false
} | ConvertTo-Json -Depth 8
