#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Root)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'read-trial.ps1')
function Assert-Token($Token, [uint32]$ProcessId, [string]$UserSid, [AllowNull()][string]$PackageSid) {
    $candidate=![string]::IsNullOrEmpty($PackageSid)
    $level=if ($candidate) { 'low' } else { 'medium' }
    $rid=if ($candidate) { 4096 } else { 8192 }
    if ($Token.isElevated -isnot [bool] -or $Token.isAppContainer -isnot [bool] -or $Token.capabilities -isnot [array]) { throw 'Token flags/capabilities require typed observations' }
    if (!$Token -or $Token.schemaVersion -ne 'aiw.dev/token-evidence/v0alpha1' -or $ProcessId -eq 0 -or $Token.processId -ne $ProcessId -or $Token.tokenType -ne 'primary' -or $Token.userSid -ne $UserSid -or $Token.isElevated -ne $false -or $Token.integrity.level -ne $level -or $Token.integrity.rid -ne $rid -or $Token.integrity.sid -ne "S-1-16-$rid" -or $Token.isAppContainer -ne $candidate -or $null -eq $Token.capabilities -or $Token.capabilities.Count -ne 0) { throw 'Control process token failed' }
    if ($candidate) {
        if ($Token.appContainerSid -ne $PackageSid) { throw 'Exact AppContainer SID mismatch' }
    } elseif ($Token.appContainerSid) { throw 'Baseline unexpectedly has package SID' }
}
$normalized=@(); $identities=@(); $configurations=@()
foreach ($trial in 1,2) {
    $directory=Join-Path $Root "trial-$trial"
    $binding=Read-ControlTrial $directory
    $journal=$binding.journal; $result=$binding.result; $record=$result.observation
    if ($record.productionEvidence -isnot [bool]) { throw 'Launcher research evidence flag requires a boolean' }
    if ($result.schemaVersion -ne 'aiw.dev/research/control-appcontainer-guest/v0alpha1' -or $result.launcherExitCode -ne 0 -or $record.schemaVersion -ne 'aiw.dev/research/control-appcontainer/v0alpha1' -or $record.productionEvidence -ne $false) { throw 'AppContainer control completion contract failed' }
    if ($result.launcherSha256 -ne $journal.launcherSha256 -or (Get-FileHash -LiteralPath (Join-Path $directory 'input\aiw-control-appcontainer.exe')).Hash.ToLowerInvariant() -ne $journal.launcherSha256) { throw 'Launcher identity changed' }
    if ($binding.normalizedConfigSha256 -ne 'f4d93e6552169a3e35dc3df6713d2d17f386923abb0631f6f663a87bcdaa16c1') { throw 'AppContainer control requires the fixed disconnected Sandbox configuration' }
    $session=[guid]::Empty
    if (![guid]::TryParse($journal.sandboxId,[ref]$session) -or $session -eq [guid]::Empty) { throw 'Invalid Sandbox identity' }
    Assert-Token $record.launcherToken $result.launcherProcessId $result.standardUserSid $null
    $package=$record.profile.sid
    foreach ($flag in @($record.profile.deleted,$record.cleanup.profileDeleted,$record.cleanup.baselineJobEmpty,$record.cleanup.appContainerJobEmpty,$record.resource.unchangedAfter)) {
        if ($flag -isnot [bool] -or $flag -ne $true) { throw 'Cleanup/resource flags require true boolean observations' }
    }
    if ($record.profile.name -ne 'AIW.Control.Research.v0alpha1' -or $package -notmatch '^S-1-15-2-(\d+-){6}\d+$' -or $record.profile.deleted -ne $true -or $record.cleanup.profileDeleted -ne $true -or $record.cleanup.baselineJobEmpty -ne $true -or $record.cleanup.appContainerJobEmpty -ne $true) { throw 'Profile identity or process/profile cleanup failed' }
    if ($record.resource.canaryPath -cne 'C:\AIW\Control\SharedCanary\canary.txt' -or $record.resource.sha256 -ne (Hash-Text 'AIW controlled readable bytes') -or $record.resource.sizeBytes -ne 29 -or $record.resource.unchangedAfter -ne $true) { throw 'Paired canary identity failed' }
    $cases=@()
    foreach ($variant in 'baseline','appContainer') {
        $candidate=$variant -eq 'appContainer'
        $sid=if ($candidate) { $package } else { $null }
        foreach ($mode in 'readCanary','child') {
            $invocation=$record.$variant.$mode; $observation=$invocation.observation
            Assert-Token $invocation.fixtureToken $invocation.processId $result.standardUserSid $sid
            Assert-Token $observation.ownProcessToken $invocation.processId $result.standardUserSid $sid
            if ($invocation.processId -eq $result.launcherProcessId -or $invocation.exitCode -ne 0 -or $observation.schemaVersion -ne 'aiw.dev/control-fixture-report/v0alpha1' -or $observation.mode -ne $mode -or $observation.result.status -ne $mode) { throw 'Fixed invocation binding failed' }
            if ($mode -eq 'readCanary') {
                $outcome=$observation.result.outcome
                if ($candidate) {
                    if ($outcome.kind -ne 'accessDenied') { throw 'Candidate did not observe native access denied' }
                } elseif ($outcome.kind -ne 'success' -or $outcome.sha256 -ne $record.resource.sha256 -or $outcome.sizeBytes -ne 29) { throw 'Baseline did not read the same canary bytes' }
            } else {
                $child=$observation.result
                Assert-Token $child.childToken $child.childProcessId $result.standardUserSid $sid
                if ($child.childProcessId -eq $invocation.processId -or $child.childProcessId -eq $result.launcherProcessId -or $child.childStdoutBytes -ne 0) { throw 'Descendant identity/capture mismatch' }
            }
            $cases += [ordered]@{variant=$variant; mode=$mode; exitCode=$invocation.exitCode; integrity=$invocation.fixtureToken.integrity.level; appContainer=$candidate; readOutcome=$(if ($mode -eq 'readCanary') { $observation.result.outcome.kind } else { $null })}
        }
    }
    $identities+=$session.ToString(); $configurations+=$journal.configSha256
    $normalized += [ordered]@{fixtureSha256=$journal.fixtureSha256; launcherSha256=$journal.launcherSha256; guestScriptSha256=$journal.guestScriptSha256; providerSha256=$journal.providerSha256; normalizedConfigSha256=$binding.normalizedConfigSha256; windowsBuild=$result.windowsBuild; packageSid=$package; canarySha256=$record.resource.sha256; cases=$cases}
}
if ($identities[0] -eq $identities[1]) { throw 'Two fresh Sandbox sessions required' }
if (($normalized[0] | ConvertTo-Json -Depth 16 -Compress) -cne ($normalized[1] | ConvertTo-Json -Depth 16 -Compress)) { throw 'AppContainer control repetitions differ' }
[ordered]@{schemaVersion='aiw.dev/research/control-appcontainer-repeatability/v0alpha1'; productionEvidence=$false; repeatedControls=$true; sandboxIds=$identities; configurationSha256=$configurations; normalized=$normalized[0]; limitations=@('Fixed project-owned control, not real application compatibility','Research driver, not approved execution evidence','Classic AppContainer with no capabilities; no network or broader resource verdict')} | ConvertTo-Json -Depth 16
