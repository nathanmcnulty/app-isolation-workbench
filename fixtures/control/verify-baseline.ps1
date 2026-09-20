#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Root)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'read-trial.ps1')
$normalized=@()
$identities=@()
$configurationHashes=@()
for ($trial=1; $trial -le 2; $trial++) {
    $directory=Join-Path $Root "trial-$trial"
    $binding=Read-ControlTrial $directory
    $journal=$binding.journal; $result=$binding.result; $normalizedConfigSha256=$binding.normalizedConfigSha256
    $configurationHashes+=$journal.configSha256
    if ($result.schemaVersion -ne 'aiw.dev/research/control-baseline/v0alpha1' -or $result.cases.Count -ne 7) { throw 'Unexpected baseline contract' }
    $identities+=$journal.sandboxId
    $cases=@()
    $expected=@('admin-read','roundtrip','allow','deny','missing','child','failure')
    for ($index=0; $index -lt 7; $index++) {
        $case=$result.cases[$index]; $observation=$case.observation; $token=$observation.ownProcessToken; $operation=$observation.result
        if ($case.case -ne $expected[$index] -or $observation.schemaVersion -ne 'aiw.dev/control-fixture-report/v0alpha1' -or $token.processId -ne $case.processId -or $case.processId -le 0 -or $token.isAppContainer -ne $false -or $token.tokenType -ne 'primary') { throw 'Control case or root token binding failed' }
        if ($index -eq 0) {
            if ($token.isElevated -ne $true -or $token.integrity.level -ne 'high') { throw 'Administrator read control is not elevated at high integrity' }
        } elseif ($token.isElevated -ne $false -or $token.integrity.level -ne 'medium' -or $token.userSid -ne $result.standardUserSid) { throw 'Standard-user token control failed' }
        $expectedExit=0; $expectedMode='readCanary'; $expectedStatus='readCanary'
        switch ($case.case) {
            roundtrip {
                $expectedMode='roundTrip'; $expectedStatus='roundTrip'
                if ($operation.initialSha256 -ne (Hash-Text "AIW control fixture initial document`r`n") -or $operation.editedSha256 -ne (Hash-Text "AIW control fixture edited document`r`n")) { throw 'Document round trip failed' }
            }
            {$_ -in 'admin-read','allow'} {
                if ($operation.outcome.kind -ne 'success' -or $operation.outcome.sha256 -ne (Hash-Text 'AIW controlled readable bytes') -or $operation.outcome.sizeBytes -ne 29) { throw 'Readable canary control failed' }
            }
            deny { if ($operation.outcome.kind -ne 'accessDenied') { throw 'Native access-denied control failed' } }
            missing { if ($operation.outcome.kind -ne 'notFound') { throw 'Missing-file control was misclassified' } }
            child {
                $expectedMode='child'; $expectedStatus='child'; $child=$operation.childToken
                if ($operation.childProcessId -le 0 -or $operation.childProcessId -eq $case.processId -or $child.processId -ne $operation.childProcessId -or $child.userSid -ne $token.userSid -or $child.integrity.level -ne 'medium' -or $child.isElevated -ne $false -or $child.isAppContainer -ne $false -or $operation.childStdoutBytes -ne 0) { throw 'Child token binding failed' }
            }
            failure { $expectedMode='expectedFailure'; $expectedStatus='expectedFailure'; $expectedExit=23; if ($operation.code -ne 'fixedExpectedFailure') { throw 'Expected failure code missing' } }
        }
        if ($case.exitCode -ne $expectedExit -or $observation.mode -ne $expectedMode -or $operation.status -ne $expectedStatus) { throw 'Control mode, status or exit code mismatch' }
        $cases += [ordered]@{case=$case.case; mode=$observation.mode; exitCode=$case.exitCode; status=$operation.status; readOutcome=$operation.outcome.kind; integrity=$token.integrity.level; elevated=$token.isElevated; appContainer=$token.isAppContainer}
    }
    $normalized += [ordered]@{fixtureSha256=$journal.fixtureSha256; guestScriptSha256=$journal.guestScriptSha256; providerSha256=$journal.providerSha256; normalizedConfigSha256=$normalizedConfigSha256; windowsBuild=$result.windowsBuild; cases=$cases}
}
if ($identities[0] -eq $identities[1]) { throw 'Two fresh sessions are required' }
if (($normalized[0] | ConvertTo-Json -Depth 12 -Compress) -ne ($normalized[1] | ConvertTo-Json -Depth 12 -Compress)) { throw 'Control repetitions differ' }
[ordered]@{schemaVersion='aiw.dev/research/control-repeatability/v0alpha1'; productionEvidence=$false; repeatedControls=$true; sandboxIds=$identities; configurationSha256=$configurationHashes; normalized=$normalized[0]; limitations=@('ACL negative control, not AppContainer isolation','Research driver, not approved execution evidence','No application compatibility or application repeatability verdict')} | ConvertTo-Json -Depth 12
