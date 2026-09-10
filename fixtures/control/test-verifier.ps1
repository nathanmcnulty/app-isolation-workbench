#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Root, [switch]$AppContainerControl)
$ErrorActionPreference='Stop'
$copy=Join-Path $env:TEMP ('aiw-control-verifier-tests-'+[guid]::NewGuid())
New-Item -ItemType Directory -Path $copy | Out-Null
foreach ($trial in @('trial-1','trial-2')) { Copy-Item -LiteralPath (Join-Path $Root $trial) -Destination $copy -Recurse }
$verifier=Join-Path $PSScriptRoot $(if ($AppContainerControl) { 'verify-appcontainer.ps1' } else { 'verify-baseline.ps1' })
& $verifier -Root $copy | Out-Null
$resultPath=Join-Path $copy 'trial-1\output\control-result.json'
$journalPath=Join-Path $copy 'trial-1\host-journal.json'
$resultBytes=[IO.File]::ReadAllBytes($resultPath)
$verificationOptions=@{}
$registryControls=$AppContainerControl -and (Get-Content $resultPath -Raw | ConvertFrom-Json).schemaVersion -eq 'aiw.dev/research/control-appcontainer-guest/v0alpha2'
if ($registryControls) { $verificationOptions.RequireRegistry=$true }
$journalBytes=[IO.File]::ReadAllBytes($journalPath)
$configPath=Join-Path $copy 'trial-1\configuration.wsb'
$configBytes=[IO.File]::ReadAllBytes($configPath)
$passed=@()
$cases=if ($AppContainerControl) { @('held-root-pid','self-root-pid','wrong-package','child-package','child-user','candidate-medium','candidate-capability','baseline-denied','candidate-missing','resource-drift','profile-cleanup','job-cleanup','launcher-exit','launcher-hash','cleanup','duplicate-session','config-bytes','config-drift','provider-drift') } else { @('root-pid','denial-is-not-missing','child-sid','failure-exit','cleanup','duplicate-session','config-bytes','config-drift','provider-drift') }
$cases+='cleanup-string-false'
if ($registryControls) { $cases+=@('registry-missing','registry-native-code','registry-view','registry-key','registry-value','registry-baseline-hash','registry-value-drift','registry-acl-drift','registry-version-downgrade') }
foreach ($case in $cases) {
    try {
        $result=[Text.Encoding]::UTF8.GetString($resultBytes).TrimStart([char]0xfeff) | ConvertFrom-Json
        $journal=[Text.Encoding]::UTF8.GetString($journalBytes).TrimStart([char]0xfeff) | ConvertFrom-Json
        switch ($case) {
            registry-missing { $result.observation.appContainer.readRegistry.observation.result.probe.outcome.kind='notFound' }
            registry-native-code { $result.observation.appContainer.readRegistry.observation.result.probe.outcome.nativeCode=2 }
            registry-view { $result.observation.appContainer.readRegistry.observation.result.probe.scope.view='registry32' }
            registry-key { $result.observation.appContainer.readRegistry.observation.result.probe.scope.key='SOFTWARE\DifferentKey' }
            registry-value { $result.observation.appContainer.readRegistry.observation.result.probe.scope.value='DifferentValue' }
            registry-baseline-hash { $result.observation.baseline.readRegistry.observation.result.probe.outcome.sha256='0'*64 }
            registry-value-drift { $result.registryBinding.valueUnchanged=$false }
            registry-acl-drift { $result.registryBinding.aclUnchanged=$false }
            registry-version-downgrade { $result.schemaVersion='aiw.dev/research/control-appcontainer-guest/v0alpha1'; $result.observation.schemaVersion='aiw.dev/research/control-appcontainer/v0alpha1' }
            held-root-pid { $result.observation.appContainer.readCanary.fixtureToken.processId=0 }
            self-root-pid { $result.observation.appContainer.readCanary.observation.ownProcessToken.processId=0 }
            wrong-package { $result.observation.appContainer.readCanary.fixtureToken.appContainerSid='S-1-15-2-1-2-3-4-5-6-7' }
            child-package { $result.observation.appContainer.child.observation.result.childToken.appContainerSid=$null }
            child-user { $result.observation.appContainer.child.observation.result.childToken.userSid='S-1-5-18' }
            candidate-medium { $result.observation.appContainer.readCanary.fixtureToken.integrity.level='medium' }
            candidate-capability { $result.observation.appContainer.readCanary.fixtureToken.capabilities=@(@{sid='S-1-15-3-1'; attributes=4}) }
            baseline-denied { $result.observation.baseline.readCanary.observation.result.outcome.kind='accessDenied' }
            candidate-missing { $result.observation.appContainer.readCanary.observation.result.outcome.kind='notFound' }
            resource-drift { $result.observation.resource.unchangedAfter=$false }
            profile-cleanup { $result.observation.cleanup.profileDeleted=$false }
            job-cleanup { $result.observation.cleanup.appContainerJobEmpty=$false }
            launcher-exit { $result.launcherExitCode=1 }
            launcher-hash { $result.launcherSha256='0'*64 }
            root-pid { $result.cases[1].observation.ownProcessToken.processId=0 }
            denial-is-not-missing { $result.cases[3].observation.result.outcome.kind='notFound' }
            child-sid { $result.cases[5].observation.result.childToken.userSid='S-1-5-18' }
            failure-exit { $result.cases[6].exitCode=0 }
            cleanup { $journal.cleanupVerified=$false }
            cleanup-string-false { $journal.cleanupVerified='false' }
            duplicate-session { $journal.sandboxId=(Get-Content (Join-Path $copy 'trial-2\host-journal.json') -Raw | ConvertFrom-Json).sandboxId }
            provider-drift { $journal.providerSha256='0'*64 }
            {$_ -in 'config-bytes','config-drift'} {
                [IO.File]::WriteAllText($configPath, [Text.Encoding]::UTF8.GetString($configBytes).Replace('<Networking>Disable</Networking>','<Networking>Enable</Networking>'))
                if ($case -eq 'config-drift') { $journal.configSha256=(Get-FileHash -LiteralPath $configPath).Hash.ToLowerInvariant() }
            }
        }
        $result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $resultPath
        # Rehash the deliberately changed record so these tests exercise semantic checks too.
        $journal.resultSha256=(Get-FileHash -LiteralPath $resultPath).Hash.ToLowerInvariant()
        $journal | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $journalPath
        $rejected=$false
        try { & $verifier -Root $copy @verificationOptions | Out-Null } catch { $rejected=$true }
        if (!$rejected) { throw "Verifier accepted negative case: $case" }
        $passed+=$case
    } finally {
        [IO.File]::WriteAllBytes($resultPath,$resultBytes)
        [IO.File]::WriteAllBytes($journalPath,$journalBytes)
        [IO.File]::WriteAllBytes($configPath,$configBytes)
    }
}
& $verifier -Root $copy | Out-Null
$outputPath=Join-Path $copy 'trial-1\output'
$savedOutput=Join-Path $copy 'trial-1\output-unlinked'
# Both exact paths are beneath this freshly created test copy. Never move the source evidence.
foreach ($path in @($outputPath,$savedOutput)) {
    if (![IO.Path]::GetFullPath($path).StartsWith([IO.Path]::GetFullPath($copy)+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Test output escaped copied workspace' }
}
Move-Item -LiteralPath $outputPath -Destination $savedOutput
try {
    New-Item -ItemType Junction -Path $outputPath -Target $savedOutput | Out-Null
    $rejected=$false
    try { & $verifier -Root $copy | Out-Null } catch { $rejected=$true }
    if (!$rejected) { throw 'Verifier accepted a linked output directory' }
    $passed+='linked-output'
} finally {
    if (Test-Path -LiteralPath $outputPath) { Remove-Item -LiteralPath $outputPath -Force }
    Move-Item -LiteralPath $savedOutput -Destination $outputPath
}
& $verifier -Root $copy | Out-Null
[ordered]@{passed=$true; rejectedCases=$passed; copiedFixture=$copy; originalModified=$false} | ConvertTo-Json
