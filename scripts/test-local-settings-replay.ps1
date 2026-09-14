#requires -Version 7.0
<#
Runs three approved disposable Sandbox trials: baseline, fixed local-settings
adaptation, and relocated-bundle replay. Never installs on the host. Evidence is
retained on failure; the CLI owns exact-session cleanup/recovery.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ImportReceipt,
    [Parameter(Mandatory)][string]$GuestAgent,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$GuestAgentSha256,
    [Parameter(Mandatory)][string]$EvidenceParent,
    [Parameter(Mandatory)][string]$ApprovedBy,
    [Parameter(Mandatory)][switch]$Approve
)
$ErrorActionPreference = 'Stop'
if (!$Approve -or [string]::IsNullOrWhiteSpace($ApprovedBy)) { throw 'Explicit approval for all three fixed Sandbox trials is required' }
$repo = Split-Path -Parent $PSScriptRoot
$aiw = Join-Path $repo 'target\debug\aiw.exe'
$evidenceRoot = Join-Path $EvidenceParent ('aiw-local-settings-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $evidenceRoot | Out-Null
Write-Host "Retaining trial evidence at $evidenceRoot"
foreach ($leaf in @('bundles', 'intakes', 'runs')) { New-Item -ItemType Directory -Path (Join-Path $evidenceRoot $leaf) | Out-Null }
function Invoke-Aiw([string]$name, [string[]]$arguments) {
    & $aiw @arguments 1> (Join-Path $evidenceRoot "$name.json") 2> (Join-Path $evidenceRoot "$name.stderr.log")
    if ($LASTEXITCODE -ne 0) { throw "AIW failed at $name; inspect $evidenceRoot\$name.stderr.log and retained run status before retrying" }
    Get-Content -LiteralPath (Join-Path $evidenceRoot "$name.json") -Raw | ConvertFrom-Json
}
function Save-Json([string]$path, $value) {
    [IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject $value -Depth 64), [Text.UTF8Encoding]::new($false))
}
$source = Invoke-Aiw 'source-verification' @('application', 'verify-import', '--receipt', $ImportReceipt)
if (!$source.verified) { throw 'Source intake verification did not pass' }
$bundle = $null
$entries = @()
$observations = @()
foreach ($mode in @('baseline', 'candidate', 'replay')) {
    if ($mode -ne 'replay') {
        $example = if ($mode -eq 'baseline') { 'notepad-plus-plus-msi.aiw.yaml' } else { 'notepad-plus-plus-local-settings.aiw.yaml' }
        $bundle = Invoke-Aiw "$mode-bundle" @('package', 'export-wsb-msi', '--project', (Join-Path $repo "examples\$example"), '--import-receipt', $ImportReceipt, '--scenario', 'install-launch-close', '--output-parent', (Join-Path $evidenceRoot 'bundles'), '--bundle-id', $mode)
        $bundlePath = $bundle.bundlePath
    } else {
        $bundlePath = Join-Path $evidenceRoot 'relocated-candidate'
        Copy-Item -LiteralPath $bundle.bundlePath -Destination $bundlePath -Recurse
    }
    $imported = Invoke-Aiw "$mode-import" @('package', 'import', '--bundle', $bundlePath, '--manifest-sha256', $bundle.manifestSha256, '--intake-parent', (Join-Path $evidenceRoot 'intakes'), '--intake-id', $mode)
    $projectPath = Join-Path $evidenceRoot "$mode-project.json"
    $receiptPath = Join-Path $evidenceRoot "$mode-intake.json"
    Save-Json $projectPath $imported.project
    Save-Json $receiptPath $imported.importReceipt
    $runId = "$mode-" + [guid]::NewGuid().ToString('N')
    $prepared = Invoke-Aiw "$mode-preparation" @('run', 'prepare-wsb-msi', '--run-id', $runId, '--project', $projectPath, '--guest-agent', $GuestAgent, '--guest-agent-sha256', $GuestAgentSha256, '--workspace-parent', (Join-Path $evidenceRoot 'runs'), '--import-receipt', $receiptPath, '--scenario', 'install-launch-close', '--created-at', ([DateTime]::UtcNow.ToString('o')))
    $workspace = $prepared.receipt.workspace.root.finalPath
    $null = Invoke-Aiw "$mode-recipe" @('package', 'inspect-wsb-msi-recipe', '--root', $workspace, '--project', $projectPath, '--guest-agent-sha256', $GuestAgentSha256)
    $null = Invoke-Aiw "$mode-planning-import" @('run', 'import-prepared-wsb', '--workspace', $workspace, '--project', $projectPath, '--guest-agent-sha256', $GuestAgentSha256, '--imported-at', ([DateTime]::UtcNow.ToString('o')))
    $plan = Get-Content -LiteralPath (Join-Path $workspace 'plan.json') -Raw | ConvertFrom-Json
    $approvalPath = Join-Path $evidenceRoot "$mode-approval.json"
    Save-Json $approvalPath ([ordered]@{ schema='aiw.dev/approval-record/v0alpha1'; runId=$runId; planHash=$prepared.receipt.runPlanSha256; trustDeltas=$plan.trustDeltas; approvedBy=$ApprovedBy; approvedAt=[DateTime]::UtcNow.ToString('o') })
    $null = Invoke-Aiw "$mode-approved" @('run', 'approve', '--root', $workspace, '--run-id', $runId, '--approval', $approvalPath)
    Write-Host "Starting $mode in its own disposable Sandbox"
    try {
        $execution = Invoke-Aiw "$mode-execution" @('run', 'start', '--root', $workspace, '--run-id', $runId, '--project', $projectPath, '--guest-agent-sha256', $GuestAgentSha256, '--timeout-seconds', '900')
    } catch {
        $executionError = $_
        try {
            $null = Invoke-Aiw "$mode-failed-report" @('run', 'report-wsb-msi-run', '--root', $workspace, '--run-id', $runId, '--project', $projectPath, '--guest-agent-sha256', $GuestAgentSha256)
        } catch { Write-Warning "Failure report unavailable; retain the original execution diagnostics: $_" }
        throw $executionError
    }
    $runReport = Invoke-Aiw "$mode-report" @('run', 'report-wsb-msi-run', '--root', $workspace, '--run-id', $runId, '--project', $projectPath, '--guest-agent-sha256', $GuestAgentSha256)
    $null = Invoke-Aiw "$mode-bundle-report" @('package', 'report-wsb-msi', '--bundle', $bundlePath, '--manifest-sha256', $bundle.manifestSha256, '--import-record', (Join-Path $evidenceRoot "$mode-import.json"), '--root', $workspace, '--run-id', $runId, '--guest-agent-sha256', $GuestAgentSha256)
    $report = $runReport.report
    if ($runReport.reportKind -ne 'completedAssessment' -or !$execution.cleanupComplete -or !$report.recordedCleanupVerified -or !$report.behavior.functionalExercise.savedDocument -or $report.behavior.functionalExercise.expectedSha256 -ne $report.behavior.functionalExercise.observedSha256) { throw "$mode did not pass the bound document workflow and cleanup" }
    $issues = @($report.behavior.afterExercise.issues | Where-Object { $_.root -in @('roamingAppData', 'localAppData') })
    if ($issues.Count) { throw "$mode settings scope is incomplete" }
    $settings = @($report.behavior.afterExercise.entries | Where-Object { $_.path -eq 'config.xml' -and $_.root -in @('roamingAppData', 'localAppData') })
    $expectedRoot = if ($mode -eq 'baseline') { 'roamingAppData' } else { 'localAppData' }
    if ($settings.Count -ne 1 -or $settings[0].root -ne $expectedRoot -or $settings[0].sizeBytes -eq 0) { throw "$mode did not retain config.xml exclusively at its expected settings location" }
    $entries += [ordered]@{id=$mode; workspaceRoot=$workspace; runId=$runId; projectPath=$projectPath; guestAgentSha256=$GuestAgentSha256}
    $observations += [ordered]@{mode=$mode; runId=$runId; manifestSha256=$bundle.manifestSha256; scenarioSha256=$report.scenario.scenarioSha256; receiptSha256=$report.receiptSha256; evidenceRootHash=$report.evidenceRootHash; settings=$settings; cleanupVerified=$true}
    Save-Json (Join-Path $evidenceRoot 'observations.json') $observations
}
$setPath = Join-Path $evidenceRoot 'report-set-input.json'
Save-Json $setPath ([ordered]@{schemaVersion='aiw.dev/wsb-msi-report-set-input/v0alpha1'; entries=$entries})
$null = Invoke-Aiw 'report-set' @('run', 'report-wsb-msi-set', '--input', $setPath)
Save-Json (Join-Path $evidenceRoot 'comparison.json') ([ordered]@{
    schemaVersion='aiw.dev/local-settings-trial-observation/v0alpha1'
    observations=$observations
    scope='Fresh-worker document workflow and settings placement; no tighter-isolation or validated-package claim'
    gaps=@('No affected-boundary canaries measured', 'No host deployment, persistence, uninstall, update, or reboot validation')
})
[ordered]@{evidenceRoot=$evidenceRoot; trialsCompleted=3; comparison=(Join-Path $evidenceRoot 'comparison.json')} | ConvertTo-Json
