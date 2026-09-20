#requires -Version 7.0
<# One explicitly approved, fixed Sandbox replay with durable stage diagnostics.
The CLI verifies all execution authority and owns exact cleanup/recovery. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Profile,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ProfileSha256,
    [Parameter(Mandatory)][string]$Project,
    [Parameter(Mandatory)][string]$ImportReceipt,
    [Parameter(Mandatory)][string]$GuestAgent,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$GuestAgentSha256,
    [Parameter(Mandatory)][string]$EvidenceParent,
    [Parameter(Mandatory)][string]$ApprovedBy,
    [Parameter(Mandatory)][switch]$Approve
)
$ErrorActionPreference = 'Stop'
if (!$Approve -or [string]::IsNullOrWhiteSpace($ApprovedBy)) { throw 'Explicit approval for this fixed Sandbox trial is required' }
$Project = (Resolve-Path -LiteralPath $Project).ProviderPath
$repo = Split-Path -Parent $PSScriptRoot
$aiw = Join-Path $repo 'target\debug\aiw.exe'
$evidenceRoot = Join-Path $EvidenceParent ('aiw-approved-profile-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $evidenceRoot | Out-Null
Write-Host "Retaining trial evidence at $evidenceRoot"
function Save-Json([string]$path, $value) {
    [IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject $value -Depth 64), [Text.UTF8Encoding]::new($false))
}
function Invoke-Aiw([string]$name, [string[]]$arguments) {
    & $aiw @arguments 1> (Join-Path $evidenceRoot "$name.json") 2> (Join-Path $evidenceRoot "$name.stderr.log")
    if ($LASTEXITCODE -ne 0) { throw "AIW failed at $name; inspect $evidenceRoot\$name.stderr.log and retained run status before retrying" }
    Get-Content -LiteralPath (Join-Path $evidenceRoot "$name.json") -Raw | ConvertFrom-Json
}
$readiness = Invoke-Aiw 'host-readiness' @('host', 'assess')
if (!$readiness.supported -or $readiness.currentSessions -ne 'available' -or @($readiness.currentSessionIds).Count -ne 0 -or @($readiness.blockers).Count -ne 0) {
    throw "Host readiness blocks the trial. See $evidenceRoot\host-readiness.json for exact sessions and blockers."
}
$runId = 'profile-' + [guid]::NewGuid().ToString('N')
$prepared = Invoke-Aiw 'preparation' @('run', 'prepare-wsb-msi', '--run-id', $runId, '--project', $Project, '--guest-agent', $GuestAgent, '--guest-agent-sha256', $GuestAgentSha256, '--workspace-parent', $evidenceRoot, '--import-receipt', $ImportReceipt, '--scenario', 'install-launch-close', '--created-at', ([DateTime]::UtcNow.ToString('o')), '--launch-profile', $Profile, '--launch-profile-sha256', $ProfileSha256)
$workspace = $prepared.receipt.workspace.root.finalPath
if ($prepared.receipt.schemaVersion -ne 'aiw.dev/wsb-preparation-receipt/v0alpha6' -or $prepared.receipt.msi.launchProfile.profileSha256 -ne $ProfileSha256) { throw 'Preparation omitted the required profile binding' }
if (@($prepared.receipt.msi.launchProfile.profile.evidence.entries).Count -ne 3 -or ($prepared.receipt.msi.launchProfile.profile.evidence.entries.id -join ',') -ne 'baseline,candidate,replay') { throw 'Profile selectors must contain exactly ordered baseline, candidate, and replay entries' }
$null = Invoke-Aiw 'recipe' @('package', 'inspect-wsb-msi-recipe', '--root', $workspace, '--project', $Project, '--guest-agent-sha256', $GuestAgentSha256)
$null = Invoke-Aiw 'planning-import' @('run', 'import-prepared-wsb', '--workspace', $workspace, '--project', $Project, '--guest-agent-sha256', $GuestAgentSha256, '--imported-at', ([DateTime]::UtcNow.ToString('o')))
$plan = Get-Content -LiteralPath (Join-Path $workspace 'plan.json') -Raw | ConvertFrom-Json
if (!($plan.trustDeltas -join ' ').Contains($ProfileSha256)) { throw 'Approval disclosure omitted the profile hash' }
$approvalPath = Join-Path $evidenceRoot 'approval.json'
Save-Json $approvalPath ([ordered]@{schema='aiw.dev/approval-record/v0alpha1'; runId=$runId; planHash=$prepared.receipt.runPlanSha256; trustDeltas=$plan.trustDeltas; approvedBy=$ApprovedBy; approvedAt=[DateTime]::UtcNow.ToString('o')})
$null = Invoke-Aiw 'approved' @('run', 'approve', '--root', $workspace, '--run-id', $runId, '--approval', $approvalPath)
Write-Host 'Starting the fixed replay in one disposable Sandbox'
try {
    $execution = Invoke-Aiw 'execution' @('run', 'start', '--root', $workspace, '--run-id', $runId, '--project', $Project, '--guest-agent-sha256', $GuestAgentSha256, '--timeout-seconds', '900')
} catch {
    $executionError = $_
    try { $null = Invoke-Aiw 'failed-report' @('run', 'report-wsb-msi-run', '--root', $workspace, '--run-id', $runId, '--project', $Project, '--guest-agent-sha256', $GuestAgentSha256) }
    catch { Write-Warning "Failure report unavailable; retain the execution diagnostics: $_" }
    throw $executionError
}
$result = Invoke-Aiw 'report' @('run', 'report-wsb-msi-run', '--root', $workspace, '--run-id', $runId, '--project', $Project, '--guest-agent-sha256', $GuestAgentSha256)
$report = $result.report
if ($result.reportKind -ne 'completedAssessment' -or $report.launchProfileSha256 -ne $ProfileSha256 -or !$execution.cleanupComplete -or !$report.recordedCleanupVerified -or !$report.behavior.functionalExercise.savedDocument -or $report.behavior.functionalExercise.expectedSha256 -ne $report.behavior.functionalExercise.observedSha256 -or $null -eq $report.standardUserContext.standardUserAcl) {
    throw 'The recorded run did not verify the profile, required workflow, ACL controls, and cleanup'
}
$comparisonInput = $prepared.receipt.msi.launchProfile.profile.evidence
$comparisonInput.entries[2].workspaceRoot = $workspace
$comparisonInput.entries[2].runId = $runId
$comparisonInput.entries[2].projectPath = $Project
$comparisonInput.entries[2].guestAgentSha256 = $GuestAgentSha256
Save-Json (Join-Path $evidenceRoot 'comparison-input.json') $comparisonInput
$comparison = Invoke-Aiw 'source-comparison' @('run', 'report-wsb-settings-comparison', '--input', (Join-Path $evidenceRoot 'comparison-input.json'))
if ($comparison.boundaryCoverage.operatingSystem -ne 'matchedRecordedVersion' -or $comparison.boundaryCoverage.canaries -ne 'measuredStandardUserFileAclOnly') { throw 'The fresh replay did not preserve required OS and file ACL coverage' }
[ordered]@{evidenceRoot=$evidenceRoot; runId=$runId; profileSha256=$ProfileSha256; cleanupVerified=$true} | ConvertTo-Json
