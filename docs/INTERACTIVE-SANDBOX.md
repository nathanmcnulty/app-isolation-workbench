# Scratch-only interactive Notepad++

The fixed interactive profile installs Notepad++ inside a disposable Windows Sandbox and opens a blank editor as `AiwStandardUser` with a verified medium-integrity token. Close the editor normally when finished. Its approved lifetime starts after the exact application window and token are observed; expiration terminates the process job, verifies cleanup, and records an unsuccessful attempt. An unsaved-document prompt does not extend the deadline.

The example allows five minutes; `waitForUserClose.timeoutSeconds` accepts 30–600 seconds. The host's total `run start --timeout-seconds` can cancel earlier. Changing the project, lifetime, application, guest agent, or compiled scenario requires fresh preparation and approval.

## Data and runtime contract

- No user-selected host folders are mapped. Network and clipboard are disabled. The existing fixed tools and untrusted protocol-output mappings remain necessary for verified execution.
- The default profile opens scratch data only; it disappears when the worker stops. An explicit transfer run may copy one bounded UTF-8 text file into the worker and retain one receipt-bound output artifact. It never maps a personal folder, preserves an original, or installs the application persistently.
- Closing the remote desktop viewer alone is not the recorded application-close contract. Close Notepad++ or use the existing cancellation/recovery commands; the owned worker is stopped and its absence checked.
- The viewer connects to the existing Sandbox desktop. The application runs as the separately verified standard user on that shared desktop. This is outer Sandbox containment, not AppContainer or a separate desktop security boundary.

Microsoft documents that [`wsb connect`](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-cli) opens the remote desktop and that [`CreateProcessWithLogonW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw) requires the target user's access to the inherited window station/desktop. The native launcher reuses its existing SID/session checks, desktop grant, suspended creation, and kill-on-close job assignment.

## Prepare, review, and launch

Use `examples/notepad-plus-plus-interactive.aiw.yaml` as the source project when exporting a [Sandbox bundle](SANDBOX-BUNDLES.md). The bundle manifest selects the distinct interactive profile and `ephemeralInteractiveScratch` data contract. Keep the expected manifest hash independently. Import it and save the complete import record, its project, and its intake receipt as described there.

Build the production guest with `scripts/build-guest-agent.ps1` and retain its independently verified hash. Use separate existing intake and run parent directories. Substitute your actual paths below; these commands never install the application on the host.

```powershell
$runId = 'interactive-' + [guid]::NewGuid().ToString('N')
$project = '<absolute replay-project.json path>'
$guest = '<absolute production aiw-guest-agent.exe path>'
$guestHash = '<independently verified lowercase SHA-256>'
$prepared = aiw run prepare-wsb-msi --run-id $runId --project $project `
  --guest-agent $guest --guest-agent-sha256 $guestHash `
  --workspace-parent '<existing absolute runs directory>' `
  --import-receipt '<absolute replay-intake.json path>' `
  --scenario install-launch-close --created-at ([DateTime]::UtcNow.ToString('o')) |
  ConvertFrom-Json
$workspace = $prepared.receipt.workspace.root.finalPath

aiw run import-prepared-wsb --workspace $workspace --project $project `
  --guest-agent-sha256 $guestHash --imported-at ([DateTime]::UtcNow.ToString('o'))
$prepared.runPlan | ConvertTo-Json -Depth 64
```

To exercise the bounded document-transfer profile, add `--document-input` to
`prepare-wsb-msi`. The path must be an existing ordinary file that is absolute,
canonical, valid UTF-8 with no NUL byte, and at most 1 MiB. The file is copied
into the worker as the fixed `C:\AIW\Tools\document-input.txt`; the application
must save the edited bytes to the fixed `C:\AIW\Output\document-output.txt`.
This changes the compiled scenario and therefore requires its own preparation
and approval.

Review the plan's `launch` lifecycle, exact scenario binding, lifetime/data warning, and mapped-folder warning before creating approval. Approval is a local immutable record, not an independent administrator attestation. Use a new output file:

```powershell
$approvalPath = Join-Path $env:TEMP "$runId.approval.json"
@{
  schema = 'aiw.dev/approval-record/v0alpha1'
  runId = $runId
  planHash = $prepared.receipt.runPlanSha256
  trustDeltas = @($prepared.runPlan.trustDeltas)
  approvedBy = $env:USERNAME
  approvedAt = [DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 16 | Out-File -LiteralPath $approvalPath -Encoding utf8 -NoClobber
aiw run approve --root $workspace --run-id $runId --approval $approvalPath
aiw run start --root $workspace --run-id $runId --project $project `
  --guest-agent-sha256 $guestHash --timeout-seconds 900
```

`run cancel` persists a cancellation request; the running execution loop handles exact cleanup. If interrupted, use the existing `run recover` command against the same workspace/run ID. Do not delete the workspace as a substitute for recovery.

## Reporting

Use `run report-wsb-msi-run` or `package report-wsb-msi`, with `--format json` or `markdown`. Normal exit produces `reportKind: interactiveSession`, including window/process observation, standard-user token/context, the duration limit, and recorded cleanup. It does not prove that a human typed, that a document workflow passed, or that an inner isolation boundary was effective. Timeout/cancellation/errors remain unsuccessful attempts; their duration is identified and guest diagnostics remain explicitly unverified.

The old `report-wsb-msi` assessment-only command rejects interactive sessions. Assessment report sets identify them as `interactiveSessionNotAssessment`, including unsuccessful interactive attempts. A successful transfer report has `schemaVersion: aiw.dev/wsb-msi-interactive-report/v0alpha2`, includes `documentTransfer` input/output hashes and sizes, and verifies the separate `document-output.txt` receipt artifact. The output is not copied to the host automatically. Export it only after reviewing the report:

```powershell
$destination = Join-Path (Get-Location) 'notepad-plus-plus-output.txt'
aiw run export-wsb-msi-document --root $workspace --run-id $runId `
  --project $project --guest-agent-sha256 $guestHash `
  --destination $destination
```

Export requires a successful transfer report, creates one new ordinary host
file, refuses an existing destination, rejects destinations inside the retained
worker, and reopens the destination to verify the exact receipt-bound bytes.
The automated v6 document benchmark remains separate and retains its prior wire
hashes and evidence semantics.

## Validation

Compiler/result checks bind lifetime to request hashes, reject out-of-range lifetimes and profile substitutions, and distinguish normal process exit from an agent-requested graceful close. Launch-lifecycle approval cannot reuse an assessment approval. Live tests also reject a changed duration after approval, verify package/report association, and check that interactive sessions do not enter assessment matrices.

The production 30-second timeout trial passed in workspace `%TEMP%\aiw-msi-live-20348-1789106512437843700`, with the controlled timeout diagnostic, unsuccessful terminal report, verified cleanup, and no remaining Sandbox sessions. Production static guest SHA-256: `40a2670060ee220623b2a532a04812f1948a60c5663fb455ce4ddc85fb968bab`. Log: `%TEMP%\aiw-interactive-timeout-live2.log`.

Normal-exit validation uses a separately built test-only guest from branch `codex/interactive-close-fixture`, commit `16db54f`. After readiness it waits two seconds, revalidates the exact HWND/PID, then requests close. That fixture is not production code and is not proof of human keyboard/mouse interaction. Its guest SHA-256 is `ec50a81c8e021a2f7c446c1311e314027f8a090a87f9cfaf4478e26aa00468d6`. Do not distribute the fixture as an interactive launcher.

The fixture passed in `%TEMP%\aiw-msi-live-6292-1789106704113934700`: distinct interactive-session report, medium non-elevated application token, no agent-requested close claim in the production result, exact cleanup, and no remaining worker. The test also rejected changing 120 to 121 seconds after approval, reverified the bundle/report association, and excluded the session from assessment reports/sets. Log: `%TEMP%\aiw-interactive-close-live.log`. Human keyboard/mouse usability remains a manual check.

The existing automated v6 document workflow also passed with the production guest in `%TEMP%\aiw-msi-live-10200-1789106900262168000`: install/open/edit/save/close, exact saved bytes, all nine stages, standard-user token, registration/capture evidence, and verified cleanup. Log: `%TEMP%\aiw-interactive-baseline-live.log`.
