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
into the worker as the fixed `C:\AIW\Tools\document-input.txt`. The editor opens
its working copy at
`C:\Users\AiwStandardUser\AppData\Local\AIW\Scenario\document.txt`; save normally
to that file and close the editor. The guest agent then publishes the verified
bytes as `C:\AIW\Output\document-output.txt`.
This changes the compiled scenario and therefore requires its own preparation
and approval.

The portable bundle remains a scratch recipe. `package report-wsb-msi` also
accepts its approved document-transfer specialization: the original project,
MSI intake, scenario ID, commands, and lifetime must still match. The staged
input hash and size are additional run-specific approval commitments.

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

The old `report-wsb-msi` assessment-only command rejects interactive sessions. Assessment report sets identify them as `interactiveSessionNotAssessment`, including unsuccessful interactive attempts. A successful transfer report has `schemaVersion: aiw.dev/wsb-msi-interactive-report/v0alpha2`, includes `documentTransfer` input/output hashes and sizes, and verifies the separate `document-output.txt` receipt artifact. The output is retained in the host run workspace. Export to a separate user-chosen file only after reviewing the report:

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

Successful transfer execution uses
`aiw.dev/wsb-interactive-msi-execution/v0alpha2`; scratch-only execution keeps
`v0alpha1`. Execution, retained reporting, and export share the same document
byte verifier. The receipt artifact media type is `text/plain`; bounded UTF-8
without NUL bytes is enforced separately, including for empty documents.

## Validation

The transfer regression uses synthetic readiness and a simulated worker with a
real protected Windows workspace. It exercises preparation construction,
approval/journal binding, completion verification, retained and bundle reports,
and exact export. Negative cases cover conflicting output hashes/sizes, changed
input binding, invalid UTF-8, NUL bytes, missing output, scenario changes,
overwrite, in-workspace destinations, and retained-output tampering. A separate
guest publication test checks that its receipt is accepted by the host artifact
contract without adding a newline to document bytes. These tests do not start
Sandbox or prove human interaction. The production human trial below supplies
the separate live edit/save/export acceptance evidence.

The 2026-09-12 human-transfer attempt in
`%TEMP%\aiw-human-transfer-20260912-202251` failed before viewer connection:
the provider start operation exceeded its 120-second deadline
(`AIW_WSB_CLI_TIMEOUT`). The user observed no Sandbox window. The durable
transaction recorded `start-response-lost` followed by `cleanupVerified`;
no guest results or exported document were produced. `trial-outcome.json`
and `final-status.json` retain the outcome alongside the preparation, approval,
and execution error. This attempt supplies no human edit/save/export evidence;
the later investigation below invalidated the empty-list cleanup assumption.

The instrumented reproduction in `%TEMP%\aiw-startup-diagnostics-20260912-203633`
repeated the startup failure at 2026-09-13 03:38 UTC. Its protected
`provider-diagnostics.jsonl` records successful enumeration, the exact start
arguments, PID 23484, a 119373 ms process wait, empty stdout/stderr, and successful
cleanup with two empty provider lists. This does not identify the underlying
host cause. The host collector recorded the Hyper-V Compute/Worker channels as
unavailable without elevation; a canceled elevation request did not collect them.

The user subsequently collected elevated events. They show successful OS boot
at 03:38:34 UTC, a guest-initiated reset at 03:40:14, and another OS boot at
03:40:19, just before the CLI deadline. The installed SDK defines compute result
`0xC0370103` as `ERROR_VMCOMPUTE_OPERATION_PENDING`, not a startup failure.
Provider identity and fixed Sandbox configuration match the earlier successful
MSI run. A diagnostic 300-second start allowance in
`%TEMP%\aiw-startup-budget-20260912-213924` also timed out with empty CLI output;
that experimental allowance was reverted rather than promoted as a fix.
The host progressed from `vmmemCmSysprep` to `vmmemCmFirstBoot`, which continued
after exact public-session absence was verified. Its initialization VHD remained
active and grew. No initialization process or service was manually stopped.
`initialization-observation.json` and the provider trace retain this distinction:
application-session cleanup is not proof that Windows image initialization ended.
The later elevated collection established that initialization finished at
04:54 UTC, about 13 minutes after launch. Windows then created the queued
application session despite the CLI having timed out. Its exact public UUID
`13ff9896-29ba-f886-6055-65efd76f37c9` and the mapped workspace matched the failed
attempt; it was explicitly stopped and the empty provider list retained in
`late-session-after.json`. The earlier `cleanupVerified` claim was incorrect.

An unacknowledged start now remains `recoveryRequired` even after empty lists.
Recovery retains the request and requires an observed exact-session stop before
declaring cleanup. Status and reporting reject historical clean markers lacking
start acknowledgement or observed-stop evidence. Such historical terminal
records require manually corroborated recovery; automated recovery does not
reopen terminal state or assume a reused UUID belongs to the original attempt.
The late-start regression covers absence during failure and recovery, followed
by the session appearing and being stopped. A new warm-image production start
in `%TEMP%\aiw-warm-transfer-20260913-104712` returned in 4943 ms with the original
120-second startup limit. It reached the interactive wait, then hit the
600-second editor deadline and cleaned up without human completion.

### Completed human transfer trial, 2026-09-13

The fresh production retry in `%TEMP%\aiw-warm-transfer-20260913-153808`, run
`human-transfer-265153547df94d7a81bc1422381f0f75`, completed successfully. Nathan
reported editing and saving the staged document, closing Notepad++, and observing
the Sandbox close automatically. The production guest was
`2efe167e1285a9cec154bfeb25d0ec87cb0eb0ea4729c50fff2b7e361fb53ff7`.
Installation and editor exit codes were zero; the editor ran as a non-elevated
standard user. The runner verified cleanup, and the final provider list was empty.

The retained report and bundle report both reverified the interactive transfer.
Explicit export produced `exports\edited-document.txt` containing
`Status: completed` and `Edited and saved by Nathan`. Its 145 bytes hash to
`fc84ae6cb67fcbf527c376d6ce87c11a0bb41d50f3d5348aef1f2d6bc4ed6831`.
The original 117-byte input remained unchanged. Execution, report, bundle report,
and export agreed on the input/output bindings. `trial-outcome.json` records the
independent exported-byte check and human observation; `execution.json`,
`report.json`, `bundle-report.json`, `export-result.json`, `final-status.json`, and
`final-provider-list.json` retain the underlying evidence in that trial directory.
This completes the bounded human transfer benchmark; it does not establish an
inner application isolation boundary or resolve cold-image startup latency.

## Startup diagnostics

Production `run start` retains `runs/<runId>/provider-diagnostics-<pid>-<timestamp>-<sequence>.jsonl` in the
protected host workspace. Each attempt creates a new trace, including retries after a failed preflight; the CLI prints its path to stderr. Each provider operation records its arguments (including rendered
configuration), UTC timestamp, deadline, elapsed time, and captured output or
failure. Timeout errors retain the process ID, stream errors, and cleanup errors
instead of dropping them. Capture remains bounded to 64 KiB per stream. Viewer
connection intentionally discards its streams because the viewer inherits their
handles; this is explicitly recorded. Logs are diagnostic observations, not
verified guest evidence or recovery authority. A diagnostic write error is
reported to stderr and does not prevent session cleanup.

Collect correlated host events with the read-only script below. Use an elevated
PowerShell for Hyper-V channels and a new output directory. The collector records
access errors separately from no matching events and marks the 1000-event cap.
It neither enables channels nor changes services or worker state.

```powershell
./scripts/collect-sandbox-diagnostics.ps1 `
  -StartTime '2026-09-13T03:38:15Z' -EndTime '2026-09-13T03:40:35Z' `
  -OutputDirectory "$env:TEMP\aiw-startup-host-events"
```

The log handle excludes other writers and deletion. For live reading, a reader
must open with read access and `FileShare.ReadWrite | FileShare.Delete`; this
shares the existing writer's rights without granting the reader write access.

Diagnostics validation: native platform suite 154 passed (9 ignored), runner
suite 88 passed (16 ignored), final report/export trace-retention regression,
CLI build, warnings-as-errors Clippy, formatting, and governance passed. A final
negative-transfer test encountered `Access is denied` during fixture creation;
its unchanged isolated retry passed. Incremental compilation also reported
nonfatal cache-finalization access errors. These host observations are retained
in `%TEMP%\aiw-launch-*.log`; their cause has not been established.

Compiler/result checks bind lifetime to request hashes, reject out-of-range lifetimes and profile substitutions, and distinguish normal process exit from an agent-requested graceful close. Launch-lifecycle approval cannot reuse an assessment approval. Live tests also reject a changed duration after approval, verify package/report association, and check that interactive sessions do not enter assessment matrices.

The production 30-second timeout trial passed in workspace `%TEMP%\aiw-msi-live-20348-1789106512437843700`, with the controlled timeout diagnostic, unsuccessful terminal report, verified cleanup, and no remaining Sandbox sessions. Production static guest SHA-256: `40a2670060ee220623b2a532a04812f1948a60c5663fb455ce4ddc85fb968bab`. Log: `%TEMP%\aiw-interactive-timeout-live2.log`.

Normal-exit validation uses a separately built test-only guest from branch `codex/interactive-close-fixture`, commit `16db54f`. After readiness it waits two seconds, revalidates the exact HWND/PID, then requests close. That fixture is not production code and is not proof of human keyboard/mouse interaction. Its guest SHA-256 is `ec50a81c8e021a2f7c446c1311e314027f8a090a87f9cfaf4478e26aa00468d6`. Do not distribute the fixture as an interactive launcher.

The fixture passed in `%TEMP%\aiw-msi-live-6292-1789106704113934700`: distinct interactive-session report, medium non-elevated application token, no agent-requested close claim in the production result, exact cleanup, and no remaining worker. The test also rejected changing 120 to 121 seconds after approval, reverified the bundle/report association, and excluded the session from assessment reports/sets. Log: `%TEMP%\aiw-interactive-close-live.log`. Human keyboard/mouse usability remains a manual check.

The existing automated v6 document workflow also passed with the production guest in `%TEMP%\aiw-msi-live-10200-1789106900262168000`: install/open/edit/save/close, exact saved bytes, all nine stages, standard-user token, registration/capture evidence, and verified cleanup. Log: `%TEMP%\aiw-interactive-baseline-live.log`.
