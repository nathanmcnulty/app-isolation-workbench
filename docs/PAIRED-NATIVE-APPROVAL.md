# Reconciliation and bounded native approval request

Request ID: `AIW-PAIRED-NATIVE-F99BBD4-20261030`. Prepared 2026-10-30.
Status: **no native execution authorized or performed**. This supersedes the
previous native proposal. The target-enrollment fields below remain required
before this can become a launch-ready Start request. Publication is separate.

## What the completed goal establishes

The implementation reviewed is `f99bbd49694611cba5105768608d9802ff8f0665`,
with runtime code last changed at `e2e44fe2bf3ca98113618131f4f6d8700354219f`,
on `codex/paired-controls`, atop main `53c02c8` including merged PR #103.
The offline implementation goal is complete. Native acceptance is not complete.

| Goal/path | Implemented production path | Exercised evidence and limits |
|---|---|---|
| Fixed paired preparation | Desktop `prepare_workflow(kind=paired)` -> `paired::assess_with_gate` -> enrolled package agent -> compiled fixed project -> static trusted identity inspection, protected role staging/import and immutable plan | Real staging/custody/import bodies with injected static inspector and fresh protected local fixtures. Production package lookup/Store inspection on VM107 has not been exercised. Preparation never invokes a provider. |
| Approval and dispatch | Actual Controller exact approval challenge, separate Start; `start_approved_windows_sandbox` statically reopens, verifies committed approval, acquires native Sandbox lease, checks current runtime identity and calls shared kernel | Coupled service tests exercise the actual gate coordinator and kernel through `Fixture.dispatch`, `Fake` and `OfflineLease`. They do not call the native Start/lease/transport boundary. Browser replay uses actual Controller snapshots, not native Tauri/provider execution. |
| Native six-case collector | Guest request -> elevated guarded WDAG agent -> held Tools inputs -> fresh standard account/resources -> measured standard-user launcher -> baseline and AppContainer fixed cases | Compiled and source-reviewed; role binaries, real account/profile setup, Win32 process/token/jobs, mapped Tools semantics and six native invocations remain untrialed for this implementation. |
| Cancellation and recovery | Owned cancellation writes the original journal; native leased kernel owns cleanup; cached original run/context only for exact-session recovery | Actual coordinator/journal/session services with strict fake provider responses. The final test-only handshake prevents reading during cancellation publication. No real provider stop/recovery was exercised for this new path. |
| Results and export | Existing retained paired reader/report-set -> bounded ResultsStore -> allowlisted JSON/Markdown exclusive new-file export | Real safe reviewed archive plus protected synthetic paired receipts, full retained-tree snapshots, determinism/negative tests and labeled UI replay. No real native paired report has yet been verified. |

Source anchors at f99bbd4: `crates/aiw-admin-workflow/src/paired.rs:320,400,437`;
`crates/aiw-runner/src/lib.rs:700,1092,1169`;
`crates/aiw-guest-agent/src/main.rs:173`;
`crates/aiw-windows-platform/src/guest_paired_controls.rs:34,57,63,162`;
`crates/aiw-windows-platform/src/control_appcontainer.rs:343,403`;
`crates/aiw-runner/src/offline_rehearsal.rs:178`;
`crates/aiw-admin-workflow/src/paired_rehearsal_tests.rs:104`.

Existing evidence is reused: 678 workspace Rust tests passed, 27 opt-in ignored;
20 desktop tests passed, 4 opt-in ignored; 28 Node tests passed; workspace/desktop
Clippy, formatting, governance and offline builds passed. The runtime-code commit
was e2e44fe; f99bbd4 adds documentation only. Logs:
`C:/aiw/paired-final-root-fixed.json`, `paired-final-gui-fixed-tests.log`,
`paired-final-gui-fixed-clippy.log`, `paired-final-node.log` and the earlier
[handoff](PAIRED-IMPLEMENTATION-HANDOFF.md). No unchanged suite was rerun here.
The new package build/verification is artifact preparation, not a native trial.
New document checks only: both PowerShell blocks parsed; only the selector block
ran against two fresh labeled synthetic non-authoritative locators (ordinary and
verbatim paths), with collision rejection and unchanged input/output bytes.
The worker/UI block was not executed. Record:
`C:/aiw/paired-approval-document-checks.json`. Source/document review found no
remaining consequential issue after the path-spelling correction; no product
source changes or native calls were needed.

Independent source review was reused and extended for this reconciliation. It
found no proven source defect preventing an attempt. Do not weaken held intake
to make the experiment start: mapped Tools must satisfy local fixed-volume,
persistent ACL, stable file identity and nonremote/no-reparse constraints.
A refusal there is an unsupported/incomplete driver result, before guest user or
control-resource setup; failed-driver evidence may still be published.

## Acceptance claim requested

One successful run can accept **the production fixed paired-control profile and
its evidence/reporting integration on the exact measured environment**. It cannot
close full Benchmark 2: [ROADMAP.md](ROADMAP.md), Benchmark 2, still requires a
real-application candidate. This request deliberately authorizes no application
trial. `paired_controls.rs:412` always reports `production_acceptance=false`;
that is intentional, not a defect to remove for a passing label.

Accept only verified native-origin evidence with a complete driver and all six
case observations, exact same-user/OS/fixture bindings, intended root/required
child tokens, unchanged canary bytes/DACLs and executable bytes, verified inner
jobs/profile cleanup, verified exact outer cleanup, and comparison reason
`fixedControlsObserved` with `eligible=true`. A succeeded completion receipt or
process exit alone is insufficient. Broken baseline/driver is inconclusive;
missing/failed/timed-out candidate evidence does not establish denial. No network,
secret/environment/IPC/UI/broker, general host isolation or compatibility claim.
One pair does not establish repeatability across environments.

## Exact target and payload

Controller is VM203, UUID `652a575b-a462-418e-95bb-360b28516925`,
`192.168.1.171`; local read-only inspection confirmed `AIW`, x64 Windows
`10.0.26300.9711`, operator `AIW\labadmin`, SID
`S-1-5-21-3556347314-2314855617-1438300668-1001`.
These observations are **not VM107 pins**. Never restore VM203 or execute the
control roles/AppContainer on the controller.

Proposed Sandbox host is **VM107 only**, historical enrollment `aiw-worker`, UUID
`e5cecc90-35c2-4831-bf9c-424be23f7d4e`, MAC `CC:34:21:B8:5A:31`,
IP `192.168.1.174`, Proxmox `pve-r630`. Verify the current tuple and exclusive
reservation with no foreign/outstanding VM/MSIX/Sandbox lease before mutation.
VM106/passkeys-worker is excluded. This request includes no snapshot restore,
power cycle, baseline provisioning, networking/feature/WinRM/security changes.
Paired code leases the **local Sandbox provider**, not Proxmox VM107: selection
and exclusive reservation of the correct VM are operator preconditions.
It has no direct-VM paired alternative. If nested Sandbox is unavailable, stop;
do not run the inner controls directly on VM107 or fall back to VM203.

Use only existing normal trusted access. If remoting is used, preserve
PowerShell.7.6/Core >=7.6 and HTTPS5986 with existing certificate
`BC14DCC4E37F83161EBB55AF8624E36A79E19256`; no TLS bypass, device-code flow,
new credentials, endpoint registration, ACL widening or feature installation.

Local unsigned package: `C:/aiw/paired-native-review-f99bbd4-20261030`.
- Receipt content commitment: `9c5c1976844f5eb14e459dae166448a8b2bbe06f78b539aeac8153bb3e373109`.
- Desktop `aiw-desktop.exe`: `839b2551fe63afb8a3cf04c57fcbf31036760becc1b6d46ccaba1014f06a1835`.
- Companion CLI `aiw.exe`: `b1e5fb3b518b0fb6e8fefabbf8626d31b8b78896edb85303b5464f89b7d934b9`.
- Verifier script SHA-256: `8398e34b15d2876cc7aa30ca45e59c290468e77afe318ba374b8f3ceab85bcfe`.
- Exact inventory, source f99bbd4 and all three enrolled agent copies verified by
  the existing package builder/verifier. Record:
  `C:/aiw/paired-approval-package-build.json`; compiler/assembly log:
  `C:/aiw/paired-approval-package-build.stderr.log`.
- These are local unsigned development bytes, not a signed/published release.
  The native guest binary is the already retained debug/static-CRT agent; the
  desktop/CLI were newly built offline from clean f99bbd4 in an isolated target.


The same 5,968,896-byte x64 static-CRT guest agent supplies **all three fixed
roles**, SHA-256:
`b5cd415894b5d142215ae9b71f8d619d43404eb2511eb9304ad63f53db097512`.
This is the independently retained `paired-final-agent-build.json` input,
rehashed for this request. No standalone research fixture/launcher binaries are
substituted. Guest role locations are:

- `C:\AIW\Tools\aiw-guest-agent.exe` (elevated WDAG dispatcher).
- `C:\AIW\Tools\aiw-control-fixture.exe` and
  `C:\AIW\Tools\aiw-control-appcontainer.exe` (held read-only mapped copies).
- `C:\AIW\Control\aiw-control-fixture.exe` and
  `C:\AIW\Control\aiw-control-appcontainer.exe` (new guest-local copies).

Control revision: `aiw.dev/paired-file-registry-child/v0alpha1`.
Control-source SHA-256:
`95201a1b89182f699358f2641e8ec47de7a45e2ed56c7fdc1b55418227803f49`.
The package enrollment must contain this `guestAgentControlSourceSha256` and
agent byte hash. The existing packager verifies the compiled CLI source identity;
metadata is producer enrollment, not a proof that arbitrary supplied bytes have
that source. The protected request/guest validates its own current source too.
The package includes inert existing application recipe metadata; this request
permits only **Fixed paired controls**, no installer selection or other workflow.

## Mandatory target fields — currently unavailable, not wildcard approval

No remote worker VM was contacted in preparing this request. Before native approval/Start,
retain VM107's current exact OS tuple and x64 architecture, operator/endpoint
identity, local trusted Store Sandbox package identity/version/publisher,
cache-verified catalog hash/trust, provider canonical file hash/size/file-ID and
static receipt v0alpha8. Required runtime protocol is
`windowsSandboxCli/v0.8.107.0`. Do not substitute historical provider hash
`247e...`, controller VM203 observations or guessed worker OS values.

Prepare/import is static and may bind those fields without a provider invocation.
Feature/virtualization readiness, protocol and absence of current Sandbox sessions
remain explicitly unmeasured until approved Start's leased runtime preflight.
No speculative Start to discover unsupported features is permitted: use a bounded
read-only feature/virtualization check first, and stop if unavailable/unsupported.
Record exact provider/OS commitments in this same request/attached preparation
before presenting the generated literal plan approval and separate Start.
A changed commitment requires fresh preparation/approval, not an in-place edit.
This missing target evidence prevents a launch-ready native approval today.
These are required fields to fill from target observations, not authorization for
any current provider/OS tuple. No execution will occur under blank or inferred pins.

## One bounded operation requested once those gates are complete

Stage the exact verified package to the new VM107 destination
`C:\AIW-Paired-f99bbd4-20261030\Package`; create sibling `Evidence` and
`Exports` directories within that new root. The containing root must not already exist; collision
means stop and choose a newly reviewed destination, never overwrite or clean it.
Verify inventory on VM107 with the exact receipt/source pins below before launch.

```powershell
$ErrorActionPreference = 'Stop'
if ((Get-CimInstance Win32_ComputerSystemProduct).UUID.ToLowerInvariant() -cne 'e5cecc90-35c2-4831-bf9c-424be23f7d4e') { throw 'Wrong VM; stop' }
$pairedAdapter = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True' | Where-Object { $_.MACAddress -ieq 'CC:34:21:B8:5A:31' -and $_.IPAddress -contains '192.168.1.174' })
if ($pairedAdapter.Count -ne 1) { throw 'Worker network identity mismatch; stop' }
$pairedPackage = 'C:\AIW-Paired-f99bbd4-20261030\Package'
$pairedVerifier = Join-Path $pairedPackage 'verify-desktop-package.ps1'
if ((Get-FileHash -LiteralPath $pairedVerifier -Algorithm SHA256).Hash.ToLowerInvariant() -cne '8398e34b15d2876cc7aa30ca45e59c290468e77afe318ba374b8f3ceab85bcfe') { throw 'Verifier drift; stop before executing it' }
$pairedVerified = & $pairedVerifier -PackageRoot $pairedPackage -ReceiptSha256 '9c5c1976844f5eb14e459dae166448a8b2bbe06f78b539aeac8153bb3e373109' -SourceRevision 'f99bbd49694611cba5105768608d9802ff8f0665' | ConvertFrom-Json
if ($pairedVerified.exactInventory -ne $true) { throw 'Package verification failed; stop' }
# Opens only the UI after prerequisite access/staging authorization. It does not
# authorize approval/Start, and no application installer/control is selected here.
Start-Process -FilePath (Join-Path $pairedPackage 'aiw-desktop.exe') -WindowStyle Normal
```

Open the verified desktop visibly on VM107, choose **Fixed paired controls**, use
the existing identified operator and `C:\AIW-Paired-f99bbd4-20261030\Evidence`.
No installer/document is supplied. The guest uses native fixed roles, not the
old PowerShell research control driver. Review immutable recipe/plan and the bound
provider/OS tuple, then approve only its generated exact literal and issue its
separate Start once. Derive every run/workspace/session/challenge value from the
fresh typed `paired-workflow.json`, plan and durable session transaction; never
predict a nonce, adopt a foreign lease or replay a historical ID.

The production path creates **one fresh Windows Sandbox**, with networking,
vGPU, audio/video input, printer and clipboard redirection disabled, Protected
Client enabled and memory 2048 MiB. Only the protected Tools directory maps
read-only to `C:\AIW\Tools`; only that run's Output maps writable to
`C:\AIW\Output`. No other host file mapping or host registry grant.
Both variants share this outer worker; the baseline is in-worker, not an endpoint
baseline. Do not run the old research control scripts or a PR #103 application.

The elevated `WDAGUtilityAccount` agent validates its native origin, token, exact
OS and three held Tools roles before creating `AiwStandardUser`. It creates a
fresh ordinary local user with a generated nonexported password, loads that
user's profile/environment and starts the fixed measured launcher. The ordinary
launcher/targets are non-elevated primary medium-integrity tokens. The candidate
uses fresh `AIW.Control.Paired.v0alpha1`, the same user SID, low integrity,
AppContainer=true and zero capability SIDs. Its required child must match the
same AppContainer SID and user. SIDs are obtained from the fresh native objects
and bound across held/self/child observations, not invented in advance.

| Invocation | Ordinary baseline | AppContainer candidate |
|---|---|---|
| Fixed file read | Success, exactly 29 bytes and approved hash | Native access denied, code 5 |
| Fixed 64-bit registry read | Success, exactly 29 REG_BINARY bytes and approved hash | Native access denied, code 5 at an allowed registry-read stage |
| Fixed child/token mode | Child completes with same-user ordinary medium token | Child completes with same-user low AppContainer token, exact package SID, zero capabilities |

Fixed file: `C:\AIW\Control\SharedCanary\canary.txt`, bytes
`AIW controlled readable bytes`, SHA-256
`6f0427a3e5b44f60867720acaf9f18004f8e1b4bc773bc2b07eaa25cbd692f48`.
Fixed registry: HKLM 64-bit `SOFTWARE\AIWControlCanary`, value `Canary`,
REG_BINARY bytes `AIW controlled registry bytes`, SHA-256
`6d602d862214f8c9e36008aa2d5a94f53432b5d213d5e94ec52345720280bf42`.
The file/key are newly created in the worker; existing names cause refusal.
Their protected DACLs grant SYSTEM/Administrators control and the ordinary user
file/key read access. No package ACE is added to the canary file or registry key.
Both bytes and DACL hashes must remain unchanged through the comparison.

Declared policy difference: classic AppContainer versus ordinary token, with
only package read/execute/traversal ACEs on `C:\AIW\Control`, the fixture image
and `SharedCanary`; read/write/execute with inheritance on
`C:\AIW\Control\AppContainerChild`. That child-output directory has a low
mandatory label for both variants. No capability SID or broader grant is added.
Fixed diagnostic output handles are explicitly inherited, not new canary grants.
Baseline output is cleared before candidate; resource bytes/DACLs remain fixed.

Guest side effects include the fresh account/profile/normal registry hive,
`C:\AIW\Control` directories, exact role copies, canary file/key, bounded
`read-canary-result.json`, `read-registry-result.json`, `child-result.json`,
`child-token.json`, `paired-launcher.json`, and bound completion/evidence files
under Output. The registry handle is closed; canary/account/control-directory
residue is destroyed with the outer Sandbox, not individually certified deleted.
Normal profile unload/environment destruction and scoped guest privilege restore
are separate from AppContainer profile deletion and job emptiness. No canary or
account is created on VM107's host OS or controller.
Host-side permitted changes are the new package/evidence/export roots, protected
run-workspace ACLs/files, existing provider lease/mutex/session bookkeeping,
normal Sandbox ephemeral state, and the desktop
`%LOCALAPPDATA%\AppIsolationWorkbench\Evidence` default parent plus bounded
startup diagnostics under its `Diagnostics` sibling if needed. Do not change existing host/VM security settings.

## Time bounds, stopping and exact cleanup

Code bounds: each fixture invocation 15 seconds; nested child 10 seconds plus
2-second termination wait; launcher 120 seconds; outer guest-launcher cleanup
5 seconds; individual native provider reads <=15 seconds, mutations <=120
seconds; receipt wait 300 seconds. These are per-operation bounds, **not a
300-second end-to-end deadline**. At 15 minutes without settlement, request the
owned cancellation once and preserve custody while its bounded native operation
and cleanup settle. No blind task kill, fresh dispatch or automatic retry.
Allow at most one explicit exact-session recovery attempt if cleanup remains
unknown, with the same 15/120-second native bounds and a five-minute observation
escalation. Persistent unknown state is a stop, not authorization to broaden cleanup.

Stop before dispatch for wrong VM/lease, unexpected existing root/resource,
untrusted package/catalog/provider, unavailable nested Sandbox, drift, unknown
input/approval, occupied session or unsupported protocol/OS. Fail closed on
mapped Tools custody; retain failed-driver evidence, do not relax the reader.
Any baseline/driver failure is inconclusive. Candidate missing error2/3, timeout,
generic failure or malformed evidence never counts as denied. Preserve valid
prefixes; no grant widening, file repair, reinstall or rerun to manufacture success.

On normal/failing completion, the existing kernel terminates/verifies inner jobs,
records fresh profile deletion where observed, stops only the exact journal-bound
Sandbox UUID and verifies absence. Before Start, identity is durable; a lost reply
means may-have-started. Do not retry Start. Owned recovery may reconcile list/stop
for that exact ID; it cannot start/connect/replay another assessment. Never stop
unrelated sessions. If identity/lease or cleanup cannot be established, retain all
records and stop further work/close; no VM restore/power-off or foreign lease
adoption is authorized as a shortcut. Additional intervention needs separate review.
Do not intentionally inject cancellation/crash in this smallest healthy run.

## Results, retained evidence and safe summaries

Production does **not** emit a selection manifest automatically. Its test-only
producer must not be used for native evidence. After the run settles, construct
one explicit entry from the exact fresh typed locator, profile `pairedControls`.
Use this read-only/bookkeeping command against only the new approved evidence
parent (the fresh locator supplies all run values); it writes only a new selection outside retained workspaces:

```powershell
$ErrorActionPreference = 'Stop'
$pairedEvidenceParent = 'C:\AIW-Paired-f99bbd4-20261030\Evidence'
$pairedSelectionPath = 'C:\AIW-Paired-f99bbd4-20261030\Exports\selection.json'
# Bounded shallow lookup in ONLY this newly owned evidence parent: no recursion,
# arbitrary retained-workspace scan, guessed run ID or synthetic test producer.
$pairedRunDirs = @(Get-ChildItem -LiteralPath $pairedEvidenceParent -Directory -Force | Select-Object -First 2)
if ($pairedRunDirs.Count -ne 1) { throw 'Expected exactly one fresh evidence root; stop' }
$pairedLocatorPath = Join-Path $pairedRunDirs[0].FullName 'paired-workflow.json'
$pairedLocatorStream = [IO.File]::Open($pairedLocatorPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
$pairedLocatorReader = $null
try {
    if ($pairedLocatorStream.Length -gt 131072) { throw 'Locator too large' }
    $pairedLocatorReader = [IO.StreamReader]::new($pairedLocatorStream,[Text.UTF8Encoding]::new($false,$true))
    $pairedRun = $pairedLocatorReader.ReadToEnd() | ConvertFrom-Json -Depth 64
} finally {
    if ($null -ne $pairedLocatorReader) { $pairedLocatorReader.Dispose() }
    $pairedLocatorStream.Dispose()
}
if ($pairedRun.schemaVersion -cne 'aiw.dev/paired-workflow-run/v0alpha1' -or $pairedRun.agentSha256 -cne 'b5cd415894b5d142215ae9b71f8d619d43404eb2511eb9304ad63f53db097512') { throw 'Wrong paired locator/agent' }
function Normalize-PairedLocatorRoot([string]$Value) {
    $pairedNormalized = [IO.Path]::GetFullPath($Value)
    if ($pairedNormalized.StartsWith('\\?\')) { $pairedNormalized = $pairedNormalized.Substring(4) }
    $pairedNormalized.TrimEnd([char]'\')
}
if ((Normalize-PairedLocatorRoot $pairedRun.evidenceRoot) -ine (Normalize-PairedLocatorRoot $pairedRunDirs[0].FullName)) { throw 'Locator root mismatch' }
$pairedSelection = [ordered]@{schemaVersion='aiw.dev/application-assessment-input/v0alpha1'; windowsSandbox=[ordered]@{schemaVersion='aiw.dev/wsb-report-set-input/v0alpha1';entries=@([ordered]@{profile='pairedControls';run=[ordered]@{id='native-fixed-pair-1';workspaceRoot=$pairedRun.workspace;runId=$pairedRun.runId;projectPath=$pairedRun.projectPath;guestAgentSha256=$pairedRun.agentSha256}})}}
$pairedSelectionBytes = [Text.UTF8Encoding]::new($false).GetBytes(($pairedSelection | ConvertTo-Json -Depth 16))
$pairedSelectionFile = [IO.File]::Open($pairedSelectionPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try { $pairedSelectionFile.Write($pairedSelectionBytes,0,$pairedSelectionBytes.Length); $pairedSelectionFile.Flush($true) } finally { $pairedSelectionFile.Dispose() }
# This selector is local bookkeeping, not a safe summary or execution authority.
# The existing Results reader must still reverify all bound retained evidence.
```

Open that one-entry selection in Results and inspect all six case/token/hash
observations plus separate inner and historical outer cleanup. Use the actual
Results exporter to create new `Exports\summary.json` and
`Exports\summary.md`, never overwrite or write into retained workspaces.
Keep original plan/approval/preparation/provider/session/evidence/receipt bytes,
full native tokens, request hashes, input hashes and failures locally. Summary
exports alone use the privacy allowlist: no raw artifacts/tokens, account IDs,
credentials or absolute private paths. No cleanup of retained inputs is authorized.

## Approval status and publication boundary

Package preparation is local and unsigned; nothing was pushed, published, signed,
installed or released. VM107 was not accessed, authenticated to or modified here.
No provider/application/control was executed by this reconciliation.

A native Start approval cannot honestly be requested as launch-ready until VM107's
current static enrollment and read-only feature/virtualization facts are retained.
The immediately reviewable prerequisite authorization is: access VM107 through its
existing trusted route solely to verify identity/exclusive reservation, inspect
those read-only facts, stage/verify this pinned package, and perform non-executing
preparation; **stop before literal plan approval or Start**. This fills this same
consolidated request rather than inventing the missing target hashes. Existing
session restrictions prohibit VM access without that authorization.

Once the target fields are filled, the single native scope above is one fresh
six-case paired assessment and only its necessary owned cleanup/recovery, with
exact plan approval and separate Start. It is a control-profile acceptance gate
supporting Benchmark 2, not full Benchmark 2 or W4/W5 closure. Publication, hosted
release/PR creation, application trials and broader acceptance remain separate.
