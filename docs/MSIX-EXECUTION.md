# Production VM MSIX execution

Current execution requires an observed stable x64 Core 7.6+ machine runtime on controller and worker, the explicit `PowerShell.7.6` HTTPS endpoint, and a new approved cold baseline containing both. Preparations and receipts bind those runtime identities. See the [setup and acceptance plan](handoffs/2026-10-24-powershell76/SETUP-AND-ACCEPTANCE.md); the historical baseline and completed trials below do not establish acceptance of this migration.

Validated 2026-10-22: the production desktop drove a fresh approved run on VM107,
collected native lifecycle evidence and completed cold restore/clean readback.
The original-host desktop and shared assessment reader reverified the retained
run. This acceptance covers the exact supported recipe below.

The first supported recipe is the exact signed Notepad++8.9.8.0 MSIX already
measured in r5. It uses a dedicated QEMU worker107 on pve-r630, not local execution
on development203 and not the Sandbox activation route that failed in research.
No106 mutation. No arbitrary package/command/script/provider verbs.

Host-owned execution requirements:
- Extend held file/protected intake with a distinct MSIX kind; package signature,
  fixed recipe, exact bytes and full220payload assembly remain separately checked.
- A v0alpha6 RunPlan action ExecuteVmMsix binds protected preparation, worker
  identity/checkpoint, package and helper. Approval and Start both reopen and hold
  workspace/tools/import receipt and reject drift. Existing WSB provenance remains.
- New fixed guest agent consumes a strict run/plan/nonce/worker/input/deadline
  request, keeps input handles, uses an already signed-in fresh standard user,
  verifies suspended token/session/image before resume, owns child jobs, executes
  a measured exit42 control before app mutation, and publishes receipts last.
- Reuse the r5 lifecycle checks as a shared pure verifier in aiw-evidence, called
  by guest and host; historical research harness delegates there too. Raw files
  remain authoritative; the report projection does not create another verdict.
- Host transport uses normal validated HTTPS WinRM (no SkipCACheck), exact guest
  UUID before mutation and saved DPAPI credentials. Private credentials are not
  staged or exported. Enroll public server certificate outside run approval;
  verify the known leaf before trusting it. Production handshake must validate.
- Proxmox forced command remains107-only. Add a narrow nonce-bound durable lease
  outside guest snapshots, pinned checkpoint/config proof, fixed NIC isolation,
  shutdown, exact TLS-clean restore/start/reconnect and lease release. Lost
  dispatch responses never cause automatic re-execution. Recover only same nonce.
- Record start intent before guest dispatch. Collect bounded hash-verified
  evidence even on failure before cold restore. Verify restored clean guest UUID,
  account/package/process/task inventory and TLS before terminal cleanup/result.
  A crash retains durable lease and recovery-required state; no silent adoption.
- Desktop adds MSIX selection, distinct review disclosures, existing approval
  challenge and separate Start, editing/restoring/recovery states, and retained
  report. The measured function workflow never upgrades broader isolation.

Current implementation:
- aiw-probe/msix_worker: fixed profile, request, deadline and phase contracts.
- aiw-orchestrator/vm_msix_plan: v0alpha6 plan and held preparation provenance.
- aiw-msix-worker + windows-platform/msix_vm_worker: native SYSTEM controller,
  primary-user control and fixed application child; atomically published receipts.
- aiw-evidence/msix_lifecycle: shared pure lifecycle verification; r5 archive
  positive proof and missing/document/session negatives preserve historical checks.
- admin-workflow/msix: host execution and exact-nonce recovery. Application
  dispatch never retries. Authenticated completed-nonce readback resolves a lost
  release reply. An unresolvable acquisition failure remains recovery-required;
  absence is never inferred from SSH failure.
- scripts/vm-msix/proxmox-worker107.sh:107-only cold TLS checkpoint and durable
  lease. `restore -> connect -> begin` consumes the clean marker before mutation;
  another restore is required before release. `completed` reads the retained nonce
  audit only. Mock tests cover wrong UUID/nonce/checkpoint, pending config drift,
  failed rollback, stale clean marker, nonce reuse, and post-operation config SHA.
- scripts/vm-msix/transport.ps1: fixed normal HTTPS WinRM verbs, protected staging,
  one-time account, SYSTEM scheduling, bounded receipts/status/export. Saved DPAPI
  credential stays outside evidence. No SkipCACheck, arbitrary command or script.
- runner/vm_msix_report: original-host raw evidence re-verification, control/job/
  privileged inventory/artifact bindings, pure recovery proof gate before terminal
  cleanup, and shared function matrix. Overall remains insufficient evidence.
- desktop: distinct signed-MSIX choice, review/Start, backend progress including
  console-edit instructions, retained report and exact-lease recovery action.
- build-msix-desktop-package.ps1: clean-source native/desktop release build,
  fixed assembly/signing hashes, the native worker SHA compiled into the host, asset inventory and receipt-last development
  package. Other Sandbox recipes require their separate product assets.

Live acceptance includes clean-source package builds, normal trusted HTTPS,
the deployed fixed wrapper, cold restore/current-pending agreement, exact lease
recovery, clean inventory/release, native account enrollment/control, packaged
editing/uninstall and original-host raw verification. Retained failures and their
corrections are recorded below; they are not substituted for the successful run.

Live corrections and retained failures (2026-10-22):
- msix-1792693343407226300 failed before staging on Windows PowerShell verbatim
  paths. The host now converts only the held path's verbatim prefix at that
  boundary. Recovery also exposed the missing Tauri command capability and
  inherited PowerShell7 module paths; both were corrected. Exact retained-lease
  recovery completed19:24:15UTC without application replay.
- msix-1792697332610735000 enrolled the standard user but exhausted the150second
  reboot wait before Control. Read-only cold/reboot waits are now6minutes. Raw
  enrollment evidence and successful cold cleanup/release were retained. A folder
  was incorrectly passed as the optional generic evidenceRoot hash; omitting it
  fixed terminal publication. Completed-nonce finalization at19:51:13UTC did not
  repeat a restore or dispatch. Execution errors are retained before collection.
- msix-1792699084357230000 reached the standard session and cleared temporary
  sign-in, but Control rejected Windows cmd.exe's servicing hardlinks. A private
  OS-image opener retains the pinned digest, non-reparse directory/file handles
  and write/delete denial through job cleanup. Application single-link intake
  remains strict. Cold cleanup/release completed20:15:02UTC.
- msix-1792700924025223800 (d203590) passed native Control42 and job cleanup, then
  failed before installation because the generated lifecycle prelude omitted the
  driver-control function wrapper.14e5691 restores the wrapper/parameter. Native
  Windows PowerShell AST checks now parse exact generated scripts and require
  driver references to remain inside the explicitly invoked function. Cold
  cleanup/release completed20:45:03UTC.
- msix-1792702354519093600 (14e5691) passed Control, packaged install/console
  editing/save53bytes/close/uninstall and child exit0/job cleanup. Native capture
  rejected ordinary generated8.3 aliases, so full raw lifecycle bytes were not
  retained and this is not a verified production lifecycle report. Failure/job
  receipts were collected; cold cleanup/release completed21:15:17UTC.34369c9
  adds a private read-only held evidence tree: long names only, case-collision
  rejection,512entries/16MiB aggregate/4MiB file/depth16 bounds, and retained
  parent-relative fileID/path/hash/nonreparse/stream/single-link checks. One bounded
  file may be hashed before the aggregate limit is rejected; no excess is copied.
  The public portable-input alias policy remains strict.16source-inspection and
  3worker tests, Clippy and independent review passed.

All failed runs remain under the original host's default Evidence directory.
Never replay any of their nonces. Packages/logs are outside the repo under
C:\AIW-Resume-20261021\production-msix-*; source is pushed on
codex/new-vm-handoff-20261021. No credentials or private keys are included.

Run msix-1792704525359564000 (34369c9) completed the native lifecycle and retained
44inventoried evidence files, with independent hash/binding audit. Document SHA
91b82efd755bd5a46b47f6277bd050954b9fb3e78e56f9f086129d04da4dbd42,53bytes;
220payloads unchanged;6configuration copies retained; standard medium packaged
process/job and uninstall absence checks passed. Final cold clean/release and
terminal receipt completed21:52:19UTC. The retained reader initially hit the same
alias assumption on host output; it now uses the bounded held evidence API with
bytes read directly from retained handles, hashed and revalidated. This exposes
no portable-import or exact-disposal authority. Re-read this run for report proof;
never repeat its application dispatch or recovery.

Final acceptance and readback:
- Execution: msix-1792704525359564000, desktop source34369c9, worker SHA
  cf2ef6402ca33c51dd8a7d85cff42132a163f396e92c67b852d93852e5c3a7c9.
  Native Control42 and the same standard-user logon preceded application work.
- Final clean readback21:52:05UTC confirmed UUID107, the seven baseline accounts,
  no trial artifacts and disabled automatic sign-in. Release/terminal receipt
  completed21:52:19UTC. The provider reports leasePresent=false for this nonce.
- Reader correction2dab30b exposes only bounded read-only evidence bytes, with
  no portable-import or disposal authority.16platform checks, the runner recovery
  gate check, Clippy and clean-source static-CRT builds passed. Independent review
  verified44/44native inventory hashes, exact document,220payloads,6retained
  configuration files, process/session/control and uninstall/job correlations.
- Shared assessment command on original VM203:
  `target/debug/aiw.exe run report-assessment --input C:\AIW-Resume-20261021\production-msix-capture-assessment-input.json --format json`.
  Output C:\AIW-Resume-20261021\production-msix-verified-assessment.json SHA
  a77d20d064d991f708160938b2b7c6c38d0add4a642230bd5805393ca24fc0ab.
  Install, launch, openDocument, editSaveDocument, close and uninstall are true;
  workflowVerified and cleanupComplete are true. The overall assessment remains
  insufficientEvidence, with compatibility/isolation notMeasured.
- Desktop readback: production-msix-desktop-reportfix, source2dab30b, receipt SHA
  6ee705592eb2c7795b0d6a1dfbe8ca05cde26af987682e735b61219ea40e93c4,
  inventory6files verified. Its read-only retained MSIX screen displayed
  **Supported workflow verified** and the six functions/cold-recovery summary.
  No guest dispatch or recovery was repeated for reader validation. This package
  is an unsigned development desktop; leave the migration release draft.

## PR103 independent review corrections, 2026-10-23

The four P2 findings against23b3c52 are addressed for a new review checkpoint:

- Both ordinary and resumed recovery atomically publish a request/nonce-bound
  `recovery-release-intent.json` with restore, connect and clean proofs before
  releasing the external lease. A lost release reply or interruption after release
  is finalized using that exact attempt and the provider's completed nonce.
- Collection first validates a bounded, quiescent, completely enumerated export,
  flushes its original bytes, and atomically publishes a hash-bound completion
  receipt. Materialization and lifecycle verification are separate. A failed
  lifecycle can clean up after its raw export is retained; an export failure keeps
  the guest and exact lease for explicit read-only collection/recovery retry.
  Explicit recovery also collects before rollback after a host crash. Native work
  still running, enumeration errors, partial export or missing export proof prevent
  rollback. No application dispatch retry or automatic evidence discard is added.
- Retained MSIX reporting uses the non-repairing committed terminal snapshot.
  Torn journal tails, missing heads and pending terminal publication are rejected
  without repairing files, creating entries or committing pending mutations.
- After reboot, read-only `Ready` checks the enrolled SID/nonce, actual Explorer
  session, WTS Active state and loaded SID profile before the one-shot Control.
  Temporary session/profile absence is polled within the bounded deadline;
  contradictory identity/session state fails without Control dispatch.

Failure-injection regressions exercise the actual host recovery/export/readiness
helpers with fixed mock operations, including lost release replies, interruption
after release, failed collection followed by read-only retry, incomplete export,
failed lifecycle with retained raw diagnostics, delayed logon, timeout and wrong
SID/session. Report regressions compare every file's bytes and directory entry
before and after malformed-journal reads. PowerShell5.1 parses the fixed transport
and compiles its read-only WTS observer during tests. These are mock/source tests,
not fresh live application acceptance.

A normal-TLS read-only `Ready` probe against cold-clean VM107 correctly rejected
the absent run-owned account on the exact worker UUID. No Control, application or
recovery operation was dispatched. The October22 complete lifecycle remains
historical evidence at its recorded source revisions; this checkpoint does not
claim a repeat of that full desktop/application trial.

Checkpoint validation:10 MSIX administrator regressions and5 retained-report
checks passed; workspace/all-target Clippy with warnings denied and governance
checks passed. The rebuilt CLI read the original successful run with
workflowVerified/cleanupComplete true and every retained directory entry/file
hash unchanged. Logs and readback are outside Git under
`C:\AIW-Resume-20261021\pr103-final-*`, `pr103-fixes-report-regressions.log`,
`pr103-live-readonly-readiness.log` and `pr103-retained-report-readback.json`.
Full checkpoint verification/audit/desktop checks are supplied by the PR's fresh
hosted CI run; earlier green CI at23b3c52 does not attest to these changes.

## Authoritative export and old preparation recovery checkpoint

The collector now captures the nonce-scoped original under the run-owned SID's
local profile, independently of the native controller's `evidence` or
`failed-evidence` copies. Directory ancestors and source files remain held while
the raw tree is read and revalidated; reparse entries, hardlinks, named streams,
changed entry sets and existing size/count/depth violations fail closed. The
export binds every `raw/` file's path, bytes and hash to a separate raw manifest.
Host or guest application-dispatch evidence requires that original source to be
present. Missing or partial controller copies cannot stand in for it. Running
or queued tasks prevent collection/rollback.

Recovery of older approved preparations still verifies and holds their original
plan, approval, agent, request, transport, signing metadata and imported package.
It runs a separately held helper from the current host's compiled source under
`output`, restricted by the backend to read-only Collect/Clean. It never replaces
approved tool bytes or enrolls a new agent. A legacy `collection-complete.json`
remains retained but cannot authorize rollback: the current collector must publish
the independently checked `collection-authoritative-complete.json` first.
Existing pre-release cold proofs can still finalize an already restored/released
nonce without repeating rollback or application execution.

The actual PS5.1 Collect body is exercised in CI by
`scripts/vm-msix/tests/test-authoritative-export.ps1`: crash before controller copy,
old-format and partial caches, queued/running tasks, missing dispatched source,
profile enumeration failure, exclusive-lock read failure and successful read-only
retry. Host regressions check unchanged old prepared inputs, separate compiled
helper identity, rejection of mutating helper verbs, legacy-marker rejection and
authoritative inventory completeness. Tests use isolated local fixtures; they do
not repeat the historical full desktop/application trial.

Checkpoint validation: all14 MSIX host/transport regressions, workspace/all-target
Clippy with warnings denied and governance checks passed. A normal-TLS read-only
Collect against cold-clean VM107 returned complete enumeration with an explicitly
absent raw source; every file hash under the old approved tools directory stayed
unchanged. That absence would not satisfy a host-recorded application dispatch.
No application or rollback was dispatched. Logs:
`C:\AIW-Resume-20261021\pr103-authoritative-final-*` and
`pr103-authoritative-live-readonly.json`. Hosted checkpoint CI remains separate
from these focused tests and the historical full application acceptance.

## Bounded Windows acceptance after f30c80e, 2026-10-24

Run `msix-bounded-1792816990610240800` is separate from the October22 full
application trial. The ignored, explicitly opted-in acceptance harness exercises
VM107 using a fresh approved preparation with the older transport from23b3c52
(SHA006c069a056c81ff8cd3232f1ceb33dc808f070edb070725e7854fb057e62813)
and retained native agent (SHA8ce377e1b1e826e4a9115f949b3e4dd85e28c32b3f1541887ffb93a01e55a472).
It runs only enrollment, fixed native Control42, inert raw-file fixtures,
read-only collection and exact cold recovery; it cannot dispatch application Run.

Unmodified f30c80e did not pass the initial live clean inspection. The separately
compiled recovery helper was held with write/delete authority, which prevents
ordinary PowerShell readers from sharing it. Production correction1879c77 holds
the exact output child read-only, verifies compiled bytes and retains identity
through execution. Its PS5.1 regression reads/parses the held helper while a
mutating reopen is rejected. The same lease resumed before enrollment; acquire,
restore and connect were not repeated. Native readiness/Control completed there.
Two subsequent harness-only interruptions (uppercase evidence leaf, and .NET's
ADS path rejection) are preserved. Explicit, exact-stage resumes skipped all
previous mutations and completed only the missing fixture setup. The fixture
now uses PS5.1's stream API. Final fixture/recovery source is abd17ea; the runtime
correction is unchanged from1879c77. No account or Control dispatch was replayed.

Live observations:
- Delayed readiness passed: WinRM reachable but active=false/profileLoaded=false,
  session0 for the exact run-owned SID. Control dispatch count remained0. After
  one planned restart, Ready observed active=true/profileLoaded=true/session1;
  exactly one native Control returned42 with jobEmpty=true. Application dispatch0.
- Authoritative recovery passed both missing-controller-copy and partial-cache
  collection cases using three inert raw originals. The original document is
  37bytes, SHA256 `29c90859da9049e6386470143ea5bf0c2ccc00b82978a3d0ca6dc5bb860ee108`.
  The partial cache deliberately contains different text. Public recovery's
  retained export includes both, independently bound to the raw manifest.
- An injected named stream made Collect fail closed before rollback. Provider
  inspect retained the exact nonce in phase dirty with leasePresent=true and no
  release intent. Removing only that test stream allowed fresh collection.
- Public recovery of the older approved tool set uses the separate current
  compiled helper. The authoritative completion receipt binds the full export
  SHA256 `1e780c6c6b83495fbfe9e0422a9714f1f3f9e4c8980afb6893e93848d90fe011`;
  enumerationComplete/quiescent are true, with three raw originals and no Run
  markers. Original approved inputs remain subject to the held preparation and
  final byte/hash equality checks.

Terminal acceptance passed at source abd17ea. All three acceptance booleans,
approvedInputsUnchanged and cleanupComplete are true. Cold clean inspection
confirmed UUID107, all seven baseline accounts, no trial artifacts and automatic
sign-in disabled. Release completed2026-10-24T05:12:46Z with leasePresent=false.
This nonce is completed: never replay or recover it. The terminal application
report correctly remains workflowVerified=false with unmeasured functions,
compatibility and isolation because no application trial occurred. The ignored
live test passed (1/1). Initial failures remain retained, not recast as successes.

Final focused validation:15 MSIX administrator/PS5.1 regressions passed, including
crash-before-copy, partial/old-cache, queued/running-task, export/readiness and
held-helper sharing checks. The ignored live test was run separately and passed.
Clippy for the affected administrator/platform targets passed with warnings denied;
format and governance checks passed. Hosted CI for the pushed checkpoint remains
separate from this live evidence and from the historical application trial.

Full private evidence and all interrupted-attempt logs remain under
`C:\AIW-Resume-20261021\bounded-windows-f30c80e`, with the protected run workspace
beneath its run ID. No credentials/private keys are included in Git. These inert
fixtures and native Control do not constitute a new install/open/edit/save/close/
uninstall acceptance. The historical full trial remains tied to34369c9/2dab30b;
compatibility and effective isolation remain unmeasured. PR103 remains unmerged.
