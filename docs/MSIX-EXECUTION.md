# Production VM MSIX execution

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
