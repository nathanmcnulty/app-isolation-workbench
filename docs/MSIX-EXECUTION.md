# Production VM MSIX execution

Work in progress, 2026-10-22. User requested the production desktop execution
flow and live validation on VM107 after the archived research-report integration.
Do not mark this complete until the app drives a fresh approved run and evidence
collection/cold restore/identity readback on107 succeed.

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

Current implementation (pending live validation):
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

Remaining acceptance: finish local checks, build a clean-source package; approve
VM107's public certificate trust outside the app run; deploy the reviewed fixed
wrapper; demonstrate live NIC current/pending agreement; drive a fresh approved
run through the desktop, perform the exact console edit, collect and verify raw
evidence, cold restore, clean TLS readback and lease release. Keep failures.
Do not describe the production workflow as verified until those checks pass.