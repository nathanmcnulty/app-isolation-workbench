# Working state

Updated 2026-10-21 for migration to the user's new dedicated VM/Codex instance.
Start with `scripts/work-status.ps1`. This is a pointer, not execution authority
or a run receipt.

## Resume here

New VM preflight is recorded in [NEW-VM-PREFLIGHT.md](NEW-VM-PREFLIGHT.md).
The checkout is now `C:\aiw\app-isolation-workbench` on QEMU machine `AIW`,
not Azure. The migration archive's exact 60-file inventory and signed MSIX
verified locally. Both PowerShell session probes passed. Proxmox host
`pve-r630` (`192.168.1.6`), VM `203`, is the development machine. Root-console
readback supplied by the user identifies VM `107`, `aiw-worker`, stopped, new MAC,
NIC link down, no snapshots, disks on `r630-fast` and UUID
`e5cecc90-35c2-4831-bf9c-424be23f7d4e`. A fixed offline worker wrapper is prepared;
installation and initial SSH readback passed, including rejection of VM 203
commands. The inherited-lock defect was confirmed and recovered by graceful
shutdown; reviewed `3c9dc99` is installed. Fresh offline start, status and inspect
pass; the guest agent reports Windows 11 build 26300, hostname AIW, no logged-in
users at boot. NIC remains disconnected. Reviewed `813d3b4` probe is now installed
and passed as SYSTEM/session zero on exact UUID 107. Tailscale uninstall and all
three documented state-path absences are verified, including the untouched legacy
system-profile path. Seven local accounts remain; no research registration or
Notepad++ process. The copied labadmin profile is loaded and authentication-path
directories remain. User choice is pending: fresh clone profile (requires known
local password and removes clone Desktop/Documents/settings) or targeted cleanup.
No profile reset or credential cleanup has been executed by the agent.
VM 106 folder concerns were resolved by the user as a separate Codex session;
do not touch that VM. No fresh clean snapshot or restoration proof exists yet.
The previous VM 203
snapshot/rollback plan is superseded:
do not power-cycle or restore the development machine for trials. The installed
SSH entry path now targets only 107. See NEW-VM-PREFLIGHT. No trial account or
application trial has started. Do not use the old Azure binding on either VM.

Branch: `codex/new-vm-handoff-20261021`, based on the complete development history
at `5688db4eb681fdc9a7e3987bb091b89de941d1bd` (`codex/msix-worker-lifecycle`).
Use [RESUME-ON-NEW-VM.md](RESUME-ON-NEW-VM.md) for exact download/verification
commands, preserved asset identities, stopping point and next acceptance gates.
Paste [RESUME-PROMPT.md](RESUME-PROMPT.md) into the new session.

The old Azure subscription ran out of funds, per the user. Its VM, account,
approvals, TEMP pointers and checkpoints are not resumption dependencies. Do not
contact/recover/clean up old infrastructure for this migration. Inspect the new
machine and rebind the closed research path before testing.

## Completed product milestone

Bambu Studio and both Notepad++ recipes passed signed public-entry Sandbox
packaging acceptance, including interactive edit/save/export and exact cleanup.
PR #93 merged at `4e39c78`; release `desktop-alpha-4e39c787e63a` was built from
that exact source. PR #94 integrated acceptance documentation at `922d0a7`.
See [BAMBU-PUBLIC-ACCEPTANCE.md](BAMBU-PUBLIC-ACCEPTANCE.md).
Broader isolation remains `insufficientEvidence`.

## Open bounded milestone

Finish [NOTEPAD-MSIX-LIFECYCLE.md](NOTEPAD-MSIX-LIFECYCLE.md). PRs #95/#96
integrated the research assembler and pinned SDK supply. Signing run
`37711841372` succeeded at `bcf6f82`. Signed installation and all 220 installed
payload entries passed, but normal non-elevated packaged execution/edit/save/
configuration/final payload verification/uninstall remain open.

The r5 direct SYSTEM WTS control failed before child creation/installation.
The subsequent default SYSTEM Scheduler fixed cmd control passed suspended child
containment, exit 42, empty output/job and independent exact cleanup readback.
Latest reviewed native WTS Scheduler templates were never submitted: r6's real
standard-user RDP login did not complete before its 30-minute window expired.
No preparation/native control was dispatched. Credentials were cleared and the
expired client closed. Preserve those distinctions.

The draft migration release preserves signed inputs, the frozen old native
executable, exact historical controllers and selected evidence. Both native and
controller code pins old VM/SIDs and needs a narrow reviewed rebind/rebuild.
Next prove the fixed native WTS control on the new disposable boundary, then
complete the real-application lifecycle. Feed observations into assessment.

## Direction and boundaries

Follow [EXECUTION-PLAN.md](EXECUTION-PLAN.md) and [ROADMAP.md](ROADMAP.md).
Classic AppContainer real-application comparison follows this delivery slice;
MXC requires its own exact-source review and disposable controls. See
[MXC-TRAJECTORY-REVIEW-2026-10-07.md](MXC-TRAJECTORY-REVIEW-2026-10-07.md).
VS Code is planned. Keep admin summaries simple with advanced evidence available.

One build owner per target. No host installer execution, generic command interface,
implicit approval, automatic overwrite or unrelated Sandbox recovery. Preserve
failed evidence in fresh directories. Never use device-code authentication.
Commit/push stable milestones; merge only after review and required exact-head CI,
then verify merged main. Leave the migration release draft.
