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
Notepad++ process. Profile cleanup postconditions are independently observed:
labadmin profile exists unloaded, all enumerated copied authentication paths
absent, and seven accounts unchanged. Latest r2 invocation refused an existing
journal before mutation; do not repeat profile reset or delete its evidence.
The earlier r2 completion receipt has not been retrieved. Clean disk/EFI/TPM
checkpoint `aiw-msix-worker107-clean-r1` was created and restored successfully.
Post-restore SYSTEM preflight verified Windows boot, unchanged accounts and
all checked copied authentication paths absent. VM 107 is running, NIC down. Evidence is external to the worker under
`C:\AIW-Resume-20261021\worker107-recovery-proof-r1`.
VM 106 folder concerns were resolved by the user as a separate Codex session;
do not touch that VM.
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

The native primary driver and preparation producer are now rebound to QEMU107
at `4fe39b4`, explicitly excluding operator RID1001. Twelve focused native tests
and both PS5.1/7 preparation controls passed; static-CRT release hash is
`05f2ff8638adb3a156696de60bb1fd23341ee201a497c105359fa926d6d0e812`.
This binary has not run on the worker; controls/lifecycle remain unmeasured.
The user enabled VM107 networking at `192.168.1.174` and explicitly authorized
all validation setup/accounts/software on 107. Its MAC matches the expected
`CC:34:21:B8:5A:31`; user console output independently confirms UUID107.
WinRM authentication now works over HTTPS5986 with Basic and unqualified
`labadmin`. Console System6167 confirmed the cloned Windows identity mismatch
behind NTLM failures. The password validated locally; no reset was needed.
Exact UUID107 and elevated operator SID1001 passed through the updated controller.
The console-observed TLS certificate is probed before credential access; the
subsequent WSMan channel uses SkipCACheck on the operator-trusted lab network,
not production channel pinning. Credentials remain DPAPI-encrypted outside
repo/evidence. Connection evidence: `C:\AIW-Resume-20261021\worker107-connection-r1`.
VM203 remains development; do not touch VM106. AiwWorkerAdmin's reported106
origin remains unverified; none of this session's trial account code has run.

Closed WinRM harness `db2d9c3` and sealed payload passed independent source and
artifact review. PS5.1/7 parse/render/native compilation/development-token checks
passed. Payload: `C:\AIW-Resume-20261021\worker107-msix-payload-r1`, source
`db2d9c37ec232f272982089a502a0d754d49b0b6`, manifest SHA-256
`70b2276e2341324cffe94a745ca5d0207152daa0c80f73360e821b2b97bcb2ef`.
Next connect and verify UUID/operator, Stage with those independently approved
identities, inspect Stage result, then Enroll/restart/Prepare/Control before Trial.
Stage passed after resolving Scheduler's `SYSTEM` name to its exact SID and
preserving the initial never-run task/intake. Enroll then failed parameter
validation before creating any account: its61-character Description exceeds
Windows'48-character limit. The source now uses47characters and checks the
literal against actual Windows cmdlet metadata in bothPowerShell test runs.
Edit's registered user name is also resolved to SID before exact comparison.
Status now uses a fixed process-only execution-policy invocation. Preserve the
early enrollment failure before fresh reviewed staging; no trial account,
native control or installation has executed.
The current Proxmox wrapper requires link_down=1 and refuses an enabled NIC.
The clean snapshot retains NIC down; preserve exported evidence before recovery.
Historical migration controllers and draft release remain unchanged.
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
