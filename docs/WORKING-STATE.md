# Working state

Updated 2026-10-21 for migration to the user's new dedicated VM/Codex instance.
Start with `scripts/work-status.ps1`. This is a pointer, not execution authority
or a run receipt.

## Resume here

VM 106 `passkeys-worker` / PASSKEYS-WORKER is running at **192.168.1.173**.
The human enabled networking and PSRemoting. Standard encrypted WinRM now actually
works as elevated AiwWorkerAdmin (SID ending 1006), with exact guest UUID verified.
Use [scripts/worker106-admin/README.md](../scripts/worker106-admin/README.md);
credentials remain controller-user DPAPI-protected, never in Git. The human gives
permission to administer/install needed software on this dedicated testing VM.

Windows preparation is finalized: fresh console profile validated, copied
labadmin and sandbox users disabled, Tailscale/service/state absent, fresh-account
device join flags all NO, system .NET/SDK/Git/Node present. Official machine-wide
PowerShell 7.6.7 MSI was hash/signature verified and installed successfully; it
actually executes as the fresh administrator. Old Store PowerShell could not.
Copied profile caches are retained behind disabled accounts, not claimed erased.

The custom QGA management bootstrap failed at Public-profile remoting setup before
its firewall/network stages. It is superseded; **do not run old bootstrap/inventory
updaters again**. Preserve failed records. The Proxmox helper was repaired to
accept the exact canonical enabled NIC form (omitted link_down=0); all identity
pins remain. Baseline `aiw-vm106-baseline-20261021` was created while stopped,
covering OS/EFI/TPM disks without saved memory, then configuration was verified.
The native driver and preparation validators are now rebound to VM 106, built and
independently reviewed. Eleven native tests passed, and the fixed SYSTEM Scheduler
cmd/exit-42 control passed live with owned-job and task/process cleanup. See
[VM106-MSIX-TRIALS.md](VM106-MSIX-TRIALS.md) for exact hashes/evidence and remaining
WTS/application gates. GitHub CLI works; the unchanged 60-file private migration
archive was downloaded and verified. A fresh standard-user console sign-in and
LSA/Winlogon cleanup passed. The first primary Scheduler wrapper stopped before
launch at normalized-duration verification; that check is fixed and independently
reviewed. Its evidence was exported, and stopped baseline rollback/restart passed.
A fresh primary control attempt is underway. Application compatibility remains
unmeasured. Original PASSKEYS remains controller.
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
