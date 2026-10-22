# Working state

Updated 2026-10-22. Start with `scripts/work-status.ps1`; this pointer is not a run
receipt or execution authority. Active branch:
`codex/msix-assessment-feedback-20261022` (documentation after merged PR #99).

## Completed current slice

The exact signed Notepad++ 8.9.8 MSIX research lifecycle passed on VM 106: actual
non-elevated packaged process in a fresh standard-user console session, GUI
edit/save/normal exit, exact 53 document bytes, per-user configuration, all 220
unchanged payload entries, normal uninstall and independent native/job/task cleanup.
The complete native terminal receipt passed. See [VM106-MSIX-TRIALS.md](VM106-MSIX-TRIALS.md)
for exact hashes, failed attempts, driver fixes, tests and verified evidence export.
[NOTEPAD-MSIX-LIFECYCLE.md](NOTEPAD-MSIX-LIFECYCLE.md) records bounded acceptance;
the measured lessons are now recorded in the existing assessment documentation.
Production assessment/approval-contract integration remains a separate authority
gate. Effective isolation is `notMeasured`, not inferred from delivery or function success.

All 12 native tests passed. Actual held-handle exit and retained uninstall-path
regressions passed under PowerShell 5.1 and 7. Independent consequential reviews
found no remaining findings; governance passed. GitHub CLI authentication and
source pushes work. The unchanged private 60-file migration archive was downloaded
and verified; historical assets/controllers remain unchanged.

Integration PR #99 merged as `40fadd0e625d9bae49e04b332ef5a99114529fc6` after
all three hosted jobs passed on exact reviewed head `06e513f`: Verify and audit,
Minimum supported Rust, and Windows desktop (run `39760962776`). Full local verification passed before a
dependency audit identified ZIP 2.4.2 advisories. The dependency is now ZIP 9.0.5
in both lockfiles, with its required Rust 1.88 core minimum aligned across CI,
local checks and current instructions. Eighty provider tests, both lockfile audits,
stable workspace Clippy, actual Rust 1.88 all-target compilation and governance
pass after the update. Independent review cleared the API adaptation and
MSRV-enabled mechanical style changes. Existing nonfatal dependency-maintenance
warnings remain visible; no advisory was suppressed.

The documentation-only feedback follow-through distinguishes source/adaptation/
delivery identity, installation from activation readiness, actual target identity
from requested runtime, uninstall from user-data deletion, and function from
effective isolation. It also corrects the old secondary-logon paragraph after R5.
Independent review found no issue. See [ASSESSMENT-REPORT.md](ASSESSMENT-REPORT.md#msix-research-feedback-and-report-boundary).
No research receipt is accepted as a production run; a future production packet
must resolve approved primary-session worker/cleanup authority first.

## Worker and remote operation

VM 106 `passkeys-worker` / PASSKEYS-WORKER has UUID
`7e686bee-8c05-43c7-9603-a9562ece224c`, MAC CC-34-21-7E-FE-59, guest IP 192.168.1.173.
Proxmox `pve-r630` is 192.168.1.6. Final successful evidence was exported, hash-checked
and independently read back before a graceful shutdown and exact baseline rollback.
The baseline `aiw-vm106-baseline-20261021` was never replaced. The worker was
subsequently started for native passkey-provider preparation: candidate signatures,
runtime/API preflight and predeployment rejection checks passed; no provider is
installed. Its private intake is retained for the separate provider acceptance work.
OS/EFI/TPM restore has now passed repeatedly. Controller PASSKEYS was not rolled back.

The repaired closed Proxmox SSH helper supports fixed inspect/status/start/shutdown/
snapshot/rollback operations and retains exact VM/disk/MAC/pending-config checks.
Integration review found that extra disks were not excluded. The reviewed source
now allows only the three pinned writable devices and the observed empty CD drive,
and rejects host VirtIOFS shares. That guard is deployed; strict-key SSH inspection
passed with the unchanged three disks and original baseline still present.
Use [PROXMOX-VM106-CONTROLLER.md](PROXMOX-VM106-CONTROLLER.md). Encrypted NTLM WinRM
and verified PSRP transfer work as AiwWorkerAdmin (SID ending 1006); credentials
remain controller-user DPAPI protected outside Git. See
[scripts/worker106-admin/README.md](../scripts/worker106-admin/README.md).
After boot, wait for QGA readiness and start WinRM remotely if needed; do not ask
the operator to copy commands into Windows. The superseded QGA management bootstrap
is not needed and must not be rerun. No copied Tailscale identity is in the baseline.

Final controller evidence is `C:\passkeys\worker106-tools\primary-vm106-r5`.
The private evidence ZIP hash and original signed-input archive hashes are recorded
in the trial document. The original migration guide remains
[RESUME-ON-NEW-VM.md](RESUME-ON-NEW-VM.md); old Azure infrastructure is not a dependency.

## Product milestones and next work

Bambu Studio and both Notepad++ recipes previously passed signed public-entry
Sandbox packaging acceptance (PRs #93/#94); see
[BAMBU-PUBLIC-ACCEPTANCE.md](BAMBU-PUBLIC-ACCEPTANCE.md).
Follow [EXECUTION-PLAN.md](EXECUTION-PLAN.md) and [ROADMAP.md](ROADMAP.md).
Integrate research observations through approved production evidence contracts,
then complete the real classic AppContainer baseline/candidate comparison using
the existing controls. MXC requires its own exact-source review/disposable controls.
Keep delivery, function success and measured containment separate. Leave migration
releases draft; do not merge or launch CI merely to check this working branch.
