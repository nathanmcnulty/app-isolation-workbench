# Working state

Updated 2026-10-22. Start with `scripts/work-status.ps1`; this pointer is not a run
receipt or execution authority. Active branch:
`codex/proxmox-vm106-controller-20261021`.

## Completed current slice

The exact signed Notepad++ 8.9.8 MSIX research lifecycle passed on VM 106: actual
non-elevated packaged process in a fresh standard-user console session, GUI
edit/save/normal exit, exact 53 document bytes, per-user configuration, all 220
unchanged payload entries, normal uninstall and independent native/job/task cleanup.
The complete native terminal receipt passed. See [VM106-MSIX-TRIALS.md](VM106-MSIX-TRIALS.md)
for exact hashes, failed attempts, driver fixes, tests and verified evidence export.
[NOTEPAD-MSIX-LIFECYCLE.md](NOTEPAD-MSIX-LIFECYCLE.md) records bounded acceptance;
production assessment/approval-contract integration remains open. Effective isolation
is `notMeasured`, not inferred from delivery or function success.

All 12 native tests passed. Actual held-handle exit and retained uninstall-path
regressions passed under PowerShell 5.1 and 7. Independent consequential reviews
found no remaining findings; governance passed. GitHub CLI authentication and
source pushes work. The unchanged private 60-file migration archive was downloaded
and verified; historical assets/controllers remain unchanged.

## Worker and remote operation

VM 106 `passkeys-worker` / PASSKEYS-WORKER has UUID
`7e686bee-8c05-43c7-9603-a9562ece224c`, MAC CC-34-21-7E-FE-59, guest IP 192.168.1.173.
Proxmox `pve-r630` is 192.168.1.6. Final successful evidence was exported, hash-checked
and independently read back before a graceful shutdown and exact baseline rollback.
**Worker is stopped on `aiw-vm106-baseline-20261021`; the baseline was never replaced.**
OS/EFI/TPM restore has now passed repeatedly. Controller PASSKEYS was not rolled back.

The repaired closed Proxmox SSH helper supports fixed inspect/status/start/shutdown/
snapshot/rollback operations and retains exact VM/disk/MAC/pending-config checks.
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