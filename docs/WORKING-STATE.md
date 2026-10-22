# Working state

Updated 2026-10-22. Start with `scripts/work-status.ps1`. Branch
`codex/new-vm-handoff-20261021`, checkout `C:\aiw\app-isolation-workbench` on VM203.
This file is a pointer, not an execution receipt.

## Current app-work slice

Production VM MSIX execution is integrated in the desktop and shared assessment
reader, **not yet end-to-end verified**. Implementation, fixes, test evidence and
failed trial IDs are in [MSIX-EXECUTION.md](MSIX-EXECUTION.md). All earlier failed
runs completed cold clean/release; never replay their nonces.

Run **msix-1792704525359564000**, reviewed/approved/separately started via desktop,
completed native lifecycle/capture and final cold clean/release at21:52:19UTC.
All44native-inventoried files are retained and independently checked; document53
bytes,220unchanged payloads,6configuration copies, uninstall and jobs passed.
The desktop/shared retained reader then rejected host output aliases using the
portable-input tree policy. A read-only held-evidence reader correction is being
validated against this existing run. **Do not replay or recover it: lease released.**
Package source34369c92604ed73d6e5350e39a06084741765f0a; receipt
087e1c0af788ab19d6097f09574867501d9f9d8b6315a45b728495a28c8db3bb.
Worker cf2ef6402ca33c51dd8a7d85cff42132a163f396e92c67b852d93852e5c3a7c9.
Remaining acceptance: corrected original-host raw reader and desktop/shared report
readback. No guest execution is needed. Package/logs and the prepared
capture assessment input are under C:\AIW-Resume-20261021\production-msix-*.

The107-only Proxmox wrapper is deployed. Normal HTTPS WinRM validates the approved
public certificate BC14DCC4E37F83161EBB55AF8624E36A79E19256. No production CA bypass.
Saved credentials remain DPAPI-private; no credentials/private keys are staged.

## Disposable worker boundary

Only VM107 is the validation worker: UUID e5cecc90-35c2-4831-bf9c-424be23f7d4e,
MAC CC:34:21:B8:5A:31, IP192.168.1.174. Never touch106/passkeys-worker or restore
VM203. User authorized107 setup/accounts/software and autonomous validation.
R5 completed install/packaged standard-user launch/console edit-save-close/
220payload checks/uninstall/native-process-job-task cleanup. Evidence was exported
before cold TLS-clean recovery; final10:40:01UTC identity+clean inventory passed.
That is historical readiness; no fresh VM observation was needed for report work.

TLS-ready snapshot aiw-msix-worker107-tls-clean-r1 includes OS/EFI/TPM/noRAM.
The deployed forced-command provider restores only this TLS-clean checkpoint;
never invoke the archived research wrapper's original clean-r1 rollback. The
production app requires exact identity, clean inventory, standard session,
cleared temporary sign-in and measured native Control before application Trial.
It collects before cold recovery and retains exact nonce ownership on failure.
HTTPS5986 Basic/unqualified labadmin works; NTLM clone-identity failure is historical.
The pinned certificate has14-day lifetime. Production checks trust/expiry and
uses normal WSMan chain/name validation. Old research SkipCACheck code is not
used by the production flow. HTTP listener is absent; firewall is scoped to203.

## Product pointers

[RESUME-ON-NEW-VM.md](RESUME-ON-NEW-VM.md) records the60-file migration/draft release;
leave release draft. [BAMBU-PUBLIC-ACCEPTANCE.md](BAMBU-PUBLIC-ACCEPTANCE.md) records
prior Sandbox product acceptance. [EXECUTION-PLAN.md](EXECUTION-PLAN.md) and
[ROADMAP.md](ROADMAP.md) retain future direction. Old Azure resources are not
resumption dependencies. No host installers, generic command interface, blind
trial retries or device-code authentication. Commit/push stable milestones;
no unsolicited PR/workflow dispatch/merge.
