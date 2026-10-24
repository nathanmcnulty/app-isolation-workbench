# Working state

Updated 2026-10-23. Start with `scripts/work-status.ps1`. Branch
`codex/new-vm-handoff-20261021`, checkout `C:\aiw\app-isolation-workbench` on VM203.
This file is a pointer, not an execution receipt.

PR103 is open and unmerged. Its independent review's four P2 corrections and
failure-sequence regressions are documented in MSIX-EXECUTION.md. The new checkpoint
is for re-review; full October22 app acceptance remains tied to its original source.
Recovery now requires durable raw export before rollback, retains pre-release proof
for completed-nonce finalization, and polls actual interactive readiness. Retained
reporting never repairs an incomplete journal. Do not replay the completed trial.

## Completed app-work slice

The exact supported signed-MSIX production execution flow is integrated and
validated on VM107. See [MSIX-EXECUTION.md](MSIX-EXECUTION.md) for implementation,
corrections, tests, provenance and acceptance. Broader compatibility/isolation
remain unmeasured; the shared assessment overall remains insufficientEvidence.

Verified run **msix-1792704525359564000**: explicit desktop review/approval/Start,
native Control42, fresh standard-user packaged install/open/edit/save/close,
53exact document bytes,220unchanged payloads,6retained configuration files,
uninstall, privileged inventory and empty jobs.44native-inventoried evidence
files were collected and independently checked. Final cold clean/release passed
at21:52:19UTC. **Lease released. Do not replay or recover this completed run.**

Execution source34369c9; retained reader2dab30b. The desktop reportfix package's
read-only screen displayed **Supported workflow verified** for the original run.
Package: C:\AIW-Resume-20261021\production-msix-desktop-reportfix (unsigned dev).
Shared report: C:\AIW-Resume-20261021\production-msix-verified-assessment.json;
its six function booleans, workflowVerified and cleanupComplete are true.
Input: C:\AIW-Resume-20261021\production-msix-capture-assessment-input.json.
Raw evidence remains in that run's protected workspace under the default Evidence.
Logs/packages: C:\AIW-Resume-20261021\production-msix-*. Prior failed runs are
preserved, all cold-clean/released; their nonces must not be replayed.

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
Those historical research receipts do not replace the production acceptance above.

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
