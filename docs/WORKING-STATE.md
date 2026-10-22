# Working state

Updated 2026-10-22. Start with `scripts/work-status.ps1`. Branch
`codex/new-vm-handoff-20261021`, checkout `C:\aiw\app-isolation-workbench` on
VM203. This file is a pointer, not an execution receipt.

## Current app-work slice

Production VM MSIX execution is now being integrated in the desktop, **not yet
live validated**. See [MSIX-EXECUTION.md](MSIX-EXECUTION.md) for scope and acceptance.
The new fixed VM107 provider, nonce lease, native agent, protected preparation,
approval/Start, WinRM transport, console editing instructions, collection, cold
recovery and shared retained assessment reader are implemented in this checkout.
Recovery never repeats application operations. New `msixVm` assessment selections
use original-host protected evidence; historical `msixResearch` pins remain intact.

A Windows Security Warning is pending for the console-observed VM107 HTTPS
certificate BC14DCC4E37F83161EBB55AF8624E36A79E19256. User action was requested
because computer-use guidance prohibits acting on security permission dialogs.
Certificate is **not yet trusted**. Do not bypass CA validation. Public certificate
is C:\AIW-Resume-20261021\worker107-public.cer; no private key was exported.

No new application trial or worker mutation has occurred during this integration.
The reviewed production Proxmox wrapper is **not deployed**. Its Linux-console
install text was prepared outside the repo but has become stale after later
source edits: regenerate from current LF-normalized source and SHA before use.
Edge is authenticated root@pam on pve-r630, node Shell. Do not paste into Windows
terminals or act on the overlaid certificate dialog. Current forced SSH wrapper
still has the earlier research grammar. Never change its key to generic SSH.

Current checks and logs: production-msix-* under C:\AIW-Resume-20261021.
Core/runner tests, shared-verifier tests,8 GUI gates,13 UI tests, provider mock,
2 native provenance tests and the approved-deadline test passed. Broad Windows
checks had173passes/10ignored and one old job-membership expectation; after
tightening that expectation all12 focused lifecycle tests passed. Component/GUI
Clippy, formatting, governance and static-CRT release compilation passed.
Clean-source package assembly and live deployment/validation remain.
The baseline b039e02 read-only report integration and pinned r5 fixture remain
historical evidence, not a fresh production execution receipt.

## Disposable worker boundary

Only VM107 is the validation worker: UUID e5cecc90-35c2-4831-bf9c-424be23f7d4e,
MAC CC:34:21:B8:5A:31, IP192.168.1.174. Never touch106/passkeys-worker or restore
VM203. User authorized107 setup/accounts/software and autonomous validation.
R5 completed install/packaged standard-user launch/console edit-save-close/
220payload checks/uninstall/native-process-job-task cleanup. Evidence was exported
before cold TLS-clean recovery; final10:40:01UTC identity+clean inventory passed.
That is historical readiness; no fresh VM observation was needed for report work.

TLS-ready snapshot aiw-msix-worker107-tls-clean-r1 includes OS/EFI/TPM/noRAM.
Use exact107 GUI for it; fixed SSH wrapper targets107 but its rollback restores
ORIGINAL clean-r1 and requires NIC down. Every fresh live trial requires identity,
clean inventory, real standard session/cleared one-time sign-in, Prepare and native
Control before Trial, with Export/Collect before recovery. Keep r2-r4 failures.
HTTPS5986 Basic/unqualified labadmin works; NTLM clone-identity failure is recorded.
Console-observed cert BC14DCC4E37F83161EBB55AF8624E36A79E19256 has14-day lifetime.
Controller prechecks it before credential access; subsequent WSMan SkipCACheck is
trusted-lab transport, not production channel pinning. Credentials are DPAPI-private
outside repo/evidence. HTTP listener absent; firewall scoped203 at last readback.

## Product pointers

[RESUME-ON-NEW-VM.md](RESUME-ON-NEW-VM.md) records the60-file migration/draft release;
leave release draft. [BAMBU-PUBLIC-ACCEPTANCE.md](BAMBU-PUBLIC-ACCEPTANCE.md) records
prior Sandbox product acceptance. [EXECUTION-PLAN.md](EXECUTION-PLAN.md) and
[ROADMAP.md](ROADMAP.md) retain future direction. Old Azure resources are not
resumption dependencies. No host installers, generic command interface, blind
trial retries or device-code authentication. Commit/push stable milestones;
no unsolicited PR/workflow dispatch/merge.
