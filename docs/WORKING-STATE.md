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

VM107's public certificate is now trusted after operator approval; normal HTTPS
WinRM identity validation passed. The production107-only wrapper is deployed and
its SHA matches the app preparation. Clean-source package d78ec1a was built and
its six-file inventory verified.

The first desktop-approved production attempt msix-1792693343407226300 failed
before staging: Windows PowerShell5.1 Join-Path rejects the held workspace's
verbatim path prefix. Initial and final cold restore/reconnect proofs passed;
the lease remains retained because that same path error blocked clean readback.
A separate fixed read-only transport call subsequently verified clean inventory
and normal HTTPS. Do not replay this application attempt. Recover its exact lease
using the corrected desktop, then prepare a fresh approved run.

The correction passes the held path's equivalent DOS spelling only at the
PowerShell boundary. A real PowerShell FileSystem-provider regression passed.
Cold-readback wait is6minutes because restored networking can take several
minutes after reconnect. Full logs and the unsigned package are outside the repo
under C:\AIW-Resume-20261021\production-msix-*.
Core/runner, native lifecycle, GUI/UI, provider mocks, Clippy, format and governance
checks passed before d78ec1a; path-fix admin suite36passed and new regression1passed.
Production lifecycle acceptance still requires fresh execution and final recovery.

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
