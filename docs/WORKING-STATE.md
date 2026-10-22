# Working state

Updated 2026-10-22. Start with `scripts/work-status.ps1`. Branch
`codex/new-vm-handoff-20261021`, checkout `C:\aiw\app-isolation-workbench` on
VM203. This file is a pointer, not an execution receipt.

## Current app-work slice

The verified MSIX lifecycle now feeds shared assessment through
`aiw run report-assessment --input <manifest> --format json|markdown`.
[REPORT-SETS.md](REPORT-SETS.md) documents the closed manifest and commands;
`examples/msix-research-assessment.json` runs directly from this checkout.
The new report reuses ApplicationReportFunctions, RunOutcome and existing evidence
gaps, delegating retained Sandbox verification to the existing reader. Legacy
Sandbox JSON/Markdown remains unchanged. Shared schemas are available through
`schema application-assessment-input` and `schema application-assessment-report`.

The MSIX reader accepts ONLY the independently reviewed r5 archive digest, before
ZIP/JSON parsing. New archives cannot supply their own acceptance hash. It projects
native/controller terminal acceptance and retains source/adaptation, signed package,
observed token, exact document, per-user configuration, payload and cleanup records.
It does not launch/install/connect to a worker. Overall outcome stays
insufficientEvidence; general compatibility/isolation stay notMeasured.
A production MSIX execution adapter and admission of future trial records remain
separate work requiring the protected intake/approval/session/receipt contracts.

Validation: runner+CLI174passed/0failed/16opt-in ignored, formatting and all-target
component Clippy with warnings denied passed. Public JSON/Markdown/schema commands,
locked desktop metadata and governance passed; independent review cleared scope
and legacy behavior. Full logs and generated reports are outside the repository
under C:\AIW-Resume-20261021\shared-assessment-* and shared-msix-assessment.*.

Reproducible fixture `fixtures/msix-lifecycle/worker107-r5.zip` is the exact
285340-byte/118-entry archive SHA256
768e9ade771bbc3345067c82745c15f2d7c0ed31c4c8e281d437d14a27c321b3.
It contains no MSIX/executable/credential/private key/account password. Fixture
README records provenance and the retained upstream configuration license.
The original external archive and connection/readback observations remain under
C:\AIW-Resume-20261021\worker107-msix-lifecycle-r5 and worker107-connection-r5.
[NOTEPAD-MSIX-LIFECYCLE.md](NOTEPAD-MSIX-LIFECYCLE.md) retains the measured result;
[NEW-VM-PREFLIGHT.md](NEW-VM-PREFLIGHT.md) retains setup/failures/recovery.

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
