# Working state

Updated 2026-10-22. Start with `scripts/work-status.ps1`; this file is a pointer,
not an execution receipt. Branch `codex/new-vm-handoff-20261021`, checkout
`C:\aiw\app-isolation-workbench` on development VM203. Trials target only VM107,
UUID `e5cecc90-35c2-4831-bf9c-424be23f7d4e`, MAC `CC:34:21:B8:5A:31`.
Do not touch VM106/passkeys-worker or restore development203.

## Resume here

Continue [NOTEPAD-MSIX-LIFECYCLE.md](NOTEPAD-MSIX-LIFECYCLE.md), using the closed
worker107 controllers in `scripts/research`. [NEW-VM-PREFLIGHT.md](NEW-VM-PREFLIGHT.md)
retains setup and measured failures. User explicitly authorized VM107 setup,
accounts/software and autonomous disposable validation.

HTTPS WinRM at192.168.1.174:5986 works with Basic and unqualified labadmin;
System6167 confirmed duplicate cloned Windows identity behind NTLM failures.
The original password validated; none was reset. Credentials remain DPAPI-private
outside repo/evidence. Console-observed certificate now
`BC14DCC4E37F83161EBB55AF8624E36A79E19256` is checked before credential access.
The subsequent WSMan channel uses SkipCACheck on the operator-trusted lab network;
this is not production channel pinning. Authenticated UUID107 and elevated SID1001
passed. HTTP listener absent, unencrypted WinRM disabled, TLS firewall scoped203.

R5 completed the exact signed Notepad++ research lifecycle on107 at10:30:49UTC:
standardSID1006/session1/medium non-elevated fulltrust, package/image identity
verified before resume, console-driven open/edit/save/close, editor exit0,
exact53saved bytes, six per-user configuration XMLs, all220payload entries and
manifest unchanged, exact uninstall and native/controller/process/job/task cleanup.
Isolation and broader compatibility remain unmeasured. This is a research result,
not yet a production assessment adapter. Next: integrate measured observations
into shared assessment contracts in NOTEPAD-MSIX-LIFECYCLE.md.

Reviewed source16ba49bfa399e38d29dfd468b90439deb6a9f4eb; native SHA256
206f439c87a73d7d3bed55dfc90f50834afc5e5ae1442e7b8a6e1732d8d9d4d6;
sealed bundle105f17f381730592a03414f923d7b17a988d5365398a7a225d61faaf6d193f4c.
Verified external C:\AIW-Resume-20261021\worker107-msix-lifecycle-r5\evidence.zip:
SHA256768e9ade771bbc3345067c82745c15f2d7c0ed31c4c8e281d437d14a27c321b3,
285340bytes/118files. Independent review found no inconsistency. Separate elevated
10:33:46UTC readback confirmed no matching registration/provisioning/install
path/native/editor processes/primary trial tasks. Keep r2/r3/r4 failed evidence
and sealed payloads historical. Console method and connection observations are
in sibling worker107-connection-r5. No foreground helper invocation in r5.

TLS-ready cold snapshot aiw-msix-worker107-tls-clean-r1 includes OS/EFI/TPM/no RAM.
R5 evidence was exported before restoring107 again. Use exact107 GUI for TLS-clean
rollback. Final10:40:01UTC Connect/clean inventory passed: seven original accounts,
four trial roots absent, package/process/research tasks0, automatic sign-in values
absent/disabled, sole pinned HTTPS listener and HTTP listen count0. Worker107 is
running with NIC connected at192.168.1.174, ready for the next authorized test.
The fixed SSH wrapper only restores ORIGINAL clean-r1 and requires NIC down.
Every fresh trial requires postrestore Connect+clean inventory, real standard
session/cleared sign-in values, Prepare and measured nativeControl before Trial.
Export/Collect before recovery. The certificate has a14-day lifetime; preserve
identity verification when renewing. Failed-action catch's Stop error after an
ended instance still fails closed; refinement deferred. Twelve focused native
tests and staticCRT build passed for the source sealed into r5.

## Product and migration pointers

Bambu Studio and both Notepad++ recipes passed public-entry Sandbox packaging,
interactive edit/save/export and exact cleanup. PR93 merged at4e39c78; alpha
release desktop-alpha-4e39c787e63a. PR94 integrated acceptance at922d0a7. See
[BAMBU-PUBLIC-ACCEPTANCE.md](BAMBU-PUBLIC-ACCEPTANCE.md). Broader isolation remains
insufficientEvidence. Historical Azure MSIX installation verified220 payload
entries; its normal launch/edit/save/uninstall remains unmeasured and is not a
result for this worker. Old Azure resources are not resumption dependencies.

[RESUME-ON-NEW-VM.md](RESUME-ON-NEW-VM.md) records the verified60-file migration
archive and draft release; credentials/private keys are excluded. Leave release
draft. [EXECUTION-PLAN.md](EXECUTION-PLAN.md) and [ROADMAP.md](ROADMAP.md) retain
future direction. No host installer execution, generic command interface, blind
retry or device-code authentication. Preserve failed evidence before cold recovery.
Commit/push stable milestones; no unsolicited PR, workflow dispatch or merge.
