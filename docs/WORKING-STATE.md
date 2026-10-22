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

R4 passed Stage/Enroll/Prepare/native launch control. Packaged Notepad++ launched
as standardSID1006/session1/medium non-elevated fulltrust, with identity/image
verified before suspended resume. Console-driven edit completed without invoking
the foreground helper: editor exit0, exact53saved bytes SHA256
91b82efd755bd5a46b47f6277bd050954b9fb3e78e56f9f086129d04da4dbd42,
six retained per-user configuration XMLs and all220payload entries unchanged.
Uninstall completed, but cleanup reporting reread the now-null live package
InstallLocation and failed. No native terminal lifecycle success is claimed.

Independent elevated10:05:03UTC readback confirms packageAllUsers0, provisioned0,
native/editor processes0 and the retained fixed install path absent. Verified
external r4 archive: C:\AIW-Resume-20261021\worker107-trial-failure-r4\evidence.zip,
SHA256492f1337acc92183fd21fe77f6d6f4c38a0804e9d064197eb722bfd95ebf62b9,
116files/284257bytes. Keep r2/r3 failures and all sealed payloads historical.

The managed-handle/typed-exit fix in429c428 is proven by r4's exit0 and exact file
receipt. The next reviewed fix captures a nonempty install-location string before
uninstall, using it for all payload/image/manifest/receipt/cleanup checks. Twelve
focused native tests pass; new staticCRT SHA256:
206f439c87a73d7d3bed55dfc90f50834afc5e5ae1442e7b8a6e1732d8d9d4d6.
Build/Stage pins agree; signed MSIX/assembly/signing remain unchanged. Seal fresh
r5 from reviewed committed sources, review artifact and confirm complete lifecycle.

TLS-ready cold snapshot aiw-msix-worker107-tls-clean-r1 includes OS/EFI/TPM/no RAM;
creation/restore/postrestore identity/clean inventory have passed. R4 exported
before another recovery. Use exact107 GUI for TLS-clean rollback; fixed SSH wrapper
only restores ORIGINAL clean-r1 and requires NIC down. Every fresh run requires
postrestore Connect+clean inventory, real standard session/cleared sign-in values,
Prepare and measured nativeControl beforeTrial. Use console-driven editing;
known helper foreground failure is preserved in r3 and helper is not retried.
Export/Collect before restoring worker after use. Evidence/controls are under
C:\AIW-Resume-20261021\worker107-connection-r3 and worker107-connection-r4.
Current catch's Stop error after an ended instance fails closed; refinement deferred.
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