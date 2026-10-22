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

R3 passed Stage/Enroll/Prepare and actual native launch control at09:10:56UTC:
standard-user child exit42, empty job, held action/native exit, task/instance
absence. Independent09:12:25UTC readback found no control processes/task/package.
The signed MSIX installed, all220payload entries verified and packaged Notepad++
launched suspended with exact image/package/SID1006/session1/medium non-elevated
identity verified before resume. This is not AppContainer isolation.

The keyboard helper failed foreground acquisition before input and was not retried.
Console-driven editing saved the exact53expected bytes and closed the owned editor.
Native validation then failed because the attached managed Process.ExitCode yielded
null; later document-output/configuration/payload/uninstall checks did not run.
Controller cleanup failed closed on Stop of an already-ended instance. Preserve
these limits; do not claim lifecycle success from this run.

Verified export: C:\AIW-Resume-20261021\worker107-trial-failure-r3\evidence.zip,
SHA2569ab90949bca654e643b363f3b4b24902134dbbe5711b8bae15cdf9f9eb754609,
107files/89948bytes, outcome failure-cold-recovery and no inferred cleanup claim.
Historical r2 failed before RunEx, with evidence at worker107-control-failure-r2.
Both failures and sealed payloads remain external to107.

Cold TLS-ready checkpoint aiw-msix-worker107-tls-clean-r1 was created/restored and
postrestore identity/clean inventory passed. It includes OS/EFI/TPM and no RAM.
After r3 export, it was restored again; fresh boot/Connect/clean inventory must
pass before r4 Stage. Fixed SSH wrapper only restores ORIGINAL clean-r1; use
exact107 Proxmox GUI for TLS-clean recovery. Wrapper requires NIC down. Evidence
and public controls: C:\AIW-Resume-20261021\worker107-connection-r3.

Focused reviewed fix opens the managed Process.Handle before resume, calls
get_ExitCode once after WaitForExit, requires an actual int and uses that value
for receipt/predicate. PS5.1 attached-process controls on107 proved typed0/42;
twelve focused native tests passed, including PS5.1 parse/compile and strict
Win32 command length. New staticCRT native SHA256:
c551938fb6c6f8f8d6a5311850e8713d020f4c888f0b3f67b88babc1d6a0dad5.
Build/Stage pins change together; frozen signed MSIX/assembly/signing unchanged.
Seal fresh r4 from reviewed committed sources and independently review artifact.
Control must pass before Trial. Prefer console-driven edit if Windows refuses
helper foreground; never repeat a helper after uncertain input. Export/Collect
and preserve evidence before restoring worker after use. Compatibility/isolation
remain bounded by actual native receipts. The catch Stop refinement is deferred.
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