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

R2 Stage/Enroll/Prepare passed with a real standard-user console sign-in and
measured clearing of temporary automatic-sign-in values. Control failed AFTER
registering its fixed task but BEFORE RunEx/native launch because Scheduler
normalized PT260S to PT4M20S. Independent readback found Ready/noinstances,
never-run result267011, no start-request/native output/package/process. No native
control or application executed. The failure archive is safely external:
`C:\AIW-Resume-20261021\worker107-control-failure-r2\evidence.zip`, SHA256
`ed14f6b5751e84713517794252b21643d97f78a1c3fd99a80efc1a2e8b6d53bb`.
It explicitly claims failure-cold-recovery, never cleanup success.

The corrected controller compares parsed durations at exact260/1500seconds and
shares parent-owned native process custody across function/scriptblock scope.
PS5.1/7 real in-memory Scheduler XML round trips, wrong-duration rejections and
strict child-scope controls pass without registering/running tasks. Verification
of the actual failed registered definition also passed read-only.

Cold OS/EFI/TPM rollback to aiw-msix-worker107-clean-r1 completed. SYSTEM preflight
at08:46:14UTC verified original seven accounts, absent copied authentication paths
and Tailscale, no research package/process. HTTPS-only setup is working again;
clean readback at08:52:17UTC confirms no trial roots/account/package/process or
automatic-sign-in password. Evidence: `C:\AIW-Resume-20261021\worker107-connection-r3`.
Cold TLS-ready checkpoint aiw-msix-worker107-tls-clean-r1 was created and restored
successfully; postrestore Connect and clean inventory passed at09:02:44UTC. Fixed SSH wrapper only restores the ORIGINAL clean-r1;
use exact107 Proxmox GUI for the new TLS checkpoint. Wrapper requires NIC down.

Native static-CRT binary remains
`05f2ff8638adb3a156696de60bb1fd23341ee201a497c105359fa926d6d0e812`.
Frozen signed MSIX/assembly/signing inputs are unchanged. R1/r2 payloads and failure
evidence are historical. Reviewed r3 source1ac58259e5a5a2c908985af78f4ee370959d7e19,
manifest e58acf7b52cfe26d46565cd29075218695f43ce374bdec5aae21932bac4f1bc1,
is sealed at C:\AIW-Resume-20261021\worker107-msix-payload-r3.
Control must pass measured exit42/job-empty/exact cleanup before Trial. Then use
fixed Edit, Export and Collect; do not infer compatibility/isolation from setup.

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