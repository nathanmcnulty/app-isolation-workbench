# Working state

Updated 2026-10-22. Start with `scripts/work-status.ps1`. Branch
`codex/new-vm-handoff-20261021`, checkout `C:\aiw\app-isolation-workbench` on
VM203. This file is a pointer, not an execution receipt.

## Current app-work slice

Production VM MSIX execution is integrated in the desktop and shared assessment
reader, **not yet lifecycle verified**. See [MSIX-EXECUTION.md](MSIX-EXECUTION.md).
The fixed107-only Proxmox wrapper is deployed. Normal HTTPS WinRM validates the
operator-approved public certificate BC14DCC4E37F83161EBB55AF8624E36A79E19256.
No CA bypass is used by production transport. Credentials remain DPAPI-private.

Live desktop failures are retained outside the repo under the default Evidence:
- msix-1792693343407226300 failed before staging on PowerShell verbatim paths.
  Its exact lease was recovered through the corrected desktop; cleanup verified.
- msix-1792697332610735000 staged and enrolled AiwStandardUser successfully, then
  exhausted the150second post-reboot reconnect window before control/app launch.
  Raw enrollment receipts were collected; cold cleanup/release and subsequent
  completed-nonce finalization passed. Both runs have failed terminal results.

Committed corrections: DOS spelling at the held PowerShell path boundary; reset
inherited PSModulePath for Windows PowerShell providers; declare/allow the guarded
GUI recovery command;6minute read-only cold/reboot waits; immediate retained
execution-error receipt; omit the optional generic evidenceRoot hash until a
native hash root is defined (folder paths are not hashes). Full37admin and14UI
checks, real PowerShell path/Certificate regression, Clippy and release builds pass.
Other native/core/provider/shared report checks passed at the integration baseline.

Attempt msix-1792699084357230000 (desktop2cd06ef) passed reconnect, cleared
temporary sign-in and established the standard session. Control failed before
app launch because application intake rejected Windows cmd.exe servicing hardlinks.
Raw receipts, final cold clean/release and failed terminal result were retained;
completed20:15:02UTC. Do not replay its dispatch. The native correction uses a
separate OS-only held opener with the same pinned digest, non-reparse checks and
write/delete denial through control cleanup. Application single-link intake is
unchanged. Focused hardlink/write-denial/hash/junction checks and independent review
pass. Fresh package production-msix-desktop-oscontrol (d203590; worker
f46b93bae23ac04e9cf88a6f5f90dffa9a0ac29736eeeef32349c352c5332f6e)
drove msix-1792700924025223800 through native Control: expected/observed42,
same standard session and empty owned job. Run then failed before installation:
the generated lifecycle prelude omitted the driver's function wrapper and read
its unset EvidenceDirectory variable. Raw failure/job cleanup retained; host
cold recovery is automatic. Never replay this nonce. Correct the composition,
check exact generated scripts with native PowerShell AST, rebuild and approve
a fresh run. Remaining live acceptance is the actual packaged lifecycle.
Logs/packages: production-msix-* under
C:\AIW-Resume-20261021. Remaining acceptance is native control, packaged lifecycle,
raw host verification, final cold cleanup/release and shared function report.

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
