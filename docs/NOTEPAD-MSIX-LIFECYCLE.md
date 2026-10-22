# First real application MSIX lifecycle

This is the next repackaging milestone after the accepted Sandbox bundles.
Produce a reproducible, signed Notepad++ package, then install, activate, edit/save
and uninstall that exact output on a fresh disposable worker. Research results
remain separate from production assessment reports until their authority and
observation contracts are integrated.

## VM 106 research acceptance completed, 2026-10-22

The exact signed 8.9.8 package passed install, verified medium-IL packaged execution
under a fresh real standard-user session, GUI edit/save/normal exit, exact document
bytes, per-user configuration, all 220 unchanged payload entries, normal uninstall
and independent native job/process/Scheduler cleanup. A complete terminal success
receipt was exported and verified before restoring the disposable baseline.
See [VM 106 trial record](VM106-MSIX-TRIALS.md#complete-application-acceptance-r5-2026-10-22)
for exact driver/package/preparation identities, failed attempts, fixes, tests and
export hashes. Research acceptance is complete for this exact workflow;
production assessment/approval-contract integration and effective containment
measurement remain separate work. No public release or broader compatibility
claim follows from this trial.
## Closed first recipe

- Input: official Notepad++ 8.9.8 x64 portable ZIP, 8,232,940 bytes, SHA-256
  `b269383239464a945d17cfabfccf53935b83d80d907922310fdfd50d80274c66`.
- [Upstream release](https://github.com/notepad-plus-plus/notepad-plus-plus/releases/tag/v8.9.8).
  Keep upstream binaries and licenses intact; this is a packaging experiment,
  not a Nathan-authored Notepad++ executable or a public application release.
- Tool: Microsoft-signed x64 MakeAppx 10.0.26100.7705, SHA-256
  `00fff202b71c1266b8c3899701e42b5468ea153b2b33a0a47215fe27695f16d0`.
  Tool drift stops assembly; inspect it before approving a different pinned tool.
  Hosted assembly obtains this identical Microsoft-signed binary from the fixed
  `Microsoft.Windows.SDK.BuildTools` 10.0.26100.7705 NuGet archive (22,582,767 bytes,
  SHA-256 `48a81375752f9f1ff56a34062084b426bfe412a5a8072e1c99b6a4be0e774841`).
  The archive is verified before extraction and the tool is independently held,
  hash-checked and publisher-verified before execution. A supplied tool path does
  not admit a different executable identity.
- Identity: `AIWResearch.NotepadPP`, version `8.9.8.0`, x64, Windows 11 24H2+.
- Publisher: `CN=Nathan McNulty, O=Nathan McNulty, L=Soldotna, S=Alaska, C=US`.
  Use the existing personal Artifact Signing profile outside the application worker.
- Delivery: `containedMsix`; runtime: `mediumIlFullTrust`. The manifest declares
  `packagedClassicApp`, `mediumIL` and `runFullTrust`. This is a delivery baseline,
  not AppContainer isolation or a replacement for the Sandbox profiles.
- Explicit adaptation: remove only `Application/doLocalConf.xml` to select
  per-user configuration rather than the immutable installation directory.
  Preserve its source hash and complete before/after inventories.
- Assembly never launches Notepad++, installs MSIX, grants capabilities, changes
  host policy or creates signing keys. Partial output is preserved; terminal
  `assembly.json` is published last. The scripts are not a production adapter.

The recipe follows [Microsoft's manual packaging guidance](https://learn.microsoft.com/en-us/windows/msix/desktop/desktop-to-uwp-manual-conversion).
The [package publisher must match the signing certificate subject](https://learn.microsoft.com/en-us/windows/msix/package/sign-msix-package-guide).

## Required final trial

Before launch, independently verify the signed package, full manifest/payload,
publisher subject, timestamp, package hash and fresh worker state. Record the exact
operator, package identity, source and adaptation; preexisting registration or a
running application stops the trial. Do not uninstall an unrelated package.

| Function or observation | Acceptance |
|---|---|
| Driver control | Project-owned process control verifies held handle, stdout/stderr, exit, deadline and cleanup before application trial |
| Install | Exact signed MSIX installs under the recorded interactive operator; capture registration, package full name, family name and manifest |
| Activation | Activate the declared package application, observe the target process and verify its actual package identity, image hash and non-elevated medium token |
| Document workflow | Open a fresh project-owned UTF-8 document, edit/save/close; independently compare exact final bytes and hash |
| Configuration | Observe the actual per-user configuration location; installation payload remains unchanged; missing evidence stays unmeasured |
| Uninstall | Remove only the exact installed package registration after process closure; verify registration absent and record supported user-data behavior |
| Cleanup | No owned process/registration remains; preserve input, output, failure and lifecycle evidence |
| Isolation | Full-trust package identity is measured; AppContainer, network denial, outer host containment and broader compatibility remain unmeasured |

The minimum boundary claim for this baseline is measured packaged, non-elevated
medium-integrity execution. It makes no denied-access or AppContainer claim.
Update, reboot, arbitrary installers, plugins, updater and shell integration are
unsupported lifecycle/functions for this first recipe, not implicit successes.
A failed function is attributed to packaging only after the driver and ordinary
application control establish the relevant comparison.

### Next control: real standard-user sign-in

The secondary-logon worker installed the package but neither tested launch path
created a usable editor. Compare the unchanged signed package under a fresh
`AiwStandardUser` Windows sign-in on the dedicated disposable VM. Do not change
package ACLs, substitute elevated/unpackaged execution, or add an automatic launch
fallback. Direct suspended launch is the first comparison; a COM comparison, if
needed, is a separate retained attempt in a restored disposable environment.

Before creating an account or installing, establish and verify a recoverable VM
boundary. A fixed privileged controller must refuse an existing account, bind
the created SID and run time, hold the executable and three signed inputs, and
record a clean global inventory. The standard user first signs in through Windows.
The fixed controller then launches the child into that existing logon; it never
creates a secondary logon or uses a stored-credential task as a substitute.

The read-only `research_msix_interactive.cs` observer captures the process token's
authentication LUID, corresponding LSA SID/logon type/time/session, WTS owner and
active state, and the shell's SID/session/authentication LUID. Its validator
requires the exact controller-owned SID and run time bounds, interactive or
remote-interactive logon, matching shell logon, and medium non-elevated tokens
without enabled administrators. A session ID or loaded profile alone is
insufficient. The observer now gates the fixed VM child before controls or
installation; local tests do not prove packaged execution.

The separate, feature-gated `vm-controller` mode requires LocalSystem session zero,
no thread impersonation, the pinned computer and Azure IMDS VM identity, and a
held, protected preparation record. It uses [WTSQueryUserToken](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
for the unique active `AiwStandardUser` session and [CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
for only the fixed executable and `vm-lifecycle-child` argument. Azure Run Command
already supplies this one-shot SYSTEM authority; no new service or token broker
is exposed. Privileges are scoped around their native calls and restored.

The existing Windows login owns the loaded profile. No credentials, profile
load/unload, desktop ACL mutation, token export or job breakaway are used.
The child is created suspended on `winsta0\default` with the WTS user's environment,
without inherited handles. Its held image, physical/token session, SID and
authentication LUID are checked; assignment and membership in the exact owned
job precede the single resume. A failure terminates that exact suspended handle.
The child's LSA/WTS/shell receipt must agree with the protected parent context.

The parent retains the existing global before, before-cleanup and after gates,
job cleanup, export and independent receipt validation. It publishes success last.
Application closure is not inferred from job membership. The immutable preparation
record carries only the closed run/account/session/source/time/nonce fields;
unknown fields are rejected. Account provisioning and recoverable-VM preparation
remain prerequisites; this driver does not create or adopt an account.

Independent review corrected one failure path: privilege restoration now occurs
only after the suspended child belongs to the kill-on-close job. If restoration
aborts the controller, job-handle closure terminates that child. The same-user
interactive receipt is correlated with the parent's held token, but is not
tamper-resistant evidence against a hostile application running as that user.

Local validation covers nine focused lifecycle tests, including rejected
preparation mutations and real PowerShell 5.1 parsing/native-source compilation;
warnings-as-errors clippy passes. The broader platform suite passed 170 tests
with ten ignored before the final reviewed cleanup-order correction; the nine
focused tests and clippy were rerun after that correction. Logs are retained as
`primary-user-platform-tests-r1.log`, `primary-user-tests-final-r1.log` and
`primary-user-clippy-final-r1.log` under the MSIX proof root. Read-only VM preflight
confirmed pinned identity, SYSTEM/session zero, the three required privileges,
and no existing `AiwStandardUser`. The Azure agent is already in a job; successful
nested owned-job assignment still requires live proof. No application was run.

On failure, preserve evidence and restore the verified disposable boundary.
On success, sign out and remove only the controller-created account/profile after
matching the retained SID. This control can prove the actual user lifecycle; it
does not prove a production service can create that interactive context.

The observer follows Microsoft's [LSA logon data contract](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-security_logon_session_data),
[WTS session query contract](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsquerysessioninformationw)
and [shell window observation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getshellwindow).
Run the prerequisite checks with `./scripts/test-msix-interactive-session.ps1`;
`-ObserveCurrent` adds read-only observations without accepting that context for
an application trial. PowerShell 5.1 and 7 are covered separately.

The initial prerequisite passed two positive and twenty rejection cases under
host PowerShell 5.1.28000.2952 and 7.6.6. Its read-only host observation confirmed
the LSA/WTS/shell bindings without executing any application. The exact reviewed
sources were separately hash-checked on the dedicated VM. Running the same check
through the actual operator RDP terminal passed on PowerShell 5.1.26100.9444:
session 2, remote-interactive logon type 10, active WTS owner and matching shell
authentication LUID. Both operator and shell were elevated, high integrity, with
Administrators enabled; this observation was explicitly not accepted for a trial.
Independent SDK readback checked the retained result and all three source hashes.
`interactive-context-probe-r1-handoff.json`,
`vm-interactive-context-probe-staged-r1.json` and
`vm-interactive-context-probe-readback-r1.json` retain this evidence under the
MSIX proof root. Result SHA-256:
`454d86b62408e8f499493c0c7b7f19b26e2667d064fa0b835d506a28967df5e8`.
No account, installation, application launch or VM power change occurred.

### Verified disposable VM recovery boundary

The dedicated VM now boots a restored copy of its cold OS-disk snapshot, with
the original disk retained and unattached. The exact VM identity and networking
were preserved. Before shutdown, the operator's provider list was empty and the
privileged inventory found no research package or trial process. A flushed
nonce-bound marker records the original account baseline. Normal Windows shutdown
returned zero; Azure independently reported stopped, then deallocated before
snapshot creation. After restored-disk boot, the marker hash and every account
name/SID/enabled flag matched. Windows events 1074 and 6006 correlate to the
shutdown request; no 6008 occurred in that interval. The agent is running and
the fixed trial input/output/preparation/profile paths remain absent.

Snapshot: `aiw-msix-cold-123e286bd0cf`; current OS disk:
`aiw-msix-restored-123e286bd0cf`, both in the dedicated resource group. They deny
disk export and disable public network access. No export SAS was issued. The
preserved original disk is
`aiw-clean-host-0921_OsDisk_1_baafcb16f0de455d84333ae2926e28e1`.
The original export policy was preserved. Recovery resources contain the VM's
retained evidence and must not be deleted before trial evidence and rollback are
accounted for.

The existing OS volume is fully encrypted with XtsAes128, but protection is off,
there are no key protectors, and no TPM is present. This is Microsoft's documented
[clear-key state](https://learn.microsoft.com/en-us/windows/win32/secprov/getprotectionstatus-win32-encryptablevolume),
not a BitLocker confidentiality claim. The exact state is unchanged after
restore; no encryption, protector or TPM setting was modified. Azure platform-key
encryption remains unchanged. Recovery material therefore requires the same
access protection as the VM itself.

The first swap request was rejected for attempting to change the immutable
`osDisk.createOption`. Independent readback confirmed the original remained
attached; the corrected request preserved that field and changed only the disk
identity while retaining caching and detach policy. No VM recreation was needed.
Full stage records, identities, inventories, rollback script and rejection are
retained under the MSIX proof root as `vm-cold-recovery-*-r1.json` and
`vm-cold-recovery-rollback-r1.py`. This proves a restored boot and clean baseline;
it does not prove the pending standard-user application lifecycle.

### Primary-session attempt after recovery

The fresh account `AiwStandardUser` was created with VM-domain RID 1001 and
only Users and Remote Desktop Users membership. The first preparation failed
on Windows' 48-character account-description limit; independent readback proved
no account, profile or created-account receipt existed before the repaired attempt.
That failure and its preparation directory remain preserved.

Normal RDP login reached this account's desktop. SYSTEM preparation independently
observed its loaded profile and unique Explorer process 5884 in session 3.
The transferred package, assembly, signing receipt and driver matched all four
expected hashes with a closed inventory. The driver hash was
`3aaf26fb1fb4902e0f6ca222769b7b1b0d4c26b6ea98679ad3fe05caef21922b`.
The protected preparation hash was
`8028dbf0783c24fd958bbdbf6f87cce88b5ee3de87d259644eba4dbe57ad1a48`.

Independent operational review corrected the preparation's lower time bound:
it must precede the actual logon, using the protected account-creation receipt,
with a fixed 30-minute upper bound. Review also corrected the launch wrapper's
general exception path to confirm exact held-controller termination and retain
primary, cleanup and publication errors separately. Both repaired scripts pass
PowerShell 5.1 parsing. Neither correction relaxes the native driver's gates.

The controller ran as SYSTEM and exited with code 1 at
`2026-10-11T06:49:03.9871451Z`, without timeout. No editor was observed.
`vm-primary-controller-launch-result-r2.json` retains PID 14632 and the owned
nonce; VM wrapper logs remain in `C:\AIW-Msix-Primary-Controller-r1`.
RDP readback recovered the four retained stage records under
`vm-primary-failure-rdp-readback-r1`. The failure is
`CreateProcessAsUserW: Access is denied. (0x80070005)` before a child handle
or application installation. The primary context matches the prepared SID,
session, authentication LUID, source hash and nonce. The privileged before
inventory has no research registration or application process. These records
identify a controller launch failure; they do not replace a final cleanup inventory.
Failure record SHA-256:
`bcc5aa7692ee01c28bd3f61fed5a1d98d1741c2a046744ed917d85f022e4b77f`.
Do not retry or restore while the diagnostic command is unresolved.
The diagnostic SDK returned an empty object, retained in
`vm-primary-controller-failure-readback-raw-r1.json`; this is not a clean-state
receipt. Azure activity correlation `4b8a3733-280e-4c4d-9586-299a93d604b9`
recorded acceptance at `2026-10-11T06:49:43.1118592Z` without a terminal event
in the subsequent readback. Inspection of the installed Azure SDK and a bounded
control using its actual `LROPoller` reproduced an empty intermediate result
after `result(timeout=0)` while `done()` was false. An explicit completion guard
rejected that result and accepted it only after the control completed.
`sdk-poller-timeout-control-r1.json` retains this narrow proof; it does not prove
guest-command completion. Future command helpers must retain protected polling
state before waiting, check completion explicitly, and require the expected
typed stdout before interpreting a result. An observation timeout does not
authorize another command, recovery or restoration.
Computer-use reconnection initially failed with `failed to activate captured
window`. A later capture exposed pending host credential dialogs. Only the three
exact owned RDP clients were closed; a protected test-account RDP file then
reconnected successfully. No personal PIN was entered and no VM power change
occurred. Clipboard-enabled RDP copied the retained JSON records into a fresh
host directory. Independent terminal observation reconfirmed RID 1001 and the
driver hash; both input-directory and executable ACLs grant that SID read/execute.

`vm-primary-rdp-diagnostics-r1.json` retains observations at
`2026-10-11T07:18:35.0948049Z`: guest `RunCommand_470` remains `transitioning`,
with its PowerShell process 1820 created at `06:49:46.904Z`, parent 10320, still
present. This confirms the timed-out observer did not stop guest execution.
Preserve the current disk, account and evidence until that command is terminal.

The inherited Azure-agent job is a leading hypothesis, not a verified cause.
Microsoft's [job assignment contract](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject)
requires processes in a job to share a session. The controller is in session zero
and attempts a session-three child without breakaway. The research driver now
retains `controller-job.json` before launch, including native membership, immediate
job limit flags and UI restrictions. The [query contract](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-queryinformationjobobject)
exposes only the immediate job, so this record cannot prove the whole parent chain
permits breakaway. Launch flags, executable ACLs and cleanup policy are unchanged.
The observation is mandatory: query or publication failure stops the research
path before inventory or installation. It cannot retroactively explain the
earlier controller's job limits.
Ten focused lifecycle tests pass, including the read-only native observer; this
does not establish cross-session launch or packaged execution. Next use a fixed
owned control through the actual controller chain before another installation.

### Fixed primary launch control

The closed `vm-launch-control` mode reuses the lifecycle controller's protected
input/source/preparation, dedicated SYSTEM/VM identity, before inventory, and WTS
primary-user gates. It branches before profile evidence creation or installation.
It holds the non-reparse System32 parent and bounded `cmd.exe` image, hashes that
held image, and requires a valid Windows Authenticode observation before launch.
The sole command is `C:\Windows\System32\cmd.exe /d /c "exit 42"`; no caller
arguments, credentials, new launch flags, breakaway, or desktop ACL changes exist.
The same suspended `CreateProcessAsUserW` path verifies held token/session/logon
and image identity, assigns the exact kill-on-close job, restores privileges,
and resumes once. Require exit 42 within ten seconds and confirmed job cleanup.

Request and terminal records are `launch-control-request.json` and
`launch-control-result.json` under the protected stage. A control never publishes
lifecycle `result.json`, and its result explicitly leaves compatibility/isolation
unmeasured. Failures identify `controlOnly` and preserve simultaneous operation
and cleanup errors, including in the prerequisite PowerShell helper. Existing
preparation expiry and fresh-output rules still apply: do not run this mode with
the retained failed trial's expired preparation or populated output.

The real local command test exercises exact command quoting, exit 42, and owned-job
cleanup. It does not prove the VM's WTS/cross-session launch. After the pending
diagnostic command is terminal and the disposable baseline is restored, perform
this control through the same Azure chain before another installation. Success
narrows the earlier failure toward the lifecycle image or execution-policy path;
the same pre-PID denial instead strengthens the common job/token/desktop hypothesis.
Neither outcome alone proves packaged activation or application compatibility.

Local validation passed 172 platform tests (ten explicitly ignored), then eight
guest-process and ten lifecycle tests on the final cleanup changes. Research-feature
warnings-as-errors clippy, release build, formatting and governance passed. The
initial platform run used the crowded long-lived TEMP and failed bounded parent
inventory checks; retained logs preserve that failure and the fresh-TEMP rerun.
No live primary-launch control has run yet. At 2026-10-11 07:42 UTC, independent
RDP readback still observed diagnostic PID 1820 and `RunCommand_470` transitioning.

Fresh readback at `2026-10-11T08:08:07.4499645Z` confirmed that PID 1820 was
absent and the exact action recorded `Command Execution Finished` at
`2026-10-11T07:59:26.8635307Z`. Despite its outer `success` status, code 1 and
stderr identify a `ConvertTo-Json` conversion failure. The diagnostic did not
produce the requested cleanup inventory; the long delay's cause remains unknown.
Retained record: `vm-primary-terminal-readback-20261011T080821Z.json` under the
proof root. Preserve the failed disk and recover bounded controller evidence
before restoring the disposable baseline; do not repeat installation to recover
diagnostic output.

The separately reviewed managed control `aiw-primary-diag-control-9f2996ca033b`
completed at `2026-10-11T08:05:58.993483Z`. Azure recorded execution success and
exit zero; the held fixed SYSTEM cmd process returned 42 and closed, with no
primary or cleanup error. This tests the managed command channel, not the WTS
launch or application lifecycle. Its optional status parser failed on JSON input;
only the independent RDP record above establishes the old action's terminal
status. The old action finished before this control started, so coexistence with
an active action was not demonstrated. Retain the managed observed record and
remove only this exact completed research resource before disk restoration.

Bounded managed SYSTEM readback recovered the controller at
`2026-10-11T08:15:18.0045873Z`. Its 121-byte stderr SHA-256 is
`fdef2873eb760f0c45dea389351bfbb7e5fbf5b546e115b19c6226fddd63155a`:
the same pre-child `CreateProcessAsUserW` access denial. The result and failure
hashes were retained with their bytes. No lifecycle driver process was observed;
the standard-user profile evidence directory existed. Package inventory was
explicitly not queried in this readback. This is failure recovery, not lifecycle
acceptance or complete cleanup proof.

Both exact completed managed diagnostics were deleted and independently returned
404 before disk recovery. The independently reviewed fixed helper
`vm-baseline-restore-r2.py` (SHA-256
`2065a546c0ffbf4b281ee289ed6d1fb48fd3a2a4328a7fda32910a190b230994`)
requested graceful Azure stop, observed stopped/deallocated state, swapped to the
exact retained original disk using the VM ETag and `Detach` policy, and restarted.
The failed disk `aiw-msix-restored-123e286bd0cf` remains retained and unattached.
The original snapshot remains available; do not treat the now-running original
disk as an immutable baseline for subsequent trials.

The resumed start poller confirmed terminal success at
`2026-10-11T08:23:41.929143Z`. Fresh managed SYSTEM baseline verification at
`2026-10-11T08:24:13.1550294Z` passed: exact marker hash and five baseline accounts,
absent trial account/profile/input/output/preparation/controller paths, zero
research package registrations/provisioning and driver processes, running guest
agent, and unchanged clear-key BitLocker state. The bounded primitive JSON
projection avoided the previous diagnostic's serialization failure. Its retained
`managed-restored-baseline-observed-*.json` record is separate from application
evidence. Fresh RDP login and account/session preparation are still required;
no primary-user launch control or packaged lifecycle has passed on this baseline.

Fresh account preparation r3 stopped before `New-LocalUser` execution because the
stale template's description exceeded Windows' 48-character limit. Failure and
request records were retained. Preparation r4 used a fresh protected directory,
checked the exact previous nonce, absent created/ready receipts, null owned failure
SID and absent account/profile, and shortened the description. It passed at
`2026-10-11T08:28:36.5968521Z`: `AiwStandardUser`, SID
`S-1-5-21-3407263227-439785483-4249424476-1001`, only Users/RDP Users, nonce
`43cd415eb41808ba1396b52a69efec17`. Credential delivery remains encrypted and
host-private. This account is fresh even though baseline restoration allowed the
same RID to be allocated again; later login binding must use the new lower time
and nonce, not the previous trial's session or preparation.

Azure network readback confirmed the unchanged static RDP endpoint
`20.118.172.1`, with TCP 3389 reachable. File-based RDP launches produced windowless
clients; only the exact owned ended/windowless clients were closed after held
process/generation checks. A normal RDP client launched with a returned window,
but computer-use capture initially failed with `foreground window did not report a process
id`. The user confirmed the connection prompt. Fresh returned window bindings
recovered capture; persistent lexical variables had shadowed newer global bindings.
The first standard-user connection disconnected with reason 2; its cause is not
established. After closing only the exact held administrator RDP client, a fresh
standard-user connection reached its own desktop. A fixed managed remote-session diagnostic
was rejected by automatic approval review as `blocked by policy`, without a
specific reason, before submission; it was not rerun. Retained handoff:
`vm-primary-login-pending-r4.json` records the earlier blocked state.

Clipboard transfer delivered the four frozen inputs. Fixed SYSTEM preparation
held each source file against writes/deletion, verified its exact size/hash, copied
it into fresh protected intake, and verified the resulting hash. The actual owned
shell was PID 6004 in session 4; only Users/RDP Users membership was accepted.
Preparation hash was
`88379f0f8210ab0309f91d35725cd5c489b36f8ea95f213569f3aa0be76622d0`.
The original 30-minute account window was preserved. Evidence:
`managed-primary-preparation-r4-observed-*.json` under the host proof root.

The `c2fda15` native `vm-launch-control` was dispatched through the Azure action
path using driver SHA-256
`b6ba89f8890383ad430fd7efe6ba68887c04ea52aceeb8c01f20f41aa6c6a01c`.
It exited 1 at `2026-10-11T08:56:38.3330171Z`, PID 13152, without timing out or
publishing a control terminal receipt. Bounded independent SYSTEM readback
confirmed no remaining driver process and no profile AIW evidence directory.
The exact error was `Closed run-owned primary preparation differs or expired`.
The retained account nonce is 32 hexadecimal characters; the native contract
requires 64. This is an account/preparation harness defect before WTS launch or
installation, not another `CreateProcessAsUserW` result. Readback:
`managed-primary-control-readback-r4-observed-*.json`; stderr was 86 bytes, SHA-256
`13b2f707eebd8c1c7da1c27598f23688d4b3190fd74d6ba6d28afbfd9fff51ba`.
Package inventory was not queried by that readback.

The repository now owns pure [preparation helpers](../scripts/research/msix-primary-preparation.ps1):
32 random bytes produce a 64-character nonce, and the preparation builder refuses
the actual short nonce, invalid account/session/image fields, and an expired or
extended account window. Its output is checked by the native validator, rather
than only testing a handwritten JSON fixture. These helpers establish record
shape only; SYSTEM identity, held intake, fresh account/profile, interactive
session and protected publication remain required in the live adapter. The next
trial must restore from the immutable snapshot into a new disk, use the canonical
helpers before account mutation, and retain a new account/nonce/time binding.
Do not alter the failed account receipts or extend their expired window.

### Fresh canonical preparation and inherited-job control, October 11

The canonical producer and native contract checks were independently reviewed and
pushed at `9d4a4aa`. PowerShell 5.1 and 7 each passed twelve preparation cases;
the two focused Windows-native tests, formatting and governance passed. Runtime
launch behavior was unchanged, so the live control retained the frozen `c2fda15`
driver and its independently supplied input hashes.

The immutable snapshot was copied to `aiw-msix-primary-r5-1e48cc0d203e`, disk
unique ID `c5642022-73fc-4fdf-83a9-63fb4d486c59`. Reviewed recovery preserved
both earlier disks, used the exact VM ETag and `Detach` policy, and started the VM.
Fresh SYSTEM readback at `2026-10-11T09:12:55.1533974Z` verified the baseline
marker/accounts, absent trial paths/package/processes, running guest agent and
unchanged clear-key recovery state. Recovery is not packaged execution proof.

Fresh account creation at `2026-10-11T09:14:48.4956766Z` recorded SID
`S-1-5-21-3407263227-439785483-4249424476-1001`, only Users/RDP Users membership
and the canonical 64-character nonce
`229eabfd92af9ea71f5db826d2abf1745912e3d72d5b916ba7823b0762692429`.
The immutable account window was `09:14:42.9314251Z`–`09:44:42.9314251Z`.
Real RDP sign-in reached the new user's desktop. An initial file-copy preparation
stopped on a missing Downloads input, before native launch; its record remains
retained. Corrected Explorer clipboard transfer produced all four expected files.
A new protected preparation then passed at `09:22:56.420972Z`, binding shell
PID 7680/session 2 and all input hashes. Preparation SHA-256:
`3abbf8fb81f1c466fbfd35e413c4a1dc83523576981af8260111d6220aa15f4a`.

The native control PID 6548 exited 1 at `09:23:33.8698166Z`, without timeout,
on `CreateProcessAsUserW: Access is denied. (0x80070005)`. No child handles,
control success receipt or application installation were established. Independent
bounded SYSTEM readback verified the retained failure, stderr and wrapper receipt,
no remaining driver process and no profile AIW evidence directory. Package
inventory was not queried by that final readback.

The retained primary context bound RemoteInteractive authentication ID
`00000000001452b2`, the standard-user SID and session 2. The signed fixed Windows
cmd image hash was
`97ac98b1a92c286054cce55239cfccdfc23a5517bd07fe693072c9ca96c7dabb`.
The request explicitly recorded `breakawayRequested=false`. The SYSTEM controller
reported session 0 and `inAnyJob=true`; its immediate limits/UI restrictions were
zero. Microsoft's [job contract](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject)
requires job members to share a session, and [child creation normally inherits the
parent's job](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).
Inherited Azure job/session conflict is therefore a strong hypothesis, not a
proven cause or application compatibility verdict; ancestor limits remain unknown.

Evidence under the host proof root: `primary-r5-recovery-state.json`,
`managed-primary-baseline-r5-verified.json`,
`managed-primary-preparation-r5b-observed-*.json`,
`managed-primary-control-readback-r5-observed-*.json`, and
`managed-primary-control-context-r5-observed-*.json`. Current failed guest stages
remain on the attached r5 disk. Do not repeat the native control against this
account/output or adopt its expired preparation.

The next discriminator is a protected, create-only, demand-start SYSTEM Task
Scheduler observation with a fixed action, no triggers/retries, exact task/action
binding and a deadline. The action must measure its actual job membership and
required privilege presence/enable/restore; Scheduler ancestry alone is not proof.
Then a held fixed cmd exit-42 control must prove process ownership and cleanup.
Only after those controls pass should a new snapshot clone, account and protected
preparation run the unchanged native WTS control. No breakaway flags, desktop or
executable ACL relaxation, generic command interface, or production launcher change
is justified by the current evidence.

### Default SYSTEM task observation

The protected task experiment retained three registration/validation failures
before running an action: `ServiceAccount` is not an XML `LogonType` value; the
corrected compact privilege XML was rejected at `Principal`; and a typed
`IPrincipal2` builder was rejected by validation-only at `Privilege:SeTcbPrivilege`.
The latter stopped before task creation. These are adapter observations, not
application failures. Do not assume that a documented privilege name or an
in-memory COM definition establishes registration readiness on the worker.

A fresh observation used the default SYSTEM service-account task without an
explicit `RequiredPrivileges` array. Independently reviewed fixed templates were
byte-hash pinned before normalization and placeholder expansion. The task was
create-only, demand-start only, with no triggers/retries, an exact SYSTEM/operator
DACL, one protected fixed action, a 40-second task limit and 30-second controller
deadline. Validation-only, canonical definition identity and registered semantic
readback preceded its single start. Task engine identity was retained separately
from the action's held PID generation, image, SID and session binding.

At `2026-10-11T10:00:04.5038352Z`, action PID 13040 observed SYSTEM/session 0,
no thread impersonation, and all five expected privileges present with successful
enable/restore: `SeTcbPrivilege`, `SeAssignPrimaryTokenPrivilege`,
`SeIncreaseQuotaPrivilege`, `SeImpersonatePrivilege`, and
`SeChangeNotifyPrivilege`. Actual observation governs this worker; do not infer
privilege presence or absence from generic default-task documentation.

The action reported `inAnyJob=true`, immediate limit flags `4096` (`0x1000`,
`JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK`). It exited zero; the controller verified
action exit, no remaining task instance, exact task deletion and task absence.
It attempted no cmd, WTS or application launch. Its conservative prerequisite
indicator remained false because the parent was in a job; this indicator is a
research gate, not a production compatibility verdict.

Microsoft's [job documentation](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
allows children to leave a job with this flag without requesting explicit
breakaway, but ancestor jobs can still prevent full escape. The next fixed cmd
control must observe the suspended child in **no** inherited job before assigning
it to the project's exact kill-on-close job and resuming once. Require exit 42,
bounded output/deadline, empty job inventory and confirmed cleanup. Parent flags
alone cannot establish complete escape, cross-session WTS launch or packaged
activation. No job policy or launch flags were changed by this observation.

Retained host records: `managed-task-context-r1-observed-*.json` through
`managed-task-context-r4-observed-*.json`; successful r4 resource
`aiw-task-context-r4-e35c1361e4f5`. Its task/action nonce and exact source identities
are in `managed-task-context-r4-state-r1.json`. Guest stage:
`C:\AIW-Task-Context-e35c1361e4f5b540611b4d8b4ec2a440a49cf2a8d4b92b2f2e53ac7f57dd5c18`.
Keep the failed stages, registered-definition record and cleanup receipt.
Separate SYSTEM readback at `2026-10-11T10:02:46.2742184Z` independently verified
the expanded worker hash against the host request, held generated XML identity,
retained terminal/cleanup records, current task absence and action PID absence.
Evidence: `managed-task-context-readback-r1-observed-*.json`;
controller result SHA-256
`88aebed013dfcafa7bbe1fc94ab14db14452dbf42e36740e7307dccda55de902`,
cleanup SHA-256
`9ca92ae998a4195e1e7f8f66f85b96ca217de17e662affbd0c7713f15740a558`.

### Scheduler child containment control

The independently reviewed closed control in
`scripts/research/msix-scheduler-launch-control.ps1` passed on the same dedicated
worker at `2026-10-11T10:19:22.9010198Z`. SYSTEM task action PID 2440 observed the
same immediate `0x1000` job flag. Fixed signed Windows cmd PID 11168 was created
suspended without explicit breakaway and observed in no job, then assigned to a
fresh exact kill-on-close job before identity checks or resume. Its image, SYSTEM
SID and session zero matched; one resume returned count one, exit was 42, both
streams reached EOF with zero bytes and the owned job was empty. Native cleanup,
action exit zero and exact task/instance removal all passed. This proves the
Scheduler child escape and owned containment control, not cross-session WTS or
standard-user application execution. The conservative parent-no-job diagnostic
remains false and is distinct from this measured child result.

Separate SYSTEM readback at `2026-10-11T10:21:28.5653774Z` verified the held worker
and generated XML hashes, retained launch/controller association, cleanup, current
task absence and both recorded PIDs absent. Host records are
`managed-scheduler-cmd-r2-state-r1.json`, `managed-scheduler-cmd-r2-observed-*.json`
and `managed-scheduler-cmd-readback-r1-observed-*.json`. Resource:
`aiw-scheduler-cmd-r2-4e4a54fc13c5`; nonce:
`4e4a54fc13c5a8c03054ec4ffdb8018078ea8f94a32fec9a992029278c533100`.
Retained launch result SHA-256:
`fa4fb6a572551bbcb5dca1bfcedab9f954b44f1a8fd92411a2a661e9088c959d`;
cleanup SHA-256:
`3b6bbb9802bfc999f005a0e69aaf5f20f51e8b87652268482952e9f4e6be5d7d`.
Next use a fresh cold boundary, account and canonical preparation to run the
unchanged native `vm-launch-control` through this default SYSTEM task route.

## Current evidence

The first unsigned package assembled with the pinned tool. Two subsequent fresh
assemblies passed independent archive payload hashing and semantic inventory
equivalence, retained licenses, the explicit removed-file contract, tampered-input
rejection before output and existing-output refusal. Unsigned MSIX hashes differed;
semantic payload/manifest equivalence, not byte identity, is the reproducibility
claim. MakeAppx's OPC entry `notepad%2B%2B.exe` maps to physical `notepad++.exe`;
the verifier uses exact per-segment URI encoding rather than skipping that file.
The first verifier's literal-path failure is retained separately.

Host evidence pointer: `%TEMP%\aiw-msix-proof-root.txt`.
`assembly-checks-r2/checks.json` and both assembly records retain exact identities.
No Notepad++ executable or application installer ran on the host.
Signing and installed payload verification are complete. The required
non-elevated lifecycle is **not yet verified**; the first activation stopped at
the token check, before document editing.
PR #95 merged at `9c25780` after exact-head review and all required checks passed.
The first hosted signing research run `37710593027` stopped before assembly or
signing because the runner's installed SDK differed from the approved tool. The
fixed NuGet archive provides the same approved tool without accepting runner drift;
SDK mismatch diagnostics now include the observed hash and version.
`notepad-msix-research.yml` is a manual owner/main-only assembly/signing workflow;
it has no public-release permission and never installs or executes the application.
Owner gates require both the original `github.actor` and the current
`github.triggering_actor` on assembly and signing, including reruns. The existing
personal signing control and desktop candidate use the same direct signing gate;
desktop publication also checks the triggering actor. See [GitHub's actor context
semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts).

### Signed package and first worker result

PR #96 merged the pinned SDK supply at `bcf6f8243334c4478f06ee825b8ef20867c9da38`.
Research signing run [37711841372](https://github.com/nathanmcnulty/app-isolation-workbench/actions/runs/37711841372)
assembled and signed that exact source. The signed `application.msix` is
8,641,353 bytes, SHA-256
`2ae3a7c685e811eb34479980bff41d1442b023578074e19f4dca8fc676070437`.
Host and dedicated-worker verification independently checked its valid personal
publisher signature and timestamp. Host verification hashed all 220 signed
payload entries against the hosted assembly inventory and bound the source,
assembly and signing records. Local and hosted raw manifests differed only by
eight CRLF sequences; this was explicitly recorded, while the raw signed manifest
was still verified against its hosted inventory. The producer now emits LF
regardless of checkout format; the assembly test exercises actual LF and CRLF
script copies. This change does not change the identity of the already signed output.

On the dedicated disposable VM, the project-owned process control passed before
installation. The signed package installed as
`AIWResearch.NotepadPP_8.9.8.0_x64__q1fhfzcjv9wt6`; all 220 installed payload
entries matched. Package activation returned PID 8072 in interactive session 2.
Its observed package identity and executable hash matched, but its actual token
was elevated, high integrity (`S-1-16-12288`), and not AppContainer. The recorded
`aiwoperator` SID ends in RID 500: the renamed built-in Administrator. The visible
editor also displayed `[Administrator]`. The driver stopped at activation and
retained the failure before editing. A manifest declaration of `mediumIL` did
not establish the required non-elevated execution observation.

The exact owned editor was closed. A SYSTEM-context removal targeting the recorded
operator SID returned but left registration pending removal. That failed cleanup
check remains preserved. Removal in the actual operator's context then completed;
fresh independent readback found no current-user or all-user registration, no
Notepad++ process, and no package-private configuration directory. Configuration
had previously appeared in `LocalCache/Roaming/Notepad++` under the package's
per-user directory. Neither the accepted cross-user command nor early configuration
creation proves the required completed lifecycle.

Under the host proof root, `signed-artifacts-bcf6f82/signed-verification.json`,
`vm-msix-lifecycle-readback.json`, `vm-msix-recovery-inspection.json` and
`vm-msix-recovery-final-readback.json` preserve these distinct observations.
The worker's original `lifecycle-evidence` directory retains the failure and both
cleanup results. Document edit/save, post-workflow immutable payload and normal
uninstall remain open. The next trial must first prove a fresh standard user's
profile, medium non-elevated token and visible owned control, then install the
same verified package with new evidence. Do not weaken the token gate or change
the VM's UAC policy to pass this trial.

### Standard-user research control

The `aiw-windows-platform` example `msix_standard_user_control` is compiled only
with the explicit `research-msix-control` feature. Default production builds
exclude it. It accepts no command or path arguments and requires the native
Sandbox operator name plus a fresh `C:\AIW-Msix-Control-Output` mapping.
It calls the production `StandardUserSession` and `GuestProcess` implementations:
fresh account/profile/environment, one-use credentials, suspended-child token
and session validation, exact-SID desktop grant/access preflight, owned handles
and job. Its only child is a fixed project-owned GUI control, not Notepad++.
It retains process/token/window/profile observations, a child transcript,
pre-cleanup PID inventory and post-cleanup job readback before a terminal result.
Cleanup and evidence-export failures preserve the primary operation error.
The account and desktop grant live only in the disposable Sandbox and require
disposal of that exact owned session. A passing control is a prerequisite for
the application trial; it is not install or compatibility proof.

The first control-only Sandbox (`b316e9ee-19be-4eab-b25a-663ac96d08ff`)
opened but never entered its PowerShell file bootstrap. Guest inspection observed
`Restricted` execution policy; an explicitly attributed diagnostic reproduction
retained the script-disabled `SecurityError`/`UnauthorizedAccess` rejection.
No application ran. The exact session was stopped in its recorded operator's
context, and a fresh provider readback was empty. The failed stage remains intact.
The corrected research launch uses the fixed compiled control directly, with its
input held read-only against host replacement throughout the connected session.
It does not change execution policy. Missing control receipts remain an
unaccepted trial; provider start/connect alone cannot prove process completion.

This diagnosis also exposed a monitoring boundary: SYSTEM/session-0 provider
inventory was empty while the interactive operator's exact Sandbox was visibly
running and appeared in that operator's provider inventory. Readiness and cleanup
observations must retain the querying identity/session; a different actor's empty
list cannot establish that the owned interactive worker is absent.

The fresh direct-launch control (`146a783d-9856-43fe-9798-082ea65143f3`)
retained a standard-user profile context, then failed before child creation with
`CreateProcessWithLogonW` error 87. Independent readback verified the input lock
denied write access. The control command exceeded that API's documented 1024
character limit. The shared launcher now checks the actual quoted UTF-16 buffer
before launch side effects, using a conservative limit including its terminator;
tests cover ASCII and supplementary Unicode boundaries. The shortened fixed
control has a separate test against the same quoting and native limit. These
checks do not prove a successful live standard-user control or application trial.

The next fresh control, built from `965b07ac71c11c2acc2e727f976886043714f885`,
passed in owned Sandbox `3b6428bd-28e0-4bf1-8b87-9b6d911dd6ee`. Independent
readback bound the held input hash
`2487c7cf42ab250ecec8fd480fc66e434a21e56e815140520e046d55500da88b`
to the recorded source and worker. Child PID 6736 had the context's exact SID,
medium integrity and no elevation. Its GUI was visibly observed over RDP;
the retained window observation matched the PID. The child result recorded
the same SID/profile, guest session 1 and completed GUI loop. Exit was zero;
normal cleanup and evidence export had no errors, with zero job processes
before and after cleanup. The terminal research result explicitly says the
application trial was not run.

The exact worker was subsequently stopped in its recorded operator SID/session;
native exit zero and the operator's empty provider inventory were independently
read back. The dedicated VM remained running and its RDP desktop remained
accessible. Under the host proof root, `vm-msix-control-short-readback-r2.json`
and `vm-msix-control-short-final-readback.json` retain these observations. The VM
stage `AIW-MSIX-Control-0a335285792644c1a35de52ece073974` retains the complete
control output and ownership/provider records. This proves the narrow launcher
prerequisite, not MSIX installation, editing or isolation. Independent outer
driver process/stream/deadline supervision and the real application lifecycle
remain required before accepting that trial.

### Closed lifecycle driver

The feature-gated `msix_standard_user_lifecycle` example implements the full
fixed trial; it is excluded from production builds and has not yet passed a live
application trial. Its native parent reuses the held standard-user launcher and
owns the process job. The native child runs only the embedded lifecycle script,
with the package, assembly and signing identities compiled in. No caller command,
script path or executable identity is accepted. Success requires every stage
receipt, independently checked document/configuration bytes, all 220 payload
entries, actual application token/package identity, registration readback and
owned-job cleanup. A failed brokered application is retained for inspection and
disposal of the exact worker, not automatically adopted or retried.

A read-only VM check exposed kernel pseudo-processes whose executable image
query fails although Windows positively reports no package identity. The fixed
inventory queries package identity first on the same held handle. Unknown
identity and open/session failures stop the privileged parent's global acceptance;
unqueryable named Notepad++ candidates stop either actor. Image failures are
retained separately only after native
`APPMODEL_ERROR_NO_PACKAGE`; their receipt shape is validated. This proves absence
of the target package identity and named application, plus absence of its path
among successfully queried images. It does not prove complete image visibility;
listed non-package image paths remain unmeasured. See Microsoft's
[package identity API contract](https://learn.microsoft.com/en-us/windows/win32/api/appmodel/nf-appmodel-getpackagefullname).
The initial failing observation is retained as `lifecycle-parser-current-r2.json`
under the host proof root, separately from subsequent corrected probes. These
SYSTEM-context checks are syntax/native-query diagnostics, not standard-user
execution, operator provider readiness or application compatibility proof.

The first full-driver attempt used source `83b55a7` and executable SHA-256
`911b17a313204c8e28382026a380e70c73387478eb080a6ca57eb560ed02cb14`,
in Sandbox `60c0ef25-47ba-4885-a72b-018f9dc2add0`. It stopped at preflight:
the standard user could not inspect 68 system processes. No install-started
receipt or success result was published. Failure export, exact child identity,
empty owned-job cleanup and the privileged parent's empty registration/process
inventory were independently read back. The exact worker was stopped by its
recorded operator; exit zero and that operator's empty provider inventory were
independently verified. The VM remains available. Retained evidence:
`vm-lifecycle-failure-detail-r1.json` and `vm-lifecycle-final-readback-r1.json`;
VM stage `AIW-MSIX-Lifecycle-1baaecea11d945c6b59e951880999b48`.

The correction assigns global inventory to the privileged parent before launch,
after child completion **before** job cleanup, and after job cleanup. Each scan
must prove absent registration/provisioning, no application candidate and no
unknown package-identity query. The application user's scans retain every failed
query with explicit diagnostic authority; they cannot claim global absence.
Positive application matches and named-target failures still stop that child.
It proves exact held-editor closure before current-user uninstall; global absence
is verified at the parent's recorded checkpoints, not inferred during the
editor-close/uninstall interval. This correction still requires a fresh live trial.

The retry at `ff822b8` in Sandbox `049769b2-df60-4e36-8ba1-be4039bf97d9`
passed all three actual standard-user driver controls: captured stdout/stderr,
exit zero, deliberate exit 42, and exact deadline termination, each in the
inherited job. It then stopped before installation because PowerShell 5.1
StrictMode rejected `.Sum` on an empty configuration snapshot. The native child
and failure export completed; the parent recorded absent registration/processes
and zero job processes. This is another driver prerequisite failure, not an
application compatibility observation. Retained evidence is
`vm-lifecycle-failure-summary-r2.json`, in VM stage
`AIW-MSIX-Lifecycle-7885747d0a394539bdab52c94520c783`.
Exact worker disposal subsequently returned zero; independent readback of
`vm-lifecycle-final-readback-r2.json` confirmed the recorded operator's empty
provider inventory. The dedicated VM remained running and accessible.
The configuration helper now starts its byte sum at zero. The focused
`scripts/research/test-msix-lifecycle-configuration.ps1` test extracts only the
actual configuration helpers without executing the trial. Empty and single-file
snapshots, combined count/byte bounds and individual file bounds pass in both
PowerShell 7 and 5.1. The subsequent fresh worker reached installation, as recorded
below; the complete application lifecycle remains unverified.

The retry at `ba1fb17` used executable SHA-256
`89bc3729c65d9079088e660bfbdd2c32b740a03e2881a9a97973119344c9e6d5`
in Sandbox `4c678c71-1c21-4c9a-8631-d89a7009636f`. The actual application-user
supervisor had the expected SID/profile, medium integrity, no elevation, no enabled
Administrators group and inherited job ownership. The signed MSIX installed with
status `Ok` and the exact expected registration. All 220 installed payload entries
passed the driver checks; independent retained-receipt comparison against the
hash-verified assembly confirmed their paths and hashes. The raw installed manifest
also matched the expected hash. Evidence: `vm-lifecycle-install-detail-r3.json` and
`vm-lifecycle-payload-readback-r4.json`, under the host proof root; VM stage
`AIW-MSIX-Lifecycle-52389bcc9c4f448e9a297b97fdfdec4b`.

`IApplicationActivationManager::ActivateApplication` then failed with
`0x80070520` (the specified logon session does not exist). No activation-returned,
observed-application, awaiting-edit or success receipt was published. The owned job
was emptied, but the parent's registration inventory correctly refused success
because the package remained installed. Failure evidence was retained before
disposing only the exact owned worker; no automatic uninstall or repeated install
was performed. Independent readback of `vm-lifecycle-final-readback-r3.json`
confirmed stop exit zero and the recorded operator's empty provider inventory.
RDP remained connected to the VM. This is an activation-context failure, not an
application compatibility verdict.

The launcher uses `CreateProcessWithLogonW` for the alternate standard user on the
existing desktop. A matching Windows session ID, loaded profile and visible control
GUI do not establish that packaged activation works in that context. Microsoft's
[activation API contract](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-iapplicationactivationmanager-activateapplication)
specifies activation in the current session; it does not establish this alternate
user arrangement as supported. The next control must establish the actual package
activation context and independently observe package/image/token identity before
another full document lifecycle. Do not substitute elevated or unpackaged execution
for the required observation, or infer that every alternate-user activation is
unsupported from this single HRESULT.

The closed driver now implements a bounded research control for suspended creation of the exact
registered installed executable. Before resuming application code, require the
held process's exact package full name and
`AIWResearch.NotepadPP_q1fhfzcjv9wt6!Notepad` application identity, image hash/path
and standard-user token/session. Missing or mismatched identity must terminate
the suspended process and stop; an unpackaged launch cannot satisfy this control.
Use [GetApplicationUserModelId](https://learn.microsoft.com/en-us/windows/win32/api/appmodel/nf-appmodel-getapplicationusermodelid)
to distinguish the declared application from its package. This is an experiment,
not an accepted replacement activation route. If it fails, compare against a
disposable VM with a real standard-user interactive sign-in before changing the
production launcher or inferring application incompatibility.

The native helper holds both creation handles, permits one resume with the expected
suspend count, and terminates/waits on an unresumed process when disposed. The
pre-resume and resume receipts are required for terminal acceptance; absent/wrong
application identity or an unverified launch cannot pass. Any-job membership is a
diagnostic only: it does not identify the project's owned job. Application closure
and privileged process inventories remain separate from owned-job cleanup. Local
PowerShell 5.1 compilation and the focused negative receipt checks pass; these are
driver checks, not a live packaged-execution result.

The fresh trial at `48bd1fd` used executable SHA-256
`c12ac8107472a941499c31f98470ccbf9ba303350d55be76b611d80baea581c7`
in Sandbox `cca23753-8bd6-4887-9ffe-b17d2879e562`. Installation succeeded,
but the fixed suspended `CreateProcessW` call returned `Access is denied` before
returning a process ID. No suspended-identity, resume, visible-window, document-edit
or success receipt was published. The parent verified zero owned-job processes and
refused success because registration remained. Evidence is retained in
`vm-lifecycle-suspended-stage-r2.json`; VM stage
`AIW-MSIX-Lifecycle-34344d8cf8114ee993698b8f3d070547`.
Exact worker disposal returned zero; independent readback in
`vm-lifecycle-suspended-final-r1.json` confirmed the recorded operator's empty
provider inventory. The dedicated VM and RDP session remained available.
This does not establish why the access check failed, or whether the same package
will activate in a primary interactive standard-user session. That comparison is
the next control; do not relax executable ACLs or use elevated/unpackaged execution
to bypass the observed failure.

## Feedback into assessment

The completed trial must inform shared assessment without introducing a second
verdict engine: distinguish source application identity from delivery package
identity, requested trust level from observed token/package identity, installation
paths from observed user-data paths, and uninstall registration cleanup from data
deletion. Preserve the explicit adaptation and before/after inventories. A package
or SDK error is a delivery/driver result, not application incompatibility. Reuse
the existing protected intake, approval/session binding and receipt-last evidence
publication when promoting this research into a production path.

The first worker result already demonstrates two reporting requirements: token
claims need observations of the actual application process, and uninstall success
needs registration readback rather than command acceptance. An unsuitable worker
operator is a trial prerequisite failure, not evidence that the application is
incompatible. Existing assessment standard-user controls remain the implementation
to reuse; this research does not introduce a separate compatibility verdict.

Installation and activation readiness must also stay separate. The latest worker
proves that successful signed installation and payload verification do not establish
a usable packaged activation session. Shared assessment should retain this as an
unverified execution prerequisite until a matching activation control passes,
preserving the successful installation observation without upgrading compatibility
or isolation claims.
