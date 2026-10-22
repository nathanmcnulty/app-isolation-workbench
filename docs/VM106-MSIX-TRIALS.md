# VM 106 MSIX trial continuation

This is research-driver readiness and control evidence, not application acceptance.
The disposable baseline is `aiw-vm106-baseline-20261021`; do not replace it.

## Rebound native driver

The closed driver now pins guest UUID
`7e686bee-8c05-43c7-9603-a9562ece224c`, computer PASSKEYS-WORKER, physical MAC
CC-34-21-7E-FE-59, administrator SID
`S-1-5-21-3849540285-1795134874-2442050430-1006` and that machine SID prefix.
The old Azure IMDS dependency is replaced with local UUID/name/adapter checks.
The native and PowerShell preparation validators explicitly exclude administrator
RID 1006. Standard-user identity, real WTS session/authentication, medium integrity,
input/package identities, held processes/jobs, freshness, ACLs and cleanup remain.

Eleven native lifecycle tests passed. Preparation nonce/time/SID/VM negative cases
passed under PowerShell 7 and 5.1. An initial native command-length regression was
retained in `vm106-native-tests.log`: CRLF checkout bytes made the embedded command
exceed its existing limit. Normalizing embedded CRLF to LF fixed the existing
limit test; all eleven tests then passed in `vm106-native-tests-r2.log`.
Release x64 MSVC/static-CRT build succeeded, log `vm106-driver-build.log`.
Independent reviews found no remaining findings in the rebind or transport.

Built executable SHA-256:
`6d312e1ad135c9bfe8be36cc810079e5607f021f514af4320c1458930fa7437d`.
Controller binary is under
`C:\passkeys\worker106-tools\build-msix-vm106\x86_64-pc-windows-msvc\release\examples`.
The same bytes were transferred to
`C:\AIW-Worker-Setup\msix-vm106-staging\msix_standard_user_lifecycle.exe` on VM 106.
That staging path is intentionally not the executable's accepted run path.
No native WTS/application launch was attempted there.

## Actual Scheduler control

Worker preflight reported no AIWResearch.NotepadPP registration/process, no old
lifecycle input/output/preparation stage and no signed-in user. Its cmd.exe had a
Valid Authenticode signature and SHA-256
`15cd209c995b7d3009c91ca40892d5b8f1fb162f3e5f10716642ea278e8e0d7b`.
The existing fixed `msix-scheduler-launch-control.ps1` was rebound to those observed
worker/image identities; its native control logic was retained.

The new paired worker/controller runs only that control, in an atomically created
SYSTEM/administrator-only stage. It pins and holds both source files. A fixed
SYSTEM scheduled task publishes its PID/start-time record and waits for an
acknowledgment. The administrator holds and verifies that exact PowerShell process,
including start time, image, session zero and SYSTEM owner, before acknowledging.
Deadline cleanup never terminates an unverified PID; owned-task cleanup is attempted
independently even if exact-process termination fails. Both errors are retained.
Fault injection of the actual finally block passed under PowerShell 7 and 5.1:
unverified PID, failed exact termination, and simultaneous process/task failures.
Independent review identified those two cleanup issues; both were fixed before
dispatch. LF attributes preserve the payloads' pinned committed bytes.

Stage: `C:\AIW-Worker-Setup\msix-vm106-staging\scheduler-control-r1`.
Task: `AIW-VM106-Scheduler-Control-20261021` (verified absent after completion).
Reviewed outer controller: `controller-reviewed.ps1`, SHA-256
`6fb21010d43dfbfd5e85b645be837b40f6f34ed05c603f762698e8e8336314b7`.
The unused `controller.ps1` source is retained; it was never dispatched.

The first file invocation stopped at execution policy before source execution;
`scheduler-control-live-r1.json` retains it. The actual dispatch used process-scope
Bypass, without changing machine/user execution policy. It passed: scheduled SYSTEM
parent, immediate silent-breakaway premise, suspended child not in an inherited
job, exact owned kill-on-close job assignment, fixed cmd image/SID/session, one
resume, exit 42, empty stdout/stderr, empty owned job and confirmed native cleanup.
The outer controller independently recorded its held worker exited, task absent,
and no operation/cleanup errors. No standard-user account or application was created.

Controller receipts in `C:\passkeys\worker106-tools`:
`vm106-trial-preflight-result.json`, `vm106-trial-ready-summary.json`,
`scheduler-control-live-r2.json`, `scheduler-control-native-result.json`, and
`scheduler-control-controller-result.json`. File exports were SHA-256 checked on
both sides using the encrypted PSRP transport. No rollback or baseline replacement
was performed after this successful bounded control.

## Primary interactive continuation, 2026-10-22

GitHub CLI authentication is working and source push succeeded. The private draft
migration ZIP was downloaded through CLI: 9,133,397 bytes, SHA-256
`fb7b8ba88e091562bd50bab514d4b6de2181f4fa5623a8e5e6eba8750b6911e7`.
All 59 manifest entries and the exact 60-file archive inventory were verified.
Historical controllers remain unchanged in the extracted archive. Rebound closed
r6 Scheduler templates are in `scripts/research/worker106-primary`.

Attempt r1 created a fresh timed standard user (SID ending 1007), completed an
actual console sign-in, and observed its unique Explorer process in session 1.
SYSTEM cleanup verified the one-time LSA autologon secret absent and every changed
Winlogon value restored. No plaintext password was logged or put in Git.
The Scheduler definition then failed verification before its first RunEx call:
Windows normalized `PT260S` to `PT4M20S`. No native driver or application launched.
Registered instance count was zero and last-run time was the never-run default.
The task and stage were preserved because native custody was not established.
The exact canonical duration check was fixed; read-only COM positive and wrong-
duration negative checks passed against the live registered definition.

Attempt r1 evidence is on the controller under
`C:\passkeys\worker106-tools\primary-vm106-r1`; `evidence.zip` SHA-256 is
`d4d48ac6ebe2a1708dda1feb9684ebe1ef593ec9ec2d47499566de899a66fdf5`.
A graceful shutdown, exact stopped-state check, baseline rollback of OS/EFI/TPM,
and restart all returned exit zero (08:28 UTC). This is the first actual restore
proof; `cold-restore.json` retains the operation results. Baseline was not replaced.

Attempt r2 uses a fresh account nonce and controller evidence directory. Signed
input staging again passed hashes, publisher and timestamp verification. The
corrected primary-session control passed live: WTS user/session/authentication binding,
cmd exit 42, native parent outside inherited jobs, empty owned job, held native
exit zero, action exit zero, task and instance absent. Terminal receipt SHA-256
`d42d4e82a77fbe258c27e250c85b82f43dbfeac152a223dc868cbe456f1a9a4a`;
export ZIP SHA-256 `cd66cd1a025568f76f0911e444d9ec125aaea2a849d54a3d15148b1b351d15cd`.

After exporting control evidence, another cold baseline restore/restart passed.
Attempt r3 is a fresh disposable trial for the signed Notepad++
lifecycle: actual non-elevated packaged process, GUI edit/save, exact bytes,
configuration, unchanged payload, normal uninstall and independent cleanup.
Controls and builds do not establish application compatibility or effective isolation.
## Application attempt r3 and held-handle exit fix

A fresh baseline/account/nonce trial actually installed the signed package and
validated its 220 installed payload entries. Suspended-process evidence verified
package full name, AUMID, installed executable hash/path, standard-user SID,
authentication/session and medium integrity before resume. Its actual visible
Notepad++ window opened the prepared document. The GUI appended the exact validation
line, saved, and closed normally. Retained document bytes are exactly the expected
53 bytes (UTF-8 without BOM, CRLF). Screenshot `packaged-editor-saved.png` is under
controller evidence directory `C:\passkeys\worker106-tools\primary-vm106-r3`.

The driver then stopped at `document-workflow`: .NET's externally obtained Process
object reported `closed:true` but `exitCode:null`. No Notepad++ crash events were
observed. No exit zero or complete lifecycle is inferred from that absence.
The package was deliberately retained, native child/job cleanup completed, and
independent inventory correctly reported remaining package registration. The
Scheduler failure path also retained a harmless stop-of-completed-instance error;
its native held-process exit was confirmed. Export ZIP SHA-256:
`0fe2344fe0df608573908f60d4cd3a01c08cc7f84bf1fe56395ec6b1e0dbd8f3`.
After verified export, stopped baseline rollback/restart passed again.

The fixed editor wrapper now waits on its original held CreateProcess handle and
queries GetExitCodeProcess only after the wait signals. Timeout/query errors and
nonzero application exits still fail; receipt records the held-handle observation.
[Microsoft's API contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess)
requires a process handle with query rights; the original CreateProcess handle
provides them. Independent review found no remaining defect. Fourteen actual
controlled-cmd regression checks passed under Windows PowerShell 5.1 and PowerShell
7.6.5, including 0/42/259/uint-max exits, timeout, invalid states and query errors.
No installer or MSIX trial ran on the controller.

The first rebuilt image (`41d2757e...`) was staged but never launched: the full
native tests caught its fixed command exceeding 32767 UTF-16 units. Removing
standalone comments/leading indentation from the closed embedded sources retained
current script semantics; all eleven tests then passed. The actual compacted script
also parsed and its literal C# compiled under Windows PowerShell 5.1.
Final static-CRT x64 driver SHA-256:
`442265d9c40fefade23ccbe9db90d10058d0969643d52eb8854aa65fb921b1ca`.
All current closed template/input pins use those bytes. The r4 input bundle was
transferred, expanded and all eleven files verified on the restored worker.
The fresh application acceptance rerun remains pending; r3 is partial evidence.