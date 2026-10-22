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

## Remaining gates

GitHub CLI 2.103.0 on controller PASSKEYS\labadmin reported its keyring token
invalid; the private draft release download returned HTTP 401. No token environment
override or alternate CLI executable was present. The connected GitHub integration
can read release metadata but cannot download release binaries. The human requested
CLI access and later explicitly authorized `gh auth login --web` using a device
code in the local computer's browser, overriding the earlier repository rule for
this recovery. Do not substitute a browser asset download.
Restore CLI authentication, then download and verify the unchanged 60-file archive
using the sizes/hashes in RESUME-ON-NEW-VM.md. Leave the release draft and preserve
historical controllers unchanged. No archive was downloaded in this continuation.

Next rebind the archived r6 Scheduler controllers into fresh source with the new
executable hash, worker identity and baseline. Arrange actual standard-user remote
interactive login before starting its 30-minute window. Only after that real shell
and matching token/session are verified, publish fresh preparation and prove native
`vm-launch-control` (WTS user, exit 42, empty exact owned job, native/task cleanup).
The SYSTEM-only control above does not satisfy WTS standard-user proof.
Then use a fresh disposable trial for the signed Notepad++ lifecycle: actual
non-elevated packaged process, GUI edit/save, exact bytes, configuration, unchanged
payload, normal uninstall and independent cleanup. No compatibility or broader
isolation verdict follows from the controls or successful build.
