# Dedicated QEMU VM preflight

Observed October 21, 2026 (America/Anchorage), starting from clean
`9f92cfdae0a5ef56b2e90f280b252387fe8d62a9` on
`codex/new-vm-handoff-20261021`. Checkout: `C:\aiw\app-isolation-workbench`.
This is setup evidence, not a disposable-boundary or lifecycle acceptance receipt.

## Machine and inputs

- Windows 11 Enterprise x64, build 26300; computer `AIW`.
- QEMU Standard PC (Q35 + ICH9, 2009), hypervisor present. SMBIOS UUID:
  `652A575B-A462-418E-95BB-360B28516925`.
- Operator `AIW\labadmin`, SID
  `S-1-5-21-3556347314-2314855617-1438300668-1001`.
  Observed token and Explorer shell share session 1 and authentication LUID;
  both are medium integrity, non-elevated, with Administrators disabled.
  This existing administrator account is not the controller-created trial user.
- Azure IMDS was unreachable. Do not substitute this SMBIOS UUID into the Azure
  identity contract; a reviewed QEMU-specific binding and recovery proof are needed.
- Rust/Cargo 1.99.1, x64 MSVC target, Visual Studio Build Tools 2022 with x64 C++
  tools, Windows SDK libraries 10.0.26100.0, PowerShell 7.6.5 and Windows PowerShell
  5.1.26100.9711 are present. GitHub CLI uses existing authenticated credentials.
- Downloaded archive to `C:\AIW-Resume-20261021\AIW-Migration-20261021.zip`.
  Its size/hash match [RESUME-ON-NEW-VM.md](RESUME-ON-NEW-VM.md). Extraction at
  `C:\AIW-Resume-20261021\assets` matches the committed inventory: 59 hashed
  assets plus `inventory.json`, no missing or extra files.
- Windows Authenticode returned `Valid` for `inputs\application.msix`, with the
  expected Nathan McNulty publisher and Microsoft timestamp signer. Full payload
  association must still be verified on the eventual disposable trial worker.

## Session probe

Each PowerShell version passed two positive and twenty rejection cases, with a
read-only current-session observation. Neither accepted the current session for
an application trial. Local results and failures are preserved at
`C:\AIW-Resume-20261021\new-vm-preflight`.

Windows PowerShell initially rejected script loading under its default policy.
The successful invocation used `-ExecutionPolicy Bypass` for that process only;
no persistent execution policy was changed. It also exposed an empty
`$PSScriptRoot` during default-parameter evaluation. The probe now resolves its
default source directory after parameter binding. Both versions passed using
that default after the correction.

```powershell
$ErrorActionPreference = 'Stop'
Set-Location C:\aiw\app-isolation-workbench
& 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\aiw\app-isolation-workbench\scripts\test-msix-interactive-session.ps1 -ObserveCurrent
if ($LASTEXITCODE -ne 0) { throw 'Windows PowerShell session probe failed' }
& .\scripts\test-msix-interactive-session.ps1 -ObserveCurrent
```

## Remaining gate

The unchanged native source at `9f92cfd` built successfully with
`research-msix-lifecycle`, `--release --locked --target x86_64-pc-windows-msvc`
and static CRT. Output:
`C:\AIW-Build\msix-new-vm-baseline\x86_64-pc-windows-msvc\release\examples\msix_standard_user_lifecycle.exe`,
SHA-256 `7d22740dab342f0811003105b298762027e4fbd22f26bb38f9ffe9ee2a0099d6`.
Build log: `C:\AIW-Resume-20261021\new-vm-preflight\baseline-release-build.log`.
This binary retains the old Azure pins and has not been executed. It verifies
the build environment only. Governance validation and `git diff --check` passed
for the preflight documentation and session-probe correction.

The user identified Proxmox host `pve-r630`, `192.168.1.6`, and VM `203` (`aiw`).
The host-supplied VM configuration matches this guest's SMBIOS UUID. Its OS, EFI
and TPM volumes are on `r630-bulk`; no snapshot existed at the supplied readback.
SSH host Ed25519 fingerprint supplied through the root console and independently
matched before key authentication:
`SHA256:J/kc0UwUBil5TFBQbQhwBoRKnDoRlZ8ggXAhmYEpq1E`.
The dedicated `aiw-codex` Linux account authenticated, but has no privileged
management access. The user prefers native Proxmox commands without sudo.

`scripts/research/proxmox-vm203.sh` provides a fixed root SSH forced-command
boundary: `inspect`, `status`, `shutdown`, `start`, `snapshot`, `rollback`.
Every call checks root, the exact host, VM name and UUID. It accepts no shell text,
caller-selected VM ID or snapshot name. Snapshot/rollback require a stopped VM
and use only `aiw-msix-baseline-20261021`. An existing snapshot is not overwritten.
Install only as root-owned code with a `restrict,command=` public-key entry;
the ordinary account must not be allowed to modify the wrapper. The user
installed the independently reviewed wrapper from `d6f293a`. Restricted root SSH
`inspect` passed and `qm status 204` was rejected with exit 64 before dispatch.
Readback is retained locally as `new-vm-preflight\proxmox-inspect-r1.txt` and
`proxmox-rejected-command-r1.txt` under the migration root. `r630-bulk` is active
LVM-thin: 833392640 KiB total, 129092519 used and 704300120 available. VM 203
remains running with no snapshots. No power operation or snapshot creation has
been dispatched.

A flushed baseline marker at `C:\AIW-Recovery-Baseline-20261021\baseline.json`
records the observed machine, source, operator, seven local account SIDs/enabled
states and fresh nonce. SHA-256:
`8fb923e208de8489ee454ccb3f8b533608a13f5104c9b52ff4be926317523434`.
It is a recovery comparison marker, not privileged application evidence.

## Revised recovery direction: separate worker VM 107

The user chose a separate full clone instead of snapshotting/restoring the
development machine. VM 203 keeps Codex, checkout and retained evidence. The
previous host-shell shutdown/snapshot/rollback/start block for 203 is superseded;
do not run it for application testing. The marker above describes the source
machine only, not fresh clone identity or disposable-boundary proof.

Agreed preparation was a clean shutdown of 203, full clone with a new MAC and
disconnected NIC, leave the clone powered off, then restart 203. The user's
subsequent root-console readback identifies:

| Field | Worker identity |
| --- | --- |
| VM ID/name | `107`, `aiw-worker` |
| State | stopped; no snapshots |
| SMBIOS UUID | `e5cecc90-35c2-4831-bf9c-424be23f7d4e` |
| VM generation ID | `f2a6f03a-fae8-46d8-8398-9c26a6a54bdc` |
| NIC | `CC:34:21:B8:5A:31`, `vmbr0`, `link_down=1` |
| OS disk | `r630-fast:vm-107-disk-1`, 100 GiB |
| EFI | `r630-fast:vm-107-disk-0`, 4 MiB, enrolled 2023 keys |
| TPM | `r630-fast:vm-107-disk-2`, 4 MiB, TPM 2.0 |
| Guest agent | enabled in VM configuration; runtime untested |

The inherited description still names the source/template and `r630-bulk`;
it does not override the actual worker disk records. The commands used were:

```bash
qm config 107
qm status 107
qm listsnapshot 107
```

`scripts/research/proxmox-worker107.sh` is prepared using those observed fields.
It checks current and pending configuration, the exact worker name/UUID/disks,
disconnected NIC, and additional attachment restrictions. A root-controlled lock
serializes requests; rollback rechecks the snapshot's identity and NIC state.
Only fixed `inspect`, `status`, `guest-info`, `shutdown`, `start`, `snapshot` and
`rollback` are accepted. `guest-info` uses read-only guest-agent builtins; there
is no caller-selected guest execution or network-enable command. Its only
snapshot name is `aiw-msix-worker107-clean-r1`, to be created after sanitization.

Installation will replace the bytes at `/usr/local/sbin/aiw-vm203`, the existing
forced-command entry point, with the reviewed worker-107 wrapper. The legacy
filename remains solely to avoid editing the root authorized-key record; the
new code contains no VM 203 management command. The user installed revision
`66cddd5`; both old/new script hashes verified. Independent SSH `inspect`
confirmed stopped/offline VM 107 and active `r630-fast` LVM-thin storage:
911142912 KiB total, 95487777 used, 815655134 available. A request for
`qm status 203` was rejected with exit 64. Do not bypass the wrapper. Do not
guess that cloning changed Windows account SIDs or hostname.

## First offline boot: post-start observation blocked

Bootstrap evidence is retained on development VM 203 at
`C:\AIW-Resume-20261021\worker107-bootstrap-r1`. Before startup, independent
host inspection verified the stopped worker and exact disconnected NIC.
`start` returned zero at `2026-10-22T03:15:16.1947286Z`; stdout retained the
swtpm message that existing TPM state was not overwritten. This is command
completion, not successful Windows boot or guest-agent proof.

Subsequent `guest-info`, `inspect` and `status` each returned 1 with no output.
The installed revision does not identify failed identity/configuration guards.
No guest observation, application trial, credential cleanup or recovery proof
was accepted. Root-console `qm status 107`, `qm config 107 --current 1` and
`qm pending 107` have been requested to diagnose actual post-start state.
Do not adopt an assumed cause or weaken checks before that readback.

The source now reports fixed stage labels on failures, without dumping guest
data or changing the command set, identity predicates, NIC policy or lock.
Two positive and eleven negative tests against the extracted shell identity
function still pass and all negative cases emit a stage diagnostic; local
results are `new-vm-preflight\worker107-identity-tests-r2\results.json` under
the migration root. This diagnostic revision is not yet installed on Proxmox.

The user's subsequent root-console readback confirms VM 107 is running, exact
worker NIC/disks/UUID unchanged, with `qm pending 107` containing only `cur`
records and no pending changes. This rules out adopting a guessed pending-device
change as the explanation. It does not yet identify the exact wrapper failure.

## Lock descriptor custody correction

The original wrapper passes its open lock descriptor 9 to `qm start`, allowing
a long-lived descendant to retain that lock after the request exits. This is a
source-backed failure hypothesis consistent with later requests timing out.
Root-console `fuser -v /run/aiw-worker107/lock` subsequently confirmed two root
holders: PID 919856 `swtpm` and PID 919865 `kvm`, both with `F....` access.
Typed user-supplied readback is retained as
`worker107-bootstrap-r1\root-lock-holders-r1.json` under the migration root.
This confirms the live descendant retention. Do not unlink the lock file or
kill QEMU/swtpm. Recovery must gracefully shut down only VM 107, verify it is
stopped and the existing lock can be acquired, then install the corrected bytes.
No development VM power change is needed.

The correction invokes every fixed `qm` command through `run_qm`, closing
descriptor 9 only in the invoked process and explicitly returning its status.
The wrapper shell retains its descriptor and lock through validation/operation;
`pvesm` also receives no lock descriptor. No identity predicate or allowed
operation changed. Linux documents inherited descriptors and recommends closing
the locking descriptor in descendants that should not retain it:
[flock manual](https://man7.org/linux/man-pages/man1/flock.1.html).

A bounded control ran via the existing unprivileged `aiw-codex` host account,
using only a fresh project-owned temporary directory and short `sleep` children.
It reproduced inherited-child retention, verified child descriptor closure lets
the lock release after the parent exits, and verified a live waiting parent
still serializes competitors. Evidence: `worker107-bootstrap-r1\lock-control-r2.sh`
and `lock-control-r2.stdout.json` under the migration root. The first control
failure is preserved: its last foreground `sleep` allowed shell tail execution
to close the intended parent's descriptor; a subsequent no-op kept the waiting
parent alive in the corrected control. No VM operation was used for that control.
The controls prove the mechanism; the later root readback identifies the live
holders. Independent review found no actionable issue in the descriptor fix at
`3c9dc996b6263102e19c7a057aba76735a17be5e`. Its published script was downloaded
back and verified, SHA-256
`be175786efc8842112732c9fc735e1fe556d95e7cb7d355b8c8b762f6504db33`.
Installation and post-recovery independent readback remain pending.

## Recovered offline boot and guest agent

The user ran the exact graceful-shutdown/lock-free/install block and supplied
successful SHA/readback output. Independent bootstrap evidence is retained at
`C:\AIW-Resume-20261021\worker107-bootstrap-r2` on development VM 203.
Fresh `inspect`, `start`, subsequent `status` and post-start `inspect` all passed
with the descriptor fix. The worker remains running with its exact NIC link down.
The first guest-agent request reported not running; a later bounded request
returned Windows 11 x64 build 26300, hostname `AIW` and no logged-in users. This
was ordinary startup delay, separate from the earlier inherited-lock failure.
No application trial, account creation, credential cleanup, snapshot or rollback
has been dispatched. The source VM's QEMU-GA service was independently observed
running/automatic without changing it.

`worker107-preflight.ps1` and the fixed `guest-preflight` wrapper operation are
prepared to observe the worker's SYSTEM/session-zero context, exact UUID,
accounts, profile load states, known authentication path existence, research
package/process inventory and Tailscale installation/service metadata. It reads
no credential/state-file contents and performs no setup mutation. The root host
holds a fixed hash-bound script; only its UTF-16 encoded bytes may be submitted
to the fixed Windows PowerShell executable through QGA. No caller command/path
or stdin payload is accepted. QGA process completion, integer exit zero, no
truncation and a parsed matching observation object are required. A successful
process exit without guest observations is rejected. Two positive and fifteen
negative result-gate tests pass; both PowerShell 5.1 and 7 reject execution on
the ordinary development token before inventory. Guest execution awaits root
installation of the reviewed extension; ordinary QGA builtin results are not
application driver-control proof.

## Tailscale cleanup steering

The user explicitly asked to log out or uninstall Tailscale on the clone before
connecting its NIC. Keep VM 107 offline and prefer complete local removal there.
The original VM 203 has a running automatic Tailscale service; do not modify it
or remove its device registration. Tailscale's official Windows uninstall guide
documents that uninstalling can leave local state at:

- `C:\ProgramData\Tailscale`
- `C:\Users\labadmin\AppData\Local\Tailscale`
- `C:\Windows\System32\config\systemprofile\AppData\Local\Tailscale` (older clients)

Source: [Tailscale uninstall guide](https://tailscale.com/docs/features/client/uninstall).
The read-only probe includes these exact presence checks and service/uninstall
registry metadata, without reading node keys/logs or invoking Tailscale. No
Tailscale cleanup has been executed by the agent. Verify clone-only uninstall
and residual state removal before creating the clean baseline or enabling NIC.

The user subsequently reported deleting the ProgramData and labadmin AppData
Tailscale directories, while leaving the legacy system-profile path alone.
Respect that boundary: the pending probe checks path presence only. Actual
uninstall/service state and whether a directory was recreated remain unobserved.
A concern about AIW folders on `passkeys-worker` VM 106 was resolved by the user:
they originated in a different Codex session given the wrong prompt. This chat
has not targeted VM 106; no cleanup or management there is authorized or needed.

## Pending read-only probe installation

The independently reviewed final source revision is
`813d3b46855e9baeb2409d0fc0fcae376c4bf3b2`. Both published files were downloaded
back and verified on VM 203, then staged through the existing unprivileged
`aiw-codex` account at `/home/aiw-codex/aiw-preflight-813d3b4` on `pve-r630`.
Independent host SHA-256 readback matched:

| File | SHA-256 |
| --- | --- |
| `proxmox-worker107.sh` | `fae3c89052fe14eeb6ab70f7d4fd857d5f9afff5f5fef2ee24943b6c9227c35f` |
| `worker107-preflight.ps1` | `f4663c141f187e7d6f1b5cc582acd01caf510fe2d7f3c84ee792f4445d654eb9` |

Staging evidence is at
`C:\AIW-Resume-20261021\worker107-preflight-install-r1` on development VM 203.
These are public sources, not credentials. Root must copy them into a fresh
root-only directory before hash verification and installation, so later changes
to the unprivileged staging files cannot alter the verified install inputs.
Reject symlink/nonregular copies. Install the guest source root:root 0644 at
`/usr/local/lib/aiw-worker107/preflight.ps1`, and the wrapper root:root 0755 at
the existing forced-command entry `/usr/local/sbin/aiw-vm203`. This adds only the
fixed `guest-preflight` operation; no generic guest command or NIC-enable route
is exposed. The guest source accepts no arguments and requires the exact 107
UUID plus SYSTEM session zero. Installation need not reboot the worker.

After installation, run `guest-preflight` through the restricted SSH route and
retain the raw QGA object and parsed matching observation on VM 203. Do not infer
Tailscale cleanup, profile freshness or recovery acceptance from an installer
exit or absent service alone. Choose subsequent cleanup from actual observations.

## Accepted guest preflight and remaining profile decision

The user completed root installation. The restricted `guest-preflight` operation
passed with a completed guest process, exit zero and matching parsed observation.
Retained evidence on VM 203:
`C:\AIW-Resume-20261021\worker107-preflight-r1\qga-result.json`,
`observation.json`, `result.json` and `stage.json`. Observation SHA-256:
`792dba98e1bec248672f7b53d8ca1db4b81023b9c0e4d25644bdec0804fcd3b3`.
Observed at `2026-10-22T04:47:40.5714236Z` (October 21 in Alaska):

- Exact worker UUID, SYSTEM SID `S-1-5-18`, process session zero, Windows 11
  Enterprise build 26300 and inherited hostname `AIW`.
- Seven local accounts, with the same cloned SID prefix
  `S-1-5-21-3556347314-2314855617-1438300668`; labadmin RID 1001 enabled.
- Only one nonspecial profile: `C:\Users\labadmin`, matching that account and
  currently loaded. SYSTEM/LocalService/NetworkService profiles are special.
- No Tailscale service or uninstall entry. All three documented state paths
  are absent; this agrees with the user's uninstall/cleanup report and required
  no deletion within the legacy system profile.
- `.ssh`, `.azure`, `.codex`, Edge User Data and Windows credential/Vault/Protect
  directories remain under the labadmin profile. Contents and credential validity
  were not read or inferred. Chrome User Data is absent.
- No research Notepad++ registration and no Notepad++ process.

The user explicitly authorized replacing the disposable labadmin profile on 107
and confirmed knowing the account password. Preserve the SAM account/password,
original 203 profile and all special profiles. An offline reboot completed;
SYSTEM preflight at `2026-10-22T05:08:19.6220778Z` confirms the exact profile is
unloaded. Evidence: `C:\AIW-Resume-20261021\worker107-profile-reset-preparation-r1\pre-reset-qga-r1.json`.
Before r1 execution, fixed `worker107-reset-profile.ps1` checked SYSTEM/session
zero, worker UUID, exact enabled account and unloaded nonspecial profile, then
rechecks regular directory identities and ProfileList path immediately before
native DeleteProfileW. CreateProfile retains the account and creates a fresh
profile. A protected, non-overwriting stage journal prevents blind retries.
PowerShell 5.1/7 controls passed 16 invalid context cases and six invalid path
cases; no native profile APIs were invoked by those controls. Execution still
requires the user's Proxmox root console: restricted SSH deliberately has no
arbitrary guest execution capability. Keep the NIC disconnected and preserve
any partial result before deciding recovery.
The native driver and preparation helpers still pin the old Azure VM. The new
operator has RID 1001, so a later identity rebind must explicitly reject the
operator SID as the trial SID: the old `RID >= 1000` check implicitly excluded
the old RID-500 operator but will no longer do so. Preserve that existing
negative test and bind both parent/child worker UUID checks before live controls.

Inspect and remove copied development authentication material from the clone
before enabling its network or application trials; preserve the originals on 203.
Then establish clone-specific identity, a fresh clean snapshot and verified
restoration, with evidence retained on 203 outside the disposable worker.

Do not create the timed trial account or run the application before establishing
and verifying recovery. Preserve worker evidence on VM 203 before rollback.
Native/controller rebinding must preserve fixed identity checks, real interactive
token/session binding, held process custody and exact cleanup. Archived
controllers remain unchanged.

## Profile reset r1 failure and bounded recovery

The user ran reviewed helper ea5728c from root staging
`/root/aiw-profile-reset.kLszgx`, SHA-256
`8f144d82a0b6c423cf924a875315b6b3d210b5a950828c2c0422becbc8566463`.
Guest exited 1 at DeleteProfileW with `The parameter is incorrect`; creation
was not reached. The managed string parameter converted PowerShell `$null` to
an empty string rather than a native NULL. A harmless PS5.1 managed control
reproduced the conversion. Microsoft's API requires lpComputerName NULL.

The first post-failure preflight timed out at guest-exec. Guest health then
passed and the bounded second preflight succeeded. It confirms the original
unloaded labadmin profile, all seven unchanged accounts, copied authentication
paths still present and Tailscale absent. Evidence is retained outside the worker
at `C:\AIW-Resume-20261021\worker107-profile-reset-failure-r1`; failed logs are
preserved. This does not claim every original profile file is unchanged.

Recovery r2 uses a private native import with a two-argument managed wrapper
that supplies literal C# null. A managed stand-in exercises that exact forwarding
method without native calls; PS5.1/7 context/path/null regression controls pass.
The helper requires the matching r1 before/failure records with no deleted/result
receipt and uses new `C:\AIW-Worker107-Profile-Reset-r2`, preserving the entire
r1 journal. No recovery execution or clean recovery boundary is claimed yet.

Independent exact-source review of recovery commit 20e1826 found no remaining
source/recovery-gate blocker. Downloaded GitHub LF source and staged Proxmox
source both hash to
`a51746a9fe20a8b47939ce0cc5d4e3d03ef8a2c4ca3a274785d3637b9f0e2140`.
Public staging: `/home/aiw-codex/aiw-profile-reset-20e1826/reset.ps1`.
Encoded command size: 26,424 characters. User root-console execution remains
pending; no reset success is claimed.

## Independently observed cleanup and offline checkpoint

The user's latest r2 invocation at root staging
`/root/aiw-profile-reset-r2.HgdXEl` stopped at the existing-r2-journal guard
(source line 91), before deletion. Do not repeat cleanup or remove that journal.
The earlier r2 completion receipt has not been retrieved through restricted SSH.
A fresh fixed SYSTEM preflight at `2026-10-22T05:32:10.0515543Z` independently
confirms the desired current postconditions: original labadmin SID/profile exists
unloaded and nonspecial, all seven accounts unchanged, all thirteen enumerated
authentication path flags false (including copied SSH/Azure/Codex, browser,
Credentials/Vault/Protect and Tailscale paths), no Tailscale install/service,
no research package or Notepad++ process. Profile contents were not read.
This is observed cleanup state, not an inferred r2 completion receipt.
Evidence: `C:\AIW-Resume-20261021\worker107-profile-reset-r2-existing`.

The already-reviewed fixed management wrapper gracefully stopped 107 and created
cold checkpoint `aiw-msix-worker107-clean-r1` on `r630-fast` for the OS, EFI and
TPM disks. Inspection confirms the expected UUID/disks and disconnected NIC.
Recovery evidence is retained outside the disposable worker at
`C:\AIW-Resume-20261021\worker107-recovery-proof-r1`. No account/application
trial is part of this preparation slice.

The first proof-cycle shutdown, dispatched soon after startup, timed out; its
stdout/stderr/result remain under `restore-shutdown.*`. Guest health then
returned the expected Windows/hostname and no logged-in users. The bounded
second graceful shutdown succeeded (`restore-r2-shutdown.*`); no forced power
off, process kill, lock deletion, profile reset or application retry was used.


Operational recovery verification passed. The fixed rollback returned success,
then Windows booted and the full fixed SYSTEM preflight at
`2026-10-22T05:39:43.4616751Z` confirmed the same worker UUID, original unloaded
labadmin profile, unchanged seven-account inventory, all checked copied auth
paths absent, no Tailscale install/service and no research package/process.
Final Proxmox inspection confirms running VM107, expected disks, NIC down and
checkpoint present. Typed summary: `worker107-recovery-proof-r1\result.json`;
full guest observation: `post-restore-observation.json`. Startup probes and
partial guest-health failures are preserved alongside successful evidence.
This proves snapshot/rollback operations, restored Windows boot and observed
cleanup state; no deliberate byte-marker restore test was performed. The earlier
r2 completion receipt remains uncollected, and no reset retry is needed.

VM107 preparation is complete for the offline research boundary. Next work is
the reviewed QEMU native/controller identity rebind and project-owned WTS control,
then the real MSIX lifecycle. Keep NIC down; do not use old Azure bindings.

## Native QEMU rebind and network management direction

Native/preparation rebind `adb5c15` replaces Azure IMDS with exact SMBIOS UUID107
in both privileged parent and standard-user observation. The SID prefix now
matches the clone; RID1001 operator is explicitly rejected. Synthetic positive
fixtures use RID2000 and are not live account assignments. PS5.1/7 each passed
one positive and eleven preparation rejections. Native focused tests first found
the included lifecycle command over the Windows UTF-16 command limit because
checkout CRLF conversion inflated it. `4fe39b4` normalizes the embedded command
to LF and all twelve tests now pass. Initial failure and passing logs retained
under `C:\AIW-Resume-20261021\worker107-rebind-r1`.

Static-CRT release driver (built, not run):
`C:\AIW-Build\msix-worker107-r1\x86_64-pc-windows-msvc\release\examples\msix_standard_user_lifecycle.exe`
SHA-256 `05f2ff8638adb3a156696de60bb1fd23341ee201a497c105359fa926d6d0e812`.
Independent review accepted the UUID/operator checks and command-length fix.
No account creation, app control, installation or lifecycle was dispatched.

The user chose to enable VM107's NIC and supplied IP `192.168.1.174`.
Targeted probes found RDP3389 open and WinRM5985/5986 closed. Development203 is
`192.168.1.171`. A Windows remoting bootstrap is required before direct staging.
A client helper outside the repo configures exact-IP TrustedHosts (preserving
existing entries) and requests the password through Windows' credential prompt.
Its optional DPAPI-encrypted credential file is under the original operator's
private profile directory, excluded from all evidence/repository/artifact paths.
No credential contents are logged. Do not ask for a password in chat.
The current forced Proxmox entry still rejects a connected NIC; disconnect107
again before using it for recovery, or separately review a narrow network-state
update. Do not change development203's NIC or restore it.

Eight unfinished ISO/Scheduler/UI harness draft sources are retained externally
at `C:\AIW-Resume-20261021\worker107-msix-harness-draft-r1`. A passive draft ISO
was built and its directory listing inspected, but was not installed or attached.
The draft ISO's sourceCommit precedes its uncommitted draft harness and is not a
release/provenance claim. Use the actual source files for subsequent adaptation;
finish parsing/compilation/guard tests and exact review before executing them.
## Reviewed WinRM harness; authentication restored

The user explicitly authorized creating accounts and installing needed software
on validation VM107. Current development UUID203 and original seven accounts
were read back unchanged. User-reported AiwWorkerAdmin on VM106 has not been
attributed; no account-creation operation in this session has executed.

The first connection was blocked before authentication: only RDP3389 was
reachable on `192.168.1.174`; 5985/5986/445/135 were closed. Its MAC was observed
as `CC-34-21-B8-5A-31`, matching107. The user then supplied console proof of the
exact UUID107 and a local WinRM listener. TCP5985 became reachable, but two
`New-PSSession` attempts with the supplied encrypted `AIW\labadmin` credential
returned Access denied. No password contents were exposed. A scoped read-only
request was subsequently executed through the user-opened VM107 Proxmox console.
Security4625 showed Status0xc000006d/SubStatus0x0; System6167 explicitly reported
the cloned machine-ID mismatch. Endpoint permissions include Administrators.
This initial user-selected workgroup HTTP/Negotiate/TrustedHosts route assumed an
operator-trusted lab network. It does not provide production cryptographic
server-identity proof before authentication. The later UUID/SID guard remains a
required operational wrong-target check, not a claim against LAN impersonation.

HTTPS5986 now works using Basic authentication with the unqualified `labadmin`
name. The supplied password was encrypted to VM107's newly generated server
certificate for local validation: it was already valid, so no reset occurred.
That encrypted diagnostic is retained only under the protected private credential
directory, outside evidence and this repository. Plaintext was never displayed.
The server certificate thumbprint, read independently in the Proxmox console, is
`92BB9858EF5D21F4A30F3E2E66D54A3FAA7E1E18`; CN and IP SAN are192.168.1.174,
with fourteen-day validity. The exact-MAC guest NIC was set to Private after
WSMan configuration refused Public; the explicit5986 firewall rule permits only
development203 at192.168.1.171. AllowUnencrypted remains false. Initial partial
configuration failures and the final setup sources are retained externally.

The controller probes that exact TLS certificate before accessing the encrypted
credential, then uses HTTPS/Basic and SkipCACheck with normal name checks. The
probe and WSMan session are separate channels; this is still operator-trusted
lab transport, not a cryptographic pin on the authenticated WSMan channel.
Current-user Root-store additions prompted and were canceled; no certificate
trust change or warning dialog remains. Authenticated UUID107/elevated SID1001
and the final controller's Connect passed. A mismatched-certificate control
failed before credential access. Independent review found no Stage blocker under
this lab scope. PowerShell7 and5.1 harness controls passed; the first5.1 invocation
was refused by its default execution policy before running, and the process-only
Bypass invocation passed. Evidence: `C:\AIW-Resume-20261021\worker107-connection-r1`.

`0213bf3` adapts the preserved draft into a closed Windows management harness.
`db2d9c3` adds independently approved manifest/source identities, exact thirteen
payload file names, post-transfer rehashing before SYSTEM dispatch, and a flushed
CreateNew restart marker before reboot. One-shot requests prevent repeating
account/install/input operations after uncertain transport. The normal operator
may read status; executable worker operations require SYSTEM/session zero without
impersonation and exact107 UUID. Protected evidence grants SYSTEM/operator full
control and grants only the actual new trial SID read access where required.

Both PowerShell5.1/7 checks parse eight sources/render both fixed Scheduler modes,
compile the x64 keyboard INPUT helper and reject four executable operations from
the normal development token. The initial test harness SizeOf overload failure
and corrected receipts are preserved at
`C:\AIW-Resume-20261021\worker107-winrm-validation-r1`. No GUI input or application
execution occurred during these checks. Independent exact-source/artifact review
found no remaining source/artifact blocker under the documented lab transport
assumption. Earlier draft ISO transport is not installed or needed.

Sealed from clean `db2d9c37ec232f272982089a502a0d754d49b0b6`:
`C:\AIW-Resume-20261021\worker107-msix-payload-r1\bundle.json`, SHA-256
`70b2276e2341324cffe94a745ca5d0207152daa0c80f73360e821b2b97bcb2ef`.
All thirteen file hashes/lengths and nine normalized text sources independently
match. Native image remains `05f2ff8638adb3a156696de60bb1fd23341ee201a497c105359fa926d6d0e812`.

After authentication works, first use `invoke-worker107-msix.ps1 -Operation Connect`
and retain exact UUID/operator evidence. Only then Stage with this concrete call:

```powershell
& C:\aiw\app-isolation-workbench\scripts\research\invoke-worker107-msix.ps1 -Operation Stage -PayloadDirectory C:\AIW-Resume-20261021\worker107-msix-payload-r2 -ApprovedSourceCommit c46836185d398075a654fe2864c8f15001ed8998 -ApprovedManifestSha256 bc81724bfdf3f13d3a1f35b215499275dd2feccf53520236dbbf51248230f9a4
```

Inspect typed Status before advancing. Enroll creates the actual run-owned
standard account with a 30-minute window and temporary one-time console sign-in;
ClearLogon deletes that temporary password setting and a measured absence receipt
is required before Prepare/Control/Trial/Export. Finish staging/review before
starting that window. Restart is one-shot even if WinRM drops the response.
Prepare derives session/SID from the real signed-in account; native checks bind
its actual WTS token and authentication LUID. Control must pass before Trial.
The fixed Edit task rechecks actual package/image/user/session/held-window identity
before keyboard open/append/save/close; it never writes the test document itself.
The native lifecycle independently validates exact saved bytes and cleanup.
Export requires terminal operation evidence, labels failure/cold-recovery archives
without success implications, and verifies cleanup receipts for a success claim.
Collect retains and hashes the exact bounded archive on development203.
No remote Stage/Enroll/Control/Trial has been dispatched yet.

The first live Stage transferred and verified the sealed payload, then registered
`AIW107-Transport-Stage-r1`, but stopped before creating a request or invoking
RunEx: Scheduler returns the principal as `SYSTEM` rather than `S-1-5-18`.
Readback found Ready/state3, no instances/triggers, last result267011 (never run),
last-run year1999 and the exact fixed PowerShell action. Research/input/output
roots remain absent. The controller now resolves names to SIDs and still requires
exact SYSTEM/logon5/runlevel1. All three SYSTEM spellings resolve; the ordinary
operator is rejected. Bounded recovery checks those identities, manifest/content,
inventory and absence of any started-operation markers twice, retains external
task XML/SDDL evidence, deletes only the never-run transport task and preserves
the entire intake at `C:\AIW-Worker107-Intake-before-system-name-fix-r1` before
a fresh Stage. No installer or account creation is retried.

That bounded recovery completed and fresh Stage passed at2026-10-22T07:53:40Z.
The worker retained the original signed payload identity and observed no created
account or application execution. Status initially encountered the remote
session's default Restricted execution policy; it now launches only the fixed
read-only Status source through a process-only Bypass invocation, with native
exit checking. Live Status confirmed Stage success.

Enroll stopped at07:55:25Z before New-LocalUser execution: its literal description
was61characters, exceeding the Windows cmdlet's48-character ValidateLength bound.
No account receipt or automatic-sign-in setting was reached. The description is
now47characters; bothPowerShell test runs extract it via AST and compare it to the
actual Windows cmdlet metadata without creating an account. The later Edit
registration guard also resolves account names to SID before exact comparison,
retaining logon3/runlevel0 and the pinned trial-user SID requirement.
Early-failure recovery requires exact UUID/operator, terminal inactive task
definitions, original manifest/content hashes, the exact description failure,
no trial account/package/process/automatic-sign-in material/later markers and
empty native output. It flushes an external task/failure preimage before removing
only the two inactive outer tasks and preserving all five preparation directories
under `C:\AIW-Worker107-PreparationFailure-r1`. This is a fresh preparation after
a proven pre-creation validation failure, not a retry of an account or installer.

Early-failure recovery completed with no account/application creation. Updated
source `c46836185d398075a654fe2864c8f15001ed8998` was committed/pushed and sealed
into `C:\AIW-Resume-20261021\worker107-msix-payload-r2`, manifest SHA-256
`bc81724bfdf3f13d3a1f35b215499275dd2feccf53520236dbbf51248230f9a4`.
Native image and three signed inputs remain unchanged. The concrete Stage call
above now names r2; retain r1 and both failure archives as historical evidence.

## R2 measured failure and fresh recovery

R2 Stage, Enroll and Prepare completed on exact107. The run-owned standard user
signed into console session1; temporary automatic-sign-in values were measured
absent before preparation. Control registered its fixed SYSTEM task but failed
before RunEx: Scheduler normalized requested PT260S to equivalent PT4M20S.
The catch path also read an uninitialized script-scoped native process variable.
Independent readback found the task Ready with no instances, last-run year1999
and result267011, no start-request record, no native process/output and no research
package registration. No native control or MSIX/application execution occurred.

The retained failure archive is
`C:\AIW-Resume-20261021\worker107-control-failure-r2\evidence.zip`, SHA256
`ed14f6b5751e84713517794252b21643d97f78a1c3fd99a80efc1a2e8b6d53bb`,
36692bytes,20files. Its explicit outcome is failure-cold-recovery and it makes no
cleanup claim. The actual registered task definition is retained separately.
The duration guard now compares parsed TimeSpan values, preserving the exact
260/1500-second limits. Parent-owned process custody is shared across function
and invoked-scriptblock scope. Both PS5.1/7 checks exercise actual in-memory
Scheduler XML round trips, reject wrong durations and exercise strict child-scope
binding without registering/running a task. Read-only verification of the actual
failed task also passed with the corrected predicate.

Cold rollback of OS/EFI/TPM to aiw-msix-worker107-clean-r1 completed. SYSTEM
preflight at2026-10-22T08:46:14Z verified UUID107, seven original accounts, absent
copied authentication paths/Tailscale and no research package/process. Evidence:
`C:\AIW-Resume-20261021\worker107-connection-r3`. R2 is preserved; never retry it.
The next fresh payload must include the duration and shared-custody corrections.
