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
