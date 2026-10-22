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

Inspect and remove copied development authentication material from the clone
before enabling its network or application trials; preserve the originals on 203.
Then establish clone-specific identity, a fresh clean snapshot and verified
restoration, with evidence retained on 203 outside the disposable worker.

Do not create the timed trial account or run the application before establishing
and verifying recovery. Preserve worker evidence on VM 203 before rollback.
Native/controller rebinding must preserve fixed identity checks, real interactive
token/session binding, held process custody and exact cleanup. Archived
controllers remain unchanged.
