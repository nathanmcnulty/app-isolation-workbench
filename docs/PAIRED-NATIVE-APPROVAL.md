# Reconciliation and bounded native approval request

Request ID: `AIW-PAIRED-NATIVE-F99BBD4-20261030`. Prepared 2026-10-30.
Status: **prerequisite work completed; a host-readiness false negative is now
corrected offline and reviewed; provider acquisition is in progress**. The old
f99bbd4 package remains unchanged. A refreshed package is required before new
preparation. No plan approval, Start or native control trial is authorized.


## Blocker remediation — 2026-10-30 (America/Anchorage)

The user authorized fixing the blockers and continuing, with the existing stop
before plan approval/Start and publication retained. Stronger read-only target
observations correct the initial firmware-only interpretation: VM107 returned
S_OK from `WHvGetCapability(HypervisorPresent)`, exactly four bytes and BOOL1;
Device Guard reports VBS running. The Windows hypervisor is already active.
No Proxmox CPU change, guest feature toggle or security weakening is warranted.

Microsoft documents the firmware flag's false-negative case under an active
Hyper-V root OS ([explanation](https://devblogs.microsoft.com/oldnewthing/20201216-00/?p=104550/)).
The supported [Windows hypervisor capability query](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvgetcapability)
provides an independent prerequisite observation. Generic hypervisor/vendor bits
are insufficient; [QEMU can expose Hyper-V identification](https://www.qemu.org/docs/master/system/i386/hyperv.html).

The local source correction reuses one private native observation for static and
full readiness: the existing firmware flag OR an exact successful Windows API
query. It loads only the fixed DLL under the OS-supplied absolute System32 path,
restricts dependency search to System32, holds/frees the module safely, initializes
outputs and rejects missing/error/short/invalid outputs. It creates no partition
and invokes no Sandbox provider. Every existing Store/catalog/OS/hash/session/
approval gate remains. Schema and control verdicts are unchanged.

A closed `aiw admin prepare-paired --evidence <existing-parent> --identity <operator>`
command now calls the same enrolled-agent/static preparation/import service as
the desktop. It writes only a pending review/proposed approval and has no approval,
Start, recovery, executable or policy-override input. Desktop agent custody remains
held through its original gates. This provides non-executing preparation through
the existing trusted remoting route without interactive sign-in changes.

Focused checks passed: two virtualization tests (including seven malformed/error
cases), five preparation/parser/integration checks, two affected static-pipeline
regressions, affected all-target Clippy with warnings denied, desktop all-target
Clippy and formatting. Independent implementation review found no consequential
issue in either the query or preparation-only entry point. Logs under `C:/aiw`:
`paired-hypervisor-fix-tests.log`, `paired-preparation-command-tests.log`,
`paired-hypervisor-static-regression.log`, `paired-hypervisor-preparation-clippy.log`,
`paired-hypervisor-desktop-clippy.log`. Unchanged broad suites were not rerun.

Current diagnosis evidence is at the directory recorded in
`C:/aiw/paired-current-remediation-root.txt`. Store catalog access initially stopped
at its required transaction-terms and region-sharing consent. The user explicitly
accepted those source terms/region sharing; the approved catalog query is now in
progress. No terms were silently accepted before that reply. No new provider,
Sandbox instance or control has yet been installed/launched by this remediation.
The historical prerequisite observations below remain retained; the firmware flag
alone no longer justifies labeling this active Hyper-V target unavailable.

## Approved prerequisite result — 2026-10-30 (America/Anchorage)

The user explicitly approved VM107 identity/readiness inspection, staging the
pinned f99bbd4 package and non-executing preparation, stopping before approval or
Start. Normal trusted Core HTTPS and the existing fixed read-only hypervisor
metadata verb were used. No install, configuration change or native trial ran.

**Outcome:** package staged and verified; preparation is blocked. The required
Store package is not registered, and the exact native virtualization API used by
AIW reports false. We stopped at the declared prerequisite gate. The production
preparation API/UI was **not invoked**, so there is no API error/result receipt to
claim. The expected refusal below is source-backed inference. No protected plan,
approval challenge, session UUID or preparation receipt exists for this target.

| Target observation | Exact observed value |
|---|---|
| VM / UUID | 107 / `e5cecc90-35c2-4831-bf9c-424be23f7d4e` |
| MAC / IPv4 | `CC:34:21:B8:5A:31` / `192.168.1.174` |
| Computer / operator / SID | `AIW` / `AIW\labadmin` / `S-1-5-21-3556347314-2314855617-1438300668-1001` |
| OS | Windows `10.0.26300.9711`, Enterprise 26H2, x64 |
| Core / endpoint | `7.6.9` / `PowerShell.7.6`, native x64 Core; zero compatibility sessions |
| Direct pwsh / SHA-256 | `C:\Program Files\PowerShell\7\pwsh.exe` / `2a6769a3330dc1084d0154bfde7d164ab750ca7f700f313f9d417c1be78b2233` |
| Loaded SMA SHA-256 / MVID | `e767f5c26347b254dd06fa0b65e18424cc4eb93fc3102c5a8fdd9dd88355db97` / `3cdcbc79-3cd6-4f39-a354-e3f5c63accfe` |
| WSMan host SHA-256 | `5767426ba5c35fd51dd6619b1dcbb155590f98db41af0152803c289cb0aa8dbf` |
| Loaded plugin SHA-256 | `ab16acc15bfe2edc54793cf363daa7c786317b592dcf8dee33e1d433d8a254a5` |
| Endpoint config / startup SHA-256 | `14d52a954f5eb61e3967ec47879784eb7695d0c730d3b45b5a066559b43535bf` / `add8a2db2c9a130df381b506638c0f2b0e7fd92d4b63f374500acf90f5454591` |
| HTTPS listener | port 5986, `CN=192.168.1.174`, thumbprint `BC14DCC4E37F83161EBB55AF8624E36A79E19256`; normal trust verification |
| Listener certificate expiry | 2026-11-04 23:49:10 America/Anchorage (2026-11-05T08:49:10Z); observed only, not renewed |
| Current checkpoint / config SHA-256 | `aiw-msix-worker107-core76plus-clean-r2` / `11c1c0d216647eb18844661086837c2ef38c5dce6fa0b451af0c626c3d07026e` |
| Current VM config SHA-256 | `5ec2d6ae94a71dfd9460116011068a95a03045dff911c16d6b4243ba67782ff9` |
| Read-only hypervisor provider SHA-256 | `4c04db8da745ccc9ff84b704a2923380a0f10b3e243487eb7be79c1efc35fb5a`; matches current normalized source, not a Sandbox executable hash |
| VM state / lease | running; `leasePresent=false`, phase `none`; unchanged before/after staging; no lease acquired |
| Optional-feature WMI observations | `Containers-DisposableClientVM: InstallState=1`; Hyper-V-All, VirtualMachinePlatform and HypervisorPlatform each `InstallState=2` |
| Native firmware query | `IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED=21) = false` |
| CIM CPU observations | VM monitor, firmware virtualization and SLAT flags each false; hypervisorPresent=true; no claim of nested readiness |
| Required Store package | `MicrosoftWindows.WindowsSandbox`: zero current-user and zero all-user registrations, using the native Core Appx cmdlet |
| Sandbox provider path/hash/size/file-ID | **not available: no registered package resolved** |
| Catalog hash/trust / observed CLI protocol | **not available / unmeasured**; no substitute hashes or version probes |
| Classic System32 files | WindowsSandbox.exe and WindowsSandboxClient.exe present; System32 wsb.exe absent; none executed or accepted as authority |
| Native runtime sessions | unmeasured; no `wsb list` or other Sandbox provider command invoked |
| Staged package | `C:\AIW-Paired-f99bbd4-20261030\Package`; exact 14-payload inventory verified; receipt `9c5c1976844f5eb14e459dae166448a8b2bbe06f78b539aeac8153bb3e373109` |
| New Evidence / Exports | both empty at final observation; no plan or approval records |

The raw observations and checksummed result index are retained locally under
`C:/aiw/paired-target-preparation-38602e66-2c6f-4327-9662-63164f198333` (`result-index.json`). They are engineering evidence, not a
privacy-limited Results summary. These records include actual target values;
VM203 observations and old 7.6.7/r1/provider pins were not substituted.

Source implication at f99bbd4: `resolve_package` requires the operator's exact
Store package and maps zero matches to `AIW_WSB_CLI_PACKAGE_MISSING`. It offers
no classic System32 fallback. `require_static_identity` also requires firmware
virtualization `Available`. `prepare_paired_with_inspector` checks both before
creating the protected workspace. The admin wrapper would create an evidence
root/project first if invoked; it was not invoked here and Evidence remains empty.
The initial source review confirmed the conservative f99 refusal from those
limited observations. The later stronger capability observation and reviewed
readiness correction above supersede the firmware-only interpretation; no bypass
of provider trust or approval is permitted. Enabling/installing provider or virtualization prerequisites,
launching classic Sandbox to bootstrap Store registration, or changing VM settings
is outside this approval. The mapped-Tools native question also remains untested.

## What the completed goal establishes

The implementation reviewed is `f99bbd49694611cba5105768608d9802ff8f0665`,
with runtime code last changed at `e2e44fe2bf3ca98113618131f4f6d8700354219f`,
on `codex/paired-controls`, atop main `53c02c8` including merged PR #103.
The offline implementation goal is complete. Native acceptance is not complete.

| Goal/path | Implemented production path | Exercised evidence and limits |
|---|---|---|
| Fixed paired preparation | Desktop `prepare_workflow(kind=paired)` -> `paired::assess_with_gate` -> enrolled package agent -> compiled fixed project -> static trusted identity inspection, protected role staging/import and immutable plan | Real staging/custody/import bodies with injected static inspector and fresh protected local fixtures. The production static inspector API was not invoked on VM107 after the preflight stop; the independent current/all-user registration checks above are actual target observations. Preparation never invokes a provider. |
| Approval and dispatch | Actual Controller exact approval challenge, separate Start; `start_approved_windows_sandbox` statically reopens, verifies committed approval, acquires native Sandbox lease, checks current runtime identity and calls shared kernel | Coupled service tests exercise the actual gate coordinator and kernel through `Fixture.dispatch`, `Fake` and `OfflineLease`. They do not call the native Start/lease/transport boundary. Browser replay uses actual Controller snapshots, not native Tauri/provider execution. |
| Native six-case collector | Guest request -> elevated guarded WDAG agent -> held Tools inputs -> fresh standard account/resources -> measured standard-user launcher -> baseline and AppContainer fixed cases | Compiled and source-reviewed; role binaries, real account/profile setup, Win32 process/token/jobs, mapped Tools semantics and six native invocations remain untrialed for this implementation. |
| Cancellation and recovery | Owned cancellation writes the original journal; native leased kernel owns cleanup; cached original run/context only for exact-session recovery | Actual coordinator/journal/session services with strict fake provider responses. The final test-only handshake prevents reading during cancellation publication. No real provider stop/recovery was exercised for this new path. |
| Results and export | Existing retained paired reader/report-set -> bounded ResultsStore -> allowlisted JSON/Markdown exclusive new-file export | Real safe reviewed archive plus protected synthetic paired receipts, full retained-tree snapshots, determinism/negative tests and labeled UI replay. No real native paired report has yet been verified. |

Source anchors at f99bbd4: `crates/aiw-admin-workflow/src/paired.rs:320,400,437`;
`crates/aiw-runner/src/lib.rs:700,1092,1169`;
`crates/aiw-guest-agent/src/main.rs:173`;
`crates/aiw-windows-platform/src/guest_paired_controls.rs:34,57,63,162`;
`crates/aiw-windows-platform/src/control_appcontainer.rs:343,403`;
`crates/aiw-runner/src/offline_rehearsal.rs:178`;
`crates/aiw-admin-workflow/src/paired_rehearsal_tests.rs:104`.

Existing evidence is reused: 678 workspace Rust tests passed, 27 opt-in ignored;
20 desktop tests passed, 4 opt-in ignored; 28 Node tests passed; workspace/desktop
Clippy, formatting, governance and offline builds passed. The runtime-code commit
was e2e44fe; f99bbd4 adds documentation only. Logs:
`C:/aiw/paired-final-root-fixed.json`, `paired-final-gui-fixed-tests.log`,
`paired-final-gui-fixed-clippy.log`, `paired-final-node.log` and the earlier
[handoff](PAIRED-IMPLEMENTATION-HANDOFF.md). No unchanged suite was rerun here.
The new package build/verification is artifact preparation, not a native trial.
New document checks only: both PowerShell blocks parsed; only the selector block
ran against two fresh labeled synthetic non-authoritative locators (ordinary and
verbatim paths), with collision rejection and unchanged input/output bytes.
The worker/UI block was not executed. Record:
`C:/aiw/paired-approval-document-checks.json`. Source/document review found no
remaining consequential issue after the path-spelling correction; no product
source changes or native calls were needed.

Independent source review was reused and extended for this reconciliation. It
found no proven source defect preventing an attempt. Do not weaken held intake
to make the experiment start: mapped Tools must satisfy local fixed-volume,
persistent ACL, stable file identity and nonremote/no-reparse constraints.
A refusal there is an unsupported/incomplete driver result, before guest user or
control-resource setup; failed-driver evidence may still be published.

## Acceptance claim requested

One successful run can accept **the production fixed paired-control profile and
its evidence/reporting integration on the exact measured environment**. It cannot
close full Benchmark 2: [ROADMAP.md](ROADMAP.md), Benchmark 2, still requires a
real-application candidate. This request deliberately authorizes no application
trial. `paired_controls.rs:412` always reports `production_acceptance=false`;
that is intentional, not a defect to remove for a passing label.

Accept only verified native-origin evidence with a complete driver and all six
case observations, exact same-user/OS/fixture bindings, intended root/required
child tokens, unchanged canary bytes/DACLs and executable bytes, verified inner
jobs/profile cleanup, verified exact outer cleanup, and comparison reason
`fixedControlsObserved` with `eligible=true`. A succeeded completion receipt or
process exit alone is insufficient. Broken baseline/driver is inconclusive;
missing/failed/timed-out candidate evidence does not establish denial. No network,
secret/environment/IPC/UI/broker, general host isolation or compatibility claim.
One pair does not establish repeatability across environments.

## Exact target and payload

Controller is VM203, UUID `652a575b-a462-418e-95bb-360b28516925`,
`192.168.1.171`; local read-only inspection confirmed `AIW`, x64 Windows
`10.0.26300.9711`, operator `AIW\labadmin`, SID
`S-1-5-21-3556347314-2314855617-1438300668-1001`.
These observations are **not VM107 pins**. Never restore VM203 or execute the
control roles/AppContainer on the controller.

The inspected target and conditional future Sandbox host is **VM107 only**,
enrollment `aiw-worker`, UUID
`e5cecc90-35c2-4831-bf9c-424be23f7d4e`, MAC `CC:34:21:B8:5A:31`,
IP `192.168.1.174`, Proxmox `pve-r630`. Verify the current tuple and exclusive
reservation with no foreign/outstanding VM/MSIX/Sandbox lease before mutation.
VM106/passkeys-worker is excluded. This request includes no snapshot restore,
power cycle, baseline provisioning, networking/feature/WinRM/security changes.
Paired code leases the **local Sandbox provider**, not Proxmox VM107: selection
and exclusive reservation of the correct VM are operator preconditions.
It has no direct-VM paired alternative. If nested Sandbox is unavailable, stop;
do not run the inner controls directly on VM107 or fall back to VM203.

Use only existing normal trusted access. If remoting is used, preserve
PowerShell.7.6/Core >=7.6 and HTTPS5986 with existing certificate
`BC14DCC4E37F83161EBB55AF8624E36A79E19256`; no TLS bypass, device-code flow,
new credentials, endpoint registration, ACL widening or feature installation.

Local unsigned package: `C:/aiw/paired-native-review-f99bbd4-20261030`.
- Receipt content commitment: `9c5c1976844f5eb14e459dae166448a8b2bbe06f78b539aeac8153bb3e373109`.
- Desktop `aiw-desktop.exe`: `839b2551fe63afb8a3cf04c57fcbf31036760becc1b6d46ccaba1014f06a1835`.
- Companion CLI `aiw.exe`: `b1e5fb3b518b0fb6e8fefabbf8626d31b8b78896edb85303b5464f89b7d934b9`.
- Verifier script SHA-256: `8398e34b15d2876cc7aa30ca45e59c290468e77afe318ba374b8f3ceab85bcfe`.
- Exact inventory, source f99bbd4 and all three enrolled agent copies verified by
  the existing package builder/verifier. Record:
  `C:/aiw/paired-approval-package-build.json`; compiler/assembly log:
  `C:/aiw/paired-approval-package-build.stderr.log`.
- These are local unsigned development bytes, not a signed/published release.
  The native guest binary is the already retained debug/static-CRT agent; the
  desktop/CLI were newly built offline from clean f99bbd4 in an isolated target.


The same 5,968,896-byte x64 static-CRT guest agent supplies **all three fixed
roles**, SHA-256:
`b5cd415894b5d142215ae9b71f8d619d43404eb2511eb9304ad63f53db097512`.
This is the independently retained `paired-final-agent-build.json` input,
rehashed for this request. No standalone research fixture/launcher binaries are
substituted. Guest role locations are:

- `C:\AIW\Tools\aiw-guest-agent.exe` (elevated WDAG dispatcher).
- `C:\AIW\Tools\aiw-control-fixture.exe` and
  `C:\AIW\Tools\aiw-control-appcontainer.exe` (held read-only mapped copies).
- `C:\AIW\Control\aiw-control-fixture.exe` and
  `C:\AIW\Control\aiw-control-appcontainer.exe` (new guest-local copies).

Control revision: `aiw.dev/paired-file-registry-child/v0alpha1`.
Control-source SHA-256:
`95201a1b89182f699358f2641e8ec47de7a45e2ed56c7fdc1b55418227803f49`.
The package enrollment must contain this `guestAgentControlSourceSha256` and
agent byte hash. The existing packager verifies the compiled CLI source identity;
metadata is producer enrollment, not a proof that arbitrary supplied bytes have
that source. The protected request/guest validates its own current source too.
The package includes inert existing application recipe metadata; this request
permits only **Fixed paired controls**, no installer selection or other workflow.

## Target-provider gates — inspected and blocked

The exact OS, operator, runtime, endpoint and VM metadata are now recorded above.
The Sandbox provider/catalog/file-ID pins cannot be filled: the required package
is absent for this operator and all users. Firmware virtualization is also not
reported available by AIW's exact native query. These are observed blockers, not
blank fields to fill with historical hashes. Required protocol remains
`windowsSandboxCli/v0.8.107.0`; it was not probed or observed.

No plan or v0alpha8 preparation receipt was created. Separate authorization and
an environment decision are required to address these prerequisites. This request
authorizes no installation, feature/VM changes, classic Sandbox bootstrap launch
or controller fallback. After any separately approved environment change, capture
fresh exact provider/OS/static pins and create a fresh plan before requesting
literal approval or Start. Do not modify old records in place.

## Conditional future assessment — not authorized by prerequisite approval

The approved first staging operation is complete at
`C:\AIW-Paired-f99bbd4-20261030\Package`, with empty sibling `Evidence` and
`Exports` directories. Do not replay copying or overwrite this root. Retain it
unchanged. The commands below remain a future verification/UI procedure only;
package verification was executed separately, while the UI was not launched.
Do not run them past verification while the target-provider gates are blocked.

```powershell
$ErrorActionPreference = 'Stop'
if ((Get-CimInstance Win32_ComputerSystemProduct).UUID.ToLowerInvariant() -cne 'e5cecc90-35c2-4831-bf9c-424be23f7d4e') { throw 'Wrong VM; stop' }
$pairedAdapter = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True' | Where-Object { $_.MACAddress -ieq 'CC:34:21:B8:5A:31' -and $_.IPAddress -contains '192.168.1.174' })
if ($pairedAdapter.Count -ne 1) { throw 'Worker network identity mismatch; stop' }
$pairedPackage = 'C:\AIW-Paired-f99bbd4-20261030\Package'
$pairedVerifier = Join-Path $pairedPackage 'verify-desktop-package.ps1'
if ((Get-FileHash -LiteralPath $pairedVerifier -Algorithm SHA256).Hash.ToLowerInvariant() -cne '8398e34b15d2876cc7aa30ca45e59c290468e77afe318ba374b8f3ceab85bcfe') { throw 'Verifier drift; stop before executing it' }
$pairedVerified = & $pairedVerifier -PackageRoot $pairedPackage -ReceiptSha256 '9c5c1976844f5eb14e459dae166448a8b2bbe06f78b539aeac8153bb3e373109' -SourceRevision 'f99bbd49694611cba5105768608d9802ff8f0665' | ConvertFrom-Json
if ($pairedVerified.exactInventory -ne $true) { throw 'Package verification failed; stop' }
# Opens only the UI after prerequisite access/staging authorization. It does not
# authorize approval/Start, and no application installer/control is selected here.
Start-Process -FilePath (Join-Path $pairedPackage 'aiw-desktop.exe') -WindowStyle Normal
```

Open the verified desktop visibly on VM107, choose **Fixed paired controls**, use
the existing identified operator and `C:\AIW-Paired-f99bbd4-20261030\Evidence`.
No installer/document is supplied. The guest uses native fixed roles, not the
old PowerShell research control driver. Review immutable recipe/plan and the bound
provider/OS tuple, then approve only its generated exact literal and issue its
separate Start once. Derive every run/workspace/session/challenge value from the
fresh typed `paired-workflow.json`, plan and durable session transaction; never
predict a nonce, adopt a foreign lease or replay a historical ID.

The production path creates **one fresh Windows Sandbox**, with networking,
vGPU, audio/video input, printer and clipboard redirection disabled, Protected
Client enabled and memory 2048 MiB. Only the protected Tools directory maps
read-only to `C:\AIW\Tools`; only that run's Output maps writable to
`C:\AIW\Output`. No other host file mapping or host registry grant.
Both variants share this outer worker; the baseline is in-worker, not an endpoint
baseline. Do not run the old research control scripts or a PR #103 application.

The elevated `WDAGUtilityAccount` agent validates its native origin, token, exact
OS and three held Tools roles before creating `AiwStandardUser`. It creates a
fresh ordinary local user with a generated nonexported password, loads that
user's profile/environment and starts the fixed measured launcher. The ordinary
launcher/targets are non-elevated primary medium-integrity tokens. The candidate
uses fresh `AIW.Control.Paired.v0alpha1`, the same user SID, low integrity,
AppContainer=true and zero capability SIDs. Its required child must match the
same AppContainer SID and user. SIDs are obtained from the fresh native objects
and bound across held/self/child observations, not invented in advance.

| Invocation | Ordinary baseline | AppContainer candidate |
|---|---|---|
| Fixed file read | Success, exactly 29 bytes and approved hash | Native access denied, code 5 |
| Fixed 64-bit registry read | Success, exactly 29 REG_BINARY bytes and approved hash | Native access denied, code 5 at an allowed registry-read stage |
| Fixed child/token mode | Child completes with same-user ordinary medium token | Child completes with same-user low AppContainer token, exact package SID, zero capabilities |

Fixed file: `C:\AIW\Control\SharedCanary\canary.txt`, bytes
`AIW controlled readable bytes`, SHA-256
`6f0427a3e5b44f60867720acaf9f18004f8e1b4bc773bc2b07eaa25cbd692f48`.
Fixed registry: HKLM 64-bit `SOFTWARE\AIWControlCanary`, value `Canary`,
REG_BINARY bytes `AIW controlled registry bytes`, SHA-256
`6d602d862214f8c9e36008aa2d5a94f53432b5d213d5e94ec52345720280bf42`.
The file/key are newly created in the worker; existing names cause refusal.
Their protected DACLs grant SYSTEM/Administrators control and the ordinary user
file/key read access. No package ACE is added to the canary file or registry key.
Both bytes and DACL hashes must remain unchanged through the comparison.

Declared policy difference: classic AppContainer versus ordinary token, with
only package read/execute/traversal ACEs on `C:\AIW\Control`, the fixture image
and `SharedCanary`; read/write/execute with inheritance on
`C:\AIW\Control\AppContainerChild`. That child-output directory has a low
mandatory label for both variants. No capability SID or broader grant is added.
Fixed diagnostic output handles are explicitly inherited, not new canary grants.
Baseline output is cleared before candidate; resource bytes/DACLs remain fixed.

Guest side effects include the fresh account/profile/normal registry hive,
`C:\AIW\Control` directories, exact role copies, canary file/key, bounded
`read-canary-result.json`, `read-registry-result.json`, `child-result.json`,
`child-token.json`, `paired-launcher.json`, and bound completion/evidence files
under Output. The registry handle is closed; canary/account/control-directory
residue is destroyed with the outer Sandbox, not individually certified deleted.
Normal profile unload/environment destruction and scoped guest privilege restore
are separate from AppContainer profile deletion and job emptiness. No canary or
account is created on VM107's host OS or controller.
Host-side permitted changes are the new package/evidence/export roots, protected
run-workspace ACLs/files, existing provider lease/mutex/session bookkeeping,
normal Sandbox ephemeral state, and the desktop
`%LOCALAPPDATA%\AppIsolationWorkbench\Evidence` default parent plus bounded
startup diagnostics under its `Diagnostics` sibling if needed. Do not change existing host/VM security settings.

## Time bounds, stopping and exact cleanup

Code bounds: each fixture invocation 15 seconds; nested child 10 seconds plus
2-second termination wait; launcher 120 seconds; outer guest-launcher cleanup
5 seconds; individual native provider reads <=15 seconds, mutations <=120
seconds; receipt wait 300 seconds. These are per-operation bounds, **not a
300-second end-to-end deadline**. At 15 minutes without settlement, request the
owned cancellation once and preserve custody while its bounded native operation
and cleanup settle. No blind task kill, fresh dispatch or automatic retry.
Allow at most one explicit exact-session recovery attempt if cleanup remains
unknown, with the same 15/120-second native bounds and a five-minute observation
escalation. Persistent unknown state is a stop, not authorization to broaden cleanup.

Stop before dispatch for wrong VM/lease, unexpected existing root/resource,
untrusted package/catalog/provider, unavailable nested Sandbox, drift, unknown
input/approval, occupied session or unsupported protocol/OS. Fail closed on
mapped Tools custody; retain failed-driver evidence, do not relax the reader.
Any baseline/driver failure is inconclusive. Candidate missing error2/3, timeout,
generic failure or malformed evidence never counts as denied. Preserve valid
prefixes; no grant widening, file repair, reinstall or rerun to manufacture success.

On normal/failing completion, the existing kernel terminates/verifies inner jobs,
records fresh profile deletion where observed, stops only the exact journal-bound
Sandbox UUID and verifies absence. Before Start, identity is durable; a lost reply
means may-have-started. Do not retry Start. Owned recovery may reconcile list/stop
for that exact ID; it cannot start/connect/replay another assessment. Never stop
unrelated sessions. If identity/lease or cleanup cannot be established, retain all
records and stop further work/close; no VM restore/power-off or foreign lease
adoption is authorized as a shortcut. Additional intervention needs separate review.
Do not intentionally inject cancellation/crash in this smallest healthy run.

## Results, retained evidence and safe summaries

Production does **not** emit a selection manifest automatically. Its test-only
producer must not be used for native evidence. After the run settles, construct
one explicit entry from the exact fresh typed locator, profile `pairedControls`.
Use this read-only/bookkeeping command against only the new approved evidence
parent (the fresh locator supplies all run values); it writes only a new selection outside retained workspaces:

```powershell
$ErrorActionPreference = 'Stop'
$pairedEvidenceParent = 'C:\AIW-Paired-f99bbd4-20261030\Evidence'
$pairedSelectionPath = 'C:\AIW-Paired-f99bbd4-20261030\Exports\selection.json'
# Bounded shallow lookup in ONLY this newly owned evidence parent: no recursion,
# arbitrary retained-workspace scan, guessed run ID or synthetic test producer.
$pairedRunDirs = @(Get-ChildItem -LiteralPath $pairedEvidenceParent -Directory -Force | Select-Object -First 2)
if ($pairedRunDirs.Count -ne 1) { throw 'Expected exactly one fresh evidence root; stop' }
$pairedLocatorPath = Join-Path $pairedRunDirs[0].FullName 'paired-workflow.json'
$pairedLocatorStream = [IO.File]::Open($pairedLocatorPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
$pairedLocatorReader = $null
try {
    if ($pairedLocatorStream.Length -gt 131072) { throw 'Locator too large' }
    $pairedLocatorReader = [IO.StreamReader]::new($pairedLocatorStream,[Text.UTF8Encoding]::new($false,$true))
    $pairedRun = $pairedLocatorReader.ReadToEnd() | ConvertFrom-Json -Depth 64
} finally {
    if ($null -ne $pairedLocatorReader) { $pairedLocatorReader.Dispose() }
    $pairedLocatorStream.Dispose()
}
if ($pairedRun.schemaVersion -cne 'aiw.dev/paired-workflow-run/v0alpha1' -or $pairedRun.agentSha256 -cne 'b5cd415894b5d142215ae9b71f8d619d43404eb2511eb9304ad63f53db097512') { throw 'Wrong paired locator/agent' }
function Normalize-PairedLocatorRoot([string]$Value) {
    $pairedNormalized = [IO.Path]::GetFullPath($Value)
    if ($pairedNormalized.StartsWith('\\?\')) { $pairedNormalized = $pairedNormalized.Substring(4) }
    $pairedNormalized.TrimEnd([char]'\')
}
if ((Normalize-PairedLocatorRoot $pairedRun.evidenceRoot) -ine (Normalize-PairedLocatorRoot $pairedRunDirs[0].FullName)) { throw 'Locator root mismatch' }
$pairedSelection = [ordered]@{schemaVersion='aiw.dev/application-assessment-input/v0alpha1'; windowsSandbox=[ordered]@{schemaVersion='aiw.dev/wsb-report-set-input/v0alpha1';entries=@([ordered]@{profile='pairedControls';run=[ordered]@{id='native-fixed-pair-1';workspaceRoot=$pairedRun.workspace;runId=$pairedRun.runId;projectPath=$pairedRun.projectPath;guestAgentSha256=$pairedRun.agentSha256}})}}
$pairedSelectionBytes = [Text.UTF8Encoding]::new($false).GetBytes(($pairedSelection | ConvertTo-Json -Depth 16))
$pairedSelectionFile = [IO.File]::Open($pairedSelectionPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try { $pairedSelectionFile.Write($pairedSelectionBytes,0,$pairedSelectionBytes.Length); $pairedSelectionFile.Flush($true) } finally { $pairedSelectionFile.Dispose() }
# This selector is local bookkeeping, not a safe summary or execution authority.
# The existing Results reader must still reverify all bound retained evidence.
```

Open that one-entry selection in Results and inspect all six case/token/hash
observations plus separate inner and historical outer cleanup. Use the actual
Results exporter to create new `Exports\summary.json` and
`Exports\summary.md`, never overwrite or write into retained workspaces.
Keep original plan/approval/preparation/provider/session/evidence/receipt bytes,
full native tokens, request hashes, input hashes and failures locally. Summary
exports alone use the privacy allowlist: no raw artifacts/tokens, account IDs,
credentials or absolute private paths. No cleanup of retained inputs is authorized.

## Approval status and publication boundary

The approved inspection/staging scope has been used and is stopped. Package
files were copied only to the declared new VM107 root and verified there. Normal
TLS/Core identity inspection and two fixed read-only hypervisor metadata probes
ran. The VM configuration hash and lease state stayed unchanged. No security,
feature, provider installation, snapshot, network or power change was made.
No Sandbox provider, control executable, application installer or UI was launched.

Non-executing preparation could not produce a plan because its prerequisite gate
is blocked; the production preparation API was not invoked. Plan approval and
Start remain unperformed and unauthorized. No native acceptance or cleanup trial
is claimed; no historical run was replayed/recovered. Existing Rust/Node review
and test evidence was reused without rerunning unchanged suites.

The eventual native scope, if prerequisites are separately resolved and freshly
pinned, remains one fresh six-case pair and only its necessary owned cleanup or
exact recovery. That later operation requires its own exact plan approval and
separate Start. Full Benchmark 2/W4/W5 closure and publication remain separate.
No push, PR, signing, publication or release occurred.
