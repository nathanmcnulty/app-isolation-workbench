# Reconciliation and bounded native approval request

Request ID: `AIW-PAIRED-NATIVE-F99BBD4-20261030`. Prepared 2026-10-30.
Status: **approved console installation and non-executing preparation completed;
stopped at pending approval**.
The current source is `d370ec8cd5bcaa6915ac24801789070dd0040e3b`; the original
f99bbd4 reconciliation and package remain retained. Exact current provider,
catalog, file-ID, workspace and fresh plan pins are recorded below.
No plan approval, Start or native control trial is authorized.

## Current console installation and prepared plan — 2026-10-30 America/Anchorage

The user explicitly authorized VM107 console installation, followed by
non-executing preparation, stopping before plan approval/Start and publication.
Browser access worked in this turn. The direct-IP OpenID route reported a redirect
mismatch; the established `https://pve.wombat-universe.ts.net/` route completed
normal existing-account sign-in without changing authentication configuration.
Only VM107 (`aiw-worker`, `pve-r630`) was selected. Its console reached the existing
labadmin desktop; trusted HTTPS/Core independently confirmed VM UUID/operator SID
and active console session 1. No Windows credential was typed or changed.

Store search did not expose this system component. The exact approved Store link
was opened through File Explorer; Edge's first-run flow was left unfinished before
applying personalization settings, without browser sign-in or data import.
With the console user and Store initialized, the same exact approved WinGet
installation succeeded (exit 0), and the console Store download queue visibly
showed Windows Sandbox downloaded and then installed. No Update all/check-for-
updates action or other application installation was requested. Sandbox was not
opened. The earlier 0x80070520 limitation is resolved, not a current blocker.

Audit directory:
`C:/aiw/paired-console-preparation-efe09ad0-3ac2-42de-b0a1-605685618350`.
Installation record: `vm107-install-with-active-console.json`; console proof:
`sandbox-installing-console.png`, `sandbox-installed-console.png`.

The independently hashed d370ec8 CLI/verifier and all 14 package payloads were
reverified on VM107. Exactly one `admin prepare-paired` call then completed
successfully through trusted Core remoting. The actual production static inspector
verified Store registration, cache-only catalog membership and held provider file
identity; preparation staged the three fixed roles, protected workspace and typed
v0alpha8 receipt, then imported the v0alpha7 plan under a v0alpha4 planning-import
receipt. No provider lease/runtime
command was acquired or invoked. This is actual preparation evidence, not a fake
provider result or a native control observation.

| Current exact binding | Value |
|---|---|
| Run ID | `paired-1793425345541054400` |
| Evidence root | `C:\AIW-Paired-d370ec8-20261030\Evidence\paired-1793425345541054400` |
| Workspace / CLI `--root` | `C:\AIW-Paired-d370ec8-20261030\Evidence\paired-1793425345541054400\paired-1793425345541054400` |
| Project path | evidence root + `\paired-project.yaml` |
| Exact locator / pending review | evidence root + `\paired-workflow.json` / `\paired-review.json` |
| Created / imported | 2026-10-30 21:42:25 / 21:42:30 America/Anchorage (2026-10-31T05:42:25Z / 05:42:30Z) |
| Canonical run-plan hash | `b0d2e739ce45e7c9bbb0a0ed9651905cefcd0dfaae53c4e06450c1108035f234` |
| Canonical Sandbox-plan hash | `291de53cf6c90fc35801631c40bed87fe82d090cf7261e1a41894957649abc69` |
| Project revision hash | `c1b4c4e9323d7b25ebc7397aab9f7194eeb9bc0d30c874f08fd545107bef4e66` |
| Fixed profile hash | `8eab0eaac3e8fe3d1aa400996a643b207298f5b22d50f2d72f356527e508a6cb` |
| Workspace identity / security-policy hash | `cb246b2b5cd2b80dd36ffcb9f941e5e749b1baf60efa77b85def6f51a9d5c4ef` / `5b304775afdaed1a7acbbbd80658f36e7b60b9896cae2ae626691aae59a8f878` |
| Canonical preparation-receipt commitment in import | `62a10d1d3d0b99825e6277c05d36c7d02dec406560a18e872f87ef98eda1e02e` |
| Preparation-file bytes SHA-256 (6876 bytes) | `5f59f8330879c03c91e356723ccd7eb79dc05058cbcbce58226fa36b7f2d7038` |
| Plan-file bytes SHA-256 (3525 bytes) | `f3611b8d0c1b22c181047c7c30341acfd108a594d4ee32dfaf430ca1b75431e6` |
| Registered provider package | `MicrosoftWindows.WindowsSandbox_0.8.107.0_x64__cw5n1h2txyewy`, Store, status OK |
| Package family / publisher | `MicrosoftWindows.WindowsSandbox_cw5n1h2txyewy` / `CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US` |
| Provider path | `C:\Program Files\WindowsApps\MicrosoftWindows.WindowsSandbox_0.8.107.0_x64__cw5n1h2txyewy\wsb.exe` |
| Provider SHA-256 / size | `247e092b5c5bd37820f225a7dd3ddf10ae37a67e2751a19c24b802c84769c441` / 156160 bytes |
| Provider file volume / ID | `322b0dfe` / `000300000002a99d` |
| Catalog | same package root + `\AppxMetadata\CodeIntegrity.cat` |
| Catalog SHA-256 / volume / ID | `a5cd4096113be4c7240049327b55d7018c06ee009809999a42cd7ecaca035905` / `322b0dfe` / `000500000002531e` |
| Catalog member / trust | `9B406D701D4E6AADC1AD76D80C72FCC2F527E6BFA4597FCF2E4C73E44EA702DF` / `catalogMember`, `cacheOnlyWholeChainExcludeRoot`, verification available |
| Workspace volume / root file ID | `28322b3c322b0dfe` / `f4a90200000004000000000000000000` |
| Verified persisted status | `pendingApproval`, journal sequence 1; Windows Sandbox session status `none` |

The provider executable's runtime version is **unmeasured** (`version=null`);
package version 0.8.107.0 is observed. The receipt declares required protocol
`windowsSandboxCli/v0.8.107.0`, observation `requiredAtStartNotObserved`.
Runtime protocol, full feature readiness, global session availability and mapped
guest Tools behavior remain deferred to the separately authorized Start. The
plan's intended `nativeWorker` origin is not a measured control result.

`paired-review.json.proposedApproval` contains a typed proposal for this exact
run/hash/operator/trust-delta tuple. Its prefilled `approvedAt` is **not consent**;
no approval record was committed. A read-only `run status` verified pending state
and session `none`, with nine fixed retained plan/receipt/journal/tool file hashes
unchanged before/after. Approval, cancellation, result, revocation and session-
transaction artifacts are absent; guest Output and Exports are empty. Historical
f99 Evidence/Exports remain empty and untouched. Zero provider runtime/control
calls occurred. Records: `vm107-preparation-result.json`,
`vm107-prepared-stop-state-v2.json`, plus exact retained document copies.


## Earlier blocker remediation — retained history

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
accepted those source terms/region sharing. The exact product ID extracted
read-only from Microsoft's installed OS launcher is `9NSMXC3NB0HN`; WinGet's
Microsoft Store catalog confirmed **Windows Sandbox**, publisher **Microsoft
Windows**, free. Broad search did not find it; no guessed ID or third-party
package source was used. The first installation attempt stopped without package
agreement acceptance. After the user separately accepted the displayed Store
License Terms, transaction terms and seizure warning, exact-ID installation
failed with **0x80070520**, "A specified logon session does not exist. It may
already have been terminated." Post-attempt native Appx queries still returned
zero current-user and all-user packages; no Sandbox/control processes or
interactive logged-on user were observed. No provider or control was launched.
The error is an installation/logon limitation, not an assessment result.

Observation files and hashes are indexed by `remediation-observation-index.json`
under `C:/aiw/paired-blocker-remediation-5a322331-1eb5-4fa4-8e7c-790918ce420d`.
The approved install command was the existing installed WinGet with
`install --source msstore --id 9NSMXC3NB0HN --exact --accept-source-agreements
--accept-package-agreements --disable-interactivity`. It was not retried after
the logon failure. No account sign-in, scheduled logon, credential/grant change,
classic Sandbox bootstrap launch or unofficial download workaround was attempted.
Microsoft's [Sandbox upgrade documentation](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-versions)
warns that classic launch can continue into the older app; that route cannot be
used within this no-launch authorization. A logged-on VM107 operator can perform
the already approved exact Store installation; do not launch the installed app.
Then re-inspect the registration and prepare a fresh plan using the command below.
The historical prerequisite observations below remain retained; the firmware flag
alone no longer justifies labeling this active Hyper-V target unavailable.

## Historical first prerequisite result — before remediation

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

Historical unsigned package: `C:/aiw/paired-native-review-f99bbd4-20261030`.
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


Current refreshed unsigned package:
`C:/aiw/paired-native-readiness-fix-d370ec8-20261030`, source
`d370ec8cd5bcaa6915ac24801789070dd0040e3b`.

- Receipt content commitment: `dc2e9499cc82e1258b7fe81da51abe2c2a9d83b83581d8e015f2146989f56390`.
- Desktop SHA-256: `123e27aa899b94b2b091ecbf7c954b252d9a39faa3f8dc9d865a2c8c3a0905c8`.
- CLI SHA-256: `0dccb24c04f895a22e647af10b7ce0d72b70902c328e59b4b2329013cb5a111a`.
- Verifier SHA-256 unchanged: `8398e34b15d2876cc7aa30ca45e59c290468e77afe318ba374b8f3ceab85bcfe`.
- Offline assembly and exact inventory passed; build record
  `C:/aiw/paired-readiness-fix-package-build.json`, compiler log
  `C:/aiw/paired-readiness-fix-package-build.stderr.log`.
- New VM107 staging root: `C:\AIW-Paired-d370ec8-20261030`, with `Package`,
  `Evidence` and `Exports` siblings. Preserve the old f99bbd4 root unchanged.
- Controller and remote verifiers both confirmed all 14 payload files and exact
  inventory. Records under the earlier remediation directory:
  `controller-package-verification.json`, `vm107-package-verification.json`,
  `stage-readiness-fix-result.json`. Final trusted endpoint inspection confirms
  both old and new Evidence/Exports directories empty at that historical stage.
  Current preparation subsequently created only the exact pending run above.

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

## Current target-provider gates — statically verified, runtime deferred

The current provider/catalog/file-ID and v0alpha8 preparation pins are recorded
above, from actual production static inspection. The following command completed
once on VM107; **do not repeat it or create another plan**:

```powershell
& 'C:\AIW-Paired-d370ec8-20261030\Package\aiw.exe' admin prepare-paired --evidence 'C:\AIW-Paired-d370ec8-20261030\Evidence' --identity 'AIW\labadmin'
if ($LASTEXITCODE -ne 0) { throw 'Preparation failed; preserve evidence and stop' }
# STOP. Completed; paired-review.json remains pending, not approval or a result.
```

No `host assess`, `wsb --version`, list, Start, approval, recovery, classic
bootstrap, feature/VM/security changes or controller fallback was performed.
Runtime checks remain required after a future exact approval and separate Start.

## Conditional future assessment — not authorized by console/preparation approval

Use the **existing pending run** and exact immutable pins above. Do not reprepare
in the desktop: its Prepare action creates a different run/plan, invalidating this
request's bindings. This smallest native assessment would use the existing CLI
approval and Start entry points into the same shared native runner used by the
desktop. It would exercise production native provider/guest/collector/reporting,
but **would not exercise desktop Controller/Tauri approval/Start interaction**;
that UI's completed fake-provider/replay evidence remains a separate limitation.

After a new explicit authorization for this request, the operator must reverify
VM identity, package inventory, retained plan/receipt/tool hashes, provider/catalog
identity and exclusive reservation. Any drift requires a new request, not repair
or silent re-preparation. The intended approval record has:

- schema `aiw.dev/approval-record/v0alpha1`, run `paired-1793425345541054400`;
- `planHash=b0d2e739ce45e7c9bbb0a0ed9651905cefcd0dfaae53c4e06450c1108035f234`;
- `approvedBy=AIW\labadmin`; actual future consent/recording time in `approvedAt`;
- exactly the two trust deltas in the retained plan/proposal: the fixed ordinary
  versus zero-capability classic AppContainer controls in one offline Sandbox,
  and read-only Tools mapping with writable Output treated as untrusted.

Copy those fields from the bounded pending review **only after** that new consent,
updating the timestamp to actual recording time. Publish a new
`C:\AIW-Paired-d370ec8-20261030\Authorized-approval.json` exclusively (never
replace an existing file), then use `aiw run approve --approval` with the exact
workspace and run below. That step commits approval but does not start execution.
No authorized-approval file exists now. Stop if any existing committed approval,
cancellation, result, transaction, unexpected output or foreign resource is found.
The exact future commands are documented for review only; **neither was run**:

```powershell
$ErrorActionPreference = 'Stop'
$pairedCli = 'C:\AIW-Paired-d370ec8-20261030\Package\aiw.exe'
$pairedWorkspace = 'C:\AIW-Paired-d370ec8-20261030\Evidence\paired-1793425345541054400\paired-1793425345541054400'
$pairedRunId = 'paired-1793425345541054400'
if ((Get-FileHash -LiteralPath $pairedCli -Algorithm SHA256).Hash.ToLowerInvariant() -cne '0dccb24c04f895a22e647af10b7ce0d72b70902c328e59b4b2329013cb5a111a') { throw 'CLI drift' }
# FUTURE GATE 1: only after explicit consent and exclusive new approval-file creation.
& $pairedCli run approve --root $pairedWorkspace --run-id $pairedRunId --approval 'C:\AIW-Paired-d370ec8-20261030\Authorized-approval.json'
if ($LASTEXITCODE -ne 0) { throw 'Approval failed; stop, no Start' }
# FUTURE GATE 2: separate Start, once; a lost response is not permission to retry.
& $pairedCli run start --root $pairedWorkspace --run-id $pairedRunId --project 'C:\AIW-Paired-d370ec8-20261030\Evidence\paired-1793425345541054400\paired-project.yaml' --guest-agent-sha256 'b5cd415894b5d142215ae9b71f8d619d43404eb2511eb9304ad63f53db097512' --timeout-seconds 300
if ($LASTEXITCODE -ne 0) { throw 'Start did not settle successfully; preserve records and follow exact owned cleanup/recovery conditions' }
```

The shared native runner reopens and holds the prepared inputs, verifies committed
approval, acquires its local provider lease and performs current protocol/session/
feature checks before dispatch. All outcomes and cleanup must be retained; no
request for plan approval or Start has been fulfilled by preparing this document.

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
parent (the fresh locator supplies all run values); it writes only a new selection
outside retained workspaces. The **exact prepared-run locator** is pinned below;
use it only after that same run is separately approved/executed and settles.
Preserve other pending/failed roots; do not enumerate them to choose a run:

```powershell
$ErrorActionPreference = 'Stop'
$pairedLocatorPath = 'C:\AIW-Paired-d370ec8-20261030\Evidence\paired-1793425345541054400\paired-workflow.json'
$pairedEvidenceParent = 'C:\AIW-Paired-d370ec8-20261030\Evidence'
$pairedSelectionPath = 'C:\AIW-Paired-d370ec8-20261030\Exports\selection.json'
# Explicit approved-run locator only: no discovery, guessed ID or test producer.
function Normalize-PairedLocatorRoot([string]$Value) {
    $pairedNormalized = [IO.Path]::GetFullPath($Value)
    if ($pairedNormalized.StartsWith('\\?\')) { $pairedNormalized = $pairedNormalized.Substring(4) }
    $pairedNormalized.TrimEnd([char]'\')
}
$pairedLocatorPath = Normalize-PairedLocatorRoot $pairedLocatorPath
$pairedExpectedRoot = [IO.Path]::GetDirectoryName($pairedLocatorPath)
if ([IO.Path]::GetFileName($pairedLocatorPath) -cne 'paired-workflow.json' -or [IO.Path]::GetDirectoryName($pairedExpectedRoot) -ine (Normalize-PairedLocatorRoot $pairedEvidenceParent)) { throw 'Locator outside approved evidence parent' }
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
if ($pairedRun.runId -cne 'paired-1793425345541054400' -or $pairedRun.planSha256 -cne 'b0d2e739ce45e7c9bbb0a0ed9651905cefcd0dfaae53c4e06450c1108035f234') { throw 'Locator differs from approved run/plan' }
if ((Normalize-PairedLocatorRoot $pairedRun.evidenceRoot) -ine $pairedExpectedRoot -or !(Normalize-PairedLocatorRoot $pairedRun.workspace).StartsWith($pairedExpectedRoot + '\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Locator root/workspace mismatch' }
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

The user authorized blocker remediation and non-executing preparation, preserving
the stop before plan approval/Start. Source fixes are committed at d370ec8 and
independently reviewed; focused checks and refreshed offline assembly passed.
Normal trusted TLS/Core remoting was used. No security, feature, CPU, snapshot,
network or power change was made. Exact Store installation succeeded after the
separately authorized console session/Store initialization resolved 0x80070520.
Only the approved prerequisite was installed. No Sandbox provider/runtime,
control executable, application trial or AIW desktop UI was launched. Old package/
evidence remains unchanged.

Non-executing production preparation/import completed once and produced the exact
pending plan pinned at the top of this request. Read-only status verified pending
approval, journal sequence 1 and no bound session transaction. Global provider
session availability remains unmeasured. Plan approval and Start remain
unperformed and unauthorized. No native acceptance or cleanup trial
is claimed; no historical run was replayed/recovered. Existing Rust/Node review
and test evidence was reused without rerunning unchanged suites.

The eventual native scope, if separately authorized with these exact bindings
still current, remains this one six-case pair and only its necessary owned cleanup or
exact recovery. That later operation requires its own exact plan approval and
separate Start. Full Benchmark 2/W4/W5 closure and publication remain separate.
No push, PR, signing, publication or release occurred.

Earlier document review found and fixed one procedure issue: CLI preparation and
later fresh UI preparation can leave two roots, so selection now uses only the
exact approved-run locator instead of counting/discovering children. All three
PowerShell blocks parsed. The changed selector alone ran against a clearly
labeled synthetic two-root example: selected the explicit run, rejected output
collision and outside-parent input, preserved locator bytes, zero provider calls.
Record: remediation directory `updated-selector-check.json`. No unchanged native
or broad test suite was rerun; document governance and diff checks passed.
Independent read-only review rechecked the correction and completed staging
facts; no remaining consequential finding was reported.

Current console/preparation document checks: all three PowerShell blocks parsed;
only the selector bookkeeping block was exercised with a labeled synthetic
two-root fixture and temporary destinations. Explicit selection, collision and
outside-parent rejection, unchanged input bytes and zero provider calls passed
(`pinned-selector-check.json` in the current audit directory). Neither the
documented completed preparation command nor future approve/Start block was run
as a document check. Independent review matched current pins and pending status
to retained receipts; its plan-schema/import-receipt wording finding was fixed.
Unchanged source suites/builds were reused; only document governance/diff checks
are new here.
