# PowerShell 7.6 offline migration validation

## Subsequent WSMan identity correction

The [WSMan correction record](WSMAN-IDENTITY-CORRECTION.md) supersedes the
original endpoint identity model below. It separates the actual wsmprovhost.exe
host and loaded Core engine from the independently observed worker pwsh.exe.
The original migration's test counts, package worker hash and hosted run remain
historical evidence for their identified source; they are not new correction
results. Fresh correction checks and independent review are recorded separately.
Stages A–D and merge remain blocked.

This record distinguishes source/inert checks from separately gated installation,
remoting, baseline provisioning and native application acceptance. The adopted
goal covers the offline source package and one sanitized checkpoint push only.

## Runtime contract and source changes

Supported minimum: stable x64 Core 7.6, with explicit rejection of preview/prerelease,
wrong edition/architecture, user/Store/PATH executables and unexpected PSHOME.
Recommended and hosted-CI pinned patch: 7.6.7 (Microsoft release, 2026-10-13).
Local existing inert-test runtime: bundled 7.6.5 on Windows kernel 10.0.26300.9711 (26H2). Machine-wide
runtime is absent locally; it was not installed by this migration.

New execution binds observed host/worker version, edition, prerelease, architecture,
image/hash, PSHOME, native capabilities and zero compatibility sessions into the
approved preparation/request and receipts. Both command and file-transfer routes
use the same explicitly selected PowerShell.7.6 HTTPS session. A held read-only
image/helper survives through dispatch. Native SYSTEM, Control and lifecycle
receipts must all match the approved worker runtime, including independent report
readback. Raw evidence bytes/hash/BOM support and legacy request hashes are retained.
Historical records lacking a runtime binding remain readable; fresh remote recovery
of an incompatible outstanding preparation fails clearly without rewriting it.
Already completed cold-recovery proofs can still finalize without a runtime launch.

Framework-only directory creation was replaced by protected ACL-at-creation.
Product dispatch/collection/readiness deadlines were not enlarged. Inert PowerShell
subprocess tests share a local process guard under normal suite concurrency;
inherited output pipes also obey the original subprocess deadline with diagnostics.
The completed old bounded harness was retired rather than exposing nonce replay.
Historical106/107 execution utilities are explicitly retired; pure builders/data
readers remain supported. The offline PowerShell Sandbox control bootstrap and
legacy native research launchers fail before execution because a verified Core
payload/bootstrap is not present. Native Rust Sandbox profiles are independent.

## Coverage and evidence

The migrated recovery/export/readiness suite passed 16 tests under normal suite
concurrency on Core 7.6.5, retaining held-helper, crash/missing/partial-cache,
enumeration/read-failure/retry, queued/running-task and delayed-readiness coverage.
New pure regressions reject old/preview/unexpected runtime identities and mixed
legacy/different lifecycle runtime receipts; absent optional runtime fields retain
historical serialized bytes/hash semantics. Static graph checks cover standalone,
emitted, native-script and Rust launch sites plus all four workflow runtime gates.
No test silently substitutes a Windows PowerShell compatibility process.

Inert local imports confirmed CIM, LocalAccounts, ScheduledTasks, WSMan, DISM and
Appx load natively on the controller with automatic compatibility loading disabled;
Appx loaded `Microsoft.Windows.Appx.PackageManager.Commands.Core.dll`. No
WinPSCompatSession appeared. This is module/import evidence, not proof of per-user
package install/uninstall, SYSTEM/standard-user supervision or the worker endpoint.

Local verification uses Rust/Cargo 1.99.1 and the existing bundled Core 7.6.5
executable (SHA256 `362a356ce7f0940ec74f73a8fc2c990a2cc24a38a11c90bbd8eca947110ad139`).
Core and desktop dependency audits passed with advisory warnings: core
`RUSTSEC-2024-0449`; desktop additionally `RUSTSEC-2024-0370`,
`RUSTSEC-2024-0429` and `RUSTSEC-2026-0386`. These are audit warnings,
not a claim that dependencies have no advisories. No lockfile was changed.
Desktop JavaScript controls passed all 14 tests. The controlled local native
held-process/exit regression passed all 14 cases, without launching a packaged app.

Completed local source checks:

- Full `scripts/verify.ps1`: passed, including governance/runtime policy, format,
  workspace/all-target Clippy with warnings denied, 629 workspace tests, preview
  verifier, CLI examples and schema generation. The 26 explicitly ignored tests
  were not counted as passed. Windows platform: 170 passed, 10 ignored.
- Module integration: passed through the workspace CLI contract test, preserving
  the structured stderr envelope, relative CLI path and stale native-exit control.
- Desktop: format, all-target Clippy, eight Rust tests, release configuration and
  14 JavaScript controls passed. Both dependency audits passed as qualified above.
- Optional `research-msix-control,research-msix-lifecycle` inert suite: 14 passed;
  assembled Core scripts parsed and literal native source compiled. No worker or
  packaged application was dispatched.
- The fixed provider's isolated mocked state machine passed failed-restore,
  nonce-reuse, identity, checkpoint and lease transitions without hypervisor access.
- Transport policy passed ten runtime-binding rejections, protected directory
  ACL-at-creation/existing-ACL preservation and all 61 retired-entry checks.
- Preview, desktop verifier and archive controls passed for current and historical
  receipt formats, with relative-path, stale-exit, structured-error and refusal
  coverage. The additional `-CheckSignedAssembly` control passed on clean source
  `7e43cda778446fce6926a5797e6bfaf5cd364b18`, including real unsigned-signature
  and altered-build-record refusal. Its earlier dirty-tree refusal is not a pass.

The clean-source static-CRT worker/desktop build passed, and all six package
payload files were independently size/hash checked. The desktop contains the
same worker SHA256 that its receipt records:
`03c2ff4e289b4ffbc5f8327488853d830f273aead8fe9733a74c783f04b5aeda`.
The exact final source revision and receipt hash are emitted by the fresh package
build after the final documentation commit and retained outside Git. Neither
binary was launched as an application trial. The assembly/signing metadata and
historical deployed provider pins remain unchanged; no future baseline pin is
fabricated. This is an unsigned development desktop package, not a newly signed
application or native acceptance receipt.

The first full workspace attempt found duplicate PSEdition requirements in an
assembled worker script. The assembler now emits one requirement block while
retaining fragment runtime guards; its focused regression and the final full
suite passed. Earlier failures remain in private logs, not relabeled as passes.
Local Rust 1.88/1.90 minimum checks were **not run** because those toolchains are
absent; no toolchain was installed implicitly. Fresh hosted CI on the final pushed
checkpoint checks both minimums and Core 7.6.7. Its terminal results and the exact
clean-source package receipt/worker hash belong to the consolidated checkpoint
report, distinct from these local source checks and from native acceptance.

The first published source checkpoint, `e7ab0a6`, was rejected by GitHub before
jobs started: `runner.temp` is unavailable in `steps.shell`. The corrected
workflows use a fixed native cmd wrapper to select the staged or machine Core
image. It also handles the runner's first-space shell parsing and extensionless
script files by copying original bytes to a fresh `.ps1` before `-File`. No
Windows PowerShell process is involved. Six bounded local regressions passed
using an existing-runtime copy: both routes, extensionless input, spaced paths,
exit42 propagation and preexisting-file refusal/preservation. Machine paths are
substituted only in that inert fixture; no machine runtime was installed.
All 35 custom shell declarations and all 12 job gates are checked, with only
the initial trusted runtime-copy step allowed to use the hosted `pwsh` selector.
The new regression is part of full verification; corrected governance passed.
The replacement checkpoint's CI result is reported separately from the initial
workflow-definition failure, which is not relabeled or rerun unchanged.

Logs and build products are retained outside Git under
`C:\AIW-Resume-20261021\powershell76-*`. Only source, tests and sanitized
documentation enter the final checkpoint. Historical full application acceptance
remains tied to 34369c9/2dab30b and bounded acceptance to 1879c77/abd17ea; those used
the former runtime and are not relabeled as Core 7.6 validation. All their nonces
remain completed. New provider/baseline/runtime pins require separately approved
setup and fresh observation; the old deployed provider hash is intentionally kept.

## Pending bundled approval

No local/worker runtime installation, endpoint/security/firewall/WinRM change,
VM107 setup/baseline change or fresh native/Sandbox trial occurred. See the
[single setup/native acceptance plan](SETUP-AND-ACCEPTANCE.md) for the exact MSI,
machines, endpoint/ACL/TLS scope, new baseline and fresh run controls. Full native
migration acceptance remains pending that approval and successful execution.
The current source fails before acquiring the old baseline for migrated work.
PR #103 remains unmerged; offline source validation does not grant merge authority.
