# Working state

Updated 2026-11-16 (America/Anchorage). The user-selected goal is #108: one
application-neutral assessment and packaging path, demonstrated with two
behaviorally different external fixtures without product-specific code changes.
Legacy #111 and its evidence remain preserved and paused.

Checkout: `C:\aiw\app-isolation-workbench-108`, branch
`codex/application-neutral-assessment`, draft PR #112. Base fetched main is
`04be2cefb9e9e4ffff73408e960efee6d30ea9d8`; the local `origin/main` ref can be
stale. Start with `scripts/work-status.ps1`, [scope](REPOSITORY-SCOPE.md),
[migration](APPLICATION-AGNOSTIC-MIGRATION.md), and [release gates](RELEASE-GATES.md).

## Current implementation and evidence

The generic portable/offline x64 CLI path covers protected intake, compilation,
preparation, review/approval, separate Start, ordinary-user or classic
AppContainer execution, retained reports/comparison and data-only replay.
Application facts and exact payloads are run inputs. See
[application assessment](APPLICATION-ASSESSMENT.md). Installers/GUI automation,
full descendants/registry/network/DLL/memory evidence, the seven-fixture/holdout
matrix, W4/W5 and production acceptance remain open.

Source-71 protocol selection entered generic version-2 plan hashes and approval;
its preparation receipts use v0alpha2. Start observes the matching held-provider
version before list/start. Recovery requires committed approval and the exact
persisted protocol before query/stop. Historical generic v1 remains read-only;
never relabel it or reuse its approval. Explicit adapters cover 0.8.107.0 and
0.8.114.0. The first native 114 ordinary control completed the outer lifecycle
and verified Sandbox cleanup, but refused application dispatch: under the fresh
standard user, 13 of 15 mutation opens on the mapped collector succeeded, one
was denied and one returned sharing error 32. Its retained outcome is
insufficientEvidence/notRun, not compatibility or isolation acceptance. Preserve
control-r6 and its consumed approval; do not rerun or weaken the denial gate.

Affected tests passed: admin 72 (1 ignored), orchestrator 65, probe 30, runner
152 (9 ignored), platform 208 (10 ignored). Workspace all-target Clippy,
formatting, governance and consequential source review passed. Initial runner
failures exposed contradictory synthetic package/runtime-version fixtures;
those were corrected without relaxing production checks. The later runner and
platform runs used fresh owned TEMP directories and verified their removal.

VM107's source-51b2 R5b preparation and actual plan review passed, but Start
correctly refused installed CLI 0.8.114.0 against the old 107 adapter before
list/start. Its consumed intent and retained notRun report remain preserved at
`C:\AIW\Goal108\control-r5`; no cleanup/compatibility credit follows.
Earlier custody/locator failures and their fixes remain recorded in Git history
and private `C:\aiw\generic-assessment-108\VM107-r3-*`/R4 evidence.

The source-2f2 read-only seven-query helper completed on VM107 at
`C:\AIW\Goal108\protocol-r2`: all exits 0, empty stderr, unchanged held provider,
CLI 0.8.114.0 and empty raw list. Verb help confirms explicit id/config/raw
syntax. Original envelope 14,435 bytes SHA256
`584f271d2fdc871fa249f78dce368e2e51dc4c2a929d519230d593ac6d32f37c`
and raw report 8,988 bytes SHA256
`76baad24003afd612c31c5958bb233320d4bca8827298b4c3d8ed0f28e0d54d3`
are private; independent original-byte admission passed. No start/connect/stop
or application trial occurred. See [capture](SANDBOX-PROTOCOL-CAPTURE.md).

## Storage and next work

Use only `C:\aiw\environment-probe-20261114\target-static-r1`, the existing
shared cache. Normal builders require explicit CARGO_TARGET_DIR and reject
unsafe overrides; both dev/test workspaces disable incremental/full debug.
Preflight requires 10 GiB free and cache <=8 GiB. The latest read-only check
now measures about 2.12 GB of cache and 16.34 GB free after cleanup and measured
builds. Earlier preflight correctly refused compilation below the floor. Do not
create retry caches or bypass it.
A separately audited idle GUI cache recovered 8.41 GiB. The policy-blocked
`C:\aiw\app-isolation-workbench\target\debug\incremental` remains untouched;
never retry or bypass its cleanup. Preserve source, pinned images and evidence.
An independently reviewed, separately scoped cleanup removed 833 single-link
Rust archive/metadata files from idle `target/debug/deps`, recovering an observed
6,857,707,520 bytes. All 320 linked files, 312 empty unrecognized files, executables,
DLLs, symbols and child directories were excluded. The blocked path was not
traversed. Fresh per-file custody, old Cargo coordination locks and an immutable
removal receipt were verified; no broad Cargo clean or marker creation occurred.

Exact source 458bf68 completed two consecutive dev builds with the same
2,107,562,723-byte / 2,813-file cache and identical tool hashes; the second added
zero bytes and made zero rustc calls. Its release refresh ended at
2,123,969,551 bytes in that same cache. New compiler calls (10 dev / 10 release)
showed no incremental/full-debug flags; source, complete image hashes and logs
passed 359 independent admission checks. Private evidence:
normal-windows-build-r5/measurement.json. No inherited overrides were present;
normal scripts also reject unsafe overrides before compilation.
This is a measured preflight budget, not a hard filesystem quota. Storage
policy 43, compiler-log 12, churn 1,000 cycles, real provider 126 tests,
governance and independent review passed. Local checks now clean fresh owned
fixtures on success/failure and report cleanup refusals. All transfer helpers
were stopped; the console is idle and the clipboard contains the last capture.

The four raw control-r6 originals passed independent byte/hash/binding review;
the proof and originals remain private. Missing raw request/progress bytes are
explicit admission limits; there is no application acceptance credit. The
[evidence channel design](ASSESSMENT-EVIDENCE-CHANNEL.md) passed independent
design review, including the trusted local Start anchor, crash boundaries,
key confidentiality and sampled output budgets. The implementation below now
exists; fresh native qualification remains pending.

An isolated Windows CNG primitive now supplies ephemeral P-256 keys, public-only
export/import, fixed-size SHA-256 signing/verification, public nonces and explicit
fallible key/provider release. Four native tests include RFC 6979 public-vector
verification and tamper/encoding/foreign-key cases. Consequential source review,
format and governance passed. Hosted Windows CI run 43800695240 passed all three
jobs at facbfbe; its tested merge has the identical Git tree. Independent CI
admission confirmed the Windows workspace test exit. No assessment authority or
dispatch path called this primitive at that historical revision.

The isolated pure signed-record contract and CNG components passed consequential
review and all three hosted Windows CI jobs at 76acd65 (run 43802528747, identical
tested merge tree). Four CNG and ten protocol tests are included in workspace
coverage. This proves those components, not application execution.

Current integration passed independent source review at abfb884: v3 generic
plans / alpha3 preparation / alpha2 authenticated requests / alpha4 transactions,
consumed Start intent, public local descriptor/latch, separate provider Start
marker, guest-local collector, file/process/thread/default-DACL gates, signed
raw artifact admission and provider-zero retained reports. Historical plan v1/v2
and transaction alpha2/3 hashes remain separate and read-only. No fresh native
trial has validated this integration. Compile fixes passed hosted checks, but
run 43810705670 is **not accepted** despite green job metadata: its raw workspace
summary reports exit 101 and one failing platform sharing-fixture test. The test
used a DELETE-owning staging handle instead of the guest's write-only transport
writer. Its fixture is corrected without widening production sharing. The local
check helper now throws after a failure summary, so in-process verification
cannot continue and upload artifacts after a failed test. A two-case inert
failure/success caller regression passed with no compiler/provider invocation.
Review also fixed plan-hash/XML-hash confusion with distinct-commitment coverage.

Hosted CI now has a reviewed same-cache measured build and one-day retention of
three unsigned first-party tools plus the exact checkout receipt, after all
verification/audit/governance in that job. The 92e535b artifact is not admitted
because of the workspace failure. Corrected run 43814048969 at 458bf68 passed
all three jobs. Independent admission checked original logs: workspace passed=true,
exit 0; tested merge 508796bfc090687115a75cf493825b0983ebfaad has the identical
Git tree 946bf5e992cf22085c00a61860d7a4b263cc3e73. Local exact-source release tools
are pinned once in private qualification-tools-458 (three images, 29,822,464 bytes).
No additional build cache or full build-tree copy was created.

The user-authorized VM107 SSH/SCP route is operational with a console-verified
host key, dedicated restricted key and TCP 22 restricted to the parent host.
No parent firewall change was made; the prior marker listener is stopped.
Ordinary Core console PID 6636 is bound by its full birth time.

R7 (source 458bf68) and R8 (source 9a47a5d) each stopped after collector bootstrap,
with no committed latch/ACK or application result. Preserve both consumed Starts.
R7 exposed the wrong inherited/protected output expectation. R8 independently
observed a generated bootstrap short alias; the generic reader refused it.
Original R8 diagnostics show one exact Start/connect/stop and two final empty
lists, with cleanupComplete=true. Retained Read gives
incompleteOrUnauthenticatedPublication and no function/isolation credit.

Source 9a47a5d built twice in the same cache at 2,180,364,597 bytes / 2,916 files;
pass two compiled nothing and kept identical hashes. Release ended at
2,180,349,895 bytes. Independent source/command/PE/hash admission passed. Only the
changed CLI was pinned anew; unchanged guest/fixture images reference the prior
immutable set. No additional build directory or full build-tree copy was created.

The test-only private-parent fix at dc05731 passed CI 43848997429: all three jobs,
actual workspace passed=true / exit 0 / 472.44 seconds, audit and governance.
Tested merge eb942aa has the identical tree
6bb08e0550dd603bc88d9b14d60e5d4284509d41. Earlier failed CI runs remain unaccepted.

The source-93eded3 transport correction adds closed-role alias-aware raw-file
custody, exact seven-file completion, unchanged strict generic intake, and pure
completion verification after CNG binds the original four artifacts. See
[channel design](ASSESSMENT-EVIDENCE-CHANNEL.md). Independent cross-boundary and
platform source reviews passed. Focused checks passed: five host/CNG tests with
all seven actual short aliases, sixteen provider tests and twelve platform
tests. One native symlink fixture could not be created without privilege; its
branch remains unmeasured. Full affected suites passed: provider 146, runner 163 (9 ignored), platform 222
(10 ignored). Clippy and governance passed. Source 93eded3 built twice in the
same cache at 2,210,133,247 bytes / 2,935 files after both, with identical hashes
and zero second-pass compilation. Release ended at 2,210,597,898 bytes. All three
new image pins, source and compiler flags passed independent admission.

CI 43857370994 failed the two new publication fixtures: elevated default file
ownership differed from the required operator SID. The runtime correctly refused.
A test-only owner-bound staged publisher fixes that fixture without changing
runtime policy. Its runner 7 and platform 12 focused checks, Clippy, governance
and independent review passed. These new fixtures observed no aliases; retain
the earlier source-93eded3 real-alias proofs separately. New hosted CI is pending.
R9 staging uses the exact source-93eded3 binaries; native qualification is open.

Qualify ordinary/classic positives, timeout/overflow negatives and controlled
interruption/exact recovery before either external fixture. jq and SQLite
payloads/provenance and the same data-driven private harness are ready but have
never executed. These setup refusals are driver failures, not application
incompatibility. No fallback or additional privilege/runtime/VM/security change
follows from these results.
