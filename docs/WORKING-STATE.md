# Working state

Updated 2026-11-15 (America/Anchorage). The user-selected goal is #108: one
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

Exact protocol selection now enters generic version-2 plan hashes and approval;
preparation receipts use v0alpha2. Start observes the matching held-provider
version before list/start. Recovery requires committed approval and the exact
persisted protocol before query/stop. Historical generic v1 remains read-only;
never relabel it or reuse its approval. Explicit adapters cover 0.8.107.0 and
0.8.114.0; native qualification of 114 is still pending.

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
Preflight requires 10 GiB free and cache <=8 GiB. Last completed Clippy measured
2,082,100,909 cache bytes and 10,895,130,624 bytes free. Do not create retry caches.
A separately audited idle GUI cache recovered 8.41 GiB. The policy-blocked
`C:\aiw\app-isolation-workbench\target\debug\incremental` remains untouched;
never retry or bypass its cleanup. Preserve source, pinned images and evidence.

Source 51b2 completed two consecutive dev builds with the same 1,464,790,831-byte
cache and identical tool hashes; a cold trace records 90 rustc calls without
incremental/full debug. Later test growth is accounted separately. Storage
policy 43, compiler-log 12, churn 1,000 cycles, real provider 126 tests,
governance and independent review passed. Local checks now clean fresh owned
fixtures on success/failure and report cleanup refusals. All transfer helpers
were stopped; the console is idle and the clipboard contains the last capture.

Next: finish the clean exact-source three-tool build in that same cache; seal
fresh control-r6 templates and data-only deltas. Independently review its actual
version-2 plan before separate approval/Start. Qualify ordinary/classic positives,
timeout/overflow negatives and controlled interruption/exact recovery before
running either external fixture. jq and SQLite payloads/provenance and the same
data-driven private harness are ready but have never executed. Native setup
refusals are driver blockers, not application incompatibility. No fallback,
privilege grant, runtime installation, VM or host-security change is authorized.
