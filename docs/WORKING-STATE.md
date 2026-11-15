# Working state

Updated 2026-11-15 (America/Anchorage). Active goal is #108: one generic assessment
and packaging path, demonstrated by two different external fixtures with no
product-specific code changes. Worktree `C:\aiw\app-isolation-workbench-108`,
branch `codex/application-neutral-assessment`, starts from freshly fetched main
`04be2cefb9e9e4ffff73408e960efee6d30ea9d8`. Start with `scripts/work-status.ps1`,
[roadmap](ROADMAP.md), [migration audit](APPLICATION-AGNOSTIC-MIGRATION.md) and
[release gates](RELEASE-GATES.md). The local `origin/main` ref is stale because
fetch configuration tracks another branch; use the recorded fetched commit.

## Current boundary and next work

Storage work takes priority before more native trials. The idle shared debug
incremental cache measured 32.15 GiB; compiled dependencies measured 10.06 GiB.
Automatic approval review blocked removal of that incremental cache; it remains
untouched. A separate verified idle GUI cache was removed with Cargo's exact
target-directory cleanup, recovering 8.41 GiB of volume space (11.34 GiB free).
Source and evidence were preserved. Dev/test profiles disable incremental output
and symbols. Shared preflight now covers normal builders and verification, with
one caller-selected cache, 10 GiB minimum free and an 8 GiB cache budget. Override
and compiler-log regression checks passed. Source `51b2a95` completed two identical
Windows dev builds and a release refresh in the existing shared cache. Cache size
remained 1,464,790,831 bytes / 1,815 files after every pass; artifact hashes matched,
with zero second-pass compilation. The earlier actual compiler trace contains 90
rustc invocations without incremental or full-debug flags. Four incremental
directories contain zero files/bytes. Small MSVC public-symbol PDBs are measured
within the budget. Independent evidence review passed; final host free space was
about 10.81 GiB. Hosted CI passed at `51b2a95` (run `43770608201`). Detailed private
measurement: `C:\aiw\generic-assessment-108\normal-windows-build-r3\measurement.json`.

The generic CLI/shared service path now covers held intake, compilation, protected
preparation, review/approval and separate Start, typed guest execution, retained
reports/comparison and data-only replay packaging. The elevated collector creates
ordinary-user or classic AppContainer roots suspended, observes image/token/job
facts and flushes progress before resume. Collector mutation-denial gates precede
application dispatch. Interrupted progress remains diagnostic. See
[the implementation boundary](APPLICATION-ASSESSMENT.md).

Native acceptance is blocked by a newly observed provider protocol mismatch.
The exact-source images were reconstructed and fully hash-verified on VM107 under
`C:\AIW\Goal108\control-r5`, preserving earlier roots. Fresh ordinary-control
preparation passed; its actual plan and separate approval/Start wrappers passed
independent review. Approval was recorded for plan
`c50e5904fb0cbd9e28ee19c674a0bd6e2dcf3702ceaf62d8cc7daa7610d07b94`.
Start exited 1 with complete diagnostics: installed Sandbox CLI `0.8.114.0` is
outside the reviewed `0.8.107.0` adapter. Source rejects this after held-provider
version observation, before list/start. Separate retained Read exited 0 and
reported `evidenceStatus=notRun`, with outcome/cleanup/evidence null. This is a
provider prerequisite, not application incompatibility or cleanup proof. No
retry, allowlist bypass, downgrade, installation or security change was made.
The small transfer helper was stopped and its viewer closed. Before vendor
trials, qualify a supported provider with the ordinary/classic and timeout/overflow
controls; supporting a new version requires captured/reviewed protocol behavior
and lifecycle/recovery validation, not a changed version constant.

Earlier preparation diagnostics remain preserved:
The first control preparation at `7df2d87` stopped at strict portable intake:
Windows exposed a short-name alias for the long control filename. A fresh private
input with identical bytes as `control.exe` passed intake, replay export and
verification. Prepare then exited 1 with complete captures after staging the
agent and application, leaving a preserved partial workspace. The original
generic CLI error exposes no specific cause. Diagnose retained protected intake
before a fresh preparation; no approval or Start was issued. Neither attempt
establishes guest execution or application compatibility. Private facts and raw
capture pointers are under `C:\aiw\generic-assessment-108\VM107-r3-*`.
Read-only verification subsequently admitted that retained intake. Two host
Windows regressions then reproduced sharing error 32 when workspace observations
requested ADD rights while intake custody was held. Observational opens now omit
those rights, retaining the same sharing and verification checks. Platform tests:
206 passed, 10 ignored, including both created/reopened workspace regressions and
continued write/rename denial. The old failure is preserved; fresh end-to-end
control qualification is still required on rebuilt binaries.
The rebuilt `2a777a5` preparation passed that custody stage and published its
plan, preparation and run locator on VM107. The final locator check then refused
mixed Windows path spellings: the workspace used plain DOS paths while the
canonical evidence root and project path retained the extended drive prefix.
The exact 870-byte locator is retained privately. A narrow prefix-equivalence
fix keeps all retained plan/workspace checks; independent static review passed.
Fresh control qualification remains pending; no approval or Start was issued.
Collector launch privileges are an unmeasured prerequisite; a refusal is a driver
blocker, not application incompatibility. Synchronous setup/I/O is bounded by the
outer worker watchdog, not hard real-time cancellation. No fallback, privilege
grant, runtime installation, VM or host-security change is authorized here.

Checks so far: schema 17, orchestrator 62, provider 126, guest 17, runner 143 plus
four generic preparation tests, 13 focused Windows native contracts, held intake
custody, and two package round-trip/drift tests passed. CLI 56 passed with one
historical-archive test ignored; runner's nine live tests were not invoked.
Existing admin regression cases passed; its two new fixture-construction failures
were corrected and their focused rerun passed. Workspace all-target Clippy and
governance passed. Final checks must cover subsequent changes.
Hosted Verify/audit, MSRV and Windows desktop CI all passed at `7df2d87` (run
`43684206047`), including the generic request's separate 2 MiB bound. Static x64
CLI/agent/control binaries are pinned in private build records for that revision.
The subsequent CLI reporting fix preserves safe typed preparation categories
without raw error text or invalid run IDs. CLI 58 tests passed with one historical
archive case ignored; formatting and CLI all-target Clippy passed. Earlier native
failures retain their original diagnostics and are not retrospectively reclassified.

One unchanged CLI binary compiled ordinary/classic plans and exported/reverified
packages for both real external fixtures. Semantic hashes matched across policy
selection and survived packaging. This was metadata/copy work only: zero provider
calls or fixture executions. Private proof:
`C:\aiw\generic-assessment-108\host-input-checks-r1\proof.json`.
Consequential native review found and closed ACL inheritance, total-budget and
FFI-lifetime issues. Private review receipts and test logs are under
`C:\aiw\generic-assessment-108`; no native acceptance follows from source review.

The first path is portable offline CLI execution, with exact argv/cwd, inputs,
bounded capture, exit checks and work-file assertions. Other mechanisms and
required evidence scopes remain explicit blockers until implemented. External
fixture choices are a stateless JSON CLI and a stateful database CLI; their names,
payloads, arguments and expected results remain private run inputs, never product
gates or distributed assets. Desktop intake, installer/GUI mechanisms and the
broader seven-fixture/holdout matrix remain open. Legacy execution remains until
equivalent generic regression coverage transfers; its readers/evidence stay intact.

Draft [#111](https://github.com/nathanmcnulty/app-isolation-workbench/pull/111)
is paused by user direction. Preserve its checkout at
`C:\aiw\app-isolation-workbench`, branch and all private evidence. Its in-flight
diagnostic build was stopped through its verified owned process tree; partial
artifacts/logs remain and no diagnostic ran in VM107. Private pause receipt:
`C:\aiw\environment-probe-20261114\legacy-pause-build-reconciliation-r1.json`.
Do not continue legacy 7-Zip adapters, MXC research or diagnostics for their own
sake. Reuse tracing or a Windows probe only where the generic path needs it.
See [execution packets](EXECUTION-PLAN.md). The roadmap does not authorize a live
trial, authentication, dependency install, runtime pin change or provider setup.

Vendor configuration bytes, application MSIX publication and installer-bundling
assembly are removed in the cleanup. Desktop candidate jobs remain paused until
an AIW-only layout and publication gates are reviewed. Original native archive
pins remain strict; synthetic test data is not original acceptance evidence.

## Retained evidence pointers

- [Fixed 7-Zip assessment](SEVENZIP-NATIVE-ACCEPTANCE.md): successful comparison
  and separate cancellation at source `593281a`; broader measurements remain
  unmeasured. Preserve the earlier failed attempt without inventing its cause.
- [Paired project-owned controls](PAIRED-NATIVE-APPROVAL.md) and
  [Results audit](RESULTS-ACCEPTANCE-AUDIT.md): scoped source and native records.
- [External historical archive tests](../fixtures/msix-lifecycle/README.md):
  exact native bytes are not distributed with source.

Preserve existing VMs, old packages, retained runs and unrelated work. Do not
rerun applications, recover completed sessions, delete remote releases/history
or alter retained evidence merely to align documentation.

## Integration checks

Run applicable contract, Rust, desktop and governance checks and consequential
independent review. Native acceptance requires approved disposable-worker proof;
synthetic tests, compilation and downloads do not establish it. Complete one
draft PR for this generic slice, with precise remaining limitations. Do not
claim all of #108, W4/W5 or production acceptance complete without evidence.
