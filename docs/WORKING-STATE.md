# Working state

Updated 2026-09-19. This is a compact handoff, not a run receipt or authorization.

## Where to resume

- Active development branch: `codex/wsb-typed-scenarios`. Locate it with `git worktree list` if this checkout differs. The main checkout has historically been behind this worktree.
- Latest slice: required app-token file ACL observations are bound to preparation, approval, guest results, and retained reports. The baseline/candidate/relocated comparison passed with report v0alpha10 and comparison v0alpha4; provider, requested configuration, and recorded Windows versions match. Broader containment remains unmeasured. Recipe inspection exposes exact launch settings, mappings, data lifetime, and requirements. See PACKAGING-RECIPES.md for the resumed live proof and retained failures, and INTERACTIVE-SANDBOX.md for the earlier human edit/save/close/export proof. Use scripts/work-status.ps1 for current HEAD and dirty files.
- Goal: report tested functions for exact application bytes and measured isolation configurations, then use the evidence for adaptation/repackaging. Free community project; feedback collection is not a development gate.

## Implemented versus exploratory

- Production path: protected intake; approved Windows Sandbox execution and recovery; fixed Notepad++ MSI v6 install/open/edit/save/close as a standard user after privileged install. Bound token, runtime, file/registry, stage, failure-snapshot, and MSI ProductCode observations feed retained JSON/Markdown reports and explicit report sets.
- Bambu: separate approved EXE export profile, protected staging, standard-user guest execution, stage/failure result, bounded 3MF graph/geometry verification, and retained JSON/Markdown report. Original `--info` compiler remains metadata-only. See the profile document for production validation and exact evidence.
- Mixed reports: `run report-wsb-set` combines verified MSI and Bambu results with distinct function columns, failures/unavailable entries, and verified-identity deduplication. The retained regression checks deterministic output and unchanged workspace inventories.
- Development control: paired file/registry reads and descendants passed in two fresh workers. Token, value/DACL, process/profile, and worker cleanup bindings passed. Version 2 rejects 30 altered records; historical file-only records stay unmeasured for registry. See CONTROL-FIXTURE.md. Research controls remain excluded from production application reports.
- Packaging: `package export-wsb-msi`, `package verify`, and `package import` carry exact MSI bytes and a fixed recipe, with an independently supplied manifest hash. Replay passes the existing standard-user document workflow and report checks. Both the automated assessment recipe and approved scratch-only interactive launch are supported. The transfer profile accepts one bounded text input and offers explicit receipt-bound export; persistent data, MSI/MSIX conversion, and application-level baseline/candidate isolation comparison remain open. Outer Sandbox containment is distinct from an inner application boundary.

## Next coherent slice

The required app-token file ACL milestone passed: baseline, candidate, and relocated replay all verified document save, explicit protected-file read denial, allowed local-data create/write/read, and exact cleanup. Comparison v0alpha4 and report v0alpha10 preserve historical absence as unmeasured. The successful comparison resumed after a user-requested pause; the interrupted candidate was cancelled and exactly recovered. Full evidence pointers and limits are in PACKAGING-RECIPES.md. The Sandbox provider list was empty afterward.

PR #63 integrates the accumulated branch. Local workspace tests, clippy, MSRV, format, and governance passed. Hosted validation caught an interactive-transfer export Drift error; CI now preserves full failed-check logs and export errors retain phase details. The synthetic protected-output publisher now uses the exact workspace owner/SYSTEM contract instead of token-default ownership. A fixed-clock regression also closes a real same-tick diagnostic-filename collision using a process-local atomic sequence, without adopting or overwriting files. Check PR status before merging; do not infer CI success from local results.

Benchmark 3 remains incomplete: evidence-attached reusable launch authorization and deployment-environment validation are still open. The measured control covers only fixed guest standard-user file ACL access, not host containment or descendants. Preserve recorded failures and exact recovery; do not repeat a successful installer trial solely for report-only changes.

## Read only what the slice needs

- [Execution control and retained proof](CONTROL-FIXTURE.md): fixed fixture, driver, normalizer and negative tests.
- [Sandbox bundles](SANDBOX-BUNDLES.md): commands, file contract, first fresh-worker replay, and remaining packaging scope.
- [Packaging recipes](PACKAGING-RECIPES.md): pre-import inspection command, snapshot bindings, and remaining adaptation benchmark.
- [Interactive Sandbox](INTERACTIVE-SANDBOX.md): scratch-only profile, approval/launch instructions, lifecycle proof, and data limits.
- [Bambu profile and actual research results](BAMBU-STUDIO-PROFILE.md): hashes, exact command, limitations, retained research location.
- [Roadmap](ROADMAP.md): benchmark completion criteria and later isolation/adaptation work.
- [Report sets](REPORT-SETS.md), [assessment reports](ASSESSMENT-REPORT.md): existing verified reporting contracts.
- [Notepad++ fixture](FIXTURE-NOTEPAD-PLUS-PLUS-8.9.8.md), [MSI ProductCode observation](MSI-PRODUCT-REGISTRATION.md): existing live controls and retained evidence.
- Code entry points: provider `scenario.rs`/`bambu_export.rs`/`imported_bambu.rs`/`bambu_artifact.rs`; runner `preparation.rs`/`lib.rs`/`bambu_report.rs`/`application_report_set.rs`/`report_set.rs`; guest-agent `main.rs`; native `guest_bambu.rs`/`guest_standard_user.rs`.

## Operational constraints

Use local checks first and CI sparingly. Push completed authorized changes; avoid incidental workflow triggers. Installer corpus is locally available in `%USERPROFILE%\Downloads\installers`; original files are not execution authority. Reverify retained intake/artifact bindings when used. Keep research evidence outside production report sets. Never install on the host or remove unrelated worktrees/evidence.

September 19 local storage: E: filled during final compilation. The active
worktree's incremental cache was preserved at
`%LOCALAPPDATA%\Temp\aiw-incremental-preserved-20260919`. Free space recovered
after a delay. Validation moved to `CARGO_TARGET_DIR=%LOCALAPPDATA%\Temp\aiw-os-validation-20260919`
with `CARGO_INCREMENTAL=0`, `CARGO_PROFILE_DEV_DEBUG=0`, and
`CARGO_PROFILE_TEST_DEBUG=0`. Check free space before another default-target
build. Retained trials and static guest artifacts were preserved.
