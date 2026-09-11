# Working state

Updated 2026-09-10. This is a compact handoff, not a run receipt or authorization.

## Where to resume

- Active development branch: `codex/wsb-typed-scenarios`. Locate it with `git worktree list` if this checkout differs. The main checkout has historically been behind this worktree.
- Latest slice: approved scratch-only interactive Notepad++ profile, with bounded natural-exit/timeout handling and distinct session reports. Production timeout and separate controlled-close fixture pass fresh-worker validation. Use `scripts/work-status.ps1` for current HEAD, dirty files, and locally known upstream state.
- Goal: report tested functions for exact application bytes and measured isolation configurations, then use the evidence for adaptation/repackaging. Free community project; feedback collection is not a development gate.

## Implemented versus exploratory

- Production path: protected intake; approved Windows Sandbox execution and recovery; fixed Notepad++ MSI v6 install/open/edit/save/close as a standard user after privileged install. Bound token, runtime, file/registry, stage, failure-snapshot, and MSI ProductCode observations feed retained JSON/Markdown reports and explicit report sets.
- Bambu: separate approved EXE export profile, protected staging, standard-user guest execution, stage/failure result, bounded 3MF graph/geometry verification, and retained JSON/Markdown report. Original `--info` compiler remains metadata-only. See the profile document for production validation and exact evidence.
- Mixed reports: `run report-wsb-set` combines verified MSI and Bambu results with distinct function columns, failures/unavailable entries, and verified-identity deduplication. The retained regression checks deterministic output and unchanged workspace inventories.
- Development control: paired file/registry reads and descendants passed in two fresh workers. Token, value/DACL, process/profile, and worker cleanup bindings passed. Version 2 rejects 30 altered records; historical file-only records stay unmeasured for registry. See CONTROL-FIXTURE.md. Research controls remain excluded from production application reports.
- Packaging: `package export-wsb-msi`, `package verify`, and `package import` carry exact MSI bytes and a fixed recipe, with an independently supplied manifest hash. Replay passes the existing standard-user document workflow and report checks. Both the automated assessment recipe and approved scratch-only interactive launch are supported. Personal document transfer, persistent data, MSI/MSIX conversion, and application-level baseline/candidate isolation comparison remain open. Outer Sandbox containment is distinct from an inner application boundary.

## Next coherent slice

Add a bounded text-document transfer contract to the scratch-only interactive profile: immutable input copy into the worker, fixed save destination, receipt-bound output bytes, and explicit verified export to a new host file. Do not map personal document folders or silently overwrite originals. Human keyboard/mouse usability remains a manual check; controlled close proves only lifecycle handling. Package reports expose verified bundle/run association through `package report-wsb-msi`; interactive sessions are excluded from assessment matrices. AppContainer approved reporting and real-application comparison remain separate follow-ups. No inner network restriction, persistent application installation, or host-launch capability is complete.

## Read only what the slice needs

- [Execution control and retained proof](CONTROL-FIXTURE.md): fixed fixture, driver, normalizer and negative tests.
- [Sandbox bundles](SANDBOX-BUNDLES.md): commands, file contract, first fresh-worker replay, and remaining packaging scope.
- [Interactive Sandbox](INTERACTIVE-SANDBOX.md): scratch-only profile, approval/launch instructions, lifecycle proof, and data limits.
- [Bambu profile and actual research results](BAMBU-STUDIO-PROFILE.md): hashes, exact command, limitations, retained research location.
- [Roadmap](ROADMAP.md): benchmark completion criteria and later isolation/adaptation work.
- [Report sets](REPORT-SETS.md), [assessment reports](ASSESSMENT-REPORT.md): existing verified reporting contracts.
- [Notepad++ fixture](FIXTURE-NOTEPAD-PLUS-PLUS-8.9.8.md), [MSI ProductCode observation](MSI-PRODUCT-REGISTRATION.md): existing live controls and retained evidence.
- Code entry points: provider `scenario.rs`/`bambu_export.rs`/`imported_bambu.rs`/`bambu_artifact.rs`; runner `preparation.rs`/`lib.rs`/`bambu_report.rs`/`application_report_set.rs`/`report_set.rs`; guest-agent `main.rs`; native `guest_bambu.rs`/`guest_standard_user.rs`.

## Operational constraints

Use local checks first and CI sparingly. Push completed authorized changes; avoid incidental workflow triggers. Installer corpus is locally available in `%USERPROFILE%\Downloads\installers`; original files are not execution authority. Reverify retained intake/artifact bindings when used. Keep research evidence outside production report sets. Never install on the host or remove unrelated worktrees/evidence.
