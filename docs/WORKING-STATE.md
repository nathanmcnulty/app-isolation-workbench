# Working state

Updated 2026-09-10. This is a compact handoff, not a run receipt or authorization.

## Where to resume

- Active development branch: `codex/wsb-typed-scenarios`. Locate it with `git worktree list` if this checkout differs. The main checkout has historically been behind this worktree.
- Latest slice: paired ordinary-user/AppContainer file, registry, and child controls, repeated in two fresh Sandboxes. Use `scripts/work-status.ps1` for current HEAD, dirty files, and locally known upstream state.
- Goal: report tested functions for exact application bytes and measured isolation configurations, then use the evidence for adaptation/repackaging. Free community project; feedback collection is not a development gate.

## Implemented versus exploratory

- Production path: protected intake; approved Windows Sandbox execution and recovery; fixed Notepad++ MSI v6 install/open/edit/save/close as a standard user after privileged install. Bound token, runtime, file/registry, stage, failure-snapshot, and MSI ProductCode observations feed retained JSON/Markdown reports and explicit report sets.
- Bambu: separate approved EXE export profile, protected staging, standard-user guest execution, stage/failure result, bounded 3MF graph/geometry verification, and retained JSON/Markdown report. Original `--info` compiler remains metadata-only. See the profile document for production validation and exact evidence.
- Mixed reports: `run report-wsb-set` combines verified MSI and Bambu results with distinct function columns, failures/unavailable entries, and verified-identity deduplication. The retained regression checks deterministic output and unchanged workspace inventories.
- Development control: paired file/registry reads and descendants passed in two fresh workers. Token, value/DACL, process/profile, and worker cleanup bindings passed. Version 2 rejects 30 altered records; historical file-only records stay unmeasured for registry. See CONTROL-FIXTURE.md. Research controls remain excluded from production application reports.
- No application-level baseline/candidate isolation comparison or reusable repackaging capability is complete. Outer Sandbox containment is distinct from an inner application boundary.

## Next coherent slice

Start the first packaging capability: a versioned Sandbox bundle for an existing approved typed profile (Notepad++ MSI first). Bind payload hashes, fixed scenario, runtime/data contract, and evidence references. Import/replay must reject drift, use normal preparation and fresh approval, and pass a fresh-worker trial before a validated claim. No arbitrary command/script metadata. AppContainer approved reporting and real-application comparison remain separate follow-ups; they do not block a Sandbox bundle. No inner network restriction or host-launch/reusable package capability is yet complete.

## Read only what the slice needs

- [Execution control and retained proof](CONTROL-FIXTURE.md): fixed fixture, driver, normalizer and negative tests.
- [Bambu profile and actual research results](BAMBU-STUDIO-PROFILE.md): hashes, exact command, limitations, retained research location.
- [Roadmap](ROADMAP.md): benchmark completion criteria and later isolation/adaptation work.
- [Report sets](REPORT-SETS.md), [assessment reports](ASSESSMENT-REPORT.md): existing verified reporting contracts.
- [Notepad++ fixture](FIXTURE-NOTEPAD-PLUS-PLUS-8.9.8.md), [MSI ProductCode observation](MSI-PRODUCT-REGISTRATION.md): existing live controls and retained evidence.
- Code entry points: provider `scenario.rs`/`bambu_export.rs`/`imported_bambu.rs`/`bambu_artifact.rs`; runner `preparation.rs`/`lib.rs`/`bambu_report.rs`/`application_report_set.rs`/`report_set.rs`; guest-agent `main.rs`; native `guest_bambu.rs`/`guest_standard_user.rs`.

## Operational constraints

Use local checks first and CI sparingly. Push completed authorized changes; avoid incidental workflow triggers. Installer corpus is locally available in `%USERPROFILE%\Downloads\installers`; original files are not execution authority. Reverify retained intake/artifact bindings when used. Keep research evidence outside production report sets. Never install on the host or remove unrelated worktrees/evidence.
