# Working state

Updated 2026-09-10. This is a compact handoff, not a run receipt or authorization.

## Where to resume

- Active development branch: `codex/wsb-typed-scenarios`. Locate it with `git worktree list` if this checkout differs. The main checkout has historically been behind this worktree.
- Latest slice: project-owned execution controls, repeated in two fresh Sandboxes. Use `scripts/work-status.ps1` for current HEAD, dirty files, and locally known upstream state.
- Goal: report tested functions for exact application bytes and measured isolation configurations, then use the evidence for adaptation/repackaging. Free community project; feedback collection is not a development gate.

## Implemented versus exploratory

- Production path: protected intake; approved Windows Sandbox execution and recovery; fixed Notepad++ MSI v6 install/open/edit/save/close as a standard user after privileged install. Bound token, runtime, file/registry, stage, failure-snapshot, and MSI ProductCode observations feed retained JSON/Markdown reports and explicit report sets.
- Bambu: separate approved EXE export profile, protected staging, standard-user guest execution, stage/failure result, bounded 3MF graph/geometry verification, and retained JSON/Markdown report. Original `--info` compiler remains metadata-only. See the profile document for production validation and exact evidence.
- Mixed reports: `run report-wsb-set` combines verified MSI and Bambu results with distinct function columns, failures/unavailable entries, and verified-identity deduplication. The retained regression checks deterministic output and unchanged workspace inventories.
- Development control: fixed document/read/denial/missing/child/failure cases passed twice with configuration/provider bindings and nine retained negative checks. See CONTROL-FIXTURE.md. These research records are excluded from production application reports.
- No application-level baseline/candidate isolation comparison or reusable repackaging capability is complete. Outer Sandbox containment is distinct from an inner application boundary.

## Next coherent slice

Use the proven project-owned control for a bounded AppContainer candidate trial inside a disposable worker. Keep the ordinary standard-user baseline and exact resource/fixture/environment bindings; verify both root and child AppContainer tokens, a successful baseline read, and native candidate denial for the same resource. The existing admin-only ACL denial is a negative control, not that isolation comparison. Integrate approved execution/reporting before promoting control observations into production assessments. Real-application repeatability remains open. Reuse retained evidence for reporting checks; a report change does not require another installation. No slicing/printer/cloud support is implied.

## Read only what the slice needs

- [Execution control and retained proof](CONTROL-FIXTURE.md): fixed fixture, driver, normalizer and negative tests.
- [Bambu profile and actual research results](BAMBU-STUDIO-PROFILE.md): hashes, exact command, limitations, retained research location.
- [Roadmap](ROADMAP.md): benchmark completion criteria and later isolation/adaptation work.
- [Report sets](REPORT-SETS.md), [assessment reports](ASSESSMENT-REPORT.md): existing verified reporting contracts.
- [Notepad++ fixture](FIXTURE-NOTEPAD-PLUS-PLUS-8.9.8.md), [MSI ProductCode observation](MSI-PRODUCT-REGISTRATION.md): existing live controls and retained evidence.
- Code entry points: provider `scenario.rs`/`bambu_export.rs`/`imported_bambu.rs`/`bambu_artifact.rs`; runner `preparation.rs`/`lib.rs`/`bambu_report.rs`/`application_report_set.rs`/`report_set.rs`; guest-agent `main.rs`; native `guest_bambu.rs`/`guest_standard_user.rs`.

## Operational constraints

Use local checks first and CI sparingly. Push completed authorized changes; avoid incidental workflow triggers. Installer corpus is locally available in `%USERPROFILE%\Downloads\installers`; original files are not execution authority. Reverify retained intake/artifact bindings when used. Keep research evidence outside production report sets. Never install on the host or remove unrelated worktrees/evidence.
