# Working state

Updated 2026-10-01. This is a compact handoff, not a run receipt or authorization.

## Where to resume

- PR #74 merged at `ad67784809704fa64f4b919b3e6289c63b2a7f3e`. The fixed Bambu administrator entry has an independently approved operator run; verify the current checkout with `scripts/work-status.ps1` before editing.
- The exact unsigned `08ab440` profile-bound package passed the separate-host second-operator trial. Run `admin-1790485297308064300` passed all nine fixed stages, document hash and ACL controls, and terminal cleanup; negative run `admin-1790486242125347900` rejected before intake or provider acquisition. The provider has no active session. The broader isolation outcome remains `insufficientEvidence`. See [CLEAN-HOST-PREVIEW.md](CLEAN-HOST-PREVIEW.md).
- The earlier profile-bound approved replay passed its fixed document workflow, required guest file ACL controls, recorded environment comparison, and cleanup. That remains same-host evidence for its recorded source and provider identities. See [VALIDATED-SANDBOX-LAUNCH.md](VALIDATED-SANDBOX-LAUNCH.md).
- The earlier development baseline/candidate/relocated-replay and agent-run packaged smoke remain separately recorded in [PACKAGING-RECIPES.md](PACKAGING-RECIPES.md) and [CLEAN-HOST-PREVIEW.md](CLEAN-HOST-PREVIEW.md). They are not substituted for the independent operator run.
- Goal: report tested functions for exact application bytes and measured isolation configurations, then use the evidence for adaptation/repackaging. Free community project; feedback collection is not a development gate.

## Implemented versus exploratory

- Production path: protected intake; approved Windows Sandbox execution and recovery; fixed Notepad++ MSI v6 install/open/edit/save/close as a standard user after privileged install. Bound token, runtime, file/registry, stage, failure-snapshot, and MSI ProductCode observations feed retained JSON/Markdown reports and explicit report sets.
- Bambu: separate approved EXE export profile, protected staging, standard-user guest execution, stage/failure result, bounded 3MF graph/geometry verification, and retained JSON/Markdown report. Original `--info` compiler remains metadata-only. See the profile document for production validation and exact evidence.
- Mixed reports: `run report-wsb-set` combines verified MSI and Bambu results with distinct function columns, failures/unavailable entries, and verified-identity deduplication. The retained regression checks deterministic output and unchanged workspace inventories.
- Development control: paired file/registry reads and descendants passed in two fresh workers. Token, value/DACL, process/profile, and worker cleanup bindings passed. Version 2 rejects 30 altered records; historical file-only records stay unmeasured for registry. See CONTROL-FIXTURE.md. Research controls remain excluded from production application reports.
- Packaging: `package export-wsb-msi`, `package verify`, and `package import` carry exact MSI bytes and a fixed recipe, with an independently supplied manifest hash. Replay passes the existing standard-user document workflow and report checks. Both the automated assessment recipe and approved scratch-only interactive launch are supported. The transfer profile accepts one bounded text input and offers explicit receipt-bound export; persistent data, MSI/MSIX conversion, and application-level baseline/candidate isolation comparison remain open. Outer Sandbox containment is distinct from an inner application boundary.

## Next coherent slice

The corrected interactive administrator preview `30231bb` completed its
independent operator trial, run `admin-1790878302241975300`. Exact approval,
Notepad++ install/open/edit/save/close, standard-user token, retained transfer
report, explicit export, original-input preservation, overwrite refusal, and
cleanup passed. The exported 192-byte document contains Nathan's added final
line. An operator-scoped provider query was empty. Exact executable-source
hosted checks passed; verify PR #75's exact-head checks and merge state before
resuming. See [INTERACTIVE-SANDBOX.md](INTERACTIVE-SANDBOX.md).

Next: improve administrator usability around long installation waits and
expected export refusals, using concise guidance with optional details while
preserving complete approval review and receipt-bound results. Public release
also needs a publisher-authentication/signing decision. Generic installer
conversion and broader isolation claims remain outside this preview's proof.
Follow [ROADMAP.md](ROADMAP.md) and [RELEASE-GATES.md](RELEASE-GATES.md); do not
repeat successful installation merely to change reports or guidance.

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
