# Working state

Updated 2026-09-26. This is a compact handoff, not a run receipt or authorization.

## Where to resume

- Active branch: `codex/clean-host-preview` at `3e04f1b`, pushed and clean at the last check. PR #68 merged the earlier preview package at `9c7cb4c`; five later branch commits have not been integrated. Verify with `scripts/work-status.ps1` before editing.
- Current gate: a separate-host administrator trial. The v4 assessment reached the guest MSI installation, timed out at its fixed 120-second deadline, retained a failed report, and cleaned up its exact Sandbox session. The reason the MSI did not finish within that bound is unconfirmed. The v6 assessment-only package uses a separately versioned 300-second install bound and is staged on the clean-host VM. Its evidence directory was empty on 2026-09-26; the operator trial has not been recorded. See [CLEAN-HOST-PREVIEW.md](CLEAN-HOST-PREVIEW.md).
- The earlier profile-bound approved replay passed its fixed document workflow, required guest file ACL controls, recorded environment comparison, and cleanup. That remains same-host evidence for its recorded source and provider identities. See [VALIDATED-SANDBOX-LAUNCH.md](VALIDATED-SANDBOX-LAUNCH.md).
- Goal: report tested functions for exact application bytes and measured isolation configurations, then use the evidence for adaptation/repackaging. Free community project; feedback collection is not a development gate.

## Implemented versus exploratory

- Production path: protected intake; approved Windows Sandbox execution and recovery; fixed Notepad++ MSI v6 install/open/edit/save/close as a standard user after privileged install. Bound token, runtime, file/registry, stage, failure-snapshot, and MSI ProductCode observations feed retained JSON/Markdown reports and explicit report sets.
- Bambu: separate approved EXE export profile, protected staging, standard-user guest execution, stage/failure result, bounded 3MF graph/geometry verification, and retained JSON/Markdown report. Original `--info` compiler remains metadata-only. See the profile document for production validation and exact evidence.
- Mixed reports: `run report-wsb-set` combines verified MSI and Bambu results with distinct function columns, failures/unavailable entries, and verified-identity deduplication. The retained regression checks deterministic output and unchanged workspace inventories.
- Development control: paired file/registry reads and descendants passed in two fresh workers. Token, value/DACL, process/profile, and worker cleanup bindings passed. Version 2 rejects 30 altered records; historical file-only records stay unmeasured for registry. See CONTROL-FIXTURE.md. Research controls remain excluded from production application reports.
- Packaging: `package export-wsb-msi`, `package verify`, and `package import` carry exact MSI bytes and a fixed recipe, with an independently supplied manifest hash. Replay passes the existing standard-user document workflow and report checks. Both the automated assessment recipe and approved scratch-only interactive launch are supported. The transfer profile accepts one bounded text input and offers explicit receipt-bound export; persistent data, MSI/MSIX conversion, and application-level baseline/candidate isolation comparison remain open. Outer Sandbox containment is distinct from an inner application boundary.

## Next coherent slice

Run the staged v6 package through its visible desktop launcher with the second
operator. Preserve the terminal output and retained run. Verify the completed
report, the exact guest session cleanup, and the provider's empty session list.
If installation times out again, inspect its bounded diagnostic and stage record
before changing the recipe. Do not treat the longer bound as a demonstrated fix
until a trial finishes. The package is assessment-only; a successful run still
needs a validated profile-bound candidate to close the stated release gate.

After the trial, update [CLEAN-HOST-PREVIEW.md](CLEAN-HOST-PREVIEW.md) with exact
evidence and integrate the five post-PR-#68 commits through a reviewed PR with
the required hosted checks. [EXECUTION-PLAN.md](EXECUTION-PLAN.md) gives the packet
order. Detailed older evidence remains in
[VALIDATED-SANDBOX-LAUNCH.md](VALIDATED-SANDBOX-LAUNCH.md),
[ADMINISTRATOR-WORKFLOW.md](ADMINISTRATOR-WORKFLOW.md), and
[QUALITY-REVIEW-2026-09-20.md](QUALITY-REVIEW-2026-09-20.md).

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
