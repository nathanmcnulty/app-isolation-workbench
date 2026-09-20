# Working state

Updated 2026-09-20. This is a compact handoff, not a run receipt or authorization.

## Where to resume

- Active branch: `codex/admin-assessment-summary`, based on PR #66 merge `6f19136`. PR #66 merged only after hosted verification/audit and MSRV passed. Use the status helper rather than assuming another checkout has these changes.
- Latest milestone: profile-bound approved replay passed the fixed document workflow, required guest file ACL controls, recorded environment comparison, and cleanup. PR #65 hosted verification/audit and MSRV passed; its main run was superseded and cancelled. Source evidence and the earlier worktree remain preserved. See VALIDATED-SANDBOX-LAUNCH.md.
- Goal: report tested functions for exact application bytes and measured isolation configurations, then use the evidence for adaptation/repackaging. Free community project; feedback collection is not a development gate.

## Implemented versus exploratory

- Production path: protected intake; approved Windows Sandbox execution and recovery; fixed Notepad++ MSI v6 install/open/edit/save/close as a standard user after privileged install. Bound token, runtime, file/registry, stage, failure-snapshot, and MSI ProductCode observations feed retained JSON/Markdown reports and explicit report sets.
- Bambu: separate approved EXE export profile, protected staging, standard-user guest execution, stage/failure result, bounded 3MF graph/geometry verification, and retained JSON/Markdown report. Original `--info` compiler remains metadata-only. See the profile document for production validation and exact evidence.
- Mixed reports: `run report-wsb-set` combines verified MSI and Bambu results with distinct function columns, failures/unavailable entries, and verified-identity deduplication. The retained regression checks deterministic output and unchanged workspace inventories.
- Development control: paired file/registry reads and descendants passed in two fresh workers. Token, value/DACL, process/profile, and worker cleanup bindings passed. Version 2 rejects 30 altered records; historical file-only records stay unmeasured for registry. See CONTROL-FIXTURE.md. Research controls remain excluded from production application reports.
- Packaging: `package export-wsb-msi`, `package verify`, and `package import` carry exact MSI bytes and a fixed recipe, with an independently supplied manifest hash. Replay passes the existing standard-user document workflow and report checks. Both the automated assessment recipe and approved scratch-only interactive launch are supported. The transfer profile accepts one bounded text input and offers explicit receipt-bound export; persistent data, MSI/MSIX conversion, and application-level baseline/candidate isolation comparison remain open. Outer Sandbox containment is distinct from an inner application boundary.

## Next coherent slice

Follow [EXECUTION-PLAN.md](EXECUTION-PLAN.md) for bounded work packets and model
assignments. Recommended main model: Sol medium; Luna for bounded implementation;
stronger models for specific review/escalation. The exact-commit Sol review of
terminal approval found no actionable issue. Next add the administrator summary,
then the guided workflow.

Approved profile replay passed at runtime commit `fc22efb`: preparation v0alpha6
embeds the reverified profile, approval binds its exact identity, and start
re-verifies source evidence before acquiring Sandbox. A fresh fixed trial passed
document save, local settings, required standard-user file ACL controls, matching
recorded provider/configuration/OS, and cleanup. Report v0alpha11 identifies the
approved profile. The provider list was empty afterward. See
[VALIDATED-SANDBOX-LAUNCH.md](VALIDATED-SANDBOX-LAUNCH.md) for exact evidence and
validation logs, including the preserved pre-harness executable crash.

The [focused quality review](QUALITY-REVIEW-2026-09-20.md) found and corrected
misleading preflight advice for unbound/differently bound preparations. No other
production blocker was found in the reviewed authority, historical report, or
recovery paths. Test/build failure causes remain unconfirmed; retained diagnostics
and the missing direct start-before-acquisition regression are tracked in the review.

The first administrator improvement adds [terminal approval review](ADMIN-APPROVAL.md):
show the exact plan and approval identity, require the displayed hash, and record
through the existing service without a hand-authored approval file. Cancellation
does not approve or execute anything; redirected input is rejected.

The retained MSI Markdown report now starts with an administrator overview for
exact application bytes and the fixed workflow. It separates function results,
measured observations, cleanup, and broader missing isolation evidence, then
gives a state-specific next action. Retained completed and controlled-failure
workspaces rendered correctly without changing their files. See
[ASSESSMENT-REPORT.md](ASSESSMENT-REPORT.md).

The packaged `aiw admin assess` route now composes protected intake, preparation,
visible recipe review, exact-plan terminal approval, execution, and retained
JSON/Markdown reporting. Product assets bind the fixed local-settings project,
static guest, and optional approved replay profile. A real profile-bound preview
package was assembled with a receipt; no Sandbox was run for that assembly.
Next: exercise the remaining [administrator workflow acceptance cases](RELEASE-GATES.md)
through that public package, then the clean-host/second-operator trial. Broader
AppContainer research and application conversion do not block the narrow preview.

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
