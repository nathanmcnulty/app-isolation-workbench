# Application-neutral recovery execution plan

Updated 2026-11-08. [Roadmap milestones R0-R6](ROADMAP.md#current-delivery-sequence)
are the current delivery order; [release gates](RELEASE-GATES.md) define completion.
The [earlier preview packets](EXECUTION-PLAN-HISTORY-2026-11-08.md) are historical,
not current application priorities or execution authorization.

## Resume and choose one coherent slice

1. Run `scripts/work-status.ps1`; read [working state](WORKING-STATE.md) and
   `AGENTS.md`. Verify branch, clean/dirty state and actual remote head before
   editing. Do not overwrite another worktree's unmerged changes.
2. Read the [source migration audit](APPLICATION-AGNOSTIC-MIGRATION.md), relevant
   code and the milestone's acceptance criteria. Update the inventory when a
   proposed mechanism exposes another product-specific call site.
3. Choose one concrete deliverable. The next implementation slice is R1's generic
   plan/capability contract on existing source/scenario/intake concepts, including
   unknown-app and unsupported-operation tests. Do not implement another fixed app.
4. Write the contract, failure semantics and checks before broadening execution.
   Preserve authority/recovery behavior. No schema placeholder counts as runtime
   support; no generic facade over product dispatch counts as migration.

## Bounded implementation packets

- **R1:** inspectable versioned generic plan, mechanism capabilities, reviewed
  discovery and explicit unsupported outcomes. Use inert contract/negative tests.
- **R2:** one generic installer/portable and normal-use worker path; extract native
  safety mechanisms; prove the driver with project-owned controls; then authorized
  real-app slices with durable evidence and cleanup.
- **R3/R4:** paired comparable evidence and shared GUI/CLI/report services. Implement
  the UI alongside stable operations, not after all provider research. Keep results
  read-only and historical semantics unchanged.
- **R5:** corpus/holdout acceptance, retirement of superseded product execution and
  AIW-only release inventory. Complete deletion and non-vacuous generality proof.
- **R6, when useful:** reviewed adaptation/replay/packaging. It is not a prerequisite
  for the first assessment milestone and cannot reopen vendor distribution.

## Integration and validation

One writer owns a checkout; use independent review for consequential changes and
inspect an exact stable head. Follow the active user-requested agent arrangement
rather than historical model prescriptions. Batch related reads and keep full logs
on disk. Run applicable checks once on the completed slice, repeating only for
changes, failures or unresolved concerns. Do not install dependencies, authenticate,
start live trials or alter provider/VM setup based solely on this plan.

Documentation-only changes use link/content/governance checks. Runtime/trust-boundary
changes need negative tests and approved disposable-worker proof in addition to
applicable Rust/desktop/Windows checks. Missing native prerequisites are blockers,
not permission for host execution. Use retained evidence for presentation changes.

Before integration, verify actual remote/base/head state, preserve concurrent work,
address independent findings and pass required `Verify and audit` and `Minimum
supported Rust` checks for the exact head. Do not bypass checks or relabel local
static validation as hosted acceptance. Publication requires separate release gates.

After each meaningful milestone, replace stale [working state](WORKING-STATE.md)
with concise current status, completed checks, exact evidence pointers and the next
bounded action. Do not duplicate history or leave completed implementation as a
future task. Preserve incomplete and failed evidence.
