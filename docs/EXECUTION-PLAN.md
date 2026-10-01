# Model-aware execution plan for the administrator preview

This implements the ordering in ROADMAP.md and the acceptance cases in
RELEASE-GATES.md; it does not add a new release roadmap. Model assignments below
are project recommendations, not measured cost or quality guarantees.

## Starting point

Run `scripts/work-status.ps1`, then read WORKING-STATE.md. The administrator
preview packets below have been implemented; PR #71 integrated the final
profile-bound clean-host evidence at `4b9054512213c64839a664997504a84d7c911cdb`.
Use WORKING-STATE and ROADMAP for the current bounded slice. Do not rebuild
completed work from the historical commit references below.

Use **Sol, medium** for the main task. It owns integration and the milestone.
Use **Luna, medium** for a bounded implementation with an explicit contract,
and **Terra, medium** when a task needs judgment across several files. Use Sol
at high effort for consequential trust-boundary reviews. Astra is an optional
architecture checkpoint when a concrete unresolved design risk warrants it;
it is not the default coordinator, tester, log reader, or progress monitor.

Explicitly select worker model and effort. With this session's delegation tool,
use a short standalone brief (`fork_turns: none`) instead of copying the complete
conversation. Do not dispatch a second agent unless independent work actually
helps. One writer owns a checkout; reviewers inspect an exact commit. Normally
use one worker, with one independent reviewer only when warranted.

## Ordered work packets

### 1. Closed: terminal approval review

Inspect `5766a55` against its parent, especially
`crates/aiw-cli/src/approval_review.rs`, the `ReviewApproval` command in `main.rs`,
and its CLI contract test. Check terminal visibility, exact-hash confirmation,
escaped display, cancellation, error reporting, and service validation if a plan
changes during review. Read ADMIN-APPROVAL.md for retained proof and local logs.

Sol's exact-commit review found no actionable issue. It confirmed the display,
confirmation, cancellation, terminal, and service-side validation boundaries.
The documented missing pseudo-terminal/race harness was not judged a blocker.

### 2. Make retained assessment results understandable — Luna, medium

Deliver a concise administrator overview in the existing MSI Markdown report,
using the already verified typed report. Start with
`crates/aiw-runner/src/assessment_report_markdown.rs`, `assessment_report.rs`,
and the report tests; read ASSESSMENT-REPORT.md. Avoid a second verdict engine,
new evidence schema, or caller-supplied JSON accepted as trusted evidence.

The overview must answer: which application bytes/workflow were tested, which
functions passed/failed/were not reached or measured, which boundaries were
measured, whether cleanup was recorded, and the safe next action. Separate a
passing document workflow from `insufficientEvidence` for broader isolation.
Do not infer application version from a filename, dependency from a changed file,
or containment from requested settings. Keep detailed evidence available below.

Acceptance: completed, unsuccessful/interrupted, and historical missing-evidence
examples remain truthful; output suggests an appropriate next step for each.
Verify against retained runs described in VALIDATED-SANDBOX-LAUNCH.md and failure
fixtures in existing report tests. Test semantic misclassification cases, not
every heading. No installer rerun for formatting. Terra can review the exact diff
if interpretation or multiple report paths change; otherwise Sol integrates it.

### 3. Closed: connect the supported operator workflow

`aiw admin assess` now
owns protected intake through retained report, displays the complete verified
recipe before exact-plan terminal approval, and selects assessment or
profile-bound replay only from package assets. Project, guest, and optional
profile identities are package-bound. `scripts/build-preview-package.ps1`
produced the profile-bound package and receipt. The public-entry trial completed
as run `admin-1789947096248087800`: operator approval, installation, launch,
fixed document save, required guest ACL control, report publication, and exact
cleanup all passed. The retained report keeps broader isolation as
`insufficientEvidence`. Occupied Sandbox, unsupported input, cancellation, and
profile/package drift have specific retained or tested failure paths.

Deliver a single documented CLI entry path for supported Notepad++ assessment
and replay. Before editing, write a short command/state contract in the existing
admin guide: operator inputs, read-only checks, durable stage outputs, review
point, explicit approval, execution, report, and failure/recovery next steps.
Then implement that contract through existing services. Do not build a general
wizard framework, shell-command runner, or persistent service.

Operator inputs are installer, output/evidence location, and operator identity;
supported fixed project/scenario and packaged agent identity come from verified
product-owned assets. The operator must not need developer TEMP paths, raw
approval JSON, a compiler, or guessed runtime flags. Select supported bytes only
through existing profile/compiler constraints; unsupported input stays unsupported.
Show recipe and ephemeral data/export behavior before approval. Preserve exact
profile and per-run approval binding; never repair or retry a failed worker
implicitly. Existing stages/results remain the source of resume information.

Acceptance: the documented route reaches a verified report and approved replay;
missing prerequisite, occupied Sandbox, unsupported input, cancellation, failed
attempt, and profile drift produce specific safe next steps. Use fixed controls
and negative tests before one authorized disposable-worker trial. Sol high reviews
changes crossing approval, provider acquisition, retained authority, or recovery.
If those primitives need redesign, stop that packet and explain the concrete gap.

### 4. Closed: validate the complete administrator milestone

Follow RELEASE-GATES.md's acceptance cases through the actual public entry path,
not a development-only driver. Luna can prepare documentation or inspect retained
outputs as a separate bounded task; the coordinator owns the live worker.
Preserve diagnostic evidence and recorded exact cleanup. Do not repeat successful
installation to validate report edits. Fix reproducible failures, then run only
the affected proof again. The milestone closes only when the operator loop works;
an individual command or added document does not close it.

Create one integration PR for the coherent milestone, after local validation.
Review the exact head and require successful `Verify and audit` and `Minimum
supported Rust` before merging. Commit and push stable intermediate work without
creating PRs or triggering CI just to preserve it.

The packaged entry path completed on 2026-09-20 with retained evidence linked
from ADMINISTRATOR-WORKFLOW.md. Its integration PR and required hosted checks
passed. Packet 5 followed on the separate supported VM.

### 5. Closed: clean-host preview

Package exact CLI/guest builds and supported assets with identities, prerequisite
detection, acquisition instructions, data contract, and limitations. Reuse pinned
components; do not silently fetch arbitrary latest executables. A second operator
must complete the documented loop on the declared supported host without a coding
assistant. Recreate validation on that host where required; copying same-host
evidence paths does not validate deployment. This is the release gate, not a
request to complete generic MSI/MSIX conversion or all isolation providers.

Archive mode requires clean committed source, exact retained guest and profile,
verifies identities and inventory, and emits a ZIP plus companion distribution
manifest. The second operator freshly extracted the exact `08ab440` candidate
on the separate supported VM and completed the fixed workflow, negative control,
and cleanup. See [CLEAN-HOST-PREVIEW.md](CLEAN-HOST-PREVIEW.md) for the retained
acceptance record. PR #71 is merged. The package remains an
unsigned development preview; this packet did not prove general MSI conversion
or effective host containment.

## Escalation and quota discipline

- Keep worker briefs to outcome, exact base, owned files, invariants, acceptance
  checks, and prohibited expansion. Workers return changed files, check results,
  evidence paths, and unresolved questions. Do not restate the entire history.
- One build owner per target; keep full logs on disk and return a small summary.
  Reuse already completed checks for their exact revision, not as a blanket cache.
- After two unsuccessful approaches to the same blocker, stop speculative edits
  and give Sol/Terra the reproduction and evidence. Escalate to Astra only for an
  unresolved architectural/trust-boundary decision, with a specific question.
- A model or effort change is not permission to relax requirements. Missing
  evidence remains unmeasured; failed setup is not application incompatibility.
- Do not send every small diff through multiple models. Do not add tests that
  merely repeat implementation. Do not keep Astra running solely to wait on CI.
- End each packet with a commit/push and a short handoff. Continue independent
  work when useful, but do not expand the release scope to fill waiting time.

## Ready-to-use continuation brief

> Start with work-status and WORKING-STATE. Integrate the exact-head clean-host
> PR only after its required checks. The five administrator preview packets are
> complete; preserve their retained evidence and explicit unsigned/isolation
> limits. Follow ROADMAP.md for the next bounded application benchmark. Use one
> writer and proportional checks, and escalate a concrete blocker instead of
> rebuilding the foundation.
