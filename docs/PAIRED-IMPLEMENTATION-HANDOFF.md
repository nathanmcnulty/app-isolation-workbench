# Offline implementation handoff

For the current checkout and native follow-up, start with
[working state](WORKING-STATE.md) and the
[source-pinned native record](PAIRED-NATIVE-APPROVAL.md). The
[acceptance audit](RESULTS-ACCEPTANCE-AUDIT.md) distinguishes implemented, fake-only
and native-verified paths and records the current access limitation. The evidence below is
historical and retains its recorded source/scope; it is not a current native
acceptance claim. The earlier source3b diagnostic localizes the mapped-input FileIdInfo
blocker; six native cases remain unmeasured.

Earlier follow-up: source `2ec65edfe749b73a13ddf0c923db973de1292fc8` improves
approval-without-dispatch reporting and adds a read-only Results backend example.
One subsequently approved VM107 Start stopped at required provider-list preflight,
before any control case. Actual retained exports correctly preserve all six cases
as unmeasured. See [the attempt record](PAIRED-NATIVE-ATTEMPT.md) for exact native
and backend evidence and the remaining positive acceptance gate. The baseline
offline results below retain their original source/scope; unchanged suites were
not rerun or represented as new full-suite results for this follow-up.

Completed offline implementation and validation on 2026-10-30. Native acceptance remains open.

Code commit: `e2e44fe2bf3ca98113618131f4f6d8700354219f`.
Base: main `53c02c8dfd367b7b12ff4c167e99fd03b9e1dcf1`, including merged PR #103.
Branch: `codex/paired-controls`; local only. No PR was created or submitted.

## Delivered behavior

Results opens 1–32 explicit retained assessments through existing shared verifiers,
with a 1 MiB selection limit, no recursive disk discovery and no new verdict
engine. Filters compare application, workflow, outcomes and tested functions.
Expandable rows show failed/not-reached stages, evidence status/gaps and inert
hash references. Historical cleanup remains a separate column. Application-wide
compatibility and effective isolation remain unmeasured, including successful
fixed paired controls.

Local JSON/Markdown exports serialize only the backend-owned allowlisted summary,
bind the current snapshot token and exclusively create a new file outside held
retained locations. They exclude raw artifacts, credentials, account/run IDs,
absolute private paths and raw tokens. Existing files are never overwritten.
Missing, unavailable, rejected, duplicate, partial and unsupported reports stay
explicit. Opening/filtering/exporting cannot execute, cancel, recover or write a run.

Fixed paired controls reuse the shared runner, authority, lease, approval,
journal, session and recovery services. The desktop exposes preparation, immutable
review, exact approval, separate Start, progress, owned cancellation and exact
recovery. Static preparation makes no provider invocation; runtime checks are
deferred until approved Start. Input/provider/source drift and stale approvals
fail closed. No arbitrary executable/script route was added. Synthetic records
cannot acquire a native recovery provider.

## Acceptance evidence

| Requirement | Evidence |
|---|---|
| Mixed applications, failure/not reached/unmeasured, partial and unknown cleanup | Actual ResultsStore projection tests and mixed labeled preview; original reviewed archive plus synthetic MSI/Bambu/paired examples |
| Missing/tampered evidence and duplicates | Real retained verification/report-set tests and protected synthetic coupled fixtures; no copied successful measurements on rejected rows |
| Hostile text and limits | Rust strict schema/hash/path/size/entry tests, allowlist sentinel tests and Node textContent/bidi/control-text tests |
| Export collisions, I/O failures and retained exclusion | Actual exclusive writer tests, held-source rename/containment tests, JSON/MD determinism and byte comparisons |
| Repeated clicks and out-of-order loads | Backend busy/token guards, UI single-flight/epoch tests, stale polling and cancellation/recovery regressions |
| Exact gates and no unapproved dispatch | Coupled production admin/kernel tests with closed fake process/lease and synthetic receipts; actual distinct review and Start gates |
| Drift, invalid denied codes, missing resources, tamper, duplicate/out-of-order receipts, broken driver | Coupled eight-case evidence matrix plus runner/provider/guest contract tests |
| Cancellation/interrupted dispatch, unknown cleanup, exact recovery | Actual owned cancellation service with committed-publication handshake; real kernel journal/session and strict fake recovery sequence |
| Unchanged retained inputs and zero real native calls | Whole owned-tree byte snapshots and unchanged fake-boundary call counts across repeated retained reads; explicit synthetic markers, no native acquisition in rehearsal |
| Keyboard and focus | Browser approval/Start/progress/completion/Results drill-down proof; transition focus tests, no steady-poll focus stealing |
| Independent review | Existing `results_review` agent source-reviewed authority, comparability, interpretation, recovery, static preparation, UI/export and test seams; findings fixed, final disposition no consequential issue |

Review was source-only, not an independent native trial. Resolved findings include
pending approval authority, malformed prefix/token provenance, copied-workspace
recovery binding, preparation provider invocation, staged-file custody, stale UI
failures, loopback preview privacy and unmeasured-prefix wording. The first final
workspace attempt exposed a synthetic cancellation-publication race; the corrective
commit adds a test-only stable-publication handshake without relaxing production
journal checks. Failed attempt: `C:/aiw/paired-final-root.json`; focused corrected
pass: `C:/aiw/paired-final-cancel-fix.log`.

## Final validation

- Workspace Rust: **678 passed, 0 failed, 27 opt-in ignored**, across 42 library,
  integration and documentation suites. Workspace all-target Clippy with warnings
  denied, format and governance all passed. Structured result:
  `C:/aiw/paired-final-root-fixed.json`; complete logs:
  `C:/Users/labadmin/AppData/Local/Temp/aiw-local-checks-8f0c4532-696b-4439-a8da-9a3c08b5b35c/`.
  Code remained unchanged at `e2e44fe` throughout; subsequent changes are handoff
  documentation only. Initial failed attempt remains recorded separately above.
- Desktop Rust: 20 passed, 0 failed, 4 explicitly opt-in ignored;
  `C:/aiw/paired-final-gui-fixed-tests.log`. Desktop all-target Clippy with warnings
  denied and format passed (`paired-final-gui-fixed-clippy.log`).
- Node: 28 passed, 0 failed; `C:/aiw/paired-final-node.log`.
- Seven UI/preview JavaScript syntax checks passed;
  `C:/aiw/paired-final-node-syntax.log`. No separate JS linter is configured.
- Offline desktop binary build passed; `C:/aiw/paired-final-gui-build.log`.
  Binary: `C:/aiw/app-isolation-workbench/gui/target/debug/aiw-desktop.exe`.
- Read-only compiled control-source identity matched the source pin;
  `C:/aiw/paired-final-control-source.json` (no provider invocation).
- Explicit final Controller/ResultsStore replay producer: 1 passed;
  `C:/aiw/paired-final-ui-demo.log`.
- Debug static-CRT x64 guest-agent build and PE import checks passed;
  `C:/aiw/paired-final-agent-build.json`. Agent was never executed.

## Demonstration and safe outputs

Final actual Controller/ResultsStore output:
`C:/aiw/paired-ui-replay-67b71f99-4d79-4a8e-9203-fc92b45eb68e`.
`verified-summary.json` and `.md` are the actual safe exports. `workflow-demo.json`
is an explicitly synthetic local test DTO with review details, **not** a safe
summary export. Source fixture:
`C:/Users/labadmin/AppData/Local/Temp/aiw-paired-service-16064-1`.

Browser proof from the same UI slice:
`C:/aiw/paired-ui-replay-eb704d10-26ea-40e5-b00d-ff9278f35e84/` —
`separate-start-keyboard.png`, `running-focus.png`, `results-keyboard.png`.
The persistent banner says SYNTHETIC/UI REPLAY/NO PROVIDER BACKEND. Browser clicks
replay snapshots only; actual coupled Rust services produced retained records and
exports separately. The later final projection has clearer application-gap scope;
the original Results screenshot predates that wording. The browser connection
became unavailable when attempting a refreshed final preview; final Rust producer,
projection and Node checks passed. Preview servers were stopped after proof.

Mixed-app failure proof and generated summaries:
`C:/aiw/results-explorer-160bf207-6a83-48be-b235-07f37d20b6c9`.
Paired valid/unknown-cleanup/duplicate filtered proof:
`C:/aiw/results-explorer-2d01aa1d-5314-46cb-9754-503e839094b5`.
See [Results usage](RESULTS-EXPLORER.md) and
[workflow/reproduction notes](paired-product-workflow.md).

## Remaining limits

The new native guest/provider/control workflow was not trialed. Held local file
inspection of Sandbox Tools mappings requires separately authorized disposable-worker
proof; fail closed if unsupported. No independently enrolled new desktop package
receipt/provider identity was available, so there is no invented launch-ready
package enrollment. Real production retained workspaces were not selected; safe
historical archive evidence and clearly labeled synthetic fixtures were used.
A human screen-reader usability study was not performed.

No live VM, Sandbox, AppContainer, application or control trials; authentication;
host security/grant changes; dependency installation; signing; push; publication;
PR creation; merge or release. PR #103's trials were not repeated. No general
compatibility/isolation claim, Benchmark 2/W4/W5 closure or production acceptance.
The local implementation and offline acceptance are distinct from those open gates.

[Future native proposal](PAIRED-NATIVE-ACCEPTANCE-PROPOSAL.md) ·
[Draft PR text](PAIRED-DRAFT-PR.md)


## Exact local review bundle

`C:/aiw/paired-offline-handoff-c8ba6388-8e37-4916-87ad-0b00e9a04cdd`
contains `implementation.patch`, `commits.txt`, `diff-stat.txt` and
`manifest.json` for the final reviewed code and documentation. The patch spans main
`53c02c8` through the final local handoff commit. The manifest pins the final
commit, patch SHA-256 and deterministic safe summary hashes. This review bundle
is local engineering evidence, not a Results allowlisted summary export.


The offline goal is complete. The final local documentation commit is recorded in
`commits.txt` and `manifest.json`; it adds no runtime changes. Review the patch
locally. No push, PR submission, native trial or acceptance gate is implied.
