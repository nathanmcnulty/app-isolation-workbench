# Focused foundation and product review

Reviewed baseline: `daa6b0f` (PR #65 merge). This is a bounded source/evidence
review, not a penetration test or a general isolation certification. Subsequent
dependency changes on main are outside this baseline and have their own CI.

## Decision

Continue to the administrator workflow milestone after correcting the preflight
guidance below. No other production blocker was found in the inspected paths.
Do not expand providers or general packaging yet. The useful product outcome is
an operator completing assessment, understanding its limits, and replaying a
reviewed recipe without developer assistance. Repeated successful fixture runs
are evidence for that fixture, not a substitute for the operator trial.

## Findings and disposition

| Finding | Disposition |
|---|---|
| P2: preflight advised importing an unbound preparation as though it bound the checked profile | Corrected `nextStep` to require a matching embedded profile hash. Missing or different bindings direct the operator to fresh preparation with both profile arguments. Profile Markdown now explains the same distinction. Regression covers absent, different, and matching bindings. |
| P2: roadmap ordering contradicted the preview gates and still labelled implemented work as next | Made the administrator preview sequence authoritative, separated Workbench distribution from later application conversion, and added concrete operator success/failure acceptance cases. Corrected the stale assessment report schema reference. |
| Integration checks were not enforced by repository settings | Read-only GitHub inspection reported main unprotected with no required checks. CONTRIBUTING now requires explicit successful named checks for the final head before merge; automatic merge is not a substitute. Repository-level enforcement remains an administrator follow-up; this review did not change access/settings. |
| Intermittent local test setup/executable failures have no confirmed cause | Preserve existing logs and the crashing executable. The relinked suite, fresh profile tests, and PR #65 hosted suite passed. No retry loop or ignored test was added to hide failure. Capture binary hash, exit status, toolchain/OS, TEMP root, and event/crash evidence if it recurs before retrying. |

## Inspected boundaries

- Preparation validates the profile hash and retained comparison, binds the
  embedded profile into receipt/derived plan disclosures, and checks application,
  project, scenario, agent, requested configuration, provider, and recorded OS.
  Existing negative tests reject stripping, substitution, and downgraded required
  observations. A new ordinary plan requires different approval; it cannot reuse
  the old profile-bound approval.
- Approved start verifies the bound profile before native provider acquisition.
  Recovery remains independent of profile availability so lost source evidence
  cannot prevent exact-session cleanup. It does not gain permission to stop an
  unrelated session. An independent reviewer inspected these paths separately.
- Historical report reconstruction uses recorded preparation/plan/evidence
  bindings and does not reopen source trials or substitute today's provider/OS.
  Profile identity is historical association, not current execution authority.
- The MSI Markdown report separates function observations from broader missing
  evidence. Its `insufficientEvidence` result is intentional, not a failed
  document workflow. The next admin summary must make this distinction easier to
  understand without altering underlying verdicts. Guest-admin installer behavior
  is not independently attested host containment.
- The local check driver uses a short isolated test TEMP, restores caller state,
  records per-check output/exit status, and prints failed logs into hosted output.
  These diagnostics support investigation but do not explain the preserved native
  failures by themselves. No cleanup or installer rerun was needed for this review.

## Validation and limits

PR #65's hosted `Verify and audit` and `Minimum supported Rust` both passed
([run 35491037862](https://github.com/nathanmcnulty/app-isolation-workbench/actions/runs/35491037862)).
Its main-branch run was cancelled by later pushes; it must not be reported as a
pass. The preceding full local suite passed 518 tests with 26 explicit skips and
the fresh approved Sandbox trial passed its fixed checks. Those results belong
to their recorded revisions, not automatically to every later dependency update.

The review fix uses focused profile regressions and retained preflight evidence;
it changes advice, not approval, execution, or recovery semantics. No fresh
Sandbox trial is warranted for this output-only correction.

All four focused profile tests passed, along with CLI build, warnings-as-errors
clippy, formatting, and governance. The retained unbound preparation returned
the corrected guidance; all 75 original source files kept their hashes. Proof:
`%LOCALAPPDATA%\Temp\aiw-quality-review-d5f6001515a84eb183037c78036fbbaf`.
Check logs:
`%LOCALAPPDATA%\Temp\aiw-local-checks-962b32ed-bc98-4993-bd2e-b181dc0dae44`.
The first offline CLI build lacked the already-locked clap 4.6.7 crates; downloading
those exact dependencies allowed the build to pass without lockfile changes.

One meaningful coverage gap remains: there is no direct acquisition-free
integration test proving that drift discovered at approved start returns before
native provider acquisition. Helper/binding tests and source ordering currently
cover this boundary. Add that regression before changing the start/acquisition
boundary; do not introduce a parallel execution abstraction solely for this review.

## Next milestone and stopping rule

Complete the [administrator acceptance cases](RELEASE-GATES.md#administrator-milestone-acceptance-cases),
then stop for the clean-host/second-operator trial. Record unsupported inputs,
setup failures, evidence gaps, data lifetime/export, and actionable recovery as
part of the product. Same-host profiles require accessible original evidence;
cross-host use must revalidate rather than silently relax path or OS checks.

Do not call this a general compatibility scanner or universal packager. After
the preview loop works, select the next application from a concrete admin need
and use that workflow to judge whether the abstractions generalize. Further
foundation work should name the operator task or asserted boundary it enables.
