# Working state

Updated 2026-11-14 (America/Anchorage). Checkout `C:\aiw\app-isolation-workbench`,
branch `codex/multimode-assessment`, from main `b27942a` after #106. Start with
`scripts/work-status.ps1` and [the acceptance map](MULTIMODE-ASSESSMENT.md).
The full three-mode application goal remains active; W4/W5, Benchmark 2 and
production acceptance are incomplete.

Integration includes main `04be2ce` and its application-neutral roadmap, repository
scope and dependency updates. The fixed 7-Zip work below is a bounded legacy
assessment/evidence increment, not the generic engine or a new supported-product
catalog. Follow [the migration audit](APPLICATION-AGNOSTIC-MIGRATION.md) for new
generic work. Keep vendor inputs external; the installer-bundling desktop builder
is retired and desktop publication stays paused. Preserve original evidence and
its exact-source readers. The user-authorized private VM107 trials remain scoped
to this goal; a roadmap is not additional execution authority.

## Current source and evidence

Current reporting work exposes verified execution-coverage summaries in retained
Results and sanitized exports. Receipt admission and the existing request-bound
trace gate precede summary publication; missing summaries stay unmeasured.
Common elevated installation setup is outside the candidate. See
[the implementation status](SEVENZIP-APPLICATION-TRACING.md) and acceptance map.
Reporting checks passed: 137 provider, 7 retained-reader, 27 desktop Rust tests
(4 existing manual/replay cases ignored), all 30 desktop JavaScript tests,
provider/runner and desktop all-target Clippy, format and governance. Independent
review passed before the main integration; independent merge review also passed.
Merged source `d31de7e` passed full local `scripts/verify.ps1` (workspace: 800
passed, 33 ignored, zero failed) and both dependency audits after an initial
advisory-database fetch failure. Audits report zero vulnerabilities with allowed
informational warnings. All three [hosted CI jobs](https://github.com/nathanmcnulty/app-isolation-workbench/actions/runs/43642939286)
passed on PR merge `a49db17` for head `d31de7e` / base `04be2ce`: full verification,
audit, desktop (27 Rust tests, 5 ignored), and Rust 1.88/desktop 1.90 compatibility.
[Draft PR #111](https://github.com/nathanmcnulty/app-isolation-workbench/pull/111)
remains incomplete for native acceptance; private integration logs use prefix
`main-integration-*20261114` below. These checks do not validate an old compiled
payload as this source, run an application trial, or complete the full goal.
A full build drive interrupted the first desktop link; Cargo's
package-scoped development-artifact cleanup enabled a passing retry. No new
application-native acceptance. Private logs/review: `coverage-*20261114*` below.

Frozen release payloads remain source `7fca63e886d45cb3939bbae01d977fd11a997dac`,
shared 24-file source SHA `2301eca7527c764365f6afe6cffa517b764596a180f0e4f69a265f354864250f`.
Locked offline CLI/agent/desktop builds and independent package review passed for
that source. Private package, validation and framing proofs are under
`C:\aiw\sevenzip-execution-20261106`; they do not validate later source changes.

Latest accepted native source is `1d966ca49ab843ad8213152767b6fe037ab3bff9`:
bounded first-party ordinary/classic controls, six paired lifetimes each, exact
empty-job reconciliation, code-5 owner-journal controls and owned cleanup passed.
No vendor application or MXC ran there; physical console-image equivalence is
unproved. Reuse [that native record](SEVENZIP-CODE-CONTROL-NATIVE-20261106.md),
not its completed session. Older partial/failed results remain immutable.

## Native continuation boundary

The new application package transfer last acknowledged part 95. Part 96's browser
frame matched its pin but had no observed native acknowledgment. Both receivers
returned at their fixed deadlines; no staging, CLI, installer or app trial was
started. Preserve all parts and roots; never restart execution from a timeout.
Private transport checkpoints and exact artifacts are in
`C:\aiw\sevenzip-execution-20261106\native-transport-r1`.

On November 14 the old parent transport-service PIDs were absent, and the console
showed a different desktop state. Do not reuse PID 8516 or its birth-bound commands.
New independently reviewed read-only preflight/viewer files and proof are under
`C:\aiw\sevenzip-execution-20261106`, prefix `preflight-...20261114-r1`.
No new preflight result has been observed. Direct browser access was unavailable;
native Computer Use stopped because it could not confidently determine the URL
during a console-page reconnect. Its outcome is unconfirmed. Revalidate the actual
VM/actor/Core/console, retained parts and target state before any continuation.
Windows Run truncates long commands: use only the short Core launcher there;
reviewed bounded script wrappers belong in the owned console.

## Authorization and remaining work

Official MXC 1.0.1 provenance is pinned. Its previous creation trials are
inconclusive; support/token observations do not establish execution or enforcement.
See [probe evidence](MXC-PROBE-NATIVE-20261106.md) and
[creation evidence](MXC-CREATION-NATIVE-20261106.md). Bounded raw diagnostics need
native proof. Registry foundations remain test-only pending native semantics.
The user approved this pinned runtime only inside fresh Sandboxes on existing
VM107 through reviewed Proxmox-console scripts. No parent runtime installation,
VM/security changes, DACL fallback, weaker fallback or automatic widening.

Finish actual source-pinned install/use comparisons across supported modes,
chain-reset negatives, registry controls, fresh repeats, archive-byte/metadata
investigation, new-source interruption/invalid/missing-output and non-replaying
recovery, desktop Review/Approve/Run and native Results reopen/export, review,
admin documentation, Benchmark 2 mapping and PR. Independent app progress must
continue when MXC is unavailable. Preserve exact approval/session binding,
receipt-last evidence publication, held-file custody and owned cleanup.

Reuse #105's six-control/29-file evidence and #106's `593281a` app pair, 32 retained
files, Results reopen/export and cancellation only for their recorded sources.
See [application acceptance](SEVENZIP-NATIVE-ACCEPTANCE.md). Preserve VM106, all
old VM107 packages/runs, `C:\Evidence`, unrelated apps/tabs and all private evidence.
Management TLS is expired: no bypass or access changes. Never delete retained
evidence as cleanup.
