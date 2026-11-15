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

Fresh private AIW-only release artifacts are source `c0357ca`: locked offline
CLI/agent and desktop builds passed, with identical before/after tracked-source
bytes. Compiled CLI identity matches the independently reconstructed 24-file
source SHA `4aeb6d58f9eee106f79b3ee64f690e6a130eaa1fe4597c62162a5f91d841adf2`.
Independent source/build/PE/ZIP review passed. `build-c0357ca` and
`owned-tools-c0357ca-r1` below contain records and AIW tools, without vendor
installer, MXC runtime or trial scripts. CLI and agent import `VCRUNTIME140.dll`;
fresh Sandbox availability remains unmeasured. No prerequisite installation is
authorized by this build. Preserve the older `7fca63e` package and partial
transport; neither is current-source native application proof.

Latest accepted native source is `1d966ca49ab843ad8213152767b6fe037ab3bff9`:
bounded first-party ordinary/classic controls, six paired lifetimes each, exact
empty-job reconciliation, code-5 owner-journal controls and owned cleanup passed.
No vendor application or MXC ran there; physical console-image equivalence is
unproved. Reuse [that native record](SEVENZIP-CODE-CONTROL-NATIVE-20261106.md),
not its completed session. Older partial/failed results remain immutable.

## Native continuation boundary

The November 14 reviewed read-only continuity preflight executed once after the
user restored console readiness. Original JSON is retained unchanged: 22,175
bytes, SHA `00c919b119c87885e4f4b8b2cd5bcd1946795487410a4409b1c011e97b2f1846`.
Independent lossless audit passed. It confirms the existing VM, ordinary actor,
fresh Core 7.6.10 console and registry build/UBR `26300/9974`. Old trial guards
pin `26300/9711`; do not reuse them or the retired console bindings. Actual fresh
guest servicing and loader prerequisites are still unmeasured.

All 96 historical parts 0–95 match their original size/hash pins and remained
held/stable; part 96 was not observed. The old target directory open returned
Win32 code 2 and staging remains unproven. The retained installer verified.
This establishes historical `7fca63e` transfer continuity only: no adoption,
resume, provider, vendor application or MXC runtime execution. Preserve all parts,
roots and old failed attempts; never restart execution from an observation timeout.

Private base: `C:\aiw\sevenzip-execution-20261106`; see
`native-preflight-original-20261114-r1.json`, its admission record and
`native-preflight-independent-audit-20261114-r1.json`. Capture R1's origin refusal
and R2's validation refusal are retained. The parent transcribed 22,175 as 22,775;
the diagnostic copy matched the native digest, the printed length was reobserved,
and unchanged bytes were admitted without replay. Raw copies and receipts remain
immutable. Both owned loopback helpers exited after identity checks; the owned
local tab closed, and the original console/tab remain. Revalidate the raw record's
actual console identity before any new command. Long wrappers belong in the
console, never Windows Run (which truncates long input).

The [default-off environment feature](SANDBOX-ENVIRONMENT-PROBE.md), source
`404c837`, implements a fresh first-party prerequisite observation with separate
prepare/approve/start, retained read and dispatch-bound recovery. Focused checks
passed: 138 environment-provider, 5 guest-contract, 4 host-transaction, 139 older
publication-role and 138 default-provider tests; Clippy, Rust 1.88, format and
governance. Independent code/CI/docs reviews passed after fixes. All three
[hosted CI jobs](https://github.com/nathanmcnulty/app-isolation-workbench/actions/runs/43654996049)
passed. Both static helpers passed independent PE/build review; their compiled
source commitment matches independent reconstruction. No external CRT, vendor
or delay imports were found. These artifacts do not replace the earlier tools.

The reviewed AIW-only environment packet is fully transferred and staged. After
the first receiver's deadline at parts 0–4, a reviewed continuation verified and
held that prefix, accepted only parts 5–16, then reverified all 17. The separate
data-only stager verified the complete ZIP and five members before its receipt.
The first `--inspect-host` invocation then exited with `0xc0000005`; both retained
streams are complete and empty. No watchdog kill, provider acquisition or fresh
Sandbox occurred. The failing call and descendant cleanup remain unmeasured;
do not classify this as candidate incompatibility or silently replay it.
An existing-event read returned no usable facts; its refined diagnostic reached
the native cmdlet and returned `NoMatchingEventsFound` for the fixed query window.
No faulting module, offset or cause was obtained, and the helper was not replayed.
Guest servicing, dependency availability and loader compatibility remain
unmeasured. Private records use `C:\aiw\environment-probe-20261114`; see
[the probe record](SANDBOX-ENVIRONMENT-PROBE.md) for exact evidence pins.

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
