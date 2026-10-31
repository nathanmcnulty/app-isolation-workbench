# Working state

Updated 2026-10-31 (America/Anchorage). Owning checkout
`C:\aiw\app-isolation-workbench`, branch `codex/paired-controls`, atop local main
`53c02c8` including merged PR #103. Start with `scripts/work-status.ps1`.
This pointer is not execution authority; the latest user authorization controls.

## Current milestone and authority

Offline Results Explorer and fixed paired controls are locally implemented and
reviewed. The user approved the pinned console assessment, then explicitly asked
to continue routine testing/fixes without repeated approval questions. Continue
within the existing fixed-control/VM107 scope, with reviewed fresh source/agent/
package/plan pins and preserved evidence. No blind retry, new application trial,
security/VM change, publication, push, PR creation, merge, signing or release.

Native six-case acceptance is **not achieved**; full Benchmark 2 and W4/W5 remain
open. No general compatibility, effective host isolation or production acceptance.

## Actual native state

Historical run `paired-1793425345541054400` remains unchanged: approved once,
required provider list timed out before dispatch, no transaction/result. Its
Results exports preserve all six cases as unmeasured. Do not replay/recover it.
A separately approved console readiness query succeeded (session1, empty list,
no blockers), which did not prove the timeout's cause or any control observation.

New run `paired-1793435382044001000`, plan
`afaf470e23d7b22313450c0df530ef7a757c4aac68942109abcedc14d32b8a2e`,
was approved and Start issued once in console session1, non-admin. Native outer
session `8b1276f0-0a3e-5c54-37ad-3b6e51d85b29` started/connected and published a
receipt-bound driver failure with no retained case measurements. PID6288 exited1 after68717ms. Exact-session
cleanup was verified; terminal failed / journal6 / sessionclean. No cancellation
or recovery. All six cases remain unmeasured. Actual Results backend/export:
29 retained files byte-unchanged, deterministic JSON/MD, private markers absent,
zero reader provider/execution routes. Old records and accidental empty
`C:\Evidence` are preserved; do not clean it up under test authority.

The original observer stopped after approval on a Ready-schema field error;
a source-reviewed Start-only continuation preserved approval and issued the first
Start. See [the approved execution record](PAIRED-NATIVE-APPROVAL.md#approved-execution-request-one-prepared-console-fixed-pair)
for exact pins, native outcomes, driver repairs and continuing test authority.
Raw audit: `C:/aiw/paired-console-native-execution-7d1fb92e-b439-4198-aee3-cb5166927dfc`.

## Current code and validation

The guest's specific collector/driver error was lost in logon stderr. The reviewed source
change retains bounded private diagnostics in v2 failed-driver evidence, keeps
v1 exact payload compatibility, and leaves measurement/verification/grant gates
and the summary field allowlist intact. It cannot recover the old missing error.
Provider88 / guest11 / paired-runner15 tests and the GUI privacy regression passed;
workspace and GUI all-target Clippy and formatting passed. Logs:
`C:/aiw/paired-private-diagnostic-*.log`. No consequential source-review finding.
Unchanged broad evidence remains scoped to its recorded source: workspace678,
desktop20, Node28 plus earlier lint/fixtures. Do not rerun unchanged suites.

Fresh a033 source/static agent/package were built offline and verified exact14
on VM107. One fresh preparation/approval/Start produced
`paired-1793482773445455100`, plan
`6f4a37df2ad83f4bdf7d41257439a0b06cdd5326ee2053aa00bca5a75589fed4`.
Native PID4400/session1 exited1 after69247ms with a receipt-bound v2 diagnostic:
`paired guest environment differs from approved profile`. This locates this
run's failing Windows equality gate before role custody/account/resources/cases;
actual guest version values were not retained. All six remain unmeasured. Outer
cleanup verified / journal6 / terminalfailed; no cancellation or recovery.
Actual a033 Results exports deterministic, 29 retained files unchanged, private
markers absent. New reader also reproduced old v1 summaries byte-for-byte.
Audit: `C:/aiw/paired-private-diagnostic-native-4dab54a5-6ecd-4c70-ad9d-cecab615492b`.

Diagnostic-only source `4f82f0b` retains exact expected/observed Windows tuples
while preserving equality. Focused test1, platform all-target Clippy, formatting
and governance passed. Its offline package completed exact14: receipt
`47ecdc9d07cfe51c60cf9b20b188728b8a07bf5edd05c4570f5d48b2e0524fd0`,
agent `483b82b9652e5a121bc1058b560978330e5b55b0fc60e47deab85ac8203b32bb`.
Package: `C:/aiw/paired-windows-mismatch-package-4f82f0b-20261031`.
No preparation/approval/Start for that package has occurred. Console-tool
timeouts/debugger attachment failures prevent further interactive work for now;
fresh namespace is still absent, no aiw process was active at its latest check.

Offline follow-up fixes the confirmed host/guest version conflation: versioned
profiles commit both tuples, preserving legacy hashes and exact guest equality.
CLI/desktop can supply an exact guest tuple; blank retains strict host-version
matching. Both values remain in the approval-bound profile. Independent source
review found no consequential finding. Affected Rust checks cover53 unique tests
(admin13/CLI2/probe3/provider9/runner15/guest11); desktop22 passed/4 opt-in ignored,
Node7 passed. Workspace/desktop all-target Clippy, formats and governance passed.
One stale drift-test value was corrected, then only changed cases rerun.
The new model's actual Results reader reproduced both v1/v2 native summaries
byte-for-byte, with each29-file retained snapshot unchanged and zero assessment/
provider calls. Audit: `C:/aiw/paired-host-guest-reader-53e67253-1b0f-4aaf-8010-e6461177db3d`.
Logs: `C:/aiw/paired-host-guest-*`. The actual guest tuple and positive native
acceptance remain unknown. Next: clean-source agent/package build, and use the
preserved diagnostic package for one fresh native plan once console access works.
Never guess a guest version,
relax a gate or substitute binaries in retained evidence.
See [workflow diagnostics](paired-product-workflow.md#bounded-private-driver-diagnostics-after-the-native-unmeasured-driver-failure)
and [draft PR](PAIRED-DRAFT-PR.md). Future errors must be observed, not guessed.

VM107 only: UUID `e5cecc90-35c2-4831-bf9c-424be23f7d4e`, MAC
`CC:34:21:B8:5A:31`, IP `192.168.1.174`. Never touch VM106 or restore VM203.
Trusted HTTPS5986/Core7.6 certificate `BC14DCC4E37F83161EBB55AF8624E36A79E19256`;
no TLS bypass, compatibility fallback, key/grant expansion or foreign adoption.
Historical MSIX runs remain retained and must not be replayed or recovered.
