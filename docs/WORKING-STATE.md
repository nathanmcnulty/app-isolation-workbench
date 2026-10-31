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

Next: finish governance/commit, build and verify a fresh static-agent/package from
that clean source, prepare a fresh pinned fixed-control plan, and continue native
testing under standing authority. Preserve all old packages/runs; never substitute
new binaries in retained evidence. See [workflow diagnostics](paired-product-workflow.md#bounded-private-driver-diagnostics-after-the-native-unmeasured-driver-failure)
and [draft PR](PAIRED-DRAFT-PR.md). Future errors must be observed, not guessed.

VM107 only: UUID `e5cecc90-35c2-4831-bf9c-424be23f7d4e`, MAC
`CC:34:21:B8:5A:31`, IP `192.168.1.174`. Never touch VM106 or restore VM203.
Trusted HTTPS5986/Core7.6 certificate `BC14DCC4E37F83161EBB55AF8624E36A79E19256`;
no TLS bypass, compatibility fallback, key/grant expansion or foreign adoption.
Historical MSIX runs remain retained and must not be replayed or recovered.
