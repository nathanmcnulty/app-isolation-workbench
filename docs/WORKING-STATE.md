# Working state

Updated 2026-10-30 (America/Anchorage). Owning checkout
`C:\aiw\app-isolation-workbench`, branch `codex/paired-controls`, atop local main
`53c02c8` including merged PR #103. Start with `scripts/work-status.ps1`.
This pointer is not execution authority.

## Current milestone

The user approved taking Results Explorer/fixed paired controls toward a locally
reviewable PR, including the single source-pinned VM107 assessment. Publication
remains separate. The attempt stopped in required provider readiness before
Sandbox dispatch; positive six-case native acceptance is **not achieved**.

Current source change: `2ec65edfe749b73a13ddf0c923db973de1292fc8` distinguishes
missing approval from approval recorded without dispatch in retained Results.
Both states still refuse control evidence; no execution/verdict/provider gate
changed. A read-only developer example uses the actual desktop Results backend
to verify deterministic summaries and create exclusive allowlisted JSON/Markdown
exports. Independent source review has no remaining consequential finding.

Focused affected tests passed (2 protected paired regressions, 1 shared function
matrix, 1 desktop privacy/gap check), as did runner/desktop all-target Clippy,
formatting and the offline example build. Earlier unchanged broad evidence is
retained: 678 workspace Rust tests, 20 desktop tests, 28 Node tests plus lint,
formatting and reviewed labeled fixture demonstrations. Do not rerun unchanged
suites merely for reassurance. No new JavaScript or control-agent code changed.

See [native attempt and Results](PAIRED-NATIVE-ATTEMPT.md) for exact artifacts,
current checks and limitations; [draft PR](PAIRED-DRAFT-PR.md) for review text;
[implementation handoff](PAIRED-IMPLEMENTATION-HANDOFF.md) for earlier evidence.

## Exact current native record

The d370ec8 execution package remains unchanged at
`C:\AIW-Paired-d370ec8-20261030\Package` on VM107. Source
`d370ec8cd5bcaa6915ac24801789070dd0040e3b` fixed the active-Hyper-V false negative
and added closed preparation-only CLI access. Approved console/Store setup
installed Sandbox 0.8.107.0 without security/CPU/feature changes. Production static
preparation/import completed, with exact pins in the
[consolidated request](PAIRED-NATIVE-APPROVAL.md).

Run `paired-1793425345541054400`, canonical plan hash
`b0d2e739ce45e7c9bbb0a0ed9651905cefcd0dfaae53c4e06450c1108035f234`,
was approved and Start issued **once**. Required native `list` timed out at 15039ms;
CLI exited 1 after 22s. No Sandbox dispatch transaction, guest request/output or
result exists. Read-only status is **Ready / sequence 3 / session none**, with
approval committed. No cancellation/recovery/retry was issued. This is neither
a passing assessment nor a current/global cleanup certificate.

Audit: `C:/aiw/paired-native-assessment-9fbf14ab-776c-42ed-8ee6-8b8a8009fca0`.
Actual headless Results on VM107 exports partial/unmeasured evidence correctly.
Repeat/collision/retained-destination checks preserve all 17 files in the bounded
explicit retained tree and original exports; both formats repeat byte-identically.
No provider/execution entry point exists in that reader/export path. The console
browser tool timed out after its documented reset/retry; no current native GUI
demonstration is claimed. Bounded existing AppModel/TWinUI logs supplied no matching
events; remote-context causation remains unproven.

## Remaining gates and preserved boundaries

The one-Start request is consumed. Do not replay Start or silently reprepare.
Further native work needs a reviewed bounded diagnostic/execution scope with
current exact source/context pins. Do not infer that changing session, token,
timeout, identity, grants or security settings will fix the unproven cause.
Native six-case collection, guest Tools custody, inner and outer cleanup, and
current GUI execution remain unvalidated. Keep full Benchmark 2 and W4/W5 open;
no general compatibility, effective isolation or production acceptance is claimed.

No push, PR creation, publication, signing, release, merge, security weakening,
new application trials or repeats of PR #103 are authorized. Preserve both old
f99bbd4 and d370ec8 packages, all old receipts and unrelated work.

VM107 only: UUID `e5cecc90-35c2-4831-bf9c-424be23f7d4e`,
MAC `CC:34:21:B8:5A:31`, IP `192.168.1.174`. Never touch VM106 or restore VM203.
Keep normal trusted HTTPS5986 / PowerShell.7.6, certificate
`BC14DCC4E37F83161EBB55AF8624E36A79E19256`; no TLS bypass, device-code login,
compatibility fallback, key/grant expansion or foreign lease adoption.
Never replay/recover historical runs `msix-1792704525359564000`,
`msix-bounded-1792816990610240800` or `msix-1793226013277315400`.
