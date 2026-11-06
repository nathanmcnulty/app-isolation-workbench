# Working state

Updated 2026-11-06 (America/Anchorage). Checkout C:\aiw\app-isolation-workbench,
branch codex/real-app-assessment; implementation head 5c12df0 followed by documentation. Exact native product
executables are source 593281a64dda9b233a25e3f3262d7e1751c01a6b.
Start with scripts/work-status.ps1 and the [administrator workflow](SEVENZIP-ASSESSMENT.md#administrator-workflow-for-the-tested-package).

## Demonstrated fixed application flow

The 593281a desktop package completed run sevenzip-1793956275430444300 on
VM107 after independently reviewed exact-plan approval and a separate Start.
Inside a fresh offline Sandbox, 7-Zip 26.05 installed and all four archive
functions passed in both ordinary-user and zero-capability classic AppContainer
modes. Held target tokens, selected file denials, unchanged code, profile/job
cleanup and exact outer cleanup passed. Host/guest builds were x64
10.0.26300.9711 / 10.0.26100.9711. Both archives are 579 bytes with different
hashes; their byte-difference cause remains unmeasured.

The receipt-bound comparison is workflowCompared; generic kernel outcome stays
insufficientEvidence for broader isolation. Independent offline review passed
482 assertions across exact approval/plan/request/profile/configuration, completion
artifacts, evidence, journal and session-cleanup bindings. See the
[native acceptance record](SEVENZIP-NATIVE-ACCEPTANCE.md#production-desktop-comparison-at-593281a).

Actual Results opened the original selection twice and exported byte-identical
JSON plus Markdown, with privacy checks passed. All 32 files, 43 entries and
12,283,755 bytes remained unchanged, including provider diagnostics. The reader
made no execution/provider call. Original native export hashes remain source-scoped;
later Evidence status/required guest-version label corrections are presentation
changes and were not in that tested package.

A separate approved run sevenzip-1793960096774082900 exercised native Cancel
after the owned boot window appeared. Independent offline audit passed 304
checks: exact approved plan/request/profile/import bindings, cancellation journal,
four session snapshots, one owned start/stop and two post-stop empty lists.
Kernel outcome is cancelled, evidence root absent and cleanup complete. No
application observations or incompatibility claim are added. See the
[cancellation record](SEVENZIP-NATIVE-ACCEPTANCE.md#native-owned-cancellation-at-593281a).

## Source, evidence and review

[PR #106](https://github.com/nathanmcnulty/app-isolation-workbench/pull/106)
contains the application slice. All three hosted CI jobs passed at
5c12df0dae756a427170e71b79220dd80fe7b491
([run 42200833485](https://github.com/nathanmcnulty/app-isolation-workbench/actions/runs/42200833485)).
The presentation correction passed 13 existing Rust Results tests, 17 Node UI
tests, Clippy and governance checks. It adds no native application measurements.
Source checks/review and static x64 release builds passed for their recorded
revisions; hosted CI is separate from native acceptance and is not release signing.

Private audit: C:/aiw/sevenzip-assessment-20261105. Start with
production-593281a-pins.json, production-independent-audit-593281a.json,
production-export-verification-593281a.json and
vm107-production-results-integrity-593281a.json; raw before/after inventories
and verified-exports-593281a remain beside them. Cancellation records include
vm107-cancellation-after-593281a.json and
cancellation-independent-audit-593281a.json. The private copied records
cannot replace original protected workspace identities or be imported as a new run.

Preserve the earlier 614bb0e run sevenzip-1793950517554284900: it retained
DriverIncomplete, unmeasured application facts and verified outer cleanup. Its
cause remains unknown; later success does not prove the old cause. Its retained
JSON export preserved all 26 files. Preserve the separate b7f17cf research pair,
its package and audit; it was not converted into production evidence or repeated.

PR #105 is merged and its six-control/29-file corrected Results evidence is
reused without execution. See [that native record](PAIRED-NATIVE-APPROVAL.md) and
[Results audit](RESULTS-ACCEPTANCE-AUDIT.md). Preserve VM106, every old package/run,
accidental C:\Evidence and unrelated work. Existing console access is used;
expired management TLS was not bypassed and no access/security settings changed.

## Remaining work

The successful comparison and separate native cancellation both have verified
cleanup and need no recovery; never replay or recover them to create acceptance
evidence. Native forced-fault recovery remains unexercised. Recovery bindings
and automated tests do not establish that native fault case. Complete final
review and documentation integration; the tested native package remains 593281a.

Required application-descendant evidence, registry denial for this profile,
repeatability, network/IPC/UI and ordinary endpoint claims remain unmeasured.
MXC's four-family [selection review](MXC-ASSESSMENT-SELECTION.md) and MSIX remain
complementary; the old MXC adapter is still planning-only. Broad Benchmark 2,
W4/W5 and production acceptance remain open; the [criteria mapping](SEVENZIP-ASSESSMENT.md#coverage-limits-and-acceptance)
separates this working application slice from those broader gates.
