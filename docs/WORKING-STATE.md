# Working state

Updated 2026-10-30. Owning checkout `C:\aiw\app-isolation-workbench`, branch
`codex/paired-controls`, local descendant of Results `bd63fe5`/`edf4139`, atop
main `53c02c8` including merged PR #103. Start with `scripts/work-status.ps1`.
This pointer grants no execution authority.

## Offline implementation and validation complete

Code commit `e2e44fe2bf3ca98113618131f4f6d8700354219f` contains the Results
Explorer and fixed paired-control desktop workflow. Static prepare/import never
invokes the provider; exact approval and separate Start gate the existing shared
leased runner. Typed fixed source/executable/environment/policy bindings, journal,
receipts, owned cancellation and exact-session recovery remain fail-closed.
Results reads only bounded explicit selections, keeps fixed observations and
historical cleanup separate, and exports allowlisted new JSON/Markdown files
outside retained workspaces. No generic executable/script interface was added.

The actual admin/kernel rehearsal uses fresh inert protected fixtures and strict
fake process/lease boundaries. Synthetic evidence cannot satisfy production
acceptance or acquire native recovery. Whole retained-tree snapshots verify reads
are unchanged and make no new provider-boundary calls. The desktop Controller and
ResultsStore produce a labeled replay; browser clicks have no provider backend.
Independent source review covered authority, comparability, interpretation,
recovery, static custody and UI/export; findings were fixed. The first full test
run exposed a test-only cancellation publication race, fixed in `e2e44fe` without
relaxing the production journal. Final validation passed against that code: 678 workspace Rust tests (27 opt-in
ignored), 20 desktop tests (4 opt-in ignored), 28 Node tests, all-target workspace
and desktop Clippy, formatting, governance and offline desktop build. Exact logs,
counts and limitations are in the handoff. Subsequent edits are documentation only.
The offline goal is complete; the native acceptance gates below remain open.

See [implementation handoff](PAIRED-IMPLEMENTATION-HANDOFF.md) for acceptance
coverage, exact commits/logs, demonstration and limitations;
[product workflow](paired-product-workflow.md) for implementation/reproduction;
[Results usage](RESULTS-EXPLORER.md),
[draft PR](PAIRED-DRAFT-PR.md), and
[source-pinned future native proposal](PAIRED-NATIVE-ACCEPTANCE-PROPOSAL.md).
All output remains local; no PR was submitted.

## Open acceptance and preserved boundaries

Native guest/provider/control behavior and held-file inspection through Sandbox
Tools mappings remain untrialed. Fail closed rather than weakening intake.
No independently enrolled new desktop package/provider identity was available.
Keep live Benchmark 2 acceptance and remaining W4/W5 requirements open; no general
compatibility/effective-isolation claim, release or production acceptance follows.

No live VM/Sandbox/AppContainer/application/control trials, authentication, host
security changes/grants, dependency installation, signing, push, publication,
PR creation, merge or release are authorized. The guest agent and desktop were
built offline, not run as assessments. Preserve completed records and unrelated
work; never repeat PR #103's completed trials.

Future separately authorized execution must first inspect exact current
enrollment/approval records. Historical VM107 constraints remain: UUID
`e5cecc90-35c2-4831-bf9c-424be23f7d4e`, MAC `CC:34:21:B8:5A:31`,
IP `192.168.1.174`; never touch VM106 or restore VM203. Normal HTTPS certificate
`BC14DCC4E37F83161EBB55AF8624E36A79E19256` remains required. No TLS bypass,
legacy fallback, credential/key expansion, foreign lease adoption or dispatch
retry. Keep migration release draft. Preserve old snapshots/completed leases.

Never replay/recover historical runs `msix-1792704525359564000`,
`msix-bounded-1792816990610240800` or `msix-1793226013277315400`.
Their receipts apply only to their recorded source/package/runtime identities.
This implementation adds no native acceptance clearance.
