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

Reconciliation at f99bbd4 and the approved VM107 prerequisite work are recorded
in [the consolidated request](PAIRED-NATIVE-APPROVAL.md). User approved identity/
readiness inspection, staging and non-executing preparation only, stopping before
plan approval/Start. The pinned unsigned package is now staged and exact-inventory
verified at `C:\AIW-Paired-f99bbd4-20261030\Package` on VM107. Current identity,
Windows 26300.9711/x64, Core 7.6.9 and normal HTTPS5986 pins are retained in the
request. Evidence directory:
`C:/aiw/paired-target-preparation-38602e66-2c6f-4327-9662-63164f198333`.

The user subsequently authorized fixing blockers and continuing toward preparation,
with no assessment approval/Start/publication. A stronger read-only query showed
Windows Hyper-V already active (WHvGetCapability S_OK/4bytes/BOOL1, VBS running):
the firmware-only gate was a false negative. A reviewed local source fix now uses
that supported query as an independent prerequisite, keeping all provider trust
and approval gates. No VM CPU/settings/security change was made. A closed
prepare-only CLI now reuses the desktop preparation service, with no approval,
Start, recovery or executable/policy inputs. Focused affected checks and Clippy
passed; broad unchanged suites were reused. Source fix commit is
`d370ec8cd5bcaa6915ac24801789070dd0040e3b`. Refreshed offline desktop/CLI package
assembly and exact inventory passed; pins are in the consolidated request.
The new package is staged and all 14 payloads verified on VM107 at
`C:\AIW-Paired-d370ec8-20261030\Package`. The user subsequently authorized console
installation followed by preparation only. Browser access worked; normal existing
Proxmox sign-in and VM107's labadmin console/Store initialization resolved the
Store logon error. Exact Microsoft product `9NSMXC3NB0HN` installed successfully,
without opening Sandbox, signing into Edge or importing browser data. No CPU,
feature, security, network or power setting changed.

The production static inspector verified registered Sandbox 0.8.107.0, held
provider identity and cache-only catalog trust. One closed prepare-only call
created/imported pending run `paired-1793425345541054400`, canonical plan hash
`b0d2e739ce45e7c9bbb0a0ed9651905cefcd0dfaae53c4e06450c1108035f234`.
Read-only status verified pendingApproval/sequence1, no bound Sandbox transaction;
nine fixed retained files stayed unchanged. No approval/cancellation/result/
revocation artifact exists; guest Output and Exports are empty. Old f99 staging and
Evidence/Exports remain unchanged. Full current pins and future-only execution
scope are in the consolidated request. Audit:
`C:/aiw/paired-console-preparation-efe09ad0-3ac2-42de-b0a1-605685618350`.
No plan approval, Start, provider runtime/control call, trial or publication occurred.

## Open acceptance and preserved boundaries

Native guest/provider/control behavior and held-file inspection through Sandbox
Tools mappings remain untrialed. Fail closed rather than weakening intake.
The new unsigned desktop package is now locally enrolled and inventory-verified.
VM107 current OS/runtime/endpoint and provider/catalog/file-ID pins are observed.
The active Windows hypervisor is observed and the firmware-only false negative is
fixed. Protected static preparation exists; runtime protocol/feature/session checks
and guest mapped-Tools behavior remain unmeasured until separately authorized Start.
Keep live Benchmark 2 acceptance and remaining W4/W5 requirements open; no general
compatibility/effective-isolation claim, release or production acceptance follows.

VM107 blocker remediation and non-executing preparation are authorized; the
Store source-consent action was explicitly approved. Plan approval/Start and
publication remain unapproved. No live Sandbox/AppContainer/application/control trials,
unrelated setup, security weakening/grant expansion, signing, push, publication,
PR creation, merge or release are authorized. Approval/Start were not granted.
The guest agent and desktop were built offline, not run as assessments. Preserve completed records and unrelated
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
