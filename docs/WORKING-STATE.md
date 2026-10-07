# Working state

Updated 2026-10-07. Verify this checkout with `scripts/work-status.ps1`.
This handoff is a pointer, not execution authority or a run receipt.

## Current slice

`codex/bambu-reusable-package` is implementing the second application package loop.
The [milestone contract](BAMBU-PACKAGING.md) keeps the existing fixed EXE recipe,
adds a closed bundle, fresh protected replay and exact package/run association.
Core APIs and desktop controls are implemented and pushed through `284cd58`.
Independent review found and fixed two legacy API/schema compatibility issues.
36 administrator tests, two Bambu bundle tests, the MSI relocation regression,
30 CLI contracts, 11 UI tests, focused warnings-as-errors Clippy, governance,
formatting and static Windows CLI/desktop release builds passed.
Dedicated-VM operator-context export/relocation/import passed, including rejection
of matching installer bytes from another intake against a reverified successful
historical Bambu run. Detailed identities and gaps: [development proof](BAMBU-PACKAGING.md#development-proof).
All three required integration checks passed on exact `b8ad8e1` (CI `37681516883`).
Computer use is working again after the bundled runtime update. The dedicated VM
verified all eleven development payload files, then native Bambu analysis and
package assembly passed. Fresh native package run `admin-1791408579808193500`
passed all five export checks, matched bundle reporting, independent artifact
hashing and cleanup; the provider list is empty. The current CLI independently
reverified both retained Notepad package/report associations as the limited
operator. Test registrations are removed and evidence is preserved. PR #93 is
ready for final evidence review and required final-head checks. Integration and
signed candidate acceptance remain open; keep the existing tested download.

PR #92 merged at `0a88db6`; its tree matches reviewed `1d6082e`. All required PR
checks (`37669599045`) and main checks (`37670881454`) passed. It shares held-file
identity/stream/signature observations across assessment and packaging without
changing hashes, import or approval. See [shared observations](ADMIN-PACKAGING.md#shared-assessment-observations).

## Latest public milestone

Initial Notepad++ packaging is integrated in PR #90 at
`08dcc310aa30ea9c0bc4b68deb46ac09337ea012`. Exact `e881c59` passed independent
code review; final head `a7714f1` passed all three hosted checks (`37594030722`).
Main matches the tested tree and passed CI `37595301328`. Detailed service,
negative-test and unsigned native proof: [administrator packaging](ADMIN-PACKAGING.md).

Signed prerelease `desktop-alpha-08dcc310aa30` was published by successful
release run `37595331022`. Fresh host and VM downloads verified five asset
identities, attestations on host, signatures, closed inventory and receipt.
Native GUI analysis and both package assemblies passed. Package-bound fixed run
`admin-1791363728884366700` and interactive run `admin-1791364558757379700`
passed fresh full recipe review, exact approval, separate Start, verified results
and cleanup. Interactive native edit/save/close retained 224 bytes; explicit
export matched exact text/hash and existing-destination export was refused.
Operator-context CLI independently reverified both bundle/import/run associations.
Bambu run `admin-1791365433522265300` completed all five fixed export checks
and cleanup; independent artifact hashing matches its retained report and result.
The final provider list was empty at `2026-10-07T09:45:42Z`.
See [signed packaging acceptance](PUBLIC-PACKAGING-ACCEPTANCE.md).

## Previous completed slice

`codex/admin-approval-summary` adds backend-authored approval prose by default
and expandable complete recipe, plan, workspace and approval identity. Unknown
or incomplete summaries open full details. Exact approval and separate Start
remain unchanged. Independent review found and corrected omitted Bambu access
changes; final code review approved `4abdde6`.

Seven UI tests pass, including inert text, fallback, challenge reset, polling,
exact approval arguments and separate Start. The release desktop build passed
with explicit Windows target and static CRT. Retained recipes for all three
products project successfully. Automated RDP preparation/expand/cancel acceptance
on the dedicated VM passed without approving or starting a Sandbox workflow.
Detailed source/binary/run identities are in [GUI acceptance](GUI-FIRST-FINISH-LINE.md#approval-presentation).
PR #89 integrated this slice at `612cd2926b5678f817f83869e04ae22f15d39a18`.
All three hosted checks passed; the merged tree matches the tested PR head.

## Preserved public milestone

Public signed prerelease `desktop-alpha-6c7873c4e80c` was built from exact source
`6c7873c4e80c889394ec43b27138cc52fc7df1c2` by successful release run
`37254512259`. Its assets remain unchanged. Independent downloads verified
attestations, signatures, closed inventory and receipt on host and dedicated VM.
All three public-byte GUI workflows completed, with exact approval, separate
Start, artifact verification, cleanup and explicit document export where supported.
Broader isolation remains insufficient evidence; no stable promotion is implied.
See [public acceptance](PUBLIC-ALPHA-ACCEPTANCE.md) and
[CI review](RELEASE-CI-REVIEW-2026-10-04.md). PR #88 integrated this evidence.

Historical human edit/save/export evidence and diagnostic failures remain
preserved in INTERACTIVE-SANDBOX.md and the associated retained directories.
Old unsigned `desktop-preview-e08115b` remains unpublished. Automatic policy
review rejected cleanup of two host handoffs; do not bypass or retry deletion.

## Environment and next step

Dedicated VM: `aiw-clean-host-0921`, resource group `RG-AIW-CLEAN-HOST-20260921`,
subscription `43babb60-9e73-4dc8-b769-4401c01aad73`; aiwoperator session 2.
RDP computer use and file clipboard transfer are working and authorized.
Drive redirection is unavailable in this connection. Cached Azure login lacks
blob upload authority; do not grant roles merely for development transfer.
File-based Azure Run Command with marker/error/typed-record checks is proven;
inline transport success with empty output is not execution proof.

Host evidence pointers: `%TEMP%\aiw-package-public-proof-root.txt` (current)
and `%TEMP%\aiw-public-alpha-proof-root.txt` (earlier proofs).
Verified input identities: `%TEMP%\aiw-public-acceptance-input-records.json`.
One build owner per target. Core cache: `%LOCALAPPDATA%\Temp\aiw-os-validation-20260919`;
desktop cache: `%LOCALAPPDATA%\Temp\aiw-desktop-validation-20261002`.
Use explicit Windows target and target-scoped static CRT for packages.

Signed-byte acceptance documentation is integrated in PR #91 at `2ecd17a`.
Finish the Bambu packaging contract and its live acceptance before broader
coverage. Keep generic conversion and new providers outside this milestone.

## Boundaries

No host installer execution, generic execution interface, implicit approval,
automatic export/overwrite or unrelated Sandbox recovery. Never device-code auth.
Use fresh evidence after diagnosed failures. Commit/push milestones; merge only
after required exact-head CI and review, then verify merged main tree.
