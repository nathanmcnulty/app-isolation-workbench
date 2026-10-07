# Working state

Updated 2026-10-07. Verify this checkout with `scripts/work-status.ps1`.
This handoff is a pointer, not execution authority or a run receipt.

## Current slice

The active goal is initial packaging validated using Notepad++ with a simple
installer -> analysis -> isolation/recipe selection experience. On
`codex/notepad-package-workflow`, the new `aiw-admin-workflow::packaging` service
reuses fixed recipe compilation, protected intake and bundle export/verification.
The desktop now wires installer analysis, typed preset/workflow selection and
package creation with optional technical details and operation locking. Service
tests use inert fixtures; 31 service, 7 controller and 10 UI tests pass. Native desktop
acceptance, real-installer package creation and fresh package-bound disposable-
worker validation remain required. Package replay now imports a verified bundle
only when its recipe matches the installed profile, then uses the existing review,
exact approval and separate Start. Packaging preserves completed trial/export state.
See [administrator packaging](ADMIN-PACKAGING.md). Do not treat assembly tests or
older public-alpha trials as acceptance of this new end-to-end experience.

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

Host evidence pointer: `%TEMP%\aiw-public-alpha-proof-root.txt`.
Verified input identities: `%TEMP%\aiw-public-acceptance-input-records.json`.
One build owner per target. Core cache: `%LOCALAPPDATA%\Temp\aiw-os-validation-20260919`;
desktop cache: `%LOCALAPPDATA%\Temp\aiw-desktop-validation-20261002`.
Use explicit Windows target and target-scoped static CRT for packages.

Finish the active Notepad++ packaging goal before selecting another application.
Keep generic conversion and new providers outside this initial packaging slice.

## Boundaries

No host installer execution, generic execution interface, implicit approval,
automatic export/overwrite or unrelated Sandbox recovery. Never device-code auth.
Use fresh evidence after diagnosed failures. Commit/push milestones; merge only
after required exact-head CI and review, then verify merged main tree.
