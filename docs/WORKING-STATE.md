# Working state

Updated 2026-10-03. Verify this checkout with `scripts/work-status.ps1`.
This handoff is a pointer, not execution authority or a run receipt.

## Current slice

The unsigned administrator GUI acceptance slice is complete at packaged source
`343d380a3fef4e8734ea25c693ac99d4ac6f2a6a`; PR #80 merged at
`11786078d8f2c0d047a326ed7e1ade71e87e8751`. Final entry-point documentation
corrects the stale README and records this integrated milestone. See
[GUI-FIRST-FINISH-LINE.md](GUI-FIRST-FINISH-LINE.md#completed-packaged-gui-acceptance-2026-10-03)
for package identities, detailed observations, negative controls, and archives.

Fresh GUI assessment `admin-1791022076187823100` passed all five supported
functions and verified cleanup. Fresh interactive run `admin-1791022515798013900`
visibly edited/saved/closed Notepad++, verified the 183-byte output, and explicitly
exported through the GUI. Independent checks matched the receipt/output/export,
preserved the original input, and found zero provider sessions before Start and
after completion. Broader isolation remains insufficient evidence.

Restart/read-only viewing, explicit retained export, missing/existing/workspace
export refusals, cancellation before approval, and closure after approval before
Start passed. Controls and screenshots record automated acceptance, never Nathan's
human proof. Destination selection, close-warning visibility, timer reset, and
provider console fixes are included. The fresh package verified on Windows
PowerShell 5.1; all three hosted CI jobs passed at exact code `343d380`. Earlier
failed driver/build evidence remains historical and is not compatibility proof.

The shared workflow preserves separate approval and Start, protected intake,
one-shot challenges, fixed package identities, receipt verification, and exact
cleanup. The desktop is a separate Tauri workspace with embedded local assets
and narrow IPC. Core MSRV is 1.85; desktop MSRV is 1.90. Follow ROADMAP and
RELEASE-GATES for the next bounded deliverable; public publisher signing,
additional profiles, and generic application conversion remain separate work.

## Preserved stable evidence

PR #78 merged at `688e923`: verification throws/structured results are authoritative;
do not check stale `$LASTEXITCODE` after an in-process PowerShell script. Nathan's
exact `738ea6e` run `admin-1790887375232888400` retained a 225-byte edited document,
verified cleanup, and unchanged input. PR #79 merged at `103f1ed`: packaged
`admin export-document` supplies fixed project/guest identities and defaults to a
short summary. Both formats and negative destinations passed retained-run VM
validation at exact preview `7d45b3c`, without reinstalling. See
[INTERACTIVE-SANDBOX.md](INTERACTIVE-SANDBOX.md).

## Acceptance environment and build ownership

- Dedicated VM: `aiw-clean-host-0921`, resource group `RG-AIW-CLEAN-HOST-20260921`,
  subscription `43babb60-9e73-4dc8-b769-4401c01aad73`; operator `aiwoperator`.
- RDP is usable. The supported installer and original document remain in
  `C:\AIW-Interactive-Input-738ea6e`; reverify their hashes before use. Retained
  evidence is read-only unless the exact lifecycle explicitly requires recovery.
- One target owner. Core cache: `%LOCALAPPDATA%\Temp\aiw-os-validation-20260919`.
  Desktop cache: `%LOCALAPPDATA%\Temp\aiw-desktop-validation-20261002`.
  Disable incremental/debug information for core validation. Use explicit
  `x86_64-pc-windows-msvc` and target-scoped static CRT flags for packages.
- Two parallel workspace checks encountered access-denied errors in existing
  raw-file recovery tests. The serialized workspace, clippy, MSRV, and governance
  checks passed. Desktop release configuration now has its own CI check after a
  release-only API error was found and corrected during package assembly.

## Boundaries

No host installer execution, generic command interface, implicit approval,
automatic export/overwrite, or unrelated Sandbox recovery. Never use device-code
authentication. Commit/push milestones and merge only after review and required
exact-head CI. Public signing/publisher identity, generic repackaging, and broader
isolation verdicts remain separate from this unsigned development GUI goal.
