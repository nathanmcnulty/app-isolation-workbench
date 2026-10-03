# Working state

Updated 2026-10-02. Verify this checkout with `scripts/work-status.ps1`.
This handoff is a pointer, not execution authority or a run receipt.

## Current slice

Build and independently validate the Windows administrator GUI following
[GUI-FIRST-FINISH-LINE.md](GUI-FIRST-FINISH-LINE.md). The user authorized full
dedicated-VM control and agent-driven approvals/editing; record these as automated
acceptance, never as Nathan's human proof. The goal remains active until the
packaged GUI assessment and edit/save/export loop and negative controls pass.

The shared `aiw-admin-workflow` crate retains the CLI workflow and adds separate
review/approval and Start gates. `gui/` is a separate Tauri workspace with local
embedded assets, narrow IPC, backend-owned one-shot challenges, explicit export,
verified retained reports, and truthful not-run/incomplete outcomes. Core MSRV
remains 1.85; the desktop workspace declares 1.90. Desktop assembly rebuilds from
clean source and combines both fixed Notepad++ product assets in one inventory.
An independently hash-checked startup probe visibly opened the GUI over RDP and
refused missing inputs. Windows PowerShell 5.1 exposed receipt sort differences;
explicit ordinal ordering and a same-package cross-shell fixture now address it.
Exact package `7667acd` verified under Windows PowerShell 5.1 and opened on the
VM; all CI jobs passed at that code head. Fresh GUI assessment/edit/save/export
acceptance is pending: an unrelated GitHub passkey prompt currently blocks RDP
input. Leave authentication to its owner. The GUI is idle, Sandbox was empty,
and no assessment intake exists. See the GUI plan for package/proof identities.

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
