# Working state

Updated 2026-10-04. Verify this checkout with `scripts/work-status.ps1`.
This handoff is a pointer, not execution authority or a run receipt.

## Current slice

PR #86 merged the independently reviewed public alpha publication workflow at
`90d06e7fe223bfe1166bd996f0e1db8c3a068be4`. All three hosted CI checks passed
at `40c9df8` in run `37252512658`; merged main has its exact tested tree
`cd2363c8deecc5482cd1255a6c58e3cfc00fac3b`. The repository is now public under
Nathan's authorization, with anonymous API readback. The final full-history
exposure scan covered 463 commits with no findings. Main-only environment
policies, profile-only Azure signer role, and immutable OIDC subject were checked;
visibility did not change the subject. See RELEASE-CI-REVIEW-2026-10-04.

First public alpha workflow run `37253486994` is building exact merged `90d06e7`.
Observe this run before any retry. Host watcher log:
`%TEMP%\aiw-public-alpha-37253486994.log`. Expected new tag is
`desktop-alpha-90d06e7fe223`. Public publication, all-five-file provenance and
asset verification, fresh public download, and exact-byte dedicated-VM acceptance
remain open. This acceptance branch starts at the public build source; do not
substitute its later documentation commits for the source being tested.

Private full signed control `37250759217` passed at `0cb8cad`. Independent
signature-checked download/extraction passed with exact source, inventory, receipt,
and timestamped Nathan McNulty signatures on both handoff tools and six package
paths. This is not public-byte runtime acceptance. The earlier CLI signing
control, tamper rejection, and corrected immutable federation are recorded in
RELEASE-SIGNING. Build, Azure signing, assembly, and publication have separate
runners/permissions; built executables never run with signing authority.

The old unsigned `desktop-preview-e08115b` draft remains unpublished. Automatic
policy review blocked approved cleanup of two temporary host handoffs; do not
bypass that rejection. The final handoff and retained evidence remain preserved.
PR #82 merged the Bambu GUI at `1db892d` after all three exact-head CI jobs passed;
merged main has the tested tree. The verified desktop archive handoff now has
native PowerShell 5.1 export and extraction proof on the dedicated VM; both
passed for the existing `e08115b` package; its receipt and application bytes did
not change. Both schema fixtures/negative controls and independent exact-commit
review passed. See [distribution proof and exact commands](DESKTOP-DISTRIBUTION.md).
This avoids manual ZIP work. Publisher selection is settled; signed-candidate
assembly and public acceptance remain open.

The fixed Bambu Studio export now has a validated GUI path beside the two
Notepad++ modes. Current unsigned package source is
`e08115b50fb0ee37fba1f923b377985dc3f1bc94`. Use work-status for the current
integration head; merge milestones only after exact-head hosted CI.
See [Bambu desktop acceptance](BAMBU-ADMIN-ENTRY.md#completed-desktop-acceptance-2026-10-03)
for exact package/input/launch paths, identities, observations, and evidence.

Fresh GUI run `admin-1791052004563329100` at package `170caab` passed all five
fixed export functions, verified the 9,061-byte tetrahedron 3MF, preserved input,
and verified cleanup with zero remaining sessions. It exposed a GUI label bug:
Bambu's deliberate broader-isolation `insufficientEvidence` was mistaken for an
incomplete workflow. The runner-owned typed predicate fixes that distinction;
its negative regression and independent review passed. New package `e08115b`
reopened that same run as Verified with document export disabled.

The new package also reverified retained Notepad++ transfer
`admin-1791022515798013900` and explicitly exported its matching 183-byte output.
These are automated dedicated-VM controls, not another human trial. Reporting
corrections used retained evidence; no repeat installation was needed.

PR #80 integrated the initial Notepad++ GUI at `11786078`; PR #81 corrected its
entry documentation at `8c8201f`. See [initial GUI acceptance](GUI-FIRST-FINISH-LINE.md#completed-packaged-gui-acceptance-2026-10-03)
for its fresh edit/save/export and negative lifecycle/export controls.
Follow ROADMAP and RELEASE-GATES for the next bounded deliverable. Publisher
signing, generic application conversion, and broader isolation remain separate.

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
