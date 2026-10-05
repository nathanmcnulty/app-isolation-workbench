# Working state

Updated 2026-10-04. Verify this checkout with `scripts/work-status.ps1`.
This handoff is a pointer, not execution authority or a run receipt.

## Current slice

Nathan authorized his existing personal Artifact Signing account and CI setup;
see [signing identity and control](RELEASE-SIGNING.md). The manual main-only CLI
signing control passed at merged `210bbc9` (PR #84, all three CI checks passed).
Downloaded signed bytes independently verified as timestamped Authenticode from
Nathan McNulty; a modified copy was rejected with `HashMismatch`. Initial Azure
federation rejection was corrected using GitHub's exact immutable subject.
PR #85 merged the signed-desktop candidate workflow at `0cb8cad` after all three
CI checks passed at `7d9f9d6` in run `37249517740`; merged main has the tested tree.
Independent review resolved verifier execution before authentication and overly
broad authenticity claims. Local and hosted receipt/archive tests include real
unsigned refusal, changed build-record refusal, and rejected verifier non-execution.
Full signed candidate run `37250759217` passed all three stages at merged
`0cb8cad6605b857170a199e28f9f9a3577defd05`. Independent downloaded-package
extraction verified source, receipt, exact inventory, timestamped personal
publisher signatures on both handoff tools and six fixed package paths.
See RELEASE-CI-REVIEW-2026-10-04 for hashes and retained evidence pointers.
The publication/governance diff at `5f85a7f`, with README at `9d7bd47`, passed
independent review with no actionable findings. Final exact-head hosted CI,
merged-tree proof, public transition, public CI, and public-byte VM acceptance
remain open. This checkout adds a false-by-default publication job with separate
main-only authority, per-file provenance, and draft asset checks before exposure.
Nathan authorized the subsequent sequence: candidate readiness, focused release
CI review, public repository, CI-built public prerelease, then download/verify/test
those exact artifacts before stable promotion. See RELEASE-SIGNING for the order.
Its dedicated passwordless identity, profile-only signer role, and main-only
environment are configured and independently read back. The build/sign/verify
jobs are isolated; none of the built executable runs with signing authority.
The unsigned `desktop-preview-e08115b` GitHub draft was created with all five
verified assets. Approved cleanup of two temporary host handoffs remains blocked
by automatic policy review; the final handoff and all evidence are preserved.

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
