# First administrator preview: scope and remaining gates

The first release is a narrow, supported Windows Sandbox workflow, not a universal
compatibility scanner or installer converter. An administrator should be able to
assess the supported application, read which functions passed or failed, preserve
a tested recipe, and replay it with explicit approval and drift checks.

The initial supported packaging path is Notepad++ MSI with the fixed document
workflow and ephemeral local settings. Bambu's existing export assessment is a
separate supported-profile candidate, not a reason to promise general EXE support.

## Progress that is already demonstrated

- Protected intake, fixed execution, approval, diagnostics, exact recovery, and
  hash-bound retained reporting work.
- Real Notepad++ and Bambu workflows have recorded evidence. The human document
  edit/save/close/export trial passed.
- Exact MSI bundles can be relocated, imported, and replayed in fresh Sandboxes.
- Baseline, local-settings candidate, and relocated replay passed the fixed
  document workflow and required guest standard-user file ACL controls.
- A reusable profile can bind that retained comparison to fresh preparation.

This is substantial execution and evidence infrastructure. It is not yet a
complete administrator-facing release. Counts of commits, tests, or reports do
not measure that final product outcome.

## Release-critical gates

| Gate | Concrete completion evidence |
|---|---|
| Approved profile replay — demonstrated | Profile identity is bound into approval; stripping/substitution/drift is rejected. The fresh worker at `fc22efb` completed the fixed workflow, required file ACL controls, and cleanup; report v0alpha11 identifies the approved profile. See [retained proof](VALIDATED-SANDBOX-LAUNCH.md#approved-replay-proof). |
| Administrator workflow — demonstrated | The packaged `aiw admin assess` route completed protected intake, complete recipe display, operator exact-hash approval, profile-bound replay, retained JSON/Markdown reporting, and verified cleanup for run `admin-1789947096248087800`. The report records every fixed function as passed while retaining `insufficientEvidence` for broader isolation. Occupied-session, unsupported-input, cancellation, and profile/package drift controls are retained or covered by the exact package checks and tests. See [administrator workflow proof](ADMINISTRATOR-WORKFLOW.md#public-entry-proof). |
| Clean-host distribution trial — demonstrated for the exact unsigned preview | A second operator freshly extracted and verified the `08ab440` package on the separate supported VM, approved the profile-bound recipe, and completed run `admin-1790485297308064300` with nine passed stages, saved-document and ACL controls, terminal cleanup, and no remaining Sandbox session. Unsupported input was rejected before intake or provider acquisition in `admin-1790486242125347900`. See [clean-host acceptance](CLEAN-HOST-PREVIEW.md#independent-operator-acceptance-for-this-package). Signing, publisher authentication, and broader isolation claims remain outside this proof. |
| Windows GUI operator loop — demonstrated for the exact unsigned development preview | Package `343d380` completed fresh assessment and interactive edit/save/export through actual GUI selection, review, approval, and separate Start. Independent receipt/output/input and empty-provider checks passed, as did retained viewing, cancellation/closure before Start, and export refusals. The third fixed Bambu export mode also passed a fresh GUI trial and corrected retained-result verification; see [Bambu acceptance](BAMBU-ADMIN-ENTRY.md#completed-desktop-acceptance-2026-10-03). This is automated dedicated-VM acceptance, not another human trial or a signed public release. See [GUI acceptance](GUI-FIRST-FINISH-LINE.md#completed-packaged-gui-acceptance-2026-10-03). |

After approved profile replay, pause feature expansion for a focused quality
review of approval/evidence bindings, historical reporting, recovery, and test
reliability. Resolve release-blocking findings before moving to the administrator
workflow. This is a review checkpoint with defined scope, not an open-ended
requirement to finish every isolation experiment.

The [2026-09-20 focused review](QUALITY-REVIEW-2026-09-20.md) found a preflight
guidance defect, corrected it, and confirmed the reviewed authority/recovery
boundaries. Its finite follow-ups remain visible; it does not require restarting
foundation work before the administrator milestone.

## Administrator milestone acceptance cases

- Starting with the distributed build and an operator-selected installer, show
  whether an exact supported profile exists. Unsupported bytes or application
  types produce an honest unsupported result and next step, never a guessed command.
- Detect missing prerequisites or an occupied Sandbox before starting work; show
  actionable diagnostics without stopping another task's session.
- Present tested functions as passed, failed, not reached, or not measured,
  separately from boundary measurements and requested settings. Identify the
  application/version/hash and explain what `insufficientEvidence` means without
  making successful function results look like an application failure.
- Show the proposed recipe, runtime/data lifetime, explicit export behavior, and
  approval changes before execution. Bind approval through existing services;
  operators do not hand-author internal JSON or use developer evidence paths.
- Complete assessment, retained report, recipe selection, and fresh approved
  replay from the documented path without a compiler or coding assistant.
- Exercise an unsupported input, a missing prerequisite, a failed/interrupted
  attempt, and profile drift. Each must lead to a specific safe next action and
  retained diagnostics; failed worker setup is not application incompatibility.

For the clean-host gate, publish the exact supported host/provider and application
versions, CLI/guest hashes, acquisition instructions, data contract, and known
limits. Verify the target's capabilities rather than assuming every Windows 11
24H2+ machine works. The operator must be able to retain evidence deliberately;
automatic deletion is not required. Recreate same-host validation on the target
when necessary instead of copying old paths or weakening environment checks.

The deterministic preview assembly is prepared with
`scripts/build-preview-package.ps1 -OutputDirectory <new-directory>`. It builds
the release CLI and static guest agent, copies the fixed Notepad++ project, and
publishes a package-local manifest with exact project and guest hashes. A
validated launch profile can be supplied with its canonical `profileSha256`
identity. Profile-bound replay assembly may also supply the independently
retained exact guest binary and SHA-256 that the profile binds; assembly rejects
all profile/project/scenario/guest mismatches. `receipt.json`
is written last and binds the package inventory; this assembles release inputs
but does not prove clean-host installation, signing, or Sandbox execution.

For the clean-host handoff, also supply `-ArchivePath`, the independently
retained guest and hash, and the validated profile and hash. Archive mode
requires a clean committed source tree, verifies the exact package inventory,
and emits a ZIP plus companion distribution manifest with version, source,
archive, receipt-file, receipt-core, and verifier identities. See
[clean-host preview handoff](CLEAN-HOST-PREVIEW.md). These controls prepare the
second-operator trial; the separate-host evidence remains the release gate.

The profile-bound package assembled on 2026-09-20 uses exact retained guest
SHA-256 `121daa7e6b93212037813dea948675431d1a1680bbb106cd396a2647454cfee5`,
profile `d8d7e4daddda76c535e6da1f897c210fa6b0798275640777747cea3df025d987`,
and receipt `b29693291be6779d488bff5d5a8f8d6257a12851d124202ec74d667032b0118a`.
Assembly rejected the current release guest because it did not match the
validated profile before publishing a receipt.

The public packaged route exercised the occupied-session acceptance case on
2026-09-20. It returned `AIW_ADMIN_HOST_NOT_READY`, named the retained
`host-readiness.json`, recorded session `8fd60024-30fd-41d7-8fa8-04571a405184`,
and created no intake or run. AIW did not acquire, recover, or stop that session.
The retained parent is
`%LOCALAPPDATA%\Temp\aiw-admin-public-occupied-d3fef39ab1c742adbb8fbac9dd56725e`.

The same package then completed the public profile-bound route after visible
operator approval. Run `admin-1789947096248087800` retained the exact approval,
execution, report, guest result, and clean terminal status under
`%LOCALAPPDATA%\Temp\aiw-admin-public-replay-783a99b8f9a24fcb9c1f6d25cfe90ecf`.
Installation and launch exited zero; the fixed document opened and saved the
expected SHA-256; the application ran at medium integrity without elevation;
the required guest file ACL control passed; and exact cleanup was verified. The
provider reported no sessions afterward. The report's broader outcome remains
`insufficientEvidence`, with its missing independent host, descendant, network,
IPC, persistence, and effective-backend measurements listed explicitly.

These are outcome gates, not a calendar or quota estimate. The narrow
clean-host preview loop is demonstrated for the exact unsigned package; public
distribution still needs an authenticated publication channel and signing
decision. New application classes and isolation mechanisms are not evidence
for this preview and require their own bounded validation.
Update this table when evidence closes a gate rather than repeatedly labelling
implementation slices as a release milestone.

## Later capabilities, outside that first preview

Broader application profiles; persistent application state; general MSI/MSIX
conversion; update/uninstall/reboot coverage; arbitrary user-authored scenarios;
and additional isolation providers. Add them for explicit application needs after
the first usable loop is released.

Fixed guest file ACL observations are not a verdict on host containment, network,
registry boundaries, or descendants. The first release must communicate those
limits; it need not claim measurements it does not have.
