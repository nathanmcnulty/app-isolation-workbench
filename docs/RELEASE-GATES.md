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
| Administrator workflow | A documented, guided path from intake through assessment, plain-language summary, recipe selection, and approved replay. Failures and unmeasured functions remain visible, with specific next steps and accessible diagnostics. |
| Clean-host distribution trial | A versioned Workbench build can be installed or unpacked on a clean supported host, prerequisites are detected correctly, and a second operator completes the documented assessment/replay path with retained evidence. Publish the exact build identity, support scope, and known limitations. |

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
identity. `receipt.json`
is written last and binds the package inventory; this assembles release inputs
but does not prove clean-host installation, signing, or Sandbox execution.

The public packaged route exercised the occupied-session acceptance case on
2026-09-20. It returned `AIW_ADMIN_HOST_NOT_READY`, named the retained
`host-readiness.json`, recorded session `8fd60024-30fd-41d7-8fa8-04571a405184`,
and created no intake or run. AIW did not acquire, recover, or stop that session.
The retained parent is
`%LOCALAPPDATA%\Temp\aiw-admin-public-occupied-d3fef39ab1c742adbb8fbac9dd56725e`.

These are outcome gates, not a calendar or quota estimate. The remaining
uncertainty is concentrated in the administrator workflow and clean-host trial;
new application classes and new isolation mechanisms are not prerequisites.
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
