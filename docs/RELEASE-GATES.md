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
