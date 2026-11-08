# Working state

Updated 2026-11-08. Current slice: align the application-neutral recovery plan and
repository/publication scope. Start with `scripts/work-status.ps1`,
[roadmap](ROADMAP.md), [migration audit](APPLICATION-AGNOSTIC-MIGRATION.md) and
[release gates](RELEASE-GATES.md). The work layers on local cleanup `df6f329`,
README PR #107 head `30abe101`, and main `b27942a`; verify current remote state
before integration. These are source references, not assumptions about today's HEAD.

## Current boundary and next work

Generic assessment is not implemented. Product-specific execution remains in the
CLI, desktop, guest, platform, runner and packaging paths. The recovery is one
capability-selected plan/engine with exact per-run source identity, useful
assessment before optional packaging, a diverse corpus plus independent holdout,
and retirement of fixed execution after equivalent regression coverage transfers.

Next implementation: R1's generic plan/capability contract using existing
`ApplicationSource`, `ScenarioStep` and intake/approval concepts. Begin with inert
validation and unknown-app/unsupported-operation tests, not another product adapter.
See [execution packets](EXECUTION-PLAN.md). The roadmap does not authorize a live
trial, authentication, dependency install, runtime pin change or provider setup.

Vendor configuration bytes, application MSIX publication and installer-bundling
assembly are removed in the cleanup. Desktop candidate jobs remain paused until
an AIW-only layout and publication gates are reviewed. Original native archive
pins remain strict; synthetic test data is not original acceptance evidence.

## Retained evidence pointers

- [Fixed 7-Zip assessment](SEVENZIP-NATIVE-ACCEPTANCE.md): successful comparison
  and separate cancellation at source `593281a`; broader measurements remain
  unmeasured. Preserve the earlier failed attempt without inventing its cause.
- [Paired project-owned controls](PAIRED-NATIVE-APPROVAL.md) and
  [Results audit](RESULTS-ACCEPTANCE-AUDIT.md): scoped source and native records.
- [External historical archive tests](../fixtures/msix-lifecycle/README.md):
  exact native bytes are not distributed with source.

Preserve existing VMs, old packages, retained runs and unrelated work. Do not
rerun applications, recover completed sessions, delete remote releases/history
or alter retained evidence merely to align documentation.

## Integration checks

The documentation change needs link/content/governance review and independent
exact-head review. The underlying cleanup also changes scripts/tests/assets and
requires their applicable checks plus required hosted CI before integration.
This Linux executor can run inert checks with the existing PowerShell runtime;
Windows-only/native and Rust toolchain checks must be reported separately, not
inferred from static success. Update this handoff when integration actually lands.
