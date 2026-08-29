## Summary

<!-- Describe the one user-visible vertical slice delivered by this pull request. -->

## Scope and trust boundary

- [ ] I identified the contracts, providers, artifacts, and trust boundaries changed.
- [ ] Imported content, installer output, provider output, and model text remain untrusted.
- [ ] No arbitrary command/script/helper verb, persistent privileged service, automatic permission grant, or telemetry was added.
- [ ] Any signing, packaging, elevation, path, IPC, or evidence change has a threat-model note.

## Validation

Commands run:

```text
<!-- Include exact commands and results. -->
```

- [ ] Narrow tests pass.
- [ ] `scripts/verify.ps1` passes.
- [ ] `scripts/audit-dependencies.ps1` passes.
- [ ] Schema/project compatibility and migration behavior are covered when applicable.
- [ ] Recovery, cancellation, timeout, cleanup, and structured errors are covered when applicable.
- [ ] Live Windows proof is included for any claim about real provider behavior. Mock tests are labeled as mock evidence.

## Evidence and documentation

- [ ] I documented current limitations and did not claim runner, UI, or package execution exists unless proven.
- [ ] The acceptance criteria and exit gate for the roadmap slice are satisfied.
- [ ] No sensitive installer, customer evidence, credentials, private keys, or unredacted traces are included.
