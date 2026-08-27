# Contributing to App Isolation Workbench

Thank you for helping build evidence-first Windows application isolation tooling. This repository is pre-alpha research software. Contributions are welcome, but a change must preserve the distinction between a contract or plan and a live security claim.

## Before you start

- Read [SECURITY.md](SECURITY.md), the [architecture](docs/ARCHITECTURE.md), and [threat model](docs/THREAT-MODEL.md).
- For a substantial change, open an issue describing the user outcome, affected trust boundaries, acceptance tests, and any required live Windows proof.
- Do not include installers, customer evidence, credentials, private keys, unredacted traces, or proprietary binaries in issues or pull requests.
- Do not add arbitrary command, script, path, registry, URL, or query execution to a privileged helper.

## Development workflow

Use a focused vertical slice. A pull request should deliver one coherent behavior and include its contracts, implementation, tests, documentation, and recovery/error behavior. Keep contract-changing work serialized and avoid unrelated formatting or refactors.

Run the local checks from the repository root:

```powershell
.\scripts\verify.ps1
.\scripts\audit-dependencies.ps1
```

The verification script is intentionally local and deterministic. Hosted CI runs the same checks on Windows, but CI does not prove that a provider actually isolates an application. A live provider claim requires an explicitly documented Windows 11 24H2 x64 proof with target-token, effective-backend, canary, completeness, and cleanup evidence.

## Design and security expectations

- Evidence is authoritative; model-generated text is advisory only.
- Imported project content and installer output are untrusted.
- Project files cannot contain free-form commands or scripts.
- Every mutating operation has a typed plan, an explicit approval, and a run-bound journal.
- Unsupported, degraded, incomplete, or ambiguous isolation results are `insufficientEvidence`, never success.
- There is no persistent privileged service and no automatic telemetry.
- Master Packager is a manual export/import handoff; the project must not call or embed it.

## Pull requests

Use the pull request template. Include the exact validation commands and distinguish automated checks, mock-provider evidence, and live Windows evidence. Keep commits reviewable and use the `codex/` branch prefix for branches created by project automation.

By submitting a contribution, you agree that it is provided under the [Apache License 2.0](LICENSE). Third-party code and artifacts must retain their original licenses and be recorded in the appropriate supply-chain documentation.
