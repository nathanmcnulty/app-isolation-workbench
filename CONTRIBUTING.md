# Contributing to App Isolation Workbench

Thank you for helping build evidence-first Windows application isolation tooling. This repository is experimental alpha research software. Contributions are welcome, but a change must preserve the distinction between a contract or plan and a live security claim.

## Before you start

- Read [SECURITY.md](SECURITY.md), the [architecture](docs/ARCHITECTURE.md), and [threat model](docs/THREAT-MODEL.md).
- For a substantial change, open an issue describing the user outcome, affected trust boundaries, acceptance tests, and any required live Windows proof.
- Do not include third-party installers, application packages, extracted application files, vendor configuration, customer evidence, credentials, private keys, or unredacted traces in this repository, issues, pull requests, releases, or CI artifacts. Obtain test applications separately and keep them outside the checkout.
- Prefer project-owned synthetic fixtures. Do not add app-specific executable adapters, recipe code or product packaging; see [repository scope](docs/REPOSITORY-SCOPE.md).
- Follow the [application-neutral migration](docs/APPLICATION-AGNOSTIC-MIGRATION.md): application facts may be validated declarative fixture data, not product-name/hash admission gates. Extend reusable mechanisms and preserve exact run identity/approval. The seven-fixture corpus is not a supported-app catalog.
- Do not add arbitrary command, script, path, registry, URL, or query execution to a privileged helper.

## Development workflow

Use a focused vertical slice. A pull request should deliver one coherent behavior and include its contracts, implementation, tests, documentation, and recovery/error behavior. Keep contract-changing work serialized and avoid unrelated formatting or refactors.

Run the local checks from the repository root:

```powershell
.\scripts\verify.ps1
.\scripts\audit-dependencies.ps1
```

The verification script is intentionally local and deterministic. Hosted CI runs the same checks on Windows, but CI does not prove that a provider actually isolates an application. A live provider claim requires an explicitly documented Windows 11 24H2 x64 proof with target-token, effective-backend, canary, completeness, and cleanup evidence.

For selected checks, use `scripts/check-local.ps1 -Check Workspace` or
`-Check Platform` (native Windows tests), alongside the existing `Format`,
`Provider`, `Cli`, `Clippy`, `Msrv`, and `Governance` choices. Cargo test checks
use a short, fresh temporary directory per check, retain its location in the logs,
and restore the caller's `TEMP`/`TMP`. This keeps unrelated accumulated files
from exceeding the native verifier's directory-entry bound. `verify.ps1` uses
the same workspace-test path. These selected checks require cached dependencies
(`--locked --offline`).

## Design and security expectations

- Evidence is authoritative; model-generated text is advisory only.
- Imported project content and installer output are untrusted.
- Project files cannot contain free-form commands or scripts.
- Provider execution requires a typed plan, explicit approval, and run-bound journal. Non-executing intake and preparation use explicit create-new operations with protected receipt-bound state and never grant execution authority.
- Unsupported, degraded, incomplete, or ambiguous isolation results are `insufficientEvidence`, never success.
- There is no persistent privileged service and no automatic telemetry.
- Master Packager is a manual export/import handoff; the project must not call or embed it.

## Pull requests

Use the pull request template. Include the exact validation commands and distinguish automated checks, mock-provider evidence, and live Windows evidence. Keep commits reviewable and use the `codex/` branch prefix for branches created by project automation.

Before merging, verify that both `Verify and audit` and `Minimum supported Rust`
completed successfully for the exact final PR head, then merge with that expected
head SHA. Pending, missing, failed, or cancelled checks do not pass. Do not assume
`gh pr merge --auto` waits: without enforced branch protection it can merge
immediately. Repository administrators should enforce these checks on `main`;
until then the explicit check is mandatory. A later successful run does not turn
an earlier cancelled run into successful validation.

Contribute only material you have the right to release under the [Unlicense](LICENSE), including the public-domain dedication. By submitting an original contribution, you agree to provide it under those terms. Disclose copied material and ownership restrictions before submission; a contributor cannot dedicate someone else's rights. Substantial outside contributions should include an explicit dedication from their rights holder.

Third-party dependencies keep their original licenses and notices. The project's license does not relicense them or grant redistribution rights to tested applications. See [license scope](docs/REPOSITORY-SCOPE.md#license-scope) and [supply-chain requirements](docs/SUPPLY-CHAIN-AND-SIGNING.md).
