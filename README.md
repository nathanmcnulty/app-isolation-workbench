# App Isolation Workbench

App Isolation Workbench (AIW) is free, open-source research software for assessing existing Windows applications under stronger isolation boundaries. The product has two milestones:

1. **Workbench v1** assesses MSI, EXE, and portable-directory applications, compares ordinary and isolated execution, records inspectable evidence, makes deterministic recommendations, and replays validated profiles on demand.
2. **Studio v1** retains Workbench and adds first-party MSIX/AppContainer authoring, narrowly scoped remediation, signing, and final-package validation.

The delivery sequence is `contracts -> live runner -> evidence/scenarios -> recommendations/launch -> Workbench -> package authoring -> package validation -> Studio`.

## Current status

The repository implements the W0 contract-and-governance foundation plus the first W1 Windows Sandbox native boundary. It validates the typed `aiw.dev/v0alpha2` project contract, reads `v0alpha1`, and migrates legacy projects to a new file with an explicit review gate. It contains three validated run lifecycles, a shared file-backed orchestrator, hash-bound plans and approvals, append-only run journals, versioned schemas, hash-chained evidence, deterministic comparison and canary contracts, read-only host/token probes, secure Windows Sandbox and MXC plan adapters, completion-receipt verification, and JSON CLI/PowerShell surfaces. `aiw host assess` now verifies the installed Windows Sandbox Store package, catalog membership, held file identity, pinned CLI protocol, and bounded current-session observation. An explicit ignored Windows test proves the typed leased start/list/exact-stop lifecycle on a real host. The user-facing runner remains deliberately disabled until workspace ownership and crash recovery are complete. The project does **not** yet run a model, install or launch applications, elevate, execute Windows Sandbox/MXC through `aiw run start`, provision canaries, create archives, provide the Tauri UI, author MSIX packages, sign packages, or prove that an application ran inside an isolation boundary.

The initial live target is Windows 11 24H2 (build 26100+) x64. Provider support is capability-gated and must be established by live evidence; hosted CI validates contracts and code only. Windows 10 and ARM64 are deferred. There is no automatic telemetry, persistent privileged service, automatic feature enablement, or model authority over verdicts.

## Product boundaries

- Evidence is authoritative; optional local-AI prose is cited, advisory, and non-executing.
- Raw installers, project fields, worker output, provider output, and model content are untrusted.
- Every mutating operation uses the shared run boundary: a typed hash-bound plan, exact approval, append-only journal, fail-closed recovery, and terminal cleanup evidence. Provider execution remains disabled until its later slice proves the same invariants live.
- Unsupported, degraded, incomplete, or ambiguous isolation remains `insufficientEvidence`, never success.
- Workbench launches validated applications on demand; it is not a background application-management service.
- Studio keeps delivery (`containedMsix`) separate from runtime boundary (`mediumIlFullTrust`, `appContainer`, or preview `appSiloPreview`). A converted full-trust MSIX is not an isolation claim.
- Master Packager is a manual export/import handoff. AIW will not call, embed, or automate it without a separate vendor authorization.

## Current CLI

These commands exercise the current contract and plan surfaces; they do not execute providers:

```powershell
cargo run -p aiw-cli -- project validate --path .\examples\minimal.aiw.yaml
cargo run -p aiw-cli -- probe host
cargo run -p aiw-cli -- probe token
cargo run -p aiw-cli -- provider wsb --plan .\examples\windows-sandbox-plan.json
cargo run -p aiw-cli -- provider mxc --plan .\examples\mxc-golden-probe-plan.json
cargo run -p aiw-cli -- schema project
cargo run -p aiw-cli -- evidence verify --log .\run\evidence.jsonl
cargo run -p aiw-cli -- bundle verify --root . --manifest .\assessment-bundle-manifest.json
cargo run -p aiw-cli -- canary evaluate --plan .\examples\canary-plan.json --observations .\examples\canary-observations.json --evidence-log .\examples\canary-evidence.jsonl
cargo run -p aiw-cli -- compare --left .\baseline.json --right .\candidate.json
```

All successful commands emit JSON. Diagnostics go to standard error and a nonzero exit code indicates failure. Provider commands return plans only and never start `WindowsSandbox.exe`, `wsb.exe`, or `wxc-exec.exe`.

## Local validation

```powershell
.\scripts\verify.ps1
.\scripts\audit-dependencies.ps1
```

`verify.ps1` runs formatting, Clippy with warnings denied, the workspace tests, representative contract/plan commands, schema generation, and governance-file checks. `verify.ps1 -GovernanceOnly` checks the Apache-2.0 license, required documentation/templates, required status language, and that every GitHub Action is pinned to a full commit SHA. `audit-dependencies.ps1` validates the locked metadata and runs RustSec `cargo audit`.

## Architecture and roadmap

The shared `aiw-orchestrator` service boundary is called directly by the CLI and will also be called by the future Tauri backend; the desktop application will not automate the CLI as a subprocess. The implemented lifecycles are `AssessmentRun`, `LaunchRun`, and `AuthoringRun`. Authoritative state remains inspectable on disk: immutable plans, per-run journals and evidence JSONL, content-addressed artifacts, approvals, and terminal receipts.

See [Architecture](docs/ARCHITECTURE.md), [Roadmap](docs/ROADMAP.md), and [Threat model](docs/THREAT-MODEL.md) for the detailed contracts and release gates. Supporting contracts are documented in [Assessment bundles](docs/ASSESSMENT-BUNDLES.md), [Boundary denial canaries](docs/DENIAL-CANARIES.md), [Local analyst report contract](docs/LOCAL-ANALYST-CONTRACT.md), [Windows Sandbox automation](docs/WINDOWS-SANDBOX-AUTOMATION.md), and [Windows Sandbox completion receipts](docs/WINDOWS-SANDBOX-COMPLETION.md).

## Repository layout

```text
crates/             Rust contracts, probes, evidence, planners, CLI, and native probe
powershell/         Thin administration wrapper over the CLI
examples/           Non-sensitive project and evidence examples
schemas/            Schema generation guidance
docs/               Architecture, threat model, research notes, and roadmap
third-party/        Reviewed external source pins
scripts/            Local verification, dependency, and provider-pin checks
```

## Licensing and security

The project is licensed under the [Apache License 2.0](LICENSE). Third-party components retain their own licenses; model/runtime licenses will be reviewed separately before distribution. See [CONTRIBUTING.md](CONTRIBUTING.md) for focused vertical-slice guidance and [SECURITY.md](SECURITY.md) for private vulnerability reporting and non-negotiable boundaries.
