# App Isolation Workbench

App Isolation Workbench (AIW) is an experimental, administrator-led laboratory for evaluating existing Windows applications under stronger isolation boundaries. The project aims to make AppContainer/app-silo and ProcessContainer experiments reproducible without pretending that an arbitrary legacy installer can be converted safely with one click.

The repository is private and pre-alpha. It currently contains the deterministic foundation only: versioned project contracts, validation, an append-only hash-chained evidence format, host probing, candidate comparison, and a CLI/PowerShell surface. It does **not** yet install applications, elevate, control Windows Sandbox, author MSIX packages, or launch an application in a security boundary.

## Product principles

- Evidence is authoritative; AI-generated text is advisory.
- An accepted proposal always creates a new disposable validation run.
- The first release has no long-running privileged service.
- Helpers will expose fixed typed verbs, never arbitrary command execution.
- Raw installers and worker output are untrusted.
- Every effective backend, token, policy, package, OS build, and cleanup result must be recorded.
- Local AI is optional and cannot grant, mutate, sign, install, deploy, or execute.

## Current CLI

```powershell
cargo run -p aiw-cli -- project validate --path .\examples\minimal.aiw.yaml
cargo run -p aiw-cli -- probe host
cargo run -p aiw-cli -- schema project
cargo run -p aiw-cli -- evidence verify --log .\run\evidence.jsonl
cargo run -p aiw-cli -- compare --left .\baseline.json --right .\candidate.json
```

All successful commands emit JSON. Diagnostics go to standard error and a nonzero exit code indicates failure.

## Local validation

```powershell
.\scripts\verify.ps1
.\scripts\audit-dependencies.ps1
```

The verification script checks formatting, runs Clippy with warnings denied, runs the full test suite, validates the example project and model pack, and exercises schema and host-probe output. The dependency script validates the lock file and scans it against RustSec using `cargo audit`. No GitHub Actions workflow is enabled yet; early work is intentionally validated locally.

## Repository layout

```text
crates/
  aiw-cli/       Stable command-line contract
  aiw-core/      Run state machine and deterministic comparison
  aiw-evidence/  Canonical JSON and hash-chained evidence
  aiw-probe/     Read-only host/toolchain observations
  aiw-schema/    Versioned project and model-pack domain contracts
powershell/      Thin administration wrapper over the CLI
examples/        Non-sensitive project examples
schemas/         Schema generation guidance
docs/            Architecture, threat model, and roadmap
```

## Status and licensing

This is research software, not a security boundary or production packaging product. No redistribution license has been granted yet. Model/runtime licenses will be reviewed separately before any local-AI artifact is included.
