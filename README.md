# App Isolation Workbench

App Isolation Workbench (AIW) is an experimental, administrator-led laboratory for evaluating existing Windows applications under stronger isolation boundaries. The project aims to make AppContainer/app-silo and ProcessContainer experiments reproducible without pretending that an arbitrary legacy installer can be converted safely with one click.

The repository is private and pre-alpha. It contains versioned project contracts, validation, an append-only hash-chained evidence format, deterministic assessment-bundle manifests, evidence-bound canary evaluation, a strict local-analyst report contract, host and target-token probing, candidate comparison, secure Windows Sandbox configuration rendering, a pinned MXC invocation planner, and CLI/PowerShell surfaces. It does **not** yet run a model, install applications, elevate, launch Windows Sandbox/MXC, create or upload archives, provision or execute canaries, author MSIX packages, or claim that an application ran inside a security boundary.

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
cargo run -p aiw-cli -- probe token
cargo run -p aiw-cli -- provider wsb --plan .\examples\windows-sandbox-plan.json
cargo run -p aiw-cli -- provider wsb-cli --plan .\examples\windows-sandbox-plan.json --binary C:\AIW\SystemTools\wsb.exe --sandbox-id 12345678-1234-abcd-9876-1234567890ab
cargo run -p aiw-cli -- provider wsb-receipt --output-root C:\AIW\Output --expectation .\run\wsb-completion-expectation.json
cargo run -p aiw-cli -- provider mxc --plan .\examples\mxc-golden-probe-plan.json
cargo run -p aiw-cli -- provider mxc-probe --binary C:\AIW\MXC\wxc-exec.exe
cargo run -p aiw-cli -- schema project
cargo run -p aiw-cli -- evidence verify --log .\run\evidence.jsonl
cargo run -p aiw-cli -- bundle build --root . --spec .\examples\assessment-bundle-spec.json
cargo run -p aiw-cli -- bundle verify --root . --manifest .\assessment-bundle-manifest.json
cargo run -p aiw-cli -- canary evaluate --plan .\examples\canary-plan.json --observations .\examples\canary-observations.json --evidence-log .\examples\canary-evidence.jsonl
cargo run -p aiw-cli -- analyst validate --report .\examples\analyst-report.json --evidence-log .\examples\analyst-evidence.jsonl --model-pack .\examples\model-pack.json
cargo run -p aiw-cli -- compare --left .\baseline.json --right .\candidate.json
```

All successful commands emit JSON. Diagnostics go to standard error and a nonzero exit code indicates failure.
The direct Windows Sandbox examples assume `C:\AIW` is an ordinary workspace root, `C:\AIW\Tools` contains `aiw-golden-probe.exe`, and `C:\AIW\Output` exists and is empty; rendering intentionally fails otherwise. The CLI lifecycle command additionally requires an absolute path to the resolved `wsb.exe` interface and a caller-generated UUID. Provider commands return plans only and never start `WindowsSandbox.exe`, `wsb.exe`, or `wxc-exec.exe`.

## Local validation

```powershell
.\scripts\verify.ps1
.\scripts\audit-dependencies.ps1
```

The verification script checks formatting, runs Clippy with warnings denied, runs the full test suite, validates the example project/model pack, exercises host and token probes, renders representative MXC plans, and checks all public schemas. The dependency script validates the lock file and scans it against RustSec using `cargo audit`. The optional `verify-mxc-pin.ps1` script validates representative configs against an exact local MXC source pin without running MXC. No GitHub Actions workflow is enabled yet; early work is intentionally validated locally.

## Repository layout

```text
crates/
  aiw-cli/       Stable command-line contract
  aiw-core/      Run state, canary evaluation, and advisory-report validation
  aiw-evidence/  Canonical JSON, hash-chained evidence, and assessment manifests
  aiw-golden-probe/ In-target token evidence executable
  aiw-probe/     Read-only host/toolchain observations
  aiw-provider-mxc/ Pinned, non-executing MXC plan adapter
  aiw-provider-wsb/ Hardened Windows Sandbox planning and completion verification
  aiw-schema/    Versioned project and model-pack domain contracts
  aiw-token/     Audited native Windows token evidence boundary
  aiw-windows-command-line/ Shared shell-free argument quoting
powershell/      Thin administration wrapper over the CLI
examples/        Non-sensitive project examples
schemas/         Schema generation guidance
docs/            Architecture, threat model, research notes, and roadmap
third-party/     Reviewed external source pins
```

## Status and licensing

This is research software, not a security boundary or production packaging product. No redistribution license has been granted yet. Model/runtime licenses will be reviewed separately before any local-AI artifact is included.

See [Supply chain, bundling, and signing](docs/SUPPLY-CHAIN-AND-SIGNING.md) for the proposed Artifact Signing, per-binary verification, provider pinning, and separately signed model/knowledge-pack design. Current local release builds are intentionally unsigned development artifacts.

See [Assessment bundles](docs/ASSESSMENT-BUNDLES.md) for the deterministic feedback manifest, strict allowlist, advisory-AI separation, and current export/signing limitations.
See [Boundary denial canaries](docs/DENIAL-CANARIES.md) for the synthetic-resource contract, conservative verdict rules, and future provisioner requirements.
See [Local analyst report contract](docs/LOCAL-ANALYST-CONTRACT.md) for cited plain-text output, immutable inference provenance, typed non-executing recommendations, and the Foundry Local integration boundary.
The Windows Sandbox automation research and lifecycle trust contract are documented in [Windows Sandbox automation](docs/WINDOWS-SANDBOX-AUTOMATION.md).
The strict run-bound output and receipt verifier is documented in [Windows Sandbox completion receipts](docs/WINDOWS-SANDBOX-COMPLETION.md).
