# App Isolation Workbench

App Isolation Workbench (AIW) is free, open-source research software for assessing existing Windows applications under stronger isolation boundaries. The product has two milestones:

1. **Workbench v1** assesses MSI, EXE, and portable-directory applications, compares ordinary and isolated execution, records inspectable evidence, makes deterministic recommendations, and replays validated profiles on demand.
2. **Studio v1** retains Workbench and adds first-party MSIX/AppContainer authoring, narrowly scoped remediation, signing, and final-package validation.

The delivery sequence is `contracts -> live runner -> evidence/scenarios -> recommendations/launch -> Workbench -> package authoring -> package validation -> Studio`.

## Current status

The repository implements the W0 contract-and-governance foundation plus the W1 Windows Sandbox native proof boundary. It validates the typed `aiw.dev/v0alpha2` project contract, reads `v0alpha1`, and migrates legacy projects to a new file with an explicit review gate. It contains three validated run lifecycles, a shared file-backed orchestrator, hash-bound plans and approvals, append-only run journals, versioned schemas, hash-chained evidence, deterministic comparison and canary contracts, read-only host/token probes, secure Windows Sandbox and MXC plan adapters, completion-receipt verification, and JSON CLI/PowerShell surfaces. `aiw host assess` verifies the installed Windows Sandbox Store package, catalog membership, held file identity, pinned CLI protocol, and bounded current-session observation. Opt-in Windows tests prove the typed leased start/list/connect/exact-stop lifecycle and the measured guest agent's token evidence, evidence chain, bound completion receipt, and cleanup on a real host. The private runner additionally binds the canonical identity of a protected owner-and-SYSTEM-only workspace into its approved action, start request, durable session transaction, status observation, and terminal execution evidence, while retaining the workspace handles throughout the live attempt. Native WSB calls use an exact verified image and shell-free command line, start suspended, receive only an explicit standard-handle list, join a kill-on-close job before any provider code runs, and obey bounded output, an invocation deadline, and a fixed cleanup allowance. The pinned packaged CLI requires its provider-managed process topology to survive successful calls, so the launcher removes kill-on-close only after the exact CLI root exits zero and both output streams complete within the deadline. Launch/wait failure, timeout, nonzero exit, and output-capture failure retain whole-job cleanup; later protocol-validation failures on mutating calls remain governed by the durable exact-session transaction. The public start path remains deliberately disabled until an approved start, crash, and exact recovery pass their production CLI live gate. The project does **not** yet run a model, install or launch imported applications, elevate, execute Windows Sandbox/MXC through `aiw run start`, provision canaries, create archives, provide the Tauri UI, author MSIX packages, sign packages, or prove that an imported application ran inside an isolation boundary.

Preparation and recovery update: `aiw run prepare-wsb` now creates a fresh protected workspace, holds and hash-pins the explicitly selected fixed-function guest agent, observes an empty trusted provider state, and writes `plan.json`, `wsb-plan.json`, and a final `preparation.json` completeness marker without acquiring or mutating Windows Sandbox. `aiw run verify-prepared-wsb` reopens the exact workspace after process exit and revalidates its ACL/file identities, artifact allowlist and hashes, empty output, project revision, agent, provider, package, catalog, protocol, and empty session state. `aiw run import-prepared-wsb` retains those authority handles while atomically publishing the plan, receipt-bound genesis journal, and `wsb-planning-import.json` into authoritative `PendingApproval` state. `--imported-at` is an operator-supplied receipt timestamp and must be reused exactly for an idempotent retry. Exact retries are non-mutating; generic `run plan` cannot import a WSB action. After irreversible logical revocation and protected-intent publication, the private discard workflow acquires outer-only authority and materializes and verifies an in-memory portable semantic inventory of exactly 19 objects. It records stable IDs, paths, types, ACL/link/stream/attribute policy, file sizes and hashes, and EA names/flags/lengths/hashes; unstable queried-byte counts are excluded. The inventory is not persisted and does not create a journal/head or external checkpoint. Live exact reopen detects drift. The only intent-bound tombstone convention is `.aiw-discarded-v1-<cleanupId>`. This slice still performs no workspace rename/delete, provider mutation, public discard CLI, or cleanup claim; #40 checkpoint and #39 depublish remain deferred. Approval remains a separate command. `aiw run recover --root <root> --run-id <id>` derives its mutation authority only from persisted hash-bound state. The disabled runner statement now applies specifically to `aiw run start`.

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

These commands exercise the current contract and plan surfaces. Preparation mutates only its new local workspace; none of them starts or acquires a provider:

```powershell
cargo run -p aiw-cli -- project validate --path .\examples\minimal.aiw.yaml
cargo run -p aiw-cli -- probe host
cargo run -p aiw-cli -- probe token
cargo run -p aiw-cli -- run prepare-wsb --run-id <fresh-id> --project .\examples\minimal.aiw.yaml --guest-agent <absolute-path> --guest-agent-sha256 <lowercase-sha256> --workspace-parent <canonical-existing-local-directory> --created-at <timestamp>
cargo run -p aiw-cli -- run verify-prepared-wsb --workspace <workspace-from-prepare> --project .\examples\minimal.aiw.yaml --guest-agent-sha256 <same-independently-obtained-lowercase-sha256>
cargo run -p aiw-cli -- run import-prepared-wsb --workspace <workspace-from-prepare> --project .\examples\minimal.aiw.yaml --guest-agent-sha256 <same-independently-obtained-lowercase-sha256> --imported-at <timestamp>
cargo run -p aiw-cli -- provider wsb --plan .\examples\windows-sandbox-plan.json
cargo run -p aiw-cli -- provider mxc --plan .\examples\mxc-golden-probe-plan.json
cargo run -p aiw-cli -- schema project
cargo run -p aiw-cli -- evidence verify --log .\run\evidence.jsonl
cargo run -p aiw-cli -- bundle verify --root . --manifest .\assessment-bundle-manifest.json
cargo run -p aiw-cli -- canary evaluate --plan .\examples\canary-plan.json --observations .\examples\canary-observations.json --evidence-log .\examples\canary-evidence.jsonl
cargo run -p aiw-cli -- compare --left .\baseline.json --right .\candidate.json
```

All successful commands emit JSON. Diagnostics go to standard error and a nonzero exit code indicates failure. Preparation requires an independently obtained agent hash, leaves the run `pendingApproval`, never writes approval or provider-session state, and preserves incomplete workspaces for explicit inspection. Provider commands return plans only and never start `WindowsSandbox.exe`, `wsb.exe`, or `wxc-exec.exe`.

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
