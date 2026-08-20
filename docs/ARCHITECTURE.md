# Architecture

## Objective

AIW is a controlled comparison laboratory. It runs the same application and scenarios across an ordinary Win32 baseline and one or more isolation candidates, then produces normalized evidence and a product-feedback-ready comparison.

```text
CLI / PowerShell / future UI (ordinary user)
                    |
          deterministic orchestrator
          /          |            \
 read-only probe  evidence log   provider adapters
                                  |
                        disposable worker boundary
```

The repository begins with contracts that do not require elevation. Direct Windows Sandbox and MXC plan adapters now sit behind narrow typed interfaces; neither adapter launches a process. Hyper-V, MSIX Packaging Tool, ACP, PSF, and signing remain future providers.

## Current components

- `aiw-schema`: strict deserialization and semantic validation for projects and model packs.
- `aiw-evidence`: an append-only JSON-lines record chain plus deterministic, allowlisted assessment manifests using integer-only canonical JSON and SHA-256.
- `aiw-core`: legal run-state transitions, deterministic scenario comparison, conservative boundary-canary evaluation, and advisory-report validation against verified evidence.
- `aiw-probe`: read-only environment and executable discovery. It does not execute discovered tools.
- `aiw-token`: the isolated native Win32 boundary for querying the exact target process token.
- `aiw-golden-probe`: a small in-target executable that emits versioned token evidence to stdout or a new output file.
- `aiw-provider-wsb`: validates mapped-folder intent, renders deterministic hardened `.wsb` XML, produces inspectable `wsb` lifecycle plans, and verifies run-bound completion receipts without launching the sandbox.
- `aiw-provider-mxc`: serializes the pinned MXC contract and returns inspectable dry-run/execution plans without running them.
- `aiw-windows-command-line`: shared, shell-free Windows argument quoting.
- `aiw-cli`: the stable JSON command surface consumed by PowerShell and the future desktop UI.

## Planned boundaries

```text
ordinary-user orchestrator
        |
        +-- short-lived elevated helper
        |      fixed verbs: worker setup, trace control, package deployment
        |
        +-- MXC process adapter (plan-only today)
        |
        +-- Windows Sandbox or checkpointed Hyper-V worker
                 |
                 +-- native guest agent
                 +-- untrusted installer/application
```

No first-release component will run as a persistent SYSTEM service. The elevated helper will use owner-bound IPC, caller validation, canonical paths, bounded messages, and fixed operation schemas.

## Local AI

An optional host-side AIW Analyst will consume only bounded normalized evidence. Inference providers, models, and knowledge corpora are separate trust classes. AI output is a cited hypothesis and cannot mutate project state. Model/knowledge packs are content-only, signed, hashed, versioned, and independently revocable.

## Compatibility posture

Backend support is evidence, not configuration intent. A run records the requested backend, effective backend, target token, process descendants, policy hash, worker/OS provenance, trace completeness, and cleanup outcome. Unsupported or silently degraded execution invalidates isolation conclusions.

See [Runtime evidence foundation](RUNTIME-EVIDENCE.md) for the dated API/source snapshot and [Updating the MXC pin](MXC-PIN-UPDATE.md) for the required review process.
The proposed distribution and local-model trust split is documented in [Supply chain, bundling, and signing](SUPPLY-CHAIN-AND-SIGNING.md).
The product-feedback artifact boundary is documented in [Assessment bundles](ASSESSMENT-BUNDLES.md).
The provider-neutral negative-test contract is documented in [Boundary denial canaries](DENIAL-CANARIES.md).
The provider-neutral inference output boundary is documented in [Local analyst report contract](LOCAL-ANALYST-CONTRACT.md).
The Windows Sandbox lifecycle split and mapped-output limitations are documented in [Windows Sandbox automation](WINDOWS-SANDBOX-AUTOMATION.md).
The guest-to-host terminal output contract is documented in [Windows Sandbox completion receipts](WINDOWS-SANDBOX-COMPLETION.md).
