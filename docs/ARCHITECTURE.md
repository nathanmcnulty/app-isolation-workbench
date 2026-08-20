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

The repository begins with contracts that do not require elevation. Windows Sandbox, Hyper-V, MXC, MSIX Packaging Tool, ACP, PSF, and signing integrations will be separate provider crates behind narrow typed interfaces.

## Current components

- `aiw-schema`: strict deserialization and semantic validation for projects and model packs.
- `aiw-evidence`: an append-only JSON-lines record chain using deterministic, integer-only canonical JSON and SHA-256.
- `aiw-core`: legal run-state transitions and deterministic scenario/assertion comparison.
- `aiw-probe`: read-only environment and executable discovery. It does not execute discovered tools.
- `aiw-cli`: the stable JSON command surface consumed by PowerShell and the future desktop UI.

## Planned boundaries

```text
ordinary-user orchestrator
        |
        +-- short-lived elevated helper
        |      fixed verbs: worker setup, trace control, package deployment
        |
        +-- MXC process adapter
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
