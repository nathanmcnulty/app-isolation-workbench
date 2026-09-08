# Retained MSI assessment report

`run report-wsb-msi` rebuilds a deterministic JSON report from a completed Windows Sandbox MSI workspace. It returns the verified scenario and guest root-process token observation, the original project requirements, unmeasured scenarios, and missing assessment evidence. The outcome remains `insufficientEvidence`; successful install/close observations do not produce a compatibility recommendation or containment verdict.

```powershell
cargo run -p aiw-cli -- run report-wsb-msi --root <original-workspace> --run-id <original-run-id> --project <original-project> --guest-agent-sha256 <original-independent-agent-sha256>
cargo run -p aiw-cli -- schema wsb-msi-assessment-report
```

The command reads the committed terminal journal, approval/import provenance, preparation, plans, and completed session transaction. It retains native workspace, root-file, agent, MSI, and output handles while reconstructing the approved request and verifying the completion receipt, artifact hashes, evidence chain, token bindings, and terminal evidence root. Pending or conflicting state, changed binaries/project/agent hash, unexpected output, failed/recovered runs without accepted evidence, or uncommitted results are rejected. Errors use `AIW_WSB_REPORT_REJECTED` and retain the run ID.

Reporting never acquires a provider lease, invokes a provider, repairs a journal, creates run locks, or modifies workspace files. The original intake and currently installed provider are not queried. Retained binaries and the original project must still match their recorded authority. Explicit legacy v1 profile requests remain readable; all action fields are compared against the supported compiler while retaining the historical evidence-version requirement.

`recordedCleanupVerified` means the persisted transaction and terminal result record verified cleanup. It is not a fresh check of current Sandbox sessions. Reverified guest evidence remains guest-reported rather than independent host evidence. In particular, `applicationToken` may be present while `targetToken` remains in `missingEvidence`: the snapshot does not discharge the project's required isolation assertion. Requested assertions are preserved verbatim and no assertion is silently marked passed.

Missing evidence includes ordinary baseline observations, independent host measurements, filesystem/registry changes, network/UI/IPC observations, persistence/residue, and project-required descendant, canary, backend, capture-completeness, and target-token evidence. `unmeasuredScenarios` lists project scenarios other than the one recorded in this run. This command does not accept arbitrary summaries as verified inputs to the existing descriptive `compare` command.

## Validation

The retained Notepad++ v2 fixture was reported twice with identical JSON. A before/after inventory verified unchanged directory names and file bytes. Wrong project/hash inputs and an injected extra output file were rejected. The test removed only its own create-new extra file; the report itself performed no writes. No new Sandbox or CI run was needed. The original fixture and recovery proofs remain documented in [the fixture record](FIXTURE-NOTEPAD-PLUS-PLUS-8.9.8.md).

Local validation passed: 55 orchestrator tests, 62 runner tests (four opt-in tests ignored), 13 CLI tests, and the retained-workspace read-only/drift test. Workspace/all-target Clippy, formatting, governance, schema generation, and CLI success/structured-error smoke checks passed. Independent review identified and corrected the target-token assertion accounting; no other material issue remained. Full workspace tests, Sandbox execution, and hosted CI were not repeated for this reporting slice.
