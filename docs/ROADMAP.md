# Roadmap

AIW is delivered as two milestones with vertical, evidence-gated slices. The current repository has completed the W0 foundation and has a private, live-proven W1 Windows Sandbox kernel. Fresh protected preparation, process-exit verification, and atomic import into provenance-bound `PendingApproval` state are exposed without provider acquisition; checkpoint-bound depublish is now a private transaction that commits an immutable external record before an exact non-replacing root rename, with recovery across both sides of that rename. Child disposition and the private terminal workspace-cleanup receipt are now bounded transactions over the exact 19 fixed objects; provider execution, public CLI exposure, `RunResult`, and public cleanup UX remain later slices. Production start remains unavailable until its exact approved-start/crash/recovery path passes the public live gate. Application assessment, the desktop UI, and package authoring remain later slices.

## Workbench v1

### W0 — foundation (complete)

- Implement `aiw.dev/v0alpha2` and preserve readable, non-destructive `v0alpha1` migration with an explicit review gate.
- Separate `AssessmentRun`, `LaunchRun`, and `AuthoringRun` lifecycles.
- Establish the shared `aiw-orchestrator` service boundary.
- Add Apache-2.0 licensing, governance, Windows CI, issue/PR gates, and security documentation.

**Exit gate:** old examples migrate without overwriting their source; schemas/CI are stable; no behavior bypasses approval.

### W1 — live Windows Sandbox proof (preparation/recovery exposed; start gate remains)

- Implement the runner kernel, workspace/journal, fixed-function guest agent, short-lived helper boundary, and full Windows Sandbox lifecycle.
- Revalidate plan hashes, provider identity, paths, inputs, output emptiness, and leases immediately before execution.
- Capture host/provider state, process trees, target tokens, completion receipt, and idempotent cleanup.
- Prepare a hash-bound fixed-agent workspace and plans without provider mutation; reopen and verify the exact preparation after process exit; atomically import its plan, provenance receipt, and genesis journal before separate approval.
- Depublish only an exact checkpoint-bound original workspace to its deterministic tombstone: classify original/tombstone/absent/foreign/ambiguous state, publish the immutable external commit first, then perform the exact non-replacing root rename and verify the postcondition.
- Recover before or after the root rename while retaining the commit, checkpoint, intent, and coordination bindings; preserve ambiguous or foreign state and fail closed. Each object record is published before handle-only deletion; accept only a contiguous published prefix with at most one pending record and matching physical prefix. After all 19 records and physical absence, publish the create-new self-bound terminal receipt with the exact retry timestamp. Preserve unrelated original-name replacements; do not mutate a provider, expose a CLI, or claim broad cleanup completion.

**Exit gate:** a real supported host completes the golden probe in an exact sandbox session and verifies receipt, evidence correlation, and cleanup.

### W2 — complete assessment

- Import MSI, EXE, and portable-directory sources with hashes, signer/version/architecture metadata, and non-executing compatibility findings.
- Add typed install/launch/observe/checkpoint/close/update/uninstall/reboot scenarios.
- Add filesystem, registry, process/token, network/UI/IPC, persistence, trace, and residue evidence.
- Add run-bound baseline/candidate synthetic canaries for host file, registry, DNS/TCP, clipboard, and sibling-process boundaries.

**Exit gate:** representative applications produce complete baseline/candidate evidence; missing, timed-out, or ambiguous evidence remains indeterminate.

### W3 — runtime isolation

- Add live Windows Sandbox and MXC ProcessContainer provider slices with requested/effective backend verification.
- Build deterministic comparison and recommendation rules.
- Create drift-checked, on-demand `ValidatedLaunchProfile` replay.

**Exit gate:** supported applications relaunch on demand only while app/provider/OS/policy hashes match; fallback and drift fail closed.

### W4 — recommendations and export

- Build evidence-cited recommendations, secure staging/archive export, offline bundle verification, and sanitized diagnostics.
- Add optional local Analyst output that cannot modify the deterministic verdict.

**Exit gate:** reports cite verified evidence and independently verifiable bundles reject unsafe/unlisted content.

### W5 — Workbench UX and release

- Add the Tauri desktop workflow: dashboard, intake, readiness, typed scenarios, approval, live progress/recovery, evidence explorer, recommendations, profile launch, and bundle export.
- Add accessibility, signed development/release builds, supported-host matrix, and clean-machine acceptance.

**Exit gate:** the complete Workbench acceptance suite passes on supported Windows 11 24H2 x64 without arbitrary execution or hidden telemetry.

## Studio v1

### S0 — Studio contracts and handoff

- Define `StudioRecipe`, authoring plans/receipts, package candidates, signing receipts, and final validation receipts.
- Generate a recipe only from an accepted Workbench assessment.
- Export provider-neutral Master Packager handoff; import external packages as untrusted candidates.

**Exit gate:** every package mutation has a reviewable plan, explicit approval, source/evidence binding, and required final validation.

### S1 — MSIX capture

- Use a checkpointed, clean Hyper-V worker with pinned Microsoft MSIX Packaging Tool/SDK components.
- Author a full-trust MSIX compatibility baseline, capture before/after state, require semantic repeatability, and destroy/revert the worker.

**Exit gate:** two clean captures are semantically comparable; unexpected outputs or dirty cleanup block the run.

### S2 — isolation authoring

- Author AppContainer and preview App Silo candidates.
- Normalize ACP proposals and require review of every capability.
- Return every candidate through the complete Workbench scenarios/canaries.

**Exit gate:** final target and required descendants prove the requested effective boundary with no unexpected FullTrust fallback.

### S3 — remediation, signing, and final validation

- Support only evidence-backed working-directory and package-managed file redirection fixups.
- Sign outside the worker without exposing private keys; preserve upstream signatures.
- Validate the final signed hash on a clean machine through install, launch, update, uninstall, canaries, residue, and cleanup checks.

**Exit gate:** the final validation receipt binds the signed package hash to effective isolation and complete lifecycle evidence.

### S4 — Studio evolution

- Add Studio UI flows, forward migration, documentation, release builds, and the public product rename.
- Keep the `aiw` CLI, technical namespace, and project format stable for existing automation.

**Exit gate:** Studio opens all Workbench projects and completes Assess → Package → Validate without breaking existing CLI contracts.

## Explicitly deferred

CreateProcessInSandbox remains a research lane. Windows 10/ARM64 support, MSI/PSADT/IntuneWin/appinstaller/bundle outputs, arbitrary PSF scripts/custom fixups, enterprise certificate management, fleet management, centralized telemetry, and automatic provider/feature installation are not v1 commitments.
