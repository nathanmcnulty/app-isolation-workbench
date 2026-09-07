# Typed MSI scenario integration

The fixed Notepad++ MSI profile now connects protected intake, preparation, separate import and approval, Windows Sandbox execution, completion verification, and exact-session cleanup. The pure compiler remains available through `provider compile-msi-scenario`; compilation alone grants no execution authority.

## Supported profile

The sequence is install, launch, observe the exact process and a visible window, request graceful close, and require exit code zero. The x64 MSI must match the project hash and be at most 128 MiB. Installer and application arguments must be empty in the project. The guest uses fixed MSI arguments (`/qn /norestart`) and fixed installer/application paths. Install, observation, and close waits are bounded. Reboot-required installer outcomes fail this profile.

Preparation holds and verifies the v0alpha2 intake receipt and payload, copies only held bytes to `tools\application.msi`, and binds staged identity/content, intake receipt, compiled scenario, project revision, provider, agent, and protected workspace. The tools mapping remains read-only. The original intake must remain available and valid through start.

The imported MSI action uses run-plan v0alpha4 with preparation and planning-import receipts v0alpha2. Golden profiles retain their existing versions. Import and approval are distinct operations. Public `run start` dispatches only from the approved preparation; it accepts no new installer, arguments, or scenario. The golden-only API rejects MSI approval. Private golden workspace discard rejects MSI workspaces.

The guest assigns suspended processes to kill-on-close jobs before resuming them. It records install and launch exit codes, exact process observation, and graceful-close outcome. Failures produce bounded diagnostics without a successful completion receipt. Successful execution publishes `scenario-result.json` and evidence before the completion receipt. The host verifies request/result bindings after exact cleanup; interrupted attempts reuse the persisted recovery lifecycle.

## Review and execution flow

```powershell
cargo run -p aiw-cli -- provider compile-msi-scenario --project .\examples\notepad-plus-plus-msi.aiw.yaml --scenario install-launch-close
cargo run -p aiw-cli -- run prepare-wsb-msi --run-id <fresh-id> --project .\examples\notepad-plus-plus-msi.aiw.yaml --guest-agent <absolute-path> --guest-agent-sha256 <independent-sha256> --workspace-parent <canonical-existing-local-directory> --created-at <timestamp> --import-receipt <saved-v2-msi-receipt.json> --scenario install-launch-close
```

Review the prepared plan and trust deltas. Use the shared `verify-prepared-wsb`, `import-prepared-wsb`, `approve`, and `start` commands documented in the README with the same MSI project, workspace, run ID, and independent agent hash. Approval must bind the imported plan; preparation does not create approval. The example provider identity is a planning placeholder, replaced by the observed trusted provider binding during preparation.

## Evidence and remaining scope

A local live test on 2026-09-07 installed the recorded Notepad++ 8.9.8 MSI inside Windows Sandbox, observed its visible process, closed it with WM_CLOSE, verified exit code zero, and confirmed exact cleanup with zero remaining Sandbox sessions. A separate staged-byte tamper test rejected start before request/session creation. See [the fixture evidence](FIXTURE-NOTEPAD-PLUS-PLUS-8.9.8.md).

Required assessment assertions and descendant coverage remain in the project hash. Correlated guest results do not satisfy independent containment measurements: the successful run intentionally remains `insufficientEvidence`. Ordinary baseline comparison, other installers/EXE/portable execution, update/uninstall scenarios, reboot handling, public MSI workspace discard, and complete assessment remain future work. Native fault injection and MSI-specific interrupted recovery need further live coverage. No additional hosted CI was scheduled for this slice.

## Local validation — 2026-09-07

Workspace tests passed: 365 passed, 0 failed, 14 ignored opt-in/helper tests. The live MSI success and pre-start tamper tests passed separately. Workspace/all-target Clippy with warnings denied, formatting, offline Rust 1.85 workspace/all-target compatibility, new CLI command/schema smoke checks, governance checks, and changed-document local links passed. Independent code review found no material defect. Logs remain under `%TEMP%` as `aiw-msi-workspace-tests.log` and `aiw-msi-msrv.log`. Hosted validation remains separate and was not rerun.
