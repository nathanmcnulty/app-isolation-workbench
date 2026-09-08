# Typed MSI scenario integration

The fixed Notepad++ MSI profile now connects protected intake, preparation, separate import and approval, Windows Sandbox execution, completion verification, and exact-session cleanup. The pure compiler remains available through `provider compile-msi-scenario`; compilation alone grants no execution authority.

## Supported profile

The current v3 sequence is install, launch with one fixed guest document, observe the exact process and a visible window, verify the initial editor content, edit and save fixed replacement text, request graceful close, and require exit code zero. The x64 MSI must match the project hash and be at most 128 MiB. Installer and application arguments must be empty in the project. The guest uses fixed MSI arguments (`/qn /norestart`) and fixed installer/application paths. Install, observation, and close waits are bounded. Reboot-required installer outcomes fail this profile.

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

Required assessment assertions and descendant coverage remain in the project hash. Correlated guest results do not satisfy independent containment measurements: the successful run intentionally remains `insufficientEvidence`. Ordinary baseline comparison, other installers/EXE/portable execution, update/uninstall scenarios, reboot handling, public MSI workspace discard, and complete assessment remain future work. Native process fault injection and abrupt OS/process-loss recovery still need further coverage; the controlled MSI interruption proof below covers the active-session completion boundary. No additional hosted CI was scheduled for this slice.

## Local validation — 2026-09-07

Workspace tests passed: 365 passed, 0 failed, 14 ignored opt-in/helper tests. The live MSI success and pre-start tamper tests passed separately. Workspace/all-target Clippy with warnings denied, formatting, offline Rust 1.85 workspace/all-target compatibility, new CLI command/schema smoke checks, governance checks, and changed-document local links passed. Independent code review found no material defect. Logs remain under `%TEMP%` as `aiw-msi-workspace-tests.log` and `aiw-msi-msrv.log`. Hosted validation remains separate and was not rerun.

## Interrupted MSI recovery — 2026-09-07

The ignored `live_msi_interrupted_completion_rejects_foreign_request_and_recovers` test passed in 93.24 seconds using the same static guest and protected MSI intake. It runs preparation/import/approval, holds the verified imported inputs, executes the real guest scenario, and deliberately omits normal cleanup/result publication. This models a controlled interruption at guest completion, not an OS crash.

The fixture then substitutes a structurally valid request with a foreign run ID and a recomputed canonical hash. Public recovery stops the exact Sandbox but rejects request cleanup, preserves the substituted bytes, records `recoveryRequired`, and publishes no terminal result. The test restores its retained original request bytes and retries public recovery. Cleanup verifies, the request is removed, and the terminal result is `failed` with no evidence root. Repeating recovery preserves result and journal bytes. No Sandbox sessions remain. Restoring injected test bytes is fixture behavior; production recovery never repairs or adopts foreign authority.

Evidence remains in `%TEMP%\msi-recovery-8916-1788816767718926800`; the live log is `%TEMP%\aiw-msi-recovery-live.log`. Session ID: `0b3d92f5-ac15-0e8b-4422-432e8cd9578a`. Guest output reports successful installation and graceful close (PID 412, both exit codes zero), but recovery intentionally does not promote that output into successful assessment evidence. This test changed no production behavior and scheduled no CI.

Deterministic runner coverage also rejects a structurally successful scenario result bound to a different scenario after exact cleanup, requiring the specific result-binding error and a failed terminal result without an evidence root. A separate control proves that a matching stale request and partial staging can be cleaned before a successful retry. The integrated runner suite passed 62 tests with four opt-in tests ignored; the new native recovery test passed separately. Formatting and warning-denied runner/all-target Clippy passed. The previous full-workspace results remain the baseline; this tests-only follow-up did not rerun unrelated suites or hosted CI.

## Candidate application token evidence

The earlier token slice introduced compiled-scenario and Notepad++ profile `v0alpha2`. The profile version requires a launched-application token snapshot and is included in the scenario hash, preparation, imported action, request, and approval bindings. Fresh execution requires new preparation and approval with the measured current guest agent. Existing v0alpha1 requests remain readable for exact-session recovery; an older prepared application plan is not silently upgraded.

The guest collects the token through the retained launched process handle after observing its window and before requesting close. PID is obtained from that same handle, with no reopen by PID. The typed `importedMsiApplicationToken` event is included in `evidence.jsonl` before completion. Host verification rechecks that log against the completion-verified evidence root, rejects duplicate/foreign/malformed observations, and binds the snapshot to the exact request, scenario, and launched PID. Missing token evidence rejects v0alpha2 execution. Explicit legacy v0alpha1 logs may report it missing.

`run start` exposes the observation as `applicationToken` in imported-MSI execution `v0alpha2`; a legacy result without the observation retains execution `v0alpha1`. `schema msi-application-token` describes the observation. This is a guest-captured root-process snapshot, not independent host evidence or descendant coverage. It does not establish baseline comparability, satisfy containment assertions, or change the terminal `insufficientEvidence` assessment. A disposable ordinary baseline and comparison eligibility remain separate work.

The candidate-token slice passed 108 focused local tests across provider, runner, token, CLI, and guest-agent targets (four runner opt-in tests ignored), plus the separate live v0alpha2 MSI test. Workspace/all-target Clippy with warnings denied, Rust 1.85 workspace/all-target compatibility, formatting, governance, schema generation, and v0alpha2 compilation checks passed. Independent native and integration review found no material defect. Full workspace and hosted CI were not repeated; the prior broad suite remains the baseline. See [the measured fixture](FIXTURE-NOTEPAD-PLUS-PLUS-8.9.8.md#candidate-token-snapshot--2026-09-07).

## Fixed functional exercise and file observations

New compilation emits profile `v0alpha3`, including a `documentExercise` with the fixed guest-local document path and initial/expected hashes. The project still supplies no execution arguments. Preparation and approval bind this compiled profile; old plans are never silently upgraded. Explicit v1/v2 requests remain readable for recovery and historical reporting.

The guest creates `C:\AIW\Scenario\document.txt` and passes only that fixed argument to the fixed Notepad++ executable. Bounded Windows messages inspect the same-PID visible window and Scintilla editor, verify the initial content, select all, type the fixed printable text and an Enter key message, verify the edited content, and invoke the fixed Save command. The guest retains the fixed directory ancestry and creates/observes the document through relative handles. The Scenario directory permits normal atomic saved-file replacement; its name and ordinary identity are revalidated against the held parent before observation and after close. Saved bytes are measured through a retained, bounded read handle. Every UI message rechecks the owning process, and startup readiness uses a bounded retry deadline. No caller-controlled script, clipboard, or custom cross-process pointer message is used. Failed exercise or cleanup produces no accepted success evidence.

Three guest snapshots surround installation and application use. The fixed roots, capture bounds, incompleteness rules, and packaging implications are described in [assessment reporting](ASSESSMENT-REPORT.md#functional-and-filesystem-observations). A mandatory `importedMsiBehavior` event binds the exercise and snapshots to the request/scenario, inside the completion-verified evidence chain. Missing, foreign, duplicate, malformed, or wrong-profile behavior is rejected. Behavior cannot be retroactively attached to a legacy profile. The bounded application evidence log is at most 8 MiB with at most 128 records.

Imported-MSI execution uses `v0alpha3` when behavior is present. Retained reports use `v0alpha2` and provide both raw observations and installation/exercise file diffs. `run report-wsb-msi --format markdown` produces a readable summary; JSON remains the default and includes complete file-change lists. Neither output promotes these guest measurements into containment proof or a complete compatibility verdict.

The UI implementation follows the upstream [Notepad++ command IDs](https://github.com/notepad-plus-plus/notepad-plus-plus/blob/master/PowerEditor/src/menuCmdID.h), [Scintilla Windows message handling](https://github.com/notepad-plus-plus/notepad-plus-plus/blob/master/scintilla/win32/ScintillaWin.cxx), and [Microsoft bounded message API](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagetimeoutw). Live validation against the recorded installer remains the behavior check; source inspection alone is not a passed application exercise.
