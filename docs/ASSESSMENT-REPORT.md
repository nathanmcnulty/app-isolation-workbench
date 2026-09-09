# Retained MSI assessment report

`run report-wsb-msi` rebuilds a deterministic JSON report from a completed Windows Sandbox MSI workspace. It returns the verified scenario, guest root-process token observation, and available functional and filesystem observations, the original project requirements, unmeasured scenarios, and missing assessment evidence. The outcome remains `insufficientEvidence`; successful application function observations do not produce a compatibility recommendation or containment verdict.

```powershell
cargo run -p aiw-cli -- run report-wsb-msi --root <original-workspace> --run-id <original-run-id> --project <original-project> --guest-agent-sha256 <original-independent-agent-sha256>
cargo run -p aiw-cli -- run report-wsb-msi --root <original-workspace> --run-id <original-run-id> --project <original-project> --guest-agent-sha256 <original-independent-agent-sha256> --format markdown
cargo run -p aiw-cli -- schema wsb-msi-assessment-report
```

The command reads the committed terminal journal, approval/import provenance, preparation, plans, and completed session transaction. It retains native workspace, root-file, agent, MSI, and output handles while reconstructing the approved request and verifying the completion receipt, artifact hashes, evidence chain, token bindings, and terminal evidence root. Pending or conflicting state, changed binaries/project/agent hash, unexpected output, failed/recovered runs without accepted evidence, or uncommitted results are rejected. Errors use `AIW_WSB_REPORT_REJECTED` and retain the run ID.

Reporting never acquires a provider lease, invokes a provider, repairs a journal, creates run locks, or modifies workspace files. The original intake and currently installed provider are not queried. Retained binaries and the original project must still match their recorded authority. Explicit legacy v1, v2 and v3 profile requests remain readable; all action fields are compared against the supported compiler while retaining the historical evidence-version requirement.

`recordedCleanupVerified` means the persisted transaction and terminal result record verified cleanup. It is not a fresh check of current Sandbox sessions. Reverified guest evidence remains guest-reported rather than independent host evidence. In particular, `applicationToken` may be present while `targetToken` remains in `missingEvidence`: the snapshot does not discharge the project's required isolation assertion. Requested assertions are preserved verbatim and no assertion is silently marked passed.

Missing evidence includes ordinary baseline observations, independent host measurements, filesystem/registry changes, network/UI/IPC observations, persistence/residue, and project-required descendant, canary, backend, capture-completeness, and target-token evidence. `unmeasuredScenarios` lists project scenarios other than the one recorded in this run. This command does not accept arbitrary summaries as verified inputs to the existing descriptive `compare` command.


Markdown exports summarize function results and show up to 100 file changes per phase. Any additional changes remain in the complete JSON output; the Markdown explicitly reports the omitted count. Neither format writes to the retained workspace.

## Functional and filesystem observations

Both v3 and v4 runs require a fixed document round trip and three bounded filesystem snapshots in the receipt-bound `importedMsiBehavior` event. The report exposes `behavior.functionalExercise`, `installationFileChanges` (before installation to after installation), and `exerciseFileChanges` (after installation to after the application closes). Legacy reports omit these fields; absence means not measured, never passed. Reports with this evidence use `aiw.dev/wsb-msi-assessment-report/v0alpha2`.

The fixed exercise opens `C:\AIW\Scenario\document.txt`, verifies the initial content through the exact launched application's editor, replaces it with fixed text, asks the application to save, and verifies the saved file hash. It exercises one small text document. It does not establish that plugins, networking, updates, printing, or other application features work.

Snapshot roots are `C:\Program Files\Notepad++`, the guest's `%APPDATA%\Notepad++`, and `%LOCALAPPDATA%\Notepad++`. Entries contain relative paths, sizes, and SHA-256 hashes; file contents are not included. Every snapshot has limits of 4,096 files, 64 MiB per file, 512 MiB total, and 30 seconds. Unreadable files, reparse points, concurrent changes, and exhausted limits mark the affected root incomplete. A diff suppresses all changes for a root incomplete in either snapshot and lists that root in `incompleteRoots`; a missing root with no capture issue is a complete empty snapshot.

These scoped changes can identify installed payload and application-created settings to investigate when designing a package. They are not a package recipe, a full disk/registry trace, or proof that copying those files will reproduce the application. Registry activity, dependencies outside the fixed roots, network/IPC behavior, services, drivers, and an ordinary baseline still need their own observations. Consequently `filesystemRegistryChanges` remains in `missingEvidence` even when scoped snapshots are complete.

```powershell
cargo run -p aiw-cli -- schema imported-msi-behavior-evidence
```

## Validation

The retained Notepad++ v2 fixture was reported twice with identical JSON. A before/after inventory verified unchanged directory names and file bytes. Wrong project/hash inputs and an injected extra output file were rejected. The test removed only its own create-new extra file; the report itself performed no writes. No new Sandbox or CI run was needed. The original fixture and recovery proofs remain documented in [the fixture record](FIXTURE-NOTEPAD-PLUS-PLUS-8.9.8.md).

Local validation passed: 55 orchestrator tests, 62 runner tests (four opt-in tests ignored), 13 CLI tests, and the retained-workspace read-only/drift test. Workspace/all-target Clippy, formatting, governance, schema generation, and CLI success/structured-error smoke checks passed. Independent review identified and corrected the target-token assertion accounting; no other material issue remained. Full workspace tests, Sandbox execution, and hosted CI were not repeated for this reporting slice.

## Functional benchmark validation

The v3 live fixture passed install/open/edit/save/close and exact cleanup. Its retained v2-schema assessment report was produced twice with identical JSON and an unchanged workspace inventory; wrong project/hash and unexpected-output inputs were rejected. The report shows 215 installation additions and seven use-time roaming-app-data additions, with all snapshot roots complete. Legacy v2 execution still produces the historical report with behavior/diff fields absent. See [the measured benchmark](FIXTURE-NOTEPAD-PLUS-PLUS-8.9.8.md#functional-document-and-file-change-benchmark--2026-09-07).

The slice passed 31 provider tests and an integration run with 230 passing tests (16 opt-in/helper tests ignored). Seven focused native guest tests and the retained-report tests were run after the native corrections. Formatting, governance, CLI schema/compilation/export checks, warning-denied Clippy, and Rust 1.85 workspace/all-target compatibility passed. These are local results; hosted CI was not run.

## Unsuccessful terminal attempts

`run report-wsb-msi-run` reports either a completed assessment or an unsuccessful terminal attempt. It takes the same root, run ID, project, independently supplied guest-agent hash, and JSON/Markdown format as `report-wsb-msi`. JSON uses a `reportKind` discriminator (`completedAssessment` or `unsuccessfulAttempt`) and a `report` object. The original `report-wsb-msi` command continues to reject unsuccessful attempts.

```powershell
aiw run report-wsb-msi-run --root <retained-workspace> --run-id <run-id> --project <approved-project.json> --guest-agent-sha256 <approved-sha256> --format markdown
aiw schema wsb-msi-run-report
```

An unsuccessful report requires a committed failed/cancelled result with no accepted evidence root, exact-session cleanup recorded in both the run result and session transaction, no pending transaction publication or request file, and the original project/preparation/input/request bindings. It uses the same held-file and repeated journal/transaction verification as the completed report. Reporting does not start, stop, recover, or query a Sandbox and does not write to the retained workspace.

The report includes the recorded provider lifecycle and an optional `guest-failure.json` message. The message is explicitly **unverified guest output read at report time**: it has no completion-receipt or evidence-chain binding, can be absent or rejected, and cannot establish that an application stage passed or that the application is incompatible. Reading is bounded, rejects a final reparse point/non-file, and retains a handle denying writes/deletion while reporting. Control characters and Markdown markup are sanitized for presentation. No document contents are requested by this report.

Unsuccessful attempts never receive a completed compatibility verdict, application token, or file-change result. A failed completion receipt can now supply separately verified stage progress, as described below. Malformed optional diagnostics do not erase independently validated lifecycle information; invalid host commitments reject the report.

This first slice covers terminal failed/cancelled attempts after recorded cleanup. Pre-start failures, active/interrupted runs, and pending recovery still need a lifecycle reporting extension. Such runs are rejected here rather than reported as cleaned up. The provider lifecycle describes start/cleanup transitions, not application-stage completion.

Validation of this extension used the retained failed editor-input fixture and the successful v3 fixture. Both reports were repeatable with unchanged workspace inventories. A fake successful completion placed in the failed fixture did not change its unsuccessful report; the test removed only its own create-new file. Wrong project/agent hashes were rejected, and the strict assessment command still rejected the failed attempt. Unit coverage checks absent, malformed, oversized, and non-file diagnostics, control-character sanitation, and write/delete denial while the diagnostic handle is retained. Runner/CLI tests, warning-denied workspace Clippy, Rust 1.85 all-target compatibility, formatting, governance, and CLI JSON/Markdown/schema checks passed locally. No new Sandbox or CI run was needed.

## Receipt-bound stage progress

The current guest records nine fixed stages: capture before installation, install, capture after installation, prepare the document, launch the process, open/verify the document, edit/save/verify bytes, graceful close/job cleanup, and capture after use. Results must be all passed, or a passed prefix followed by exactly one failed stage and a not-reached suffix. A failure at the final stage is valid. These are guest observations; a completed capture attempt can still contain incomplete roots, and a failed stage does not by itself identify an application incompatibility.

On success, `importedMsiStageProgress` is an additional event in the existing receipt-bound evidence log. The runner rejects contradictory failed progress in a successful result. The assessment exposes `stageProgress` and uses report schema `v0alpha3` when stage progress is the newest observation (`v0alpha4` additionally records download normalization; `v0alpha5` requires standard-user context). Older approved v3 guest binaries may omit it; their existing reports remain readable and do not gain inferred stage results. Adding these observations does not change the fixed executable, document, UI input, or approval requirements; the updated guest binary requires its own measured hash and fresh approval.

On a caught native scenario failure, the guest publishes exactly three files: `scenario-result.json` containing a strict failed-attempt record (progress plus a bounded diagnostic), `evidence.jsonl` containing the matching progress event, and finally `completion.json` with failed status/nonzero exit. It does not append an extra diagnostic file after the receipt. A failure before valid progress exists, or during publication, can still leave only the older unverified diagnostic/partial output.

After recorded exact cleanup, `report-wsb-msi-run` independently verifies the failed receipt, exact output allowlist, artifact hashes, event chain, request/scenario bindings, failed status, and equality between the artifact and event progress. `failureProgress` distinguishes absent, rejected, and verified observations. Verified failure records include the failed receipt hash and evidence root for correlation; the run remains failed/cancelled and does not acquire an accepted successful evidence root. Failed/cancelled reports use schema `v0alpha2`. A valid-looking successful receipt is rejected on this path.

```powershell
aiw schema imported-msi-stage-progress
aiw schema imported-msi-failed-attempt
```

This is terminal stage reporting, not a live streaming journal. A killed guest or interrupted publication cannot prove the last completed stage. Full registry/dependency capture, ordinary-baseline comparison, and broader lifecycle/application profiles remain separate capabilities.

Stage-progress validation passed 36 provider tests, 66 runner tests (four opt-in tests ignored), three guest tests, and the native platform suite (143 passed, one ignored). A fresh live run passed all nine stages and exact Sandbox cleanup. Three retained-fixture checks covered current success, historical success without progress, and historical failure. Warning-denied workspace Clippy, Rust 1.85 all-target compatibility, CLI exports/schema generation, formatting, and governance passed locally. The [stage benchmark](FIXTURE-NOTEPAD-PLUS-PLUS-8.9.8.md#stage-progress-benchmark--2026-09-07) records exact identities and distinguishes live proof from synthetic failure tests.


## Standard-user reports

Current v4 scenarios require receipt-bound `importedMsiRuntimeContext` evidence in addition to the application token, document exercise, scoped file snapshots and stage progress. Completed reports use schema v0alpha5 and expose `standardUserContext`: actual account SID, profile, roaming/local AppData paths and administrator-membership observation. Markdown distinguishes privileged installation from standard-user application execution. Missing or contradictory runtime evidence rejects the report.

The v4 document is `C:\Users\AiwStandardUser\AppData\Local\AIW\Scenario\document.txt`; the AppData capture roots belong to that account, not the elevated collector. Historical v3 uses `C:\AIW\Scenario\document.txt` and keeps its elevated execution interpretation. Earlier report schema descriptions above document their respective evidence versions; retained reports are not silently upgraded with observations they lack.

These are verified bindings of guest observations. They do not prove independent containment, descendant behavior, registry completeness or compatibility outside the tested functions/configuration. The assessment remains `insufficientEvidence` until the missing checks and a valid comparison are implemented.
