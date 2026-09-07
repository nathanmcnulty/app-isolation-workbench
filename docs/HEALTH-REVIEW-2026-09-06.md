# Workbench health review — 2026-09-06

## Stabilization follow-up — 2026-09-07

The assessment below is the original review snapshot. Its open findings are superseded by this follow-up where explicitly addressed.

- Recovery now publishes a failed or cancelled terminal result after fresh exact-session absence and held workspace/request cleanup. It does not interpret guest output as a successful assessment. Repeated recovery preserves an existing terminal result, and the CLI returns freshly observed core status. Legacy transactions without request-location authority remain recovery-required.
- Pre-start cancellation and workspace failures no longer claim exact-session cleanup. An earlier persisted provider attempt prevents pre-start terminalization.
- Native child creation now supplies the exact token-user owner while retaining inherited DACLs. Windows' default object owner can differ from its token user, explaining the hosted import failures. The owner mismatch rejection and exact two-ACE policy remain intact; a fresh hosted run is still required to confirm the fix there.
- The pipe-lifetime fixture signals root/descendant readiness and exits its root explicitly. Its 15-second test-only budget still requires the exact pipe-timeout result and verified job cleanup; production deadlines are unchanged.
- Additional fixture testing found that Windows can publish its kernel file-hash cache minutes after import. A timing-only intake fix and signature-cache warmup were rejected after delayed verification reproduced the problem. New file and portable intake receipts use **v0alpha2**, excluding only `$KERNEL.PURGE.SEC.FILEHASH` from their EA authority after validating the complete actual allowed set. Content SHA-256, stable identities, ACLs, streams, and the other SmartLocker metadata remain bound. Unknown EAs, changed authoritative values, and malformed canonical digests fail closed. v0alpha1 receipts are rejected before workspace I/O and require a fresh import; their meaning is not silently changed. Microsoft documents [kernel EAs as kernel-managed signature caches](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/kernel-extended-attributes); the singleton and delayed publication were observed locally.
- Fixed-tree discard retains its existing strict EA contract, including rejection of the standalone file-hash shape. Its positive native test fixture now requires matching complete read-only observations across handle-close/reopen cycles before granting deletion authority. This is bounded fixture setup; production does not retry metadata drift, delay capture, repair a checkpoint, or recapture authority after mutation begins. Private discard remains a separate deferred surface.

The intake receipt file's own kernel EA values remain unbound to avoid a self-description cycle; the full allowed set and externally compared content are still checked. There is no new sleep or signature verification step in application import.

The fresh live `live_native_recovery_after_cleanup_before_result` canary passed on Windows build 28000 / Sandbox 0.8.107.0 in 40.48 seconds on the final test, including the production pre-start workspace revalidation. It uses real preparation/import/approval, a fixed guest probe, native attempt/cleanup, deliberately omitted result publication, and public native recovery. It verified a new failed result, no evidence root, cleanup complete, and byte-identical result/journal after repeated recovery. This is a controlled publication-boundary simulation, not an OS crash injection or an installer compatibility proof. The obsolete live fixture setup was also corrected to use the required preparation import instead of generic run creation.

No downloaded installer was executed by this stabilization work.

| Final follow-up check | Result |
|---|---|
| Workspace test coverage | 345 passed, 12 ignored, combining the workspace run's 222 passing non-platform tests with the final complete native platform rerun (123 passed, nine ignored). |
| Formatting, warning-denied all-target Clippy, Cargo documentation tests | Passed on the final code. |
| Verification smoke commands and schema generation | All remaining commands from `scripts/verify.ps1` passed on the final code. |
| Rust 1.85 all-target compatibility | Passed on the final code with the locked dependencies. |
| Dependency audit | Passed; 85 locked dependencies scanned against the refreshed RustSec database. |
| Live recovery | Passed in 40.48 seconds; fresh post-test host assessment supported Sandbox and reported zero sessions. |
| Notepad++ EXE/MSI | Fresh v0alpha2 receipts verified immediately and after 519/512 seconds; originals unchanged. See the updated fixture record. |
| Independent review and local documentation links | Passed. Recovery, native ownership, intake cache projection, and fixture-only stabilization received independent review. |
| Hosted CI | One [manual CI run](https://github.com/nathanmcnulty/app-isolation-workbench/actions/runs/34153248021) tested `a4b28d79b3288a7e9710bd588a8226c115e92707`. Rust 1.85 passed. Verification reached 117 passing tests and one stale dangling-link assertion failure in the orchestrator. The expected code was corrected from nonexistent `AIW_PATH_INVALID` to the existing production `AIW_PATH_UNSAFE` and pushed as `d50cf504669fa8e0c33f9d1d50aa0011dd539db` on `codex/stabilize-health-review`. Native platform tests and subsequent verification/audit steps were not reached. No second CI run, PR, or merge was performed. |

The corrected assertion retains rejection, link preservation, and absence of a published run. The hosted run exercised the symlink branch that local tests may skip when symlink creation is unavailable. Hosted owner/ACL/native validation remains outstanding and must not be described as green. Further scenario work remains local; batch the next hosted validation with a substantive execution integration milestone to conserve Actions worker hours.

The last monolithic verification run stopped at a native fixture race. After fixing shared fixture construction, the entire native suite passed; formatting, Clippy, documentation tests, and the verification script's remaining smoke/schema stage were run separately. This records composed check coverage, not a claim that the final tree has completed a new monolithic `scripts/verify.ps1` invocation. Logs use the `aiw-stabilization-` prefix in the system temporary directory.

The next capability slice remains **approved imported-application start plus one typed installation/exercise scenario in Windows Sandbox**, using the recorded Notepad++ EXE/MSI fixtures. Golden-probe approval already exists; it does not authorize imported application execution. Public discard, comparison eligibility, MXC release gating, and larger module extractions remain separate follow-up work. None requires widening this stabilization patch into a new execution surface.

## Assessment

The core direction is sound, but the repository needs a stabilization interval before more execution capabilities. Preserve the evidence-first Workbench, typed execution authority, protected native handles, exact-session recovery, and conservative verdicts. The largest risks are unfinished recovery outcomes, an unreliable validation gate, and implementation complexity growing faster than complete user workflows. A rewrite would increase those risks.

This review covers baseline commit `210a16c0a59385f02b003c768a7f65f5a39ca177`, with independent reviews of native intake/security, runner/orchestrator/recovery, and contracts/CLI/testing. The coordinator inspected the findings, rejected overstated hypotheses, ran local verification and dependency/MSRV checks, inspected hosted CI, and made the bounded cleanup described below. This is a source and validation assessment, not a penetration test or a fresh live containment certification.

| Area | Assessment | Implication |
|---|---|---|
| Product direction | Sound, scope needs narrowing | Finish a useful Workbench assessment before Studio, local AI, or additional provider breadth. |
| Execution authority | Strong foundation | Keep the fixed, persisted-derived start boundary and owner-scoped native authority. |
| Recovery completeness | Needs correction | Provider absence alone does not finish the application-service transaction. |
| Evidence quality | Conservative, with a corrected validation gap | Hash integrity and metadata validity must both hold; neither is attestation. |
| Maintainability | Increasing risk | Large modules and repeated state inventories make changes costly to review. |
| Automated validation | Not reliably green | Hosted owner-context failure and a local deadline-test failure need distinct fixes. |
| Product usability | Pre-alpha | Intake is usable within narrow constraints; application assessment and public discard remain incomplete. |

## Findings that should precede capability expansion

### 1. Recovery can clean a session without finishing its run — P1, open

If execution is interrupted after the session transaction reaches `CleanupVerified` but before receipt interpretation and `RunResult` publication, recovery can return `terminalizable: true` without publishing any terminal result. The CLI emits the recovery envelope and stops. A further start cannot resume the attempt: retained transaction state is rejected, and existing guest output also violates the preparation path's empty-output requirement.

Evidence: `crates/aiw-runner/src/lib.rs:477`, `:688`, `:702`; `crates/aiw-runner/src/preparation.rs:707`; `crates/aiw-cli/src/main.rs:1281`. The same missing terminalization affects successful recovery from other interrupted active states. The current live-recovery test also exercises recovery after an already successful run, which is insufficient coverage for a missing result.

This is a lifecycle/availability defect, not evidence of a leaked sandbox or a containment bypass. Add a bounded, idempotent finalization step under the existing authority. An interrupted attempt must produce a truthful failed/cancelled/insufficient-evidence outcome; do not infer successful assessment from provider absence. Test interruptions before cleanup, after cleanup persistence, during result publication, and repeated recovery. Preserve the original session binding and never restart an interrupted run implicitly.

### 2. Hosted validation fails in the wrong owner context — P1 validation gate, open

[CI run 33493042429](https://github.com/nathanmcnulty/app-isolation-workbench/actions/runs/33493042429) for the reviewed commit failed both protected file and portable import success tests. The diagnostic was `object owner does not match the current user SID`. Dependency audit was skipped after verification failed. This is a real test-execution failure, not the older hosted billing problem.

[Issue #60](https://github.com/nathanmcnulty/app-isolation-workbench/issues/60) already defines the correct boundary: run native success tests in a context whose token user and created-object owner agree, and retain a negative owner-mismatch test. Do not accept Administrators as owner, broaden the DACL, skip the success paths, or relabel rejection as success. Prefer a supported ordinary-user test process; a separately controlled self-hosted validation lane is an alternative if the hosted environment cannot meet that contract.

The local review also reproduced a different failure before and after the cleanup, and in an isolated single-test run: `provider_managed_output_cannot_outlive_the_deadline` expected `AIW_WSB_CLI_PIPE_TIMEOUT` but received `AIW_WSB_CLI_TIMEOUT` (`windows_platform.rs:2236`). The overall deadline was enforced, but the helper did not reach the intended pipe-timeout state. Establish deterministic helper readiness for this test; accepting either error would lose coverage of the pipe-lifetime branch. This is a reproducible local validation gap, not a demonstrated provider escape.

### 3. Pre-start failures overstate cleanup evidence — P2, open

Pre-start cancellation and workspace drift call `record_terminal_failure`, which writes `cleanupComplete: true` and says exact-session cleanup was verified. At the earliest call, no provider session has even been listed. Other calls occur after staging but before durable start intent.

Evidence: `crates/aiw-runner/src/lib.rs:470`, `:493`, `:1258`. Distinguish “no provider attempt occurred” from “the bound provider session was cleaned.” Choose explicit phase-aware result semantics and test both preflight and post-start cancellation. Do not let a future UI or report infer observations that did not happen.

### 4. Evidence verification omitted required metadata checks — P2, fixed locally

`EvidenceLog::append` rejected empty timestamp, kind, and source fields, but `verify_records` accepted imported records with those empty fields if their hashes were self-consistent. A recomputable hash does not validate metadata.

The cleanup shares metadata validation between append and verification. A regression test constructs correctly rehashed records with empty or whitespace-only values for each field and checks both direct verification and `EvidenceLog::from_verified`. This preserves valid-record hashes and schemas. It intentionally rejects previously accepted malformed evidence; it does not add timestamp-format or source-authenticity claims.

### 5. The declared Rust minimum did not compile — P2, fixed locally

`Cargo.toml` declares Rust 1.85. An actual `cargo +1.85.0 check --workspace --all-targets --locked --offline` failed with E0658 at the schema validator's let-chain expression. Two more let chains existed in the orchestrator and one in analyst validation.

All four conditions now use equivalent stable `Option::filter`, `Result::is_ok_and`, or guarded `matches!` logic. CI gains an explicit Rust 1.85 all-target compile job, and the stable job explicitly installs `rustfmt` and `clippy` instead of relying on runner-preinstalled components. This does not resolve the separate hosted owner-context failure.

### 6. Current-status documentation contradicted implementation — P2, fixed locally

The README said Authenticode was unimplemented; multiple documents said public start was unavailable while also describing its completed public proof. The README also claimed only start could mutate the provider despite exact-stop recovery.

The README now has one capability table and links to dated proof records. Architecture, roadmap, threat model, Sandbox documents, and contribution guidance consistently distinguish non-executing intake/preparation, approved fixed-probe execution, exact-session recovery, private preparation discard, and future application execution. Detailed security contracts remain in the architecture and provider documents. Recorded historical live proofs were inspected, not rerun during this assessment.

## Design and code quality

The workspace has 14 crates and approximately 50,371 Rust source lines at the baseline, including tests. `aiw-orchestrator/src/lib.rs` alone has 7,398 lines; its main test module begins at line 4,988. Native disposal, workspace handling, runner execution, and CLI dispatch are also large. Line counts are an inspection-cost signal, not proof of poor code.

The crate graph is acyclic and most code forbids unsafe Rust. Native operations are isolated in explicit Windows boundaries. Schema validation, bounded reads, duplicate-key rejection, create-new publication, retained source handles, content/identity revalidation, and negative tests are substantial strengths. The evidence, provider, and orchestrator layers have useful separation worth preserving.

However, ownership within those layers is less clear. `aiw-probe` also owns extensive workspace/discard authority contracts. CLI dispatch performs service composition that the future Tauri backend would otherwise have to repeat. Fixed preparation, run-store, revocation, and cleanup object inventories appear in multiple handwritten validators. The exact 19-object discard contract is intentionally conservative, but adding a legitimate artifact can make different stages reject one another.

Use focused extractions when changing these areas: separate journal persistence/recovery from run services inside the orchestrator; place CLI-independent intake/start/recovery composition behind callable services; define one versioned fixed-tree contract with state-specific projections. Retain exact native validation at the trust boundary. Do not introduce a generic privileged filesystem engine or combine all transaction types into one abstraction. Add cross-stage tests before changing a workspace layout.

Comparison is currently a descriptive delta calculator, not a recommendation gate. `compare_runs` reports project/OS/backend match flags but does not validate evidence roots or input schema semantics. A zero regression count is therefore not permission to promote a candidate. Before W3 recommendations consume it, define comparison eligibility, completeness, and provenance requirements. Different backends are expected in a baseline/candidate comparison and should not be rejected indiscriminately. Missing public schema discovery for summary/comparison/manifest contracts should be addressed with that contract work.

## Direction before the next major slice

1. **Stabilize the existing golden-probe workflow.** Finish recovery terminalization and phase-correct results, restore a trustworthy native CI lane, and prove the failure paths. Complete or explicitly defer the public discard outcome tracked by [issue #28](https://github.com/nathanmcnulty/app-isolation-workbench/issues/28); avoid more private cleanup machinery without a bounded user-visible endpoint.
2. **Complete one intake-to-report outcome.** Pick a small representative fixture and one typed scenario. Bind its immutable intake, approved execution, baseline/candidate observations, evidence gaps, and terminal status into one understandable report. Keep baseline execution in an explicitly chosen disposable boundary; an ordinary baseline must not silently mean launching an untrusted installer on the user's host.
3. **Keep MXC research separate from the first useful release.** The architecture currently requires both Windows Sandbox and MXC live proof for Workbench v1. Microsoft's current [MXC README](https://github.com/microsoft/mxc#readme) warns that profiles should not currently be treated as security boundaries. Recommendation: retain the pinned non-executing adapter and experimental research lane, but decouple it from the initial Workbench delivery gate. This is a proposed scope decision; this review does not silently change the roadmap commitment or provider pin.
4. **Validate the user workflow before a large UI build.** A thin read-only evidence/status workflow can test service boundaries and language once the first report exists. Full Tauri polish, validated launch profiles, local analyst inference, and Studio remain downstream of a complete assessment. Preserve the intended Workbench-to-Studio evolution.

Intake needs an explicit downloaded-file experience. The checked-in Notepad++ fixture records that `Zone.Identifier` and `SmartScreen` streams caused rejection; working copies with those streams removed were used for the positive proof. This demonstrates the narrow current contract, but is not a suitable invisible user workflow. Design provenance capture and an explicit permitted-stream policy before generalizing intake; do not silently discard Mark-of-the-Web or suggest disabling host protections. Signer identity, timestamp, MSI metadata, and the distinction between installer bootstrapper architecture and product architecture should remain explicit unknowns until implemented.

## Validation and residual evidence

| Check | Result |
|---|---|
| Formatting and warning-denied workspace/all-target Clippy | Passed on the patched tree through `scripts/verify.ps1`. |
| Patched workspace tests | 336 passed, 1 failed, 11 ignored. The failure is the native pipe-deadline test above; the new metadata regression passed. |
| Isolated native deadline test | Failed with the same overall-timeout versus pipe-timeout mismatch, with one test thread. |
| Rust 1.85 compatibility | `cargo +1.85.0 check --workspace --all-targets --locked --offline --target-dir target/health-msrv` passed after the four syntax fixes. |
| Dependency audit | `scripts/audit-dependencies.ps1` passed; 85 locked dependencies scanned against the fetched RustSec database. Dependencies were unchanged by cleanup. |
| Governance, local documentation links, whitespace | Passed; `scripts/verify.ps1 -GovernanceOnly`, changed-document local-link validation, and `git diff --check`. |
| Independent patch review | Evidence validation, compatibility rewrites, and CI changes reviewed; no remaining material patch findings. |
| Hosted CI | Reviewed commit remains red for owner-context failures. The new workflow changes are local and have not run on GitHub. |
| Fresh live Sandbox proof | Not run. Historical PR #50 and fixture records were inspected; ignored provider and cleanup proofs remain separate. |

Full `scripts/verify.ps1` is **not green**: it stops at the native test failure, so the later smoke-command/schema loop and Cargo doc-test phase are not claimed as completed. The CLI integration suite did pass, including public schema checks and PowerShell structured-error behavior. Logs are retained in the system temporary directory under the `aiw-health-` prefix. No installers, private host traces, credentials, or provider sessions were added to the review artifact.

The review did not find a demonstrated execution-authority or Authenticode-handle bypass. An initial concern about delete sharing on newly created directories was challenged and downgraded: it permits same-user disruption, while independent receipt-bound reopening rejects altered authority, and same-user hostile control is outside the stated containment boundary. This is optional defense in depth, not a reason to redesign import.

Remaining targeted coverage should include valid/unsigned/untrusted embedded-signature fixtures, the post-cleanup/pre-result crash window, phase-correct cancellation evidence, native test-helper readiness, and successful PowerShell wrapper behavior beyond the existing structured-error test. Ignored real Sandbox and native cleanup proofs are separate opt-in evidence; passing ordinary workspace tests does not establish them.

Changes are local and uncommitted. No PR, merge, provider start/stop, or external issue mutation was performed by this review.
