# AIW PowerShell 7.6 independent migration review

Date: 2026-10-24. Terminal CI status independently rechecked at 08:44 UTC.

## Decision and reviewed scope

One active P1 blocks native setup and acceptance: the remote runtime proof treats a WSMan-hosted PowerShell engine as though it were a locally launched pwsh executable. Fix that distinction before executing the consolidated setup plan.

This is a read-only independent source review of PR103's PowerShell migration:

- Migration source checkpoint: `e7ab0a689c042f5616370660a8d8e758556e2144`.
- Comparison baseline: `7bb40d6a9f3d2ea54774631826cedeadd623e644`.
- Subsequently inspected correction: `73a9fd6dedcaa9b9fa977088ff59609147cccbca`.
- [PR103](https://github.com/nathanmcnulty/app-isolation-workbench/pull/103)
- [Adopted migration goal](https://github.com/nathanmcnulty/app-isolation-workbench/blob/e7ab0a689c042f5616370660a8d8e758556e2144/docs/handoffs/2026-10-24-powershell76/GOAL.md)

The later correction changes the four workflows, their shell regression, runtime-policy checks, verification script and validation documentation. It does not change the runtime observer, transport, runtime identity model or worker receipt checks discussed below.

No candidate code, installer, native application or VM operation was executed for this review. No endpoint, security configuration, baseline, repository branch or publication state was changed.

## Active P1 distinguish the WSMan host from the worker executable

### Exact locations

- [observe-runtime.ps1 lines 9–10](https://github.com/nathanmcnulty/app-isolation-workbench/blob/e7ab0a689c042f5616370660a8d8e758556e2144/scripts/vm-msix/observe-runtime.ps1#L9-L10): obtain the current process image and require the fixed pwsh.exe path.
- [observe-runtime.ps1 lines 40–41](https://github.com/nathanmcnulty/app-isolation-workbench/blob/e7ab0a689c042f5616370660a8d8e758556e2144/scripts/vm-msix/observe-runtime.ps1#L40-L41): execute that proof inside the explicitly selected WSMan session.
- [transport.ps1 lines 15–16](https://github.com/nathanmcnulty/app-isolation-workbench/blob/e7ab0a689c042f5616370660a8d8e758556e2144/scripts/vm-msix/transport.ps1#L15-L16) and [lines 62–65](https://github.com/nathanmcnulty/app-isolation-workbench/blob/e7ab0a689c042f5616370660a8d8e758556e2144/scripts/vm-msix/transport.ps1#L62-L65): repeat the same assumption before transport operations.
- [PowerShell runtime model](https://github.com/nathanmcnulty/app-isolation-workbench/blob/e7ab0a689c042f5616370660a8d8e758556e2144/crates/aiw-probe/src/powershell.rs): requires pwsh.exe as the executable and compares the approved worker descriptor with SYSTEM, Control and lifecycle receipts.

### Failure and impact

The proof uses `[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName` and requires `C:\Program Files\PowerShell\7\pwsh.exe`. That is appropriate for directly launched local, SYSTEM and standard-user pwsh processes. It is not the process identity of a normal Windows WSMan endpoint.

PowerShell 7's WSMan engine runs in `wsmprovhost.exe`. The current remote guard therefore rejects a correctly installed and configured Core endpoint. Runtime observation fails before preparation, and the transport guard would independently reject every operation. Installing the intended runtime and endpoint does not resolve this source defect.

This finding is a static control-flow conclusion supported by upstream platform evidence, not a claimed reproduction on the target worker:

- [PowerShell issue 27982](https://github.com/PowerShell/PowerShell/issues/27982) shows a PowerShell.7 Invoke-Command session with remote ProcessPath `C:\Windows\system32\wsmprovhost.exe`, while the corresponding local process is pwsh.exe.
- [PowerShell 7.6.7 remoting registration source](https://github.com/PowerShell/PowerShell/blob/v7.6.7/src/powershell-native/Install-PowerShellRemoting.ps1) registers `pwrshplugin.dll` and its PSHOME configuration.

### Required correction

Separate the WSMan endpoint identity from the fixed child executable identity. Preserve both boundaries:

1. Prove the actual remote endpoint's approved configuration, host kind, stable Core version, architecture, PSHOME, loaded engine identity and native capabilities. Do not infer the loaded engine merely from an endpoint name or the presence of a pwsh.exe file.
2. Independently select and validate the fixed machine pwsh.exe that native worker operations launch, and bind its actual identity into the preparation, request and SYSTEM/standard-user receipts.
3. Keep strict executable checks for direct local and worker launches. Do not globally accept arbitrary hosts or substitute an assumed pwsh path for the actual WSMan process.
4. Update serialization, comparisons and evidence verification coherently. Simply adding wsmprovhost.exe to the current executable allowlist is insufficient because downstream validation and receipt equality expect a worker pwsh identity.
5. Preserve the explicit PowerShell.7.6 endpoint, normal HTTPS validation, same-session file transfer, no compatibility fallback, held-file checks and no-replay behavior.

### Regression contract

Complete these as one source correction and validation package:

- A legitimate WSMan host with the exact approved Core engine/PSHOME must be distinguishable from a directly launched worker pwsh process and must pass the appropriate endpoint check.
- A Desktop/5.1 endpoint, prerelease or too-old runtime, wrong architecture, unexpected loaded engine/PSHOME, unexpected endpoint configuration, compatibility proxy/session, or identity mismatch must fail before AIW mutation.
- Direct local, SYSTEM and standard-user launch proofs must still reject arbitrary, user-selected, PATH/Store, linked or unexpected executable identities.
- Changing either the endpoint binding or worker runtime after preparation must invalidate execution. SYSTEM, Control and lifecycle receipts must still match the approved worker runtime.
- Historical records must retain their original serialization/hash behavior; missing runtime bindings must not become fresh execution authority.
- Add inert host-kind/model regressions now. After separate setup approval, prove the real endpoint with Invoke-Command and the same session used by Copy-Item, followed by the fresh native lifecycle and cold-clean recovery already required by the consolidated plan.

The present transport regression compares synthetic runtime descriptors and verifies that the observer and transport share identical proof text. It does not establish that the shared proof accepts a real WSMan host. See [test-powershell-runtime.ps1 lines 20–37](https://github.com/nathanmcnulty/app-isolation-workbench/blob/e7ab0a689c042f5616370660a8d8e758556e2144/scripts/vm-msix/tests/test-powershell-runtime.ps1#L20-L37).

## Historical workflow failure corrected at 73a9fd6

All four exact-e7ab workflow runs failed definition validation before jobs started. Their job APIs returned empty lists; their check suites reported failure with no check runs. These failures are not evidence of failed PowerShell runtime tests.

GitHub reported an unrecognized `runner` named value inside `runner.temp` in custom shell declarations:

- [CI run 40077549564](https://github.com/nathanmcnulty/app-isolation-workbench/actions/runs/40077549564): `ci.yml` lines 42, 158 and 232, column 16.
- [Notepad research run 40077550864](https://github.com/nathanmcnulty/app-isolation-workbench/actions/runs/40077550864): `notepad-msix-research.yml` lines 41 and 129, column 16.
- [Signing control run 40077550278](https://github.com/nathanmcnulty/app-isolation-workbench/actions/runs/40077550278): `artifact-signing-control.yml` lines 47, 128 and 236, column 16.
- [Desktop candidate run 40077551533](https://github.com/nathanmcnulty/app-isolation-workbench/actions/runs/40077551533): zero-second failure and no jobs or graph. Its annotation region was empty during inspection. The same cause is supported by the identical invalid expressions at [source lines 48, 143, 257 and 408](https://github.com/nathanmcnulty/app-isolation-workbench/blob/e7ab0a689c042f5616370660a8d8e758556e2144/.github/workflows/desktop-candidate.yml#L48), rather than by a directly retrieved annotation for this run.

The [official runner schema](https://github.com/actions/runner/blob/main/src/Sdk/DTPipelines/workflow-v1.0.json) defines the run-step shell as a non-empty string, rather than the expression-capable context used for run contents.

At 73a9fd6 all four workflows replace the affected templates with a literal cmd.exe wrapper. It expands `%RUNNER_TEMP%` at execution and copies the generated extensionless script into a fresh .ps1 file before invoking the staged or fixed machine Core executable. The correction also adds bounded shell regressions and policy checks. No Windows PowerShell fallback is introduced.

### Latest hosted evidence

[CI run 40078421842](https://github.com/nathanmcnulty/app-isolation-workbench/actions/runs/40078421842), attempt 1, completed successfully. Its associated head is `73a9fd6dedcaa9b9fa977088ff59609147cccbca`, but the actual tested checkout was the synthetic PR merge [ac4bb5087ae6860bfe47cbe5d2bf20ea8ea38c18](https://github.com/nathanmcnulty/app-isolation-workbench/commit/ac4bb5087ae6860bfe47cbe5d2bf20ea8ea38c18), combining that head with base `40fadd0e625d9bae49e04b332ef5a99114529fc6`. This is PR-merge CI evidence, not a claim that the bare head was the checked-out revision. GitHub records its terminal update at 2026-10-24 08:42:25 UTC. All three jobs passed:

- All three jobs completed actual hosted PowerShell 7.6.7 provisioning and its inline identity proof.
- Windows desktop completed successfully. Logs establish eight passed Rust tests, a release build, archive/refusal controls, the package-verifier contract and dependency audit.
- Minimum supported Rust completed successfully, including Rust 1.88 workspace and Rust 1.90 desktop checks.
- Verify and audit completed repository verification with exit 0 and an unchanged worktree, preview-package verification, dependency audit and repository governance successfully.
- Audit success follows the existing warning policy: one allowed workspace warning and four allowed desktop warnings. It does not establish zero dependency advisories.
- Runtime-policy, vm-msix runtime and hosted-shell regression scripts are included in successful verification, but their individual case results are suppressed in the logs. No per-case runtime totals are inferred.
- The cargo-audit installation steps were skipped after cache restoration; the actual audit steps ran and passed. A skipped installation is not counted as a passed test.
- The other three workflows are manual-dispatch-only. The corrected source is not evidence that their full signing, packaging or research paths have executed successfully.

These terminal run, job, step and stated log outcomes were independently checked through GitHub. They establish hosted CI success for the identified PR merge of 73a9fd6, not native VM acceptance or success for the failed e7ab runs. The producer's local test counts and six inert shell cases remain separately attributed; only the desktop test count explicitly present in the hosted logs is repeated as a hosted numerical result. The active WSMan finding is unchanged by this CI success.

## Other migration boundaries inspected

The source scan covered 228 source files, including all 96 PowerShell entry/fragment files. All 96 declare Core and version 7.6. No active powershell.exe, run_ps or UseWindowsPowerShell fallback was found in the inspected launch graph. Remaining legacy runtime literals are historical evidence readers or rejection-test data. Historical worker utilities and the unbootstrapped PowerShell Sandbox control path explicitly refuse execution; native Rust Sandbox paths remain separate.

[Transport Stage lines 138–157](https://github.com/nathanmcnulty/app-isolation-workbench/blob/e7ab0a689c042f5616370660a8d8e758556e2144/scripts/vm-msix/transport.ps1#L138-L157) uses FileSystemAclExtensions.CreateDirectory with the ACL supplied at creation. It checks resulting ACL/reparse state and refuses existing intake. The migration does not introduce a create-then-Set-Acl window.

[Assessment lines 763–766](https://github.com/nathanmcnulty/app-isolation-workbench/blob/e7ab0a689c042f5616370660a8d8e758556e2144/crates/aiw-admin-workflow/src/msix.rs#L763-L766) refuse the historical checkpoint before acquisition. The runtime-equipped baseline has a separate identity. Historical provider/checkpoint pins are retained pending separately approved observation and update; no future configuration hash is fabricated.

Historical request fields remain optional for readback and omitted from serialization when absent. Execution requires a runtime binding. Retained completed recovery proofs remain distinct from an attempt to launch an old prepared operation.

The exact PowerShell 7.6.7 x64 MSI digest and October 13 release date in the setup plan match the [official release](https://github.com/PowerShell/PowerShell/releases/tag/v7.6.7). This verifies the published input identity, not a downloaded MSI signature or a target-machine installation.

## Evidence limits and consolidated next step

The producer reports local verification of 629 repository tests, eight desktop Rust tests, 14 JavaScript tests and qualified dependency audits, with 26 ignored tests excluded. Those local verification claims remain producer evidence; this reviewer did not execute those suites. Independently observed hosted outcomes, including the separately logged eight desktop Rust tests, are reported above for the exact PR merge. Neither local inert tests nor hosted CI prove the actual worker endpoint, SYSTEM/standard-user package lifecycle or fresh cold baseline.

The [consolidated setup and native acceptance plan](https://github.com/nathanmcnulty/app-isolation-workbench/blob/e7ab0a689c042f5616370660a8d8e758556e2144/docs/handoffs/2026-10-24-powershell76/SETUP-AND-ACCEPTANCE.md) has appropriate scope and exclusions, but should not be executed while the endpoint proof is deterministically wrong.

Complete the endpoint/model correction and regressions offline in one coherent checkpoint, verify its hosted CI, then retain one consolidated approval for the exact runtime installation, restricted HTTPS endpoint, new observed baseline/provider pins and fresh native acceptance. Do not substitute a sequence of small setup handoffs.

The plan must continue to preserve VM106 exclusion, the historical baseline and evidence, fresh nonces, no historical replay, no credential reconfiguration, no broad remoting/firewall repair and no merge. Missing or incompatible evidence remains a blocker, not an implicit permission to broaden access or fall back to Windows PowerShell. This review itself grants no setup, execution, publication or merge authority.

