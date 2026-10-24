# Independent review of the e7ac987 runtime identity correction

Reviewed 2026-10-24. **Keep Stages A–D and merge blocked.** The original WSMan host finding is corrected in source, but one new P1 prevents matching worker identities from passing the embedded SYSTEM and lifecycle guards.

This is an additive follow-up to the [earlier independent migration review](https://github.com/nathanmcnulty/app-isolation-workbench/blob/7cd7bf3b4e35f02354ebea56b662cfa8c327ec51/docs/handoffs/2026-10-24-powershell76/INDEPENDENT-MIGRATION-REVIEW.md). That historical review and its CI findings remain unchanged.

## Exact scope and evidence boundary

- Repository and PR: [app-isolation-workbench #103](https://github.com/nathanmcnulty/app-isolation-workbench/pull/103).
- Reviewed implementation: `e7ac98715f173d74da674519418ee0bda1850fa6` on owning branch `codex/new-vm-handoff-20261021`.
- Comparison baseline: `73a9fd6dedcaa9b9fa977088ff59609147cccbca`.
- Review covered the 14-file correction and its unchanged embedded-script consumers, schema/model validation, receipt comparisons, regressions and setup plan.
- Source inspection and hosted log inspection were independent. No candidate execution, installation, VM contact, native application trial or setup was performed by this review. The functional failure below is a high-confidence source finding, not a claimed native reproduction.
- At the publication preflight, the owning branch remained at the reviewed head, `main` remained `40fadd0e625d9bae49e04b332ef5a99114529fc6`, and PR103 was open and unmerged.

**Remediation must start from the owning implementation checkpoint e7ac987, not from this documentation branch.** This branch carries handoff documents and older source; it is not an implementation baseline. Publication of this review authorizes no implementation, setup or merge action.

## P1 Matching identities fail JSON text equality

The direct runtime proof now builds an ordered dictionary with these top-level keys:

```text
edition, version, prerelease, architecture, psHome, engine,
capabilities, compatibilitySessionCount, executable, executableSha256
```

Rust serializes the approved worker identity in its struct declaration order:

```text
edition, version, prerelease, architecture, executable, psHome,
executableSha256, capabilities, compatibilitySessionCount, engine
```

The production request is written directly with `serde_json::to_vec(&request)`. Both embedded script guards compare the two compressed JSON strings with `-cne`. Matching field values therefore still differ at the fifth property and trigger `Approved PowerShell worker identity differs`.

Evidence at the exact reviewed head:

- Direct observation construction: [powershell_runtime.ps1 lines 87–92](https://github.com/nathanmcnulty/app-isolation-workbench/blob/e7ac98715f173d74da674519418ee0bda1850fa6/crates/aiw-probe/src/powershell_runtime.ps1#L87-L92).
- Rust field order: [powershell.rs lines 65–79](https://github.com/nathanmcnulty/app-isolation-workbench/blob/e7ac98715f173d74da674519418ee0bda1850fa6/crates/aiw-probe/src/powershell.rs#L65-L79).
- Production request write: [admin msix.rs lines 871–895](https://github.com/nathanmcnulty/app-isolation-workbench/blob/e7ac98715f173d74da674519418ee0bda1850fa6/crates/aiw-admin-workflow/src/msix.rs#L871-L895).
- Rejecting consumers: [system.ps1 lines 8–9](https://github.com/nathanmcnulty/app-isolation-workbench/blob/e7ac98715f173d74da674519418ee0bda1850fa6/crates/aiw-windows-platform/src/msix_worker/system.ps1#L8-L9) and [lifecycle.ps1 lines 13–14](https://github.com/nathanmcnulty/app-isolation-workbench/blob/e7ac98715f173d74da674519418ee0bda1850fa6/crates/aiw-windows-platform/src/msix_worker/lifecycle.ps1#L13-L14).

There is no correcting generation layer: [system_source and lifecycle_source](https://github.com/nathanmcnulty/app-isolation-workbench/blob/e7ac98715f173d74da674519418ee0bda1850fa6/crates/aiw-windows-platform/src/msix_vm_worker.rs#L115-L136) insert the proof verbatim; [compiled_script_entry](https://github.com/nathanmcnulty/app-isolation-workbench/blob/e7ac98715f173d74da674519418ee0bda1850fa6/crates/aiw-windows-platform/src/powershell.rs#L137-L148) only normalizes requirement declarations. Transport copies request bytes unchanged. Its separate `Select-AiwRuntimeIdentity` normalizes transport bindings, not the embedded script's `$AiwPowerShellRuntime`.

Ordered dictionary insertion order is intentional PowerShell behavior. The PowerShell JSON implementation iterates incoming object properties and dictionary entries rather than imposing a shared canonical ordering. See [Microsoft ordered dictionary documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_hash_tables?view=powershell-7.6) and [PowerShell 7.6.7 JsonObject implementation](https://github.com/PowerShell/PowerShell/blob/v7.6.7/src/Microsoft.PowerShell.Commands.Utility/commands/utility/WebCmdlet/JsonObject.cs).

**Impact:** the agent's structural Rust comparison can pass, then SYSTEM enrollment fails before account creation. Every SYSTEM operation shares this guard. The lifecycle script has the same independent failure if reached. This is fail-closed functional breakage, not an identity bypass.

## Repair and regression contract

Compare the complete closed worker identity structurally, or canonicalize both operands identically before comparing. Do not solve the mismatch by dropping engine fields, loosening worker executable identity or substituting the endpoint host identity. Property order is not runtime identity; field values, types and the closed schema still matter.

The corrective checkpoint must include inert tests that:

1. Exercise both actual embedded guards from the generated SYSTEM and lifecycle scripts, not a reimplementation or only the transport comparison function.
2. Use a production Rust-serialized request and the production direct-proof construction with equal identity values. Both guards must accept the unmodified pair.
3. Accept reordered top-level and nested engine object properties without weakening array/capability semantics.
4. Reject missing bindings, malformed or unexpected identity fields, incorrect types, and drift in every runtime and engine field, including executable path/hash, PSHOME, edition/version/prerelease/architecture, capabilities, compatibility-session count, assembly path/hash/version and MVID.
5. Continue rejecting a WSMan endpoint identity in place of a direct worker identity. Preserve no-5.1, no-proxy, no-compatibility and no-alternate-executable controls.
6. Preserve historical request/binding bytes and hashes for readback while refusing fresh execution when required engine or WSMan fields are absent.

Current [generated-worker regressions](https://github.com/nathanmcnulty/app-isolation-workbench/blob/e7ac98715f173d74da674519418ee0bda1850fa6/crates/aiw-windows-platform/src/msix_vm_worker.rs#L453-L561) parse scripts and inspect AST scope; their other controls cover hardlinks and deadlines. The [runtime regression](https://github.com/nathanmcnulty/app-isolation-workbench/blob/e7ac98715f173d74da674519418ee0bda1850fa6/scripts/vm-msix/tests/test-powershell-runtime.ps1) exercises transport comparators and loaded-engine capture, not these embedded equality guards. Those passes do not establish this missing acceptance case.

After repair, rerun the affected regressions and aggregate checks, obtain fresh CI for the corrective head with its actual tested merge recorded, and rebuild/reverify the clean-source worker and desktop package. Previous binaries and hashes cannot attest a later script fix compiled into the worker.

## Original WSMan finding is corrected in source

The correction distinguishes the actual `wsmprovhost.exe` endpoint host, its loaded Core engine and registration/plugin/startup evidence, and a separately launched fixed machine `pwsh.exe` worker. It preserves explicit endpoint selection, normal HTTPS, same-session transport and held runtime files. It does not weaken direct-worker executable requirements.

Rust execution validation requires the new engine and WSMan bindings. Historical omissions remain readable without granting new execution authority. Worker receipts continue to compare the worker identity, while cold-clean recovery and independent report verification compare endpoint evidence separately. No additional blocker was found in those reviewed changes. This source conclusion does not establish that a real endpoint accepts the new proof.

## Fresh hosted CI and package provenance

[Run 40118141240](https://github.com/nathanmcnulty/app-isolation-workbench/actions/runs/40118141240), attempt 1, completed successfully with all three jobs green:

- Verify and audit, job `120943677251`.
- Windows desktop, job `120943677168`.
- Minimum supported Rust, job `120943676973`.

Every checkout log identifies actual tested merge **`e4ee9c3b8c11df60a0bda9e1fd1061dc6c643366`**, merging reviewed head **`e7ac98715f173d74da674519418ee0bda1850fa6`** into base **`40fadd0e625d9bae49e04b332ef5a99114529fc6`**. This is PR-merge evidence, not bare-head testing. The earlier workflow-definition failures remain historical and are not relabeled as runtime failures.

The independently visible coverage is narrower than a full native acceptance claim:

- Repository verification and the Workspace test command exited 0, with an unchanged worktree. Successful workspace test output was redirected to runner-temp files and not uploaded, so exact workspace test totals are not independently visible in these logs.
- Desktop logs show eight Rust tests and fourteen Node display/IPC tests, archive/refusal controls and a fixture package-verifier contract passing.
- The desktop release-configuration command was `cargo check --release`, not `cargo build --release`. The PR body's hosted “release build” wording should be corrected. This does not contradict a separate local producer build.
- Minimum toolchain checks passed for workspace Rust 1.88.0 and desktop Rust 1.90.0. These were checks, not test runs.
- Hosted runtime provisioning and assertions confirmed stable Core 7.6.7. They did not install or prove the VM worker endpoint.
- Audits passed with allowed warnings: workspace one (`RUSTSEC-2024-0449`); desktop four (`RUSTSEC-2024-0370`, `RUSTSEC-2024-0449`, `RUSTSEC-2024-0429`, `RUSTSEC-2026-0386`). This is not a zero-advisory result or an independent security acceptance of those advisories.

The run artifact list is empty. The producer reports a clean-source unsigned worker/desktop package with six verified payloads, worker SHA256 `b30ae274503576316aefae92630138b67fa8bcbf62f3747b46ee4cdbe2346a05`, and receipt SHA256 `34ede84aedc7dfcc77fc5a488ec00fe5679a4257c4f47948368f65472ee673a5`. Those remain producer-side evidence, not independently inspected package bytes. Earlier migration totals and package hashes remain historical.

## Consolidated next scope and approval boundary

Use one corrective handoff on the owning PR branch: repair both embedded guards, add exact-consumer regressions, rerun validation and refresh package provenance. Keep historical baseline/provider pins unchanged during this offline correction.

The [e7ac987 consolidated setup plan](https://github.com/nathanmcnulty/app-isolation-workbench/blob/e7ac98715f173d74da674519418ee0bda1850fa6/docs/handoffs/2026-10-24-powershell76/SETUP-AND-ACCEPTANCE.md) is appropriately bounded, but is **not ready for approval while this source blocker remains**. After a clear source gate, request its existing bundled A–D approval once: exact runtime installation on VM203/107, restricted HTTPS endpoint, a new observed clean baseline and coherent provider pins, then fresh native lifecycle and cold-clean acceptance.

Publication of this document is documentation only. It does not approve runtime installation, endpoint/security/firewall changes, WinRM restart, VM operations, application trials, baseline creation or deployment. VM106 remains excluded; VM203 must never be restored. Preserve historical evidence and completed nonces without replay. No fallback to Windows PowerShell, credential expansion or merge is authorized. Native acceptance remains separate from source and hosted CI evidence.
