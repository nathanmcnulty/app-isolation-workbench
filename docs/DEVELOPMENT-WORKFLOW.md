# Efficient local development

Start with a small state snapshot and the current handoff:

```powershell
./scripts/work-status.ps1
Get-Content ./docs/WORKING-STATE.md
```

The status helper uses the checkout containing the script, caps changed-file output at 30 entries, and performs no fetch or provider calls. Upstream counts are based on local refs and may be stale; null means no configured upstream. Add `-IncludeWorktrees` only when locating a different checkout is necessary.

For the current recovery, use the [roadmap](ROADMAP.md),
[migration audit](APPLICATION-AGNOSTIC-MIGRATION.md) and
[execution packets](EXECUTION-PLAN.md). No new named-application adapter or compiled
installer allowlist belongs in the generic path. Keep fixtures declarative and
legacy readers separate from new execution.

Choose a concrete slice and the checks relevant to its changes. Run selected checks once the code is ready:

```powershell
./scripts/check-local.ps1 -Check Format,Provider
./scripts/check-local.ps1 -Check Cli,Clippy,Msrv
./scripts/check-local.ps1 -Check Governance
```

Stable x64 PowerShell Core 7.6 or later is required; previews and compatibility sessions are rejected. Recommend 7.6.7. Inert local tests may explicitly select an already available validated Core image through the test-only `AIW_TEST_PWSH` path; privileged execution always selects the fixed machine runtime and proves its identity. See the [runtime migration record](handoffs/2026-10-24-powershell76/VALIDATION.md). The helper runs from its own checkout, deduplicates checks, runs them sequentially, and stops on the first failure with exit 1. Cargo checks use locked offline dependencies; missing cached dependencies/toolchains are prerequisites, not permission to install or alter the lockfile automatically. `Msrv` uses Rust 1.88.0 for the core and hosted CI also checks the desktop's 1.90 minimum. Keep these aligned with manifests and CI.

Each invocation writes a fresh `%TEMP%\aiw-local-checks-<uuid>` directory containing full stdout/stderr files, incremental `checks.json`, and final `summary.json`. The console contains a short JSON result and bounded excerpts on failure. Inspect the relevant log if the excerpt is insufficient. Logs are not uploaded, automatically deleted, or reused to skip checks. HEAD and before/after status are diagnostic context, not a hash of uncommitted contents or proof that another process left files untouched. An interrupted invocation can retain partial logs without a final summary; do not count it as passed.

The helper deliberately does not perform live installation, start Sandbox, manage worktrees, commit, push, or trigger CI. Existing `scripts/verify.ps1` remains the full repository verification entry point, and meaningful live/retained-fixture tests remain necessary where the change requires them.

## Build storage

Core and desktop are separate Cargo workspaces. Both disable incremental
compilation and debug symbols for routine dev/test builds. Test assertions and
overflow checks keep their existing defaults; release profiles are unchanged.
Normal build scripts reject environment/config overrides that re-enable symbols
or incremental output, global/encoded Rust flags and compiler wrappers. Only the
reviewed target-specific static-CRT setting is admitted. Full-symbol debugging is
a separate development operation with an explicit storage budget, not a normal
validation default. Changing profiles/targets/flags creates compiled variants.

The shared `scripts/build-storage.ps1` policy refuses normal compilation when the
target volume has less than 10 GiB free or the cache exceeds 8 GiB. Verification,
guest/control builders and package builders use it, honor `CARGO_TARGET_DIR`, and
do not allocate per-commit or per-package compiled trees. Desktop packaging keeps
only its small assembly staging temporary; the shared build directory is outside
that staging and is never removed by packaging cleanup. Formatting/governance
still work under storage pressure. Direct Cargo commands also need this preflight.

`build-assessment-tools.ps1 -SourceRevision <clean-head> -ReportDirectory <fresh-small-report>`
runs two identical dev builds for the CLI, guest agent and project-owned control
in one selected cache, followed by a release-artifact refresh in that same cache.
It records source/toolchain identities, effective verbose
compiler arguments, before/after bytes and hashes. A watchdog checks the 8 GiB
cache budget, a 2 GiB running free-space floor, 20-minute deadline and 8 MiB log
bounds. These are sampled limits, not filesystem quotas. The same bounds are
checked after exit. Failure records retain root exit/termination facts and keep
primary and cleanup errors separate. This does not run a fixture or a provider.

Inspect cache usage at milestones and before moving to another revision. Rust incremental directories and compiled
dependencies can be rebuilt; retained evidence, source, protected intake and
pinned trial binaries have a different retention requirement. Before cleanup,
verify exact paths, absence of reparse traversal, and that all sessions have
released compilers, tests and artifact consumers. Do not run Cargo clean against
an active shared target; a target filter can also remove host artifacts. Record
what was removed and the measured space recovered. Temporary test/assembly files
created by an invocation are removed in its cleanup path by default. Retain small
logs and receipts needed for diagnosis, rather than whole failed build trees.
There is no automatic evidence deletion or cache quota claim, and a policy-blocked
cleanup must not be retried through another mechanism.

The ordinary Windows suite verifies global mutex acquisition with the current process token. Hosted Windows runners can be elevated, so they cannot prove unelevated acquisition. Run the separate environment-specific check from an unelevated PowerShell session:

```powershell
cargo test -p aiw-windows-platform unelevated_process_creates_and_acquires_global_mutex --locked --offline -- --ignored
```

That check asserts the process is unelevated before acquiring the mutex; an elevated invocation fails rather than claiming unelevated coverage. Disposal fixtures explicitly assign the token user as owner and retain the production protected/inherited ACL contract, independent of the runner's default token owner.

## Hosted CI runtime

`ci.yml` accepts any stable x64 Core **7.6.x** patch at the canonical machine path.
It reuses a compatible installed runtime without downloading or reinstalling it.
The reviewed 7.6.7 MSI/hash is only a fallback for an older or missing selected
runtime after the trusted bootstrap is staged. Installation failures include the
MSI exit code and log tail. A missing/broken initial Core bootstrap, prerelease,
unexpected identity, or newer incompatible series requires a supported hosted
image rather than a blind downgrade. This changes CI patch compatibility, not the
application/VM runtime contract or the separate release-workflow pins.
`scripts/test-ci-runtime-selection.ps1` checks the actual selection logic with
inert download/install stubs.

## Reduce repeated reasoning

- Update the short handoff at a milestone, with links to detailed evidence. Avoid rereading the entire roadmap and historical transcripts on every continuation.
- Use one implementation owner by default. Independent security review can earn its cost; parallel duplicate research, repeated reviews of unchanged code, and delegated polling usually do not.
- Prove uncertain application behavior before committing to an adapter design. First prove the driver using a tiny owned control, including exit status, output handling, deadline, and cleanup. Reuse the approved lifecycle when moving from research into production; do not grow another general-purpose Sandbox script runner.
- Preserve earlier successful capture stages when a later stage fails, so diagnostics do not require repeating an installation blindly.
- Consolidate documentation around a single evidence record and links. Report what changed, what passed, and the remaining gap; omit routine tool transcripts.

These changes should reduce repeated context reconstruction and log output. Actual quota savings have not been measured, and shorter final answers alone do not remove the cost of repeated investigation or agent work.
