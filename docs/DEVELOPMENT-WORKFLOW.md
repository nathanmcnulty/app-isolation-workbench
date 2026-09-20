# Efficient local development

Start with a small state snapshot and the current handoff:

```powershell
./scripts/work-status.ps1
Get-Content ./docs/WORKING-STATE.md
```

The status helper uses the checkout containing the script, caps changed-file output at 30 entries, and performs no fetch or provider calls. Upstream counts are based on local refs and may be stale; null means no configured upstream. Add `-IncludeWorktrees` only when locating a different checkout is necessary.

Choose a concrete slice and the checks relevant to its changes. Run selected checks once the code is ready:

```powershell
./scripts/check-local.ps1 -Check Format,Provider
./scripts/check-local.ps1 -Check Cli,Clippy,Msrv
./scripts/check-local.ps1 -Check Governance
```

PowerShell 7 is required. The helper runs from its own checkout, deduplicates checks, runs them sequentially, and stops on the first failure with exit 1. Cargo checks use locked offline dependencies; missing cached dependencies are a setup failure, not an instruction to download or alter the lockfile automatically. `Msrv` uses the repository's current Rust 1.85.0 minimum; keep it aligned with `Cargo.toml` and CI when that minimum changes.

Each invocation writes a fresh `%TEMP%\aiw-local-checks-<uuid>` directory containing full stdout/stderr files, incremental `checks.json`, and final `summary.json`. The console contains a short JSON result and bounded excerpts on failure. Inspect the relevant log if the excerpt is insufficient. Logs are not uploaded, automatically deleted, or reused to skip checks. HEAD and before/after status are diagnostic context, not a hash of uncommitted contents or proof that another process left files untouched. An interrupted invocation can retain partial logs without a final summary; do not count it as passed.

The helper deliberately does not perform live installation, start Sandbox, manage worktrees, commit, push, or trigger CI. Existing `scripts/verify.ps1` remains the full repository verification entry point, and meaningful live/retained-fixture tests remain necessary where the change requires them.

The ordinary Windows suite verifies global mutex acquisition with the current process token. Hosted Windows runners can be elevated, so they cannot prove unelevated acquisition. Run the separate environment-specific check from an unelevated PowerShell session:

```powershell
cargo test -p aiw-windows-platform unelevated_process_creates_and_acquires_global_mutex --locked --offline -- --ignored
```

That check asserts the process is unelevated before acquiring the mutex; an elevated invocation fails rather than claiming unelevated coverage. Disposal fixtures explicitly assign the token user as owner and retain the production protected/inherited ACL contract, independent of the runner's default token owner.

## Reduce repeated reasoning

- Update the short handoff at a milestone, with links to detailed evidence. Avoid rereading the entire roadmap and historical transcripts on every continuation.
- Use one implementation owner by default. Independent security review can earn its cost; parallel duplicate research, repeated reviews of unchanged code, and delegated polling usually do not.
- Prove uncertain application behavior before committing to an adapter design. First prove the driver using a tiny owned control, including exit status, output handling, deadline, and cleanup. Reuse the approved lifecycle when moving from research into production; do not grow another general-purpose Sandbox script runner.
- Preserve earlier successful capture stages when a later stage fails, so diagnostics do not require repeating an installation blindly.
- Consolidate documentation around a single evidence record and links. Report what changed, what passed, and the remaining gap; omit routine tool transcripts.

These changes should reduce repeated context reconstruction and log output. Actual quota savings have not been measured, and shorter final answers alone do not remove the cost of repeated investigation or agent work.
