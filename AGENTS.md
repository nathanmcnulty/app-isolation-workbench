# Repository working agreements

## Resume cheaply

- Start with `scripts/work-status.ps1` and `docs/WORKING-STATE.md`. Verify the current checkout before editing; do not assume another worktree or `main` has this branch's changes.
- Read the relevant implementation and one focused design document. Follow deeper history only for a specific unresolved question. The handoff is a pointer, not execution authority.
- Keep `docs/WORKING-STATE.md` short and replace stale information after a meaningful milestone. Store detailed evidence in the relevant fixture/design document, not duplicated status narratives. Do not put credentials in either.

## Deliver one coherent slice

- Choose one concrete deliverable and its acceptance checks before editing. Finish the slice before expanding it. Research uncertain external behavior before designing a production adapter around it.
- Default to one agent. Delegate only an independent subtask or consequential review that materially benefits from it; give the exact question, commit, files, and expected output. Do not duplicate checks between agents or spawn an agent just to wait, push, or summarize.
- Preserve an explicitly requested model/agent arrangement from the active conversation. User instructions take precedence over these defaults.
- Batch related reads. Use bounded searches and short excerpts; keep full logs on disk. Poll running work with bounded waits, not repeated status searches. Report findings and decisions rather than unchanged progress.

## Validate proportionally

- Operator handoffs must include copy-and-paste commands with verified target paths, installer/input identities, fresh evidence and export destinations, and independently supplied package hashes. Do not send an operator back to generic README placeholders. Provide the expected editing tasks and completion behavior, and derive new run values from retained typed records rather than guessing IDs.
- Use terminating errors and structured output for in-process PowerShell scripts. Check `$LASTEXITCODE` only for native programs or scripts explicitly documented to set it; a successful PowerShell script can leave an unrelated native exit code unchanged.

- `scripts/check-local.ps1 -Check Format,Provider` runs selected checks and emits a compact JSON result with full log paths. Choose checks for the changed code; it is not a replacement for required repository checks.
- Documentation-only edits need link/content review and governance checks, not the Rust suite. Report-only edits should use retained evidence before considering live reruns. Execution or trust-boundary changes need appropriate negative tests and disposable-worker proof.
- Run each required check once on the completed code. Repeat only when relevant code changes, a failure, or an unresolved concern justifies it. No automatic pass cache: prior logs are evidence for their recorded state, not today's checkout.
- Use one build owner per target directory. Save full test output to logs and inspect failures selectively.
- Cleanliness is part of completion: account for owned processes and temporary
  test/assembly files, remove disposable files created by that invocation, and
  retain only needed diagnostics and evidence. Keep one bounded reusable build
  cache instead of full build copies in each output package. Do not label all
  rebuildable output as evidence or preserve failed build trees by default.
- Tests retaining directory write authority use an invocation-owned parent below
  TEMP, never the shared TEMP directory itself. Release all leases before owned
  fixture cleanup, including assertion-failure paths; do not serialize unrelated
  tests or weaken sharing checks to hide fixture interference.
  Shared helpers need per-invocation uniqueness; a PID-only name collides when
  several tests call the helper in parallel.
- Before a build, measure free space on the target volume. Keep at least 10 GiB
  free before starting; reclaim verified idle build caches first if below that
  floor. Routine dev/test builds disable incremental output and debug symbols in
  both workspace manifests. Keep one stable cache per required target/flag set;
  do not create a cache for each revision or vary profile environment overrides
  casually. Full symbols are a deliberate debugging opt-in, not the default.
- Cache output is disposable; intake, evidence, pinned trial binaries and source
  are not. Verify exact cache paths, no reparse traversal, and no active compiler,
  test or artifact consumer before cleanup. Never clean a shared target while
  another session uses it. Do not use target-filtered Cargo clean as a promise
  that host artifacts will be spared.
- Use hosted CI at integration milestones. Do not create PRs, dispatch workflows, or rerun unchanged jobs merely to check a branch. Observe existing runs; honor required merge checks.

## Preserve the evidence boundary

- Installers and application trials run only inside disposable Windows Sandbox/VM workers. Never execute them on the host.
- Reuse protected intake, fixed typed commands, held-file identity, approval/session binding, receipt-last publication, and exact cleanup/recovery. Do not turn research scripts into a generic command execution interface.
- For live experiments, first verify the driver with a project-owned control: process handles/exit status, output capture, deadlines, and cleanup. Keep a durable stage/result record so one diagnostic mistake does not require repeating installation blindly.
- Separate research observations from production verified reports. An exit code, mock, or outer Sandbox session alone is not application compatibility or effective-isolation proof. Missing observations remain unmeasured.
- Never use device-code authentication. Use the cached broker or normal browser flow; report blockers without that fallback.
