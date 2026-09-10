# Project-owned execution control

`aiw-control-fixture` is a small executable with fixed operations. It helps distinguish an application failure from a broken measurement driver before adding an AppContainer candidate. It accepts a mode, not an executable path, script, URL, or arbitrary command. File names and content are fixed; its working directory is supplied by the disposable-worker driver.

| Mode | Expected observation |
|---|---|
| `round-trip` | Create, read, edit, and re-read a fixed small document |
| `read-canary` | Bounded read with success, native access denied, missing file, and other errors kept distinct |
| `child` | Run the same executable's fixed token mode; bind the child's reported token to its actual PID |
| `token` | Report the exact process token |
| `expected-failure` | Deliberately emit a known failure and exit 23 |

The native access-denied result requires Windows error 5. A missing file, timeout, generic error, or nonzero exit is not an access-denied observation. Child execution has a deadline and uses a fixed create-new token file instead of unbounded redirected output.

## Disposable baseline driver

```powershell
./scripts/build-control-fixture.ps1
./scripts/test-control-sandbox.ps1 -RunDisposableControls
```

The driver uses a pinned Sandbox CLI, refuses an already-running Sandbox, creates two fresh sessions sequentially, disables networking and device redirections, and retains exact-session cleanup records. It copies only the project-owned fixture and fixed guest driver into a read-only input mapping. The host never executes the fixture. Outputs and host journals are retained under the printed `%TEMP%\aiw-control-baseline-<uuid>` root; failed attempts are preserved for diagnosis.

Each guest creates a fresh standard user and separate fixed case directories. An administrator first reads an admin-only canary; the standard user is then denied access to that same file. A separate readable canary supplies the standard-user success control, and an absent canary supplies the missing-file control. The child case checks parent/child token identity relationships. The deliberate failure ensures the driver preserves the real exit code rather than treating process creation as success.

This is an **ACL negative control**, not an AppContainer or host-boundary denial proof. The two reads of the admin-only file use different account privileges. No ordinary-versus-isolated comparison verdict follows from them.

These records are development controls, explicitly marked `productionEvidence: false`. They do not use the approved guest-agent completion contract and cannot be imported as application reports. The driver does not replace the production provider lease, durable recovery, or receipt verifier. If interrupted, preserve its journal and reconcile only its exact recorded session before another run; do not stop unrelated sessions.

The retained verifier binds the fixture, guest script, exact configuration bytes, pinned provider identity, output hash, and recorded cleanup for each trial. Only the two recorded per-run host mapping paths are normalized in configuration comparison. Process IDs and fresh account SIDs may differ, but the exact PID/SID relationships are checked within each trial before comparing token levels and case outcomes. Document/canary bytes and all expected exit codes are checked against the fixed control contract. Child stdout is discarded; `childStdoutBytes: 0` records bytes captured by the parent, not bytes produced by the child.

Recheck without starting Sandbox using `./fixtures/control/verify-baseline.ps1 -Root <retained-root>`. Run `./fixtures/control/test-verifier.ps1 -Root <retained-root>` to check altered copies for PID/SID mismatch, denial/missing-file confusion, changed exit codes, unverified cleanup, duplicate sessions, changed configuration, and provider drift. It preserves the original records and launches no fixture or provider.

## Next integration

Run these same fixed cases under the first application-level candidate, keeping account, input bytes, and environment commitments explicit. Add parent and descendant token checks and resource-specific baseline/candidate pairing before interpreting a denial as evidence for that candidate. Integrate the control result with approved execution and reporting before using it as a production assessment prerequisite. Application workflow repeatability remains a separate benchmark; matching control results do not prove all applications are repeatable.

## Live baseline, 2026-09-10

Two fresh Sandbox sessions passed all seven driver cases on Windows `10.0.28000.0`: administrator read, standard-user document round trip, allowed read, native denied read, missing-file classification, child token binding, and deliberate exit 23. Each exact session was stopped and absence verified. An initial pair also completed the controls; review then added configuration/provider bindings and a fresh pair exercised the final contract. The final proof is `%TEMP%\aiw-control-baseline-a117448b-d3d0-4340-8a6c-40ab1dd2502c`, with JSON/Markdown repeatability reports and both trials' inputs, output, configuration, and journals.

Fixture SHA-256: `3484e22e7691f3037469b0631d5ebdbc64201feb49863e4428c085225385dada`. Reviewed provider SHA-256: `247e092b5c5bd37820f225a7dd3ddf10ae37a67e2751a19c24b802c84769c441`. Normalized configuration SHA-256: `f4d93e6552169a3e35dc3df6713d2d17f386923abb0631f6f663a87bcdaa16c1`. Exact per-trial configuration hashes remain in the report; normalization changes only the two validated run-specific host mapping paths.

Both fixture unit tests, workspace Clippy, Rust 1.85 compatibility, formatting, and governance passed. Nine retained negative checks rejected mismatched root PID, child SID, missing-file-as-denial, changed failure exit, unverified cleanup, duplicate sessions, changed config bytes, changed normalized configuration, and provider drift. No hosted CI was requested. These successful development controls do not complete the real-application repeatability or effective-isolation benchmarks.
