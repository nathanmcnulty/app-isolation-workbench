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

The paired file/child feasibility control below is complete. Add the declared registry control and integrate the result with approved execution and reporting before using it as a production assessment prerequisite. Then exercise an explicit real-application candidate. Application workflow repeatability remains a separate benchmark; matching control results do not prove all applications are repeatable.

## Paired AppContainer research control

```powershell
./scripts/build-control-fixture.ps1 -AppContainerControl
./scripts/test-control-sandbox.ps1 -RunDisposableControls -AppContainerControl
```

The fixed guest driver creates one ordinary user and invokes the project-owned native launcher as that user. The launcher compares an ordinary process with a classic AppContainer process using the same fixture and canary, with no capability SIDs. Microsoft describes this boundary as the intersection of user access and package/capability access in [Implementing an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer).

`C:\AIW\Control\SharedCanary\canary.txt` contains the same fixed 29 bytes used by the baseline control. The ordinary process must read those bytes; the candidate must report native access denied. Both variants also launch a descendant. The retained verifier checks held root tokens, fixture self-reported tokens, descendant PID/user/package relationships, baseline medium integrity, candidate low integrity, and empty capabilities. A separate low-integrity child-output directory receives the specific package SID grant needed for the child token file. That grant does not extend to the canary.

The guest verifies both executable hashes before and after the trial. The host retains both executable identities, guest script, exact configuration and provider hashes, result hash, and exact Sandbox cleanup. The launcher records process-job and profile cleanup. The verifier requires the fixed disconnected configuration and two fresh workers with matching normalized observations. These records remain `productionEvidence: false`; they cannot establish real-application compatibility or replace the approved execution/reporting contract.

This experiment covers a file read and a descendant token-file write. The roadmap's first production candidate also requires its declared registry checks and approved evidence integration. Neither registry access nor an inner AppContainer network restriction is measured here; disabling networking on the outer Sandbox does not measure the inner boundary.

Recheck retained records with `./fixtures/control/verify-appcontainer.ps1 -Root <retained-root>`. Exercise altered copies with `./fixtures/control/test-verifier.ps1 -Root <retained-root> -AppContainerControl`. Both commands are read-only with respect to the original evidence and start no provider or fixture processes.

### Live paired proof, 2026-09-10

Two fresh workers on Windows `10.0.28000.0` passed the same-user read/child comparison. Baseline root and descendant tokens were medium-integrity ordinary tokens; candidate root and descendant tokens were low-integrity AppContainer tokens with the exact profile SID and no capabilities. The baseline read the fixed canary bytes and the candidate reported native access denied. Both process jobs, the temporary profile, and each exact outer Sandbox session were cleaned up.

Retained proof: `%TEMP%\aiw-control-appcontainer-d05fadcf-3fa9-423e-a388-2ce3bf2e7f2e`, including JSON/Markdown reports and two complete input/configuration/result/journal sets. Sandbox IDs: `3eb88b5e-2b68-4517-b06e-8773cdf21afc` and `a9d923fb-70f9-4aa1-b54b-7ebcd20fe5db`. Fixture SHA-256: `c18389add2efe2772c52c9b1daafec73228b4f55b4d8c88a0ce5ba756bd5f274`. Launcher SHA-256: `7c58afb802bb6f9a2270989afd56b5e7436c14be87f2448974d28c41abea5154`. Provider and normalized configuration hashes match the baseline proof below. Exact per-worker hashes remain in the report. A later test-only import correction does not change fixture behavior; the retained binaries identify the actual live inputs.

The experiment exposed a driver assumption: canonicalizing the current executable path failed with access denied under the restricted token. The fixture now launches its OS-reported absolute image path directly, without expanding package grants to unrelated ancestors. Both variants use that same fixture. Two failed exploratory workers were also stopped exactly; the second retained the specific canonicalization error and successful profile cleanup. This is useful adaptation evidence about path handling, not a real-application result.

Twenty-one altered-copy checks rejected held/self PID drift, root/child package or user mismatches, unexpected integrity/capabilities, failed baseline reads, missing-file-as-denial, resource drift, incomplete profile/job/Sandbox cleanup, launcher exit/hash changes, duplicate sessions, configuration/provider drift, string-valued cleanup, and linked output directories. The shared baseline verifier also passed eleven negative checks after its binding logic was reused. Fixture unit tests, workspace Clippy/Rust 1.85 checks, final fixture-specific Clippy/Rust 1.85 checks, formatting, and governance passed locally. No hosted CI was requested.

## Live baseline, 2026-09-10

Two fresh Sandbox sessions passed all seven driver cases on Windows `10.0.28000.0`: administrator read, standard-user document round trip, allowed read, native denied read, missing-file classification, child token binding, and deliberate exit 23. Each exact session was stopped and absence verified. An initial pair also completed the controls; review then added configuration/provider bindings and a fresh pair exercised the final contract. The final proof is `%TEMP%\aiw-control-baseline-a117448b-d3d0-4340-8a6c-40ab1dd2502c`, with JSON/Markdown repeatability reports and both trials' inputs, output, configuration, and journals.

Fixture SHA-256: `3484e22e7691f3037469b0631d5ebdbc64201feb49863e4428c085225385dada`. Reviewed provider SHA-256: `247e092b5c5bd37820f225a7dd3ddf10ae37a67e2751a19c24b802c84769c441`. Normalized configuration SHA-256: `f4d93e6552169a3e35dc3df6713d2d17f386923abb0631f6f663a87bcdaa16c1`. Exact per-trial configuration hashes remain in the report; normalization changes only the two validated run-specific host mapping paths.

Both fixture unit tests, workspace Clippy, Rust 1.85 compatibility, formatting, and governance passed. Nine retained negative checks rejected mismatched root PID, child SID, missing-file-as-denial, changed failure exit, unverified cleanup, duplicate sessions, changed config bytes, changed normalized configuration, and provider drift. No hosted CI was requested. These successful development controls do not complete the real-application repeatability or effective-isolation benchmarks.
