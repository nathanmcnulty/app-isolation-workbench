# Windows Sandbox automation

Research snapshot: 2026-08-19. This contract targets the Store-updated Windows Sandbox available on Windows 11 24H2 and later. Its command-line surface is explicitly described by Microsoft as an early interface, so AIW treats the resolved executable identity, app version, OS build, and effective behavior as run evidence rather than permanent assumptions.

## Current Microsoft surface

Microsoft currently documents these relevant behaviors:

- `wsb start --id <uuid> --config <xml>` creates a sandbox from an inline configuration. `--raw` requests JSON output.
- `wsb list` reports the current user's sessions and their states; `wsb stop --id <uuid>` terminates one.
- `wsb exec` returns an exit code but provides no guest process I/O. Running as `ExistingLogin` requires an active connected user session, while `System` deliberately expands authority.
- `wsb share` can add a host folder after launch, including guest write access.
- `.wsb` mapped folders are established before `LogonCommand`; the default sandbox identity is `WDAGUtilityAccount` and is an administrator in the guest.
- A writable mapping persists guest changes on the host after disposal. Default networking and clipboard settings expose more host surface unless explicitly disabled.
- `ProtectedClient` adds an AppContainer Isolation layer to the RDP client path.
- The Store-delivered Windows Sandbox app can change independently of the OS and can alter clipboard, device, and folder sharing at runtime through its UI.

Primary sources:

- [Windows Sandbox command-line interface](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-cli)
- [Use and configure Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file)
- [Windows Sandbox versions](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-versions)
- [Windows Sandbox overview](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/)

## AIW design decision

AIW separates lifecycle control from guest collection:

```text
validated plan
    |
    +-- render hardened inline .wsb XML
    |       offline, redirections disabled, ProtectedClient enabled
    |       tools/input read-only, one initially-empty output mapping writable
    |       fixed LogonCommand under WDAGUtilityAccount
    |
    +-- plan shell-free wsb start/list/connect/stop argument vectors
    |
    +-- W1 executor revalidates resolved binary/app/OS identity
            and observes only the preconfigured output mapping
```

The planner never emits `wsb exec`, `wsb share`, or a `System` execution request. Those operations would bypass or expand the reviewed guest contract. An execution layer must pass the argument vector directly to a process API without a command shell.

The `start` plan carries the same XML object and SHA-256 value returned by the direct renderer. The caller supplies a canonical UUID so the intended session identity is known before launch. The W1 executor compares that ID with raw CLI output and `list` state instead of trusting process ancestry or window discovery.

The lifecycle contract is `aiw.dev/windows-sandbox-cli-lifecycle/v0alpha2`. It supersedes the plan-only `v0alpha1` shape by adding the exact `connect` invocation required to establish the guest user logon; callers must not silently synthesize that transition when reading an older plan.

## Proposed one-shot state machine

1. `Preflight`: record OS build, Windows Sandbox app/package version, resolved `wsb.exe` identity and signature, feature state, current sessions, and provider interface snapshot.
2. `Prepared`: create a new per-run workspace; populate read-only inputs/tools; create an empty output directory; hash all inputs; render and hash the effective XML.
3. `Approved`: show the exact start invocation and trust deltas. Revalidate canonical paths and file identities immediately before launch.
4. `Starting`: invoke `wsb start` without a shell using the caller-generated UUID and inline XML. Parse only bounded JSON from standard output.
5. `Connecting`: reconcile the returned ID with `wsb list`, then invoke the exact-ID `wsb connect` verb to establish the user logon that triggers the preconfigured command. The remote-session process inherits standard handles, so this fixed verb uses null handles and is verified by exit status plus exact-session reconciliation rather than captured output.
6. `Running`: observe the mapped output directory without interpreting its contents.
7. `Collecting`: after the run-bound completion receipt appears, stop accepting writes, validate the exact allowlisted tree, artifact hashes/sizes, and evidence chain, then append normalized host-side evidence.
8. `Stopping`: invoke `wsb stop` for the exact ID and confirm the session is no longer running. Do not kill unrelated sandbox processes by name.
9. `Finalized`: record cleanup status, residual files, trace completeness, provider drift, and whether conclusions are valid, incomplete, or invalidated.

Only one AIW Windows Sandbox run should own the provider lease for a user session. A pre-existing unknown session is a hard preflight conflict, not something AIW should stop automatically.

## Output and completion contract

The current golden probe writes one create-new JSON artifact into the initially empty output mapping. The lifecycle plan exposes both its expected guest and host paths, but marks the artifact as **not** being a completion receipt. This distinction matters because:

- the guest can create a partial or misleading file;
- the writable mapping is a direct host mutation surface;
- `wsb exec` cannot return output to authenticate or delimit a stream;
- an administrator inside the guest can tamper with in-guest collection;
- file appearance does not prove that the intended sandbox ID, config, process tree, or cleanup completed.

AIW now defines and verifies a separate create-new receipt that is written last. It binds the run ID, sandbox ID, rendered-config hash, request hash, agent hash, exact artifact allowlist, each artifact hash and size, terminal status, and evidence-chain root. The host rejects unexpected files and validates every artifact as untrusted input. The schema has no command, URL, policy-fragment, or glob fields. The W1 fixed-function guest agent emits this receipt and the capability-gated executor can launch only its hash-bound golden-probe plan.

This is integrity and correlation, not a claim that a guest administrator cannot forge evidence. Higher-confidence assessment requires host-side observations and cross-checks: exact target token evidence, process-tree/ETW evidence, effective backend, boundary canaries, and lifecycle state from outside the guest.

## Runtime drift controls

The Store app can update separately from Windows, and the runtime UI can change redirection or sharing state. Therefore an automated run should fail closed when:

- the resolved CLI binary or package identity differs from the approved/pinned policy;
- `--raw` output is missing, malformed, oversized, or names a different session;
- an unexpected session exists or the provider reports an unknown state;
- a host mapping changes identity, becomes a reparse point, or ceases to be empty before launch;
- files outside the receipt allowlist appear in output;
- evidence cannot show the requested hardened settings were effective;
- the user changes runtime sharing/redirection in a way the collector cannot observe and bind.

## W1 implementation status

The W1 execution kernel is an implementation candidate only. Production `aiw run start` is deliberately unavailable until its approved start, crash, and exact recovery behavior pass the public CLI live gate. The first `aiw-windows-platform` vertical now performs a read-only `v0alpha2` assessment: it resolves the exact current-user Microsoft Store package through PackageManager, opens the real package `wsb.exe` while denying write/delete sharing, binds its final path and volume/file ID, hashes the held file, verifies it as a member of the package `CodeIntegrity.cat` with cache-only `WinVerifyTrust`, pins the observed CLI version to a captured parser, and runs bounded shell-free `--version` and `list --raw` observations. It records the App Execution Alias but never treats the alias, PATH, `WindowsSandbox.exe`, PowerShell, DISM, registry utilities, or a caller-provided provider path as execution authority.

The second native vertical adds an opaque per-user-session execution lease with held provider/catalog handles and typed `list`, `start`, exact-ID `connect`, and exact-ID `stop` methods. The `0.8.107.0` adapter uses the captured `Id` and `WindowsSandboxEnvironments` JSON fields and requires the documented inline XML value for `--config`; successful `stop --raw` is exit zero with empty output followed by an independent absence check. The native launcher uses the exact verified provider path, a shell-free quoted command line, an allowlisted Unicode environment, and an explicit standard-handle inheritance list. It creates the provider suspended, assigns the CLI root to a kill-on-close job, then resumes it, so no provider code runs before assignment. Output is bounded and each multi-call operation shares one invocation deadline plus a fixed cleanup allowance. Live testing established that the packaged CLI requires provider-managed descendants across successful calls, including observations while a session exists. Kill-on-close is therefore removed only after the exact CLI root exits zero and both bounded streams complete within the invocation deadline. Launch/wait failure, timeout, nonzero exit, or output-capture failure terminates the assigned job and verifies it empty; later protocol rejection of a mutating result remains governed by the pre-persisted exact Sandbox ID and list/stop/list reconciliation. Because `wsb connect` launches a remote-session descendant that retains inherited pipes, the fixed connect verb deliberately uses null standard handles and is accepted only when its direct exit succeeds and the exact owned session remains the sole provider session. Opt-in live tests exercise both the leased lifecycle and the mapped fixed probe. This API is not connected to `aiw run start`; the remaining gate is the public CLI approved-start/crash/recovery proof.

The next native primitive creates exactly one previously missing run leaf below an existing canonical local fixed-volume parent. Its protected DACL grants inheritable full control only to the current token user and SYSTEM at creation time; existing leaves are conflicts and are never repaired or adopted. Parent, root, tools, and output handles omit delete sharing, and the evidence contract records final paths, fixed-width volume/file IDs, the owner SID, and a hash of the semantic ACL policy. Revalidation compares both held-handle and freshly reopened identities, so deletion or same-path replacement fails closed. `CreateDirectoryW` cannot return the created directory handle, leaving a small same-user race before `CreateFileW`; AIW records this limitation and returns the exact partial path for manual inspection instead of deleting an unverified path. The primitive is not a containment boundary against another process running as that same user. The private runner now binds the canonical hash of the complete `aiw.dev/workspace-binding-evidence/v0alpha1` document into its approved action, start request, durable transaction, status reconciliation, and execution result, while the live workspace guard remains held. It revalidates the held and freshly reopened identities before durable start intent, after provider preparation, and after exact cleanup. Production recovery is implemented; public start remains gated on its own approved-start/crash/recovery proof.

`aiw run prepare-wsb` now exposes the pre-approval portion of that boundary. It validates the project, an independently supplied lowercase SHA-256 for the fixed-function guest agent, and a supported empty-session provider observation before creating anything. It holds the exact opened agent without write/delete sharing through create-new staging, creates fixed tools/output mappings, and writes `plan.json` and `wsb-plan.json` inside the protected workspace. Only after those held artifacts, workspace identities, output emptiness, and the exact workspace allowlist validate does it create and sync `preparation.json` as the final completeness marker. The receipt states `pendingApproval`, `providerAcquired: false`, and `providerMutated: false`; preparation has no approval or provider-lease API.

`aiw run verify-prepared-wsb` is the process-exit verification path. The operator supplies the independently trusted agent hash again; the verifier never derives that trust anchor from the receipt it is checking. It treats the receipt as bounded untrusted input, reopens the receipt-bound workspace through its owner/SYSTEM ACL and file IDs, holds and rehashes the exact plan, WSB plan, and staged agent, requires only the fixed root entries, exactly one tools executable, and empty output, rehashes the project, and independently repeats the pinned Store provider/package/catalog/protocol and empty-session assessment. Any drift fails closed. Verification is observational and does not acquire, start, connect, stop, recover, repair, adopt, or delete anything. An incomplete workspace must be preserved and inspected; operators must not blindly remove a path reported after a failed identity check.

`aiw run import-prepared-wsb` is the only path that may publish a WSB plan into authoritative run storage. It repeats the complete verification while retaining the workspace, receipt, plan, WSB plan, and staged-agent handles. The orchestrator then uses a plan-and-receipt-derived deterministic stage for `plan.json`, `wsb-planning-import.json`, the receipt-hash-bound genesis event, and its journal head, and publishes that complete directory with one rename. Exact-prefix crash artifacts are unlinked and regenerated from trusted bytes before publication, so a precreated hard link is never appended to or retained as authoritative state. Malformed or unrelated staging is preserved and blocks publication. The import receipt binds the preparation receipt, project revision, workspace, provider, guest agent, both plans, and the operator-supplied `--imported-at`; an idempotent retry must reuse that exact timestamp. It explicitly records no approval, provider acquisition, or provider mutation. Exact pristine retries are observational, while a different receipt, lifecycle progress, session transaction, unexpected entry, or malformed journal fails closed. Generic `run plan` rejects WSB actions before creating run storage. The imported workspace itself is the run root, but only `tools` and `output` are mapped into the guest. Approval and public start remain separate trust gates, and destructive preparation discard remains a later handle-bound transaction.

The runner now persists strict, hash-linked `aiw.dev/wsb-session-transaction/v0alpha3` snapshots before and after provider mutation. In addition to the approved run, plan/project, provider/configuration, workspace, session, and request hashes, every transition binds the complete workspace evidence, the request path relative to the held tools directory, and the pinned CLI protocol. `aiw run recover` accepts only a root and run ID; it reopens and holds the exact workspace, rereads unchanged committed authority, deletes only fingerprint-matched transaction staging, independently verifies the current Store provider, and reconciles only the persisted UUID. Trusted provider servicing drift is recorded; untrusted drift fails closed. Existing `v0alpha2` histories preserve their exact hashes and can authorize exact provider cleanup, but cannot authorize request deletion because they lack its persisted relative path. Production `aiw run start` remains blocked until the complete abandoned-start recovery path is proven live. These local hashes provide integrity and correlation, not administrator-proof attestation.

`aiw host assess` is read-only and will not enable Windows Sandbox, install a provider, request elevation, stop sessions, or turn a discoverable binary into a containment claim. On the current development host it verifies Store package `MicrosoftWindows.WindowsSandbox` and CLI protocol `0.8.107.0`; unknown package or protocol versions fail closed until captured and reviewed. The development host has passed the typed exact-ID lifecycle and the full measured guest-agent proof through the suspended, pre-assigned job launcher: start, list reconciliation, connect-triggered logon, token/evidence/receipt publication, exact stop, final absence, and host receipt verification. The guest agent must be built with the CRT statically linked (`scripts/build-guest-agent.ps1`) because the clean Sandbox image does not guarantee the developer VC runtime. Public start remains blocked on its production CLI approved-start/crash/recovery proof. No imported-application containment claim is possible from this golden proof alone.

The guest agent accepts only the fixed golden-token request and emits `token.json`, `evidence.jsonl`, and a create-new `completion.json` receipt written last. Guest output is untrusted until host receipt validation and is still insufficient evidence for containment: target/descendant tokens, host trace coverage, effective backend, canaries, and cleanup evidence remain W2/W3 gates.
