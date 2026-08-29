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
    +-- plan shell-free wsb start/list/stop argument vectors
    |
    +-- W1 executor revalidates resolved binary/app/OS identity
            and observes only the preconfigured output mapping
```

The planner never emits `wsb exec`, `wsb share`, or a `System` execution request. Those operations would bypass or expand the reviewed guest contract. An execution layer must pass the argument vector directly to a process API without a command shell.

The `start` plan carries the same XML object and SHA-256 value returned by the direct renderer. The caller supplies a canonical UUID so the intended session identity is known before launch. The W1 executor compares that ID with raw CLI output and `list` state instead of trusting process ancestry or window discovery.

## Proposed one-shot state machine

1. `Preflight`: record OS build, Windows Sandbox app/package version, resolved `wsb.exe` identity and signature, feature state, current sessions, and provider interface snapshot.
2. `Prepared`: create a new per-run workspace; populate read-only inputs/tools; create an empty output directory; hash all inputs; render and hash the effective XML.
3. `Approved`: show the exact start invocation and trust deltas. Revalidate canonical paths and file identities immediately before launch.
4. `Starting`: invoke `wsb start` without a shell using the caller-generated UUID and inline XML. Parse only bounded JSON from standard output.
5. `Running`: reconcile the returned ID with `wsb list`. Observe the mapped output directory without interpreting its contents.
6. `Collecting`: after the run-bound completion receipt appears, stop accepting writes, validate the exact allowlisted tree, artifact hashes/sizes, and evidence chain, then append normalized host-side evidence.
7. `Stopping`: invoke `wsb stop` for the exact ID and confirm the session is no longer running. Do not kill unrelated sandbox processes by name.
8. `Finalized`: record cleanup status, residual files, trace completeness, provider drift, and whether conclusions are valid, incomplete, or invalidated.

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

The W1 execution kernel is an implementation candidate only. Production `aiw run start` is deliberately unavailable until the native boundary and recovery contract are complete. The first `aiw-windows-platform` vertical now performs a read-only `v0alpha2` assessment: it resolves the exact current-user Microsoft Store package through PackageManager, opens the real package `wsb.exe` while denying write/delete sharing, binds its final path and volume/file ID, hashes the held file, verifies it as a member of the package `CodeIntegrity.cat` with cache-only `WinVerifyTrust`, pins the observed CLI version to a captured parser, and runs bounded shell-free `--version` and `list --raw` observations. It records the App Execution Alias but never treats the alias, PATH, `WindowsSandbox.exe`, PowerShell, DISM, registry utilities, or a caller-provided provider path as execution authority.

The private test kernel now persists strict, hash-linked `aiw.dev/wsb-session-transaction/v0alpha1` snapshots before and after provider mutation. The transaction binds the approved run, plan and project revision, provider and configuration hashes, preselected session UUID, and guest request hash. Its only legal lifecycle is `startIntent -> active|unknown -> cleanupIntent -> cleanupVerified|recoveryRequired`; recovery may retry cleanup but may stop only that bound UUID. An injected global lease is held from the initial empty-session observation through exact-session absence and final receipt verification. Required recovery deliberately prevents a terminal run result until cleanup is independently reconciled. These local hashes provide integrity and correlation, not administrator-proof attestation.

`aiw host assess` is read-only and will not enable Windows Sandbox, install a provider, request elevation, stop sessions, or turn a discoverable binary into a containment claim. On the current development host it verifies Store package `MicrosoftWindows.WindowsSandbox` and CLI protocol `0.8.107.0`; unknown package or protocol versions fail closed until captured and reviewed. The development host has also passed a manual exact-ID start/list/stop lifecycle proof, but production execution remains blocked on the leased typed lifecycle/recovery boundary and dedicated workspace ownership controls. No application containment claim is possible from readiness or that lifecycle proof alone.

The guest agent accepts only the fixed golden-token request and emits `token.json`, `evidence.jsonl`, and a create-new `completion.json` receipt written last. Guest output is untrusted until host receipt validation and is still insufficient evidence for containment: target/descendant tokens, host trace coverage, effective backend, canaries, and cleanup evidence remain W2/W3 gates.
