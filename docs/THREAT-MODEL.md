# Threat model

## Protected assets

- Host operating system, credentials, user data, network position, and administrative tokens
- Signing identities and private keys
- Integrity and provenance of project, package, policy, model, knowledge, and evidence artifacts
- Accuracy of effective-backend, token, assertion, and cleanup claims
- Customer and product-group evidence confidentiality

## Untrusted inputs

- Installers, installed applications, packages, plug-ins, child processes, and their output
- Project YAML/JSON and imported run bundles
- Paths, registry values, event text, command lines, window titles, URLs, and document content
- Disposable-worker observations when the target can tamper with the in-guest collector
- AI prompts, completions, tool arguments, retrieved knowledge, and rendered Markdown
- Model and tokenizer files, even though they are nominally data

## Initial guarantees

The current code provides strict project parsing, safe-relative-path validation, SHA-256 validation, duplicate-ID detection, legal run-state transitions, canonical integer-only JSON, evidence-chain verification, in-process token evidence, hardened `.wsb` rendering, and a source-pinned MXC invocation plan. These mechanisms still do not prove that an application ran inside any Windows isolation boundary until the golden probe executes inside that boundary and its provenance/completeness checks pass.

The only current host-writable sandbox mapping is the required empty output directory beneath an explicit workspace root. Its contents are always untrusted. Root symlinks/reparse points, canonical workspace escapes, and canonical mapping overlap are rejected, but a launch-time revalidation is still required to reduce path-swap risk.

The `wsb` CLI lifecycle plan deliberately excludes `exec` and dynamic `share`. `exec` currently has no process-I/O return channel, `ExistingLogin` needs an active connected session, and `System` would expand the guest trust boundary. Runtime folder sharing can also diverge from the reviewed pre-launch configuration. The expected golden-probe artifact proves neither clean completion nor host provenance; a separate run-bound completion receipt remains required before automated execution can make a complete-run claim.

## Planned controls

- Disposable workers with offline-by-default networking and read-only input mappings
- Streamed output over an authenticated, run-bound channel
- Target-token and effective-backend verification rather than parent-process inference
- Boundary canaries for host file, registry, network, clipboard, and sibling-process access
- Fixed-verb, short-lived elevation with owner-bound IPC
- Signing outside the untrusted worker
- Separate trust policies for core, provider, model, and knowledge artifacts
- Append-only evidence with completeness and cleanup assertions
- Explicit human approval and a fresh run for every proposed relaxation

## Explicit non-goals

- Automatically declaring an application safe
- Automatically converting every legacy installer
- Learning and applying broad allow rules without review
- Treating Windows Sandbox telemetry as tamper-proof against an elevated in-guest adversary
- Providing a general-purpose privileged automation or local-AI tool host
