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

The current code provides strict project parsing, safe-relative-path validation, SHA-256 validation, duplicate-ID detection, legal run-state transitions, canonical integer-only JSON, evidence-chain verification, deterministic allowlisted assessment manifests, conservative denial-canary evaluation, evidence-cited advisory-report validation, in-process token evidence, hardened `.wsb` rendering, and a source-pinned MXC invocation plan. These mechanisms still do not prove that an application ran inside any Windows isolation boundary until the golden probe executes inside that boundary and its provenance/completeness checks pass.

Assessment manifests reject traversal, Windows case collisions, symbolic links/reparse points, raw executable/package/archive/private-key classes, and oversized payloads. They do not scan content for secrets and do not establish authorship without a separate signature. Unlisted files are not part of the bundle. Construction must occur after artifact writers stop because a privileged same-host path-swap race remains possible until the exporter uses handle-based staging controls.

Canary plans reference only opaque synthetic resource IDs. Imported projects cannot choose real host paths, registry keys, endpoints, clipboard contents, or process IDs through this contract. A denial passes only when a baseline control succeeds, the candidate returns explicit access denial, and both phases cite evidence. Missing, timed-out, unreachable, not-found, and generic-error outcomes remain indeterminate.

Analyst output is untrusted plain text inside a strict envelope. Every statement must cite exact verified evidence records; model, runtime, prompt, and generation provenance is recorded; actions are fixed non-executing categories; and report authority is always advisory. Citation validity does not make model reasoning correct. The trusted host must eventually measure provenance rather than accept model-authored claims.

The only current host-writable sandbox mapping is the required empty output directory beneath an explicit workspace root. Its contents are always untrusted. Root symlinks/reparse points, canonical workspace escapes, and canonical mapping overlap are rejected, but a launch-time revalidation is still required to reduce path-swap risk.

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
