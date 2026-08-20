# Boundary denial canaries

AIW denial canaries are controlled negative tests against synthetic resources provisioned for one run. They answer a narrow question: could the baseline reach a known resource, and did the isolated candidate receive an explicit denial when attempting the same operation?

The current implementation defines and evaluates the contracts. It does not provision resources, execute attempts, or translate native errors. That separation lets Windows Sandbox, MXC, and future workers produce the same evidence without embedding arbitrary host paths, registry keys, endpoints, or process IDs in a portable project.

## Contract

A canary plan contains opaque `resourceId` values and one of these fixed boundaries:

- host file read or write;
- host registry read or write;
- DNS resolution or TCP connection;
- clipboard read;
- sibling-process open.

The future trusted provisioner maps each resource ID to a fresh run-bound sentinel, gives the baseline only the access needed to prove the control, and withholds that mapping from imported project content. The target application does not choose the resource.

Each assertion requires at most one `baselineControl` and one `isolatedCandidate` observation. Observations carry a normalized outcome, optional native error code, and evidence IDs. The evaluator is deterministic and independent of input order.

```powershell
cargo run --locked -p aiw-cli -- canary evaluate `
  --plan .\examples\canary-plan.json `
  --observations .\examples\canary-observations.json `
  --evidence-log .\examples\canary-evidence.jsonl
```

## Verdict rules

| Baseline | Candidate | Evidence | Verdict | Reason |
|---|---|---|---|---|
| succeeded | access denied with native error | present on both | passed | verified denial |
| succeeded | succeeded | present on both | failed | isolation gap |
| anything else | any | present | indeterminate | baseline control not proven |
| succeeded | not found, timeout, network unreachable, unavailable, or error | present | indeterminate | candidate observation unavailable |
| missing phase | any | any | indeterminate | missing observation |
| succeeded | access denied or succeeded | absent on either | indeterminate | missing evidence |
| succeeded | access denied without native error | present on both | indeterminate | missing native error code |

Only required assertions affect the report-level verdict. Any required failure makes the report fail; otherwise any required indeterminate result makes the report indeterminate. Optional assertions remain visible but cannot weaken a required result.

Generic failure is deliberately not treated as denial. For example, a TCP timeout could mean containment, a broken canary service, or unrelated network failure. The execution layer may normalize an actual `WSAEACCES` result to `accessDenied`; it must not infer that outcome solely from configuration intent.

## Evidence and trust

The evaluator first verifies the complete evidence chain. It then validates schema versions, bounded IDs and counts, plan matching, known assertions, duplicate observations, and that every evidence ID is the exact lowercase SHA-256 hash of a record in that chain. An invented or tampered reference fails evaluation. An access-denied outcome without a native error code remains indeterminate. The evaluator preserves but does not interpret that code; mapping codes to normalized outcomes belongs in a versioned, backend-specific collector with tests against real Windows builds.

The report includes the verified evidence root and an explicit `evidenceChainVerified` flag. It is a deterministic interpretation of those records, not independent proof. Worker output remains untrusted until host-side provenance, process identity, token, completeness, and collector checks succeed.

## Provisioning requirements

The future runner should provision high-entropy, per-run values and clean them after both phases. File and registry write canaries must target dedicated disposable locations. Network canaries should use a run-bound listener or response token and must not send customer data. Clipboard and sibling-process canaries should use synthetic tokens/processes. No canary should inspect an administrator's real file, registry value, clipboard content, or unrelated process.

Baseline and isolated phases must use the same logical sentinel and record their ordering. A missing cleanup result invalidates the run. For Windows Sandbox, host resources should be reached only through the specific capability being tested; the normal writable Output mapping cannot double as a host-file denial canary.
