# Windows Sandbox completion receipts

The Windows Sandbox CLI can identify, list, and stop a sandbox, but it does not return guest process output. AIW therefore uses the preconfigured writable output mapping as an untrusted one-way return channel. A terminal receipt written last lets the host correlate that output with the exact run it approved without turning `wsb exec` into a command channel.

The current implementation includes a fixed-function guest agent and a private, fake-provider-tested runner kernel. The kernel models durable start intent, exact-session reconciliation, explicit connection for user logon, receipt waiting, stop/absence confirmation, output verification, and crash recovery under one provider lease. It binds the canonical identity of a held owner-and-SYSTEM-only workspace through approval, the session transaction, status, and execution evidence. Its native provider launcher creates the exact image suspended, assigns it to a kill-on-close job before resume, restricts inherited handles, and enforces bounded output, an invocation deadline, and a fixed cleanup allowance. Successful pinned-CLI calls release required provider-managed descendants only after the root exits zero and both output streams complete; launch/wait failure, timeout, nonzero exit, and capture failure retain whole-job cleanup, while later mutation-protocol failures are additionally bound to the exact durable Sandbox ID. An opt-in supported-host test exercises that full flow against the pinned native Store provider. Exact provider recovery is available through `aiw run recover`; public `aiw run start` is available for the imported and explicitly approved fixed golden probe following its recorded live success and interruption/recovery proofs. This does not establish imported-application containment.

## Trusted expectation

Before launch, the host creates an expectation containing:

- lowercase run ID and canonical sandbox UUID;
- SHA-256 values for the rendered configuration, serialized guest request, and measured guest-agent binary;
- one fixed relative receipt path and one fixed evidence-log path;
- an exact artifact allowlist with roles, media types, sensitivity labels, and per-file size limits;
- the operator's `noKnownSecrets` declaration used by the assessment-manifest policy.

All paths are portable ASCII relative paths using `/`. There are no globs, commands, URLs, registry paths, or policy fragments.

## Guest receipt

The guest atomically publishes its allowlisted artifacts using create-new staging plus same-directory hard links, closes them, and publishes `completion.json` last. Bounded ordinary staging files from an interrupted publication can be removed on a retry; existing final artifacts are never overwritten. The receipt repeats the run, sandbox, configuration, request, and agent bindings; reports a terminal status and exit code; and lists every artifact's path, role, media type, byte count, and SHA-256 value. It also declares the root of the JSONL evidence chain.

`succeeded` requires exit code zero. `failed` requires a nonzero exit code. A structurally valid failed receipt is still useful evidence, so verification succeeds while the returned `successful` field remains false.

## Host verification

```powershell
cargo run --locked -p aiw-cli -- provider wsb-receipt `
  --output-root C:\AIW\Runs\example\Output `
  --expectation C:\AIW\Runs\example\wsb-completion-expectation.json
```

The verifier:

1. validates the trusted expectation and its fixed bounds;
2. walks the entire output tree and rejects unexpected files/directories, non-ASCII paths, excessive depth/count, symbolic links, and Windows reparse points;
3. reads a receipt no larger than 1 MiB and requires every trusted binding to match exactly;
4. rebuilds an assessment manifest over the allowlisted artifacts and compares every reported path, role, media type, size, and hash;
5. reads the declared evidence log under its approved limit, verifies the complete hash chain, and matches its root to the receipt;
6. rebuilds the artifact manifest to detect ordinary changes during verification;
7. emits a canonical receipt hash plus separate run-binding, artifact, evidence-chain, receipt, and successful-state flags.

The output tree is exact: the receipt and approved artifacts are the only permitted files. Empty or unrelated directories are rejected.

## Trust limit

This contract and the private kernel provide integrity checking, bounded parsing, run correlation, and fake-tested lifecycle/recovery behavior. The supported-host golden proof also establishes that the fixed guest agent can return a verified receipt through the configured mapping. These are not remote attestation and cannot prevent an administrator inside the guest from forging internally consistent output. An imported-application containment conclusion still requires host-side target process/tree, target-token, effective-configuration/backend, trace-completeness, and canary evidence.

Verification also assumes guest writers have stopped. The verifier checks paths before use and measures artifacts twice, but a privileged same-host actor can still race path-based filesystem operations. A production exporter should freeze the worker/output channel and use handle-relative anti-reparse access before copying artifacts into an ACL-restricted staging directory.
