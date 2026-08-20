# Assessment bundles

An AIW assessment bundle is an explicit, deterministic manifest over a bounded set of files. It is intended for product-group feedback, vendor escalation, and repeatable internal validation. The current implementation hashes and verifies artifacts in place; it does not copy files, create an archive, upload data, or sign anything.

## Build and verify

The bundle specification is an operator-reviewed allowlist. Paths are relative to one explicit root:

```powershell
cargo run --locked -p aiw-cli -- bundle build `
  --root . `
  --spec .\examples\assessment-bundle-spec.json |
  Set-Content -LiteralPath .\assessment-bundle-manifest.json -Encoding utf8

cargo run --locked -p aiw-cli -- bundle verify `
  --root . `
  --manifest .\assessment-bundle-manifest.json
```

`bundle build` emits JSON to standard output and does not write a file. `bundle verify` re-hashes every listed file and requires an exact match for path, role, class, sensitivity, media type, byte count, file hash, totals, and bundle root hash. Files not listed in the manifest are outside the bundle and are ignored.

## Security contract

- There is no recursive discovery. Every artifact is explicitly listed.
- Paths must be ASCII, use forward slashes, remain relative, and be unique under Windows case rules.
- The root must be an ordinary directory. Every artifact path component is checked for symbolic links and Windows reparse points, and the final canonical path must remain under the canonical root.
- Individual artifacts are limited to 256 MiB, the manifest to 256 artifacts, and the total payload to 1 GiB.
- Executables, packages, scripts, archives, registry exports, memory dumps, private-key formats, disk images, and launchable `.wsb` files are rejected by extension. This is a defense-in-depth policy, not content-type detection.
- The required `noKnownSecrets` declaration is an operator assertion. AIW does not yet scan or redact secrets, personal data, screenshots, traces, or diagnostic text.
- `analystReport` artifacts are always assigned the `advisoryAnalysis` class by the implementation. A spec cannot label AI output as evidence.

The manifest root is SHA-256 over domain-separated canonical JSON containing all manifest metadata and sorted artifact records. It detects change; it does not establish authorship. A future exporter should copy the allowlisted files into a newly created, ACL-restricted staging directory, re-open them with handle-based anti-reparse controls, sign the final manifest outside the disposable worker, and then create a safe archive.

## Intended feedback shape

A useful product-feedback bundle should normally include the project definition, host probe, provider plan, target-token evidence, evidence chain and manifest, run summary, comparison report, denial-canary results, and short reproduction steps. Traces or screenshots should be exceptional and marked `confidential` unless reviewed otherwise. Raw installers are referenced by hash and signer evidence, never attached by this contract.

Advisory analysis may be included for convenience, but reviewers can exclude it and independently verify the authoritative artifacts. This keeps Foundry Local or another local model useful without making the model part of the evidence or enforcement boundary.

## Current limitations

Construction assumes the artifact writers have stopped. The path checks reduce accidental traversal and reparse abuse but do not close a privileged same-host time-of-check/time-of-use race. There is no archive format, signature envelope, certificate policy, redaction engine, provenance attestation, or upload integration yet.
