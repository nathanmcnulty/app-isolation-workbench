# Supply chain, bundling, and signing

AIW should ship as a small signed control plane plus independently governed content. A single signature over a large bundle is not enough because code, provider runtimes, models, knowledge, and test inputs have different owners, licenses, update cadences, and revocation needs.

## Recommended production layout

```text
signed AIW distribution
  signed aiw.exe and desktop UI
  signed aiw-golden-probe.exe
  signed fixed-verb guest/elevated helpers (when introduced)
  signed release manifest + SBOM + hashes

separately acquired provider runtime
  upstream-signed MXC binaries
  exact AIW-approved source/version/binary hashes

separately signed content packs
  model pack: manifest, model/tokenizer data, license/notices, detached signature
  knowledge pack: normalized documentation, source manifest, detached signature

never bundled
  private signing keys, customer installers/evidence, mutable credentials
```

The current recommendation for public Windows distribution is Microsoft Azure Artifact Signing, formerly Trusted Signing. It provides managed key custody, role-separated signing access, audit history, and digest signing; private keys are not exported. Every PE and package signature should use SHA-256 and an RFC 3161 time-stamp. The signer role should be assigned only to a release workload identity, not developers' everyday identities.

Sources: [Artifact Signing overview](https://learn.microsoft.com/en-us/azure/artifact-signing/overview), [signing integrations](https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-signing-integrations), and [certificate management](https://learn.microsoft.com/en-us/azure/artifact-signing/concept-certificate-management).

## Release sequence

1. Build from a protected, immutable tag with a locked dependency graph.
2. Run tests, Clippy, RustSec, PowerShell analysis, secret scanning, and the Windows containment test matrix.
3. Generate a release manifest containing every artifact name, size, SHA-256, target triple, source commit, toolchain, and schema/provider pin. Generate SPDX or CycloneDX SBOMs.
4. Sign each PE independently. Verify its chain, EKU, timestamp, expected publisher, and post-sign hash.
5. Package the already-signed files. If MSIX is used, sign and timestamp the package or bundle as well; the manifest Publisher must match its certificate.
6. Sign the release manifest with a release trust identity separate from the model/knowledge trust identities.
7. Re-verify from a clean machine, including extraction/install, Authenticode, manifest hashes, and no unexpected files.
8. Publish the immutable artifacts and manifest together. Never replace an artifact beneath an existing version.

Microsoft recommends timestamping MSIX packages so their signatures remain verifiable after the signing certificate expires. See [Sign an MSIX package](https://learn.microsoft.com/en-us/windows/msix/package/signing-package-overview).

## Runtime verification

Before a run, AIW should verify and record:

- its own release-manifest signature and file hash;
- the golden probe/helper Authenticode chain, publisher, timestamp, and manifest hash;
- the MXC upstream signature plus the exact AIW-approved binary hash and source pin;
- model/knowledge manifest signatures, hashes, license decisions, and trust class;
- all effective paths after canonicalization, with no mutable search-path resolution.

The runner must pass absolute executable paths and must not load security-sensitive DLLs from the working directory. `processmodel.dll` must be resolved from System32 as documented by the Create Process in Sandbox API. Signature success does not replace a hash pin for experimental provider binaries.

## Model and local-AI boundary

Foundry Local is a reasonable first provider, but it should not be fused into the trusted core:

- Prefer a separately installed, Microsoft-signed runtime when licensing and servicing permit; pin its resolved version and binaries at run time.
- Treat model/tokenizer files as untrusted data even after signature verification. Keep parsing/inference in a low-privilege, no-network host process with bounded input and output.
- Model packs remain content-only. Executables, scripts, DLLs, custom operators, and native plug-ins are forbidden.
- Use a dedicated model-signing trust class. Code-signing authority must not automatically authorize a model, and a model-signing identity must not authorize executable code.
- Record the model family, immutable source revision, resolved variant, quantization, tokenizer, runtime/provider versions, execution provider, license, payload root, and detached signature.
- AI output stays advisory and evidence-cited. It cannot execute, relax policy, grant access, install, deploy, or sign.

For enterprise/private distributions, model and knowledge manifests can use an organization-controlled private PKI or managed key service. The AIW verifier should pin the accepted trust roots or certificate identifiers by trust class and support revocation independently of the application release.

## Application Control integration

Signed AIW binaries enable Publisher or FilePublisher rules in App Control for Business. Prefer signer-based rules over mutable path rules; use minimum version constraints for narrowly scoped FilePublisher rules when appropriate. Model data should not receive executable allow rules. If catalogs are used for non-PE content, keep their signer separate from the AIW executable signer.

Source: [App Control file-rule types](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create).

## Development exception

Local builds are currently unsigned. A future runner may accept them only in an explicit development mode that is visibly marked, records every SHA-256, refuses production signing/deployment, and cannot be enabled through imported project content. Release builds must fail verification when unsigned or signed by an unapproved identity.
