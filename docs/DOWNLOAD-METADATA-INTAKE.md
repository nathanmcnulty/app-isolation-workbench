# Download metadata intake

The downloaded-file intake policy supports two exact, case-sensitive metadata names: `Zone.Identifier` and `SmartScreen`, each at most 64 KiB. These are opaque untrusted bytes. Other named streams remain unsupported. Portable directories use their existing strict policy.

`application inspect` observes these metadata streams without changing the source. JSON includes names, lengths and SHA-256 hashes, with a v0alpha2 file authority when metadata exists. Raw stream contents, including origin/referrer URLs, are omitted. Signature observation remains cache-only and applies to the held installer, not a payload later fetched by a downloader.

## Explicit import

```powershell
aiw application import --source <absolute-installer> --kind <msi|exe> --intake-parent <canonical-existing-directory> --intake-id <new-id> --archive-download-metadata
```

This option explicitly selects `archiveForSandbox`. It creates protected sidecars under `source/` (`download-zone-identifier.bin` and/or `download-smartscreen.bin`) and a payload containing only the unnamed data stream. It never removes metadata from the original download. Default import remains strict and rejects named streams before creating an intake.

The v0alpha3 receipt binds the exact source metadata, sidecar identities, content hashes, paths and semantic extended attributes. The returned receipt is the external verification authority. Raw metadata is retained locally under owner-and-SYSTEM protection and should not be published with a report. Verification excludes writers, checks the exact namespace, and rejects missing, added, modified or substituted sidecars. Partial intake is preserved and requires a new ID for retry.

```powershell
aiw application verify-import --receipt <externally-retained-receipt.json>
```

A verified receipt can supply the normalized payload to an already supported, separately approved Sandbox profile. Existing staging and workspace policies still require only the unnamed stream. Assessment and unsuccessful-attempt reports label this normalization: results do not test the original download's Mark-of-the-Web or SmartScreen handling. Import is not installation, signer trust, compatibility, or permission to execute on the host.

Streamless sources keep the existing v0alpha1 file authority and v0alpha2 import receipt, including when the option is supplied. Existing receipts serialize without the new optional fields so their recorded hashes remain valid.
