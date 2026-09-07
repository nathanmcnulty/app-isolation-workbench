# Notepad++ 8.9.8 intake fixture

This fixture records a local, non-executing intake proof performed on 2026-09-01. The installer binaries are not redistributed by this repository.

## Source identities

| Kind | File | Size | SHA-256 |
|---|---|---:|---|
| EXE | `npp.8.9.8.Installer.x64.exe` | 6,953,384 bytes | `7b2a949bf460fb37a3888c9048698f43222a185a48323023df1c51e78a3ca1c2` |
| MSI | `npp.8.9.8.Installer.x64.msi` | 7,806,976 bytes | `c29cbe1a9aaef322cc3f316ceeabe8a8071b18441a5e3c3ec348069739e59e80` |

Windows Authenticode inspection outside AIW reported both originals as validly signed by `NOTEPAD++`. AIW's held-file, cache-only whole-chain verification independently reported `signatureStatus: available` for both working copies. AIW does not yet record signer identity or timestamp.

## Negative source proof

The downloaded originals contained the unnamed data stream plus `Zone.Identifier` and `SmartScreen`. AIW rejected both before import because application source authority currently requires only the unnamed data stream. The originals were not changed and remain negative fixtures.

## Positive intake proof

Separate working copies were made outside the repository. Only `Zone.Identifier` and `SmartScreen` were removed from those copies. Their sizes, SHA-256 hashes, and external Authenticode status remained unchanged.

AIW then completed protected receipt-last imports and independent read-only verification:

| Kind | Intake ID | Receipt SHA-256 | Result |
|---|---|---|---|
| EXE | `npp-898-exe-20260901` | `afe58a59c8d686f3899122da64ee64fa854b1680dcf1a7c0e008aefc5e72db51` | `verified: true` |
| MSI | `npp-898-msi-20260901` | `4f97ad60d7282b71c7699322ed1a987f58f71230005965c3bdb5903fa5905cc6` | `verified: true` |

The protected payloads retained the source hashes and received only the explicitly recognized semantic SmartLocker extended-attribute sets, which are bound into their import receipts.

## Stabilization refresh — 2026-09-07

The downloaded originals still match the identities above and still carry `Zone.Identifier` and `SmartScreen`; they remain unchanged negative fixtures. New unnamed-stream working copies were created in a separate local temporary directory, retaining identical file content. AIW reports embedded signature availability for both copies; no installer was launched.

Delayed verification exposed a Windows kernel file-hash cache appearing after import. File and portable intake receipts now use `v0alpha2`: native EA sets are validated, then only `$KERNEL.PURGE.SEC.FILEHASH` is excluded from canonical intake authority. Other metadata and content checks remain exact. Old `v0alpha1` receipts are rejected and require fresh import.

| Kind | Fresh intake ID | v0alpha2 receipt SHA-256 | Result |
|---|---|---|---|
| EXE | `npp-v2-exe` | `1c9d8964dd585e642c45fd9a1c7b9cd2dff99241aefb030bd13939d648bd57e4` | Immediate and delayed (over eight minutes) independent verification passed. |
| MSI | `npp-v2-msi` | `41427fe2d10e57d4fd1005d4e9c328704c8b17880083d9e9a4a3cd6dac9e06c7` | Immediate and delayed (over eight minutes) independent verification passed. |

Machine-local working copies, external receipts, and verification JSON are retained under `%TEMP%\aiw-health-fixtures-176e3524e9f04ef28902716f28811d3d`. Use `exe-v2-import.json` and `msi-v2-import.json`; earlier experimental receipts in that directory are preserved diagnostic artifacts, not current intake authority. Reverify before any later approved execution.

The existing fixed golden probe also passed a separate live Sandbox cleanup-before-result recovery canary. That proof did not install or exercise these applications. The next milestone is approved imported-application execution with typed installation/exercise scenarios inside Windows Sandbox.

## Interpretation and remaining evidence

- The EXE outer PE image is x86. This does not establish the architecture of the product payload selected by the installer.
- MSI package architecture, product properties, signer identity, and timestamp are not yet recorded.
- No installer or application process was launched.
- No compatibility, containment, or safety conclusion follows from successful intake.
- Baseline and Windows Sandbox execution remain gated on the public approved-start lifecycle and typed assessment scenarios.
