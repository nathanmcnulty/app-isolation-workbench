# Verified desktop archive handoff

The desktop handoff now exports an already verified package and extracts it on
another supported Windows host without rebuilding or running an application.
This closes the manual ZIP preparation gap. It remains an **unsigned development
preview**: hashes establish exact bytes, not publisher identity. Public release
still needs an authenticated publication channel and a signing decision.

## Contract

`scripts/desktop-package-archive.ps1` has two closed operations:

- Export takes a package root, independently retained canonical receipt SHA-256,
  source revision, and fresh output directory. It verifies the package, copies a
  bounded snapshot, verifies that snapshot, writes a file-only ZIP, and verifies
  a complete extraction before publishing the handoff directory.
- Expand takes the ZIP, independently supplied archive/receipt hashes and source
  revision, and a fresh output directory. It holds the archive open without write
  sharing, checks its hash, rejects unsafe/duplicate/unexpected paths, extracts
  into an owned stage, and verifies the closed package before moving it into place.

The handoff contains `aiw-desktop.zip`, `distribution.json`, and two scripts:
`desktop-package-archive.ps1` and `verify-desktop-package.ps1`. The scripts remain
outside the application ZIP; the accepted package and receipt are unchanged.
Verify both scripts against independently delivered hashes **before executing
them**. The helper always uses its adjacent trusted verifier, never a verifier
extracted from the ZIP. The companion manifest alone is not a source of trust.

Both historical two-product v0alpha1 and current three-product v0alpha2 packages
are supported. Only their fixed file paths are accepted. Limits are 15 files,
128 MiB per file, 1 MiB for the receipt, and 512 MiB for archive/expanded content.
ZIP directory entries, alternate separators, unsupported paths, existing output
directories, and reparse ancestors are rejected. The local operator's filesystem
is trusted; this is not the protected execution-intake boundary.

All errors terminate. Success is structured JSON with `exactInventory: true`.
Do not inspect stale `$LASTEXITCODE` after these in-process PowerShell scripts.
Failed verification publishes no destination and removes only its owned stage.
An extracted package does not authorize execution or recover a retained run.

## Dedicated-VM acceptance — 2026-10-03

The archive helper at implementation commit `09c6b75` exported and extracted the
already accepted `e08115b` package using native Windows PowerShell
`5.1.26100.9444` on `aiw-clean-host-0921`. Both exact inventories passed; original
and extracted receipt bytes matched. No installer, GUI, Sandbox trial, approval,
or recovery was run for this archive proof. Existing GUI acceptance is recorded
in [Bambu desktop acceptance](BAMBU-ADMIN-ENTRY.md#completed-desktop-acceptance-2026-10-03).

VM records and files:

- Original package: `C:\AIW-Desktop-Preview-e08115b`.
- Handoff: `C:\AIW-Desktop-Distribution-e08115b`.
- Verified extraction: `C:\AIW-Desktop-Extracted-e08115b`.
- Control record: `C:\AIW-Desktop-Handoff-Tools-20261003\acceptance.json`.
- Host retained response: `%TEMP%\aiw-desktop-archive-vm-control.json`.

Independently retained identities for this exact VM handoff:

| Item | SHA-256 |
|---|---|
| ZIP (11,650,815 bytes) | `013b5aa1bd9c96c08baa284c1f13dc151da1421e38b1657b74d803a126f4ffbb` |
| Canonical package receipt | `be54677224b29ff608f7a222d27c463d06e205ac224d680b0a96c2619acab492` |
| Raw receipt file | `0ee8c734b08f9eb954eb5baa01eb04f22eb9d3b83bbf14ab483fbb4573f6140f` |
| Archive helper | `561f45aaf0a18ad3517964968e78564b2ed9e1413630892ba85906ffe54dd684` |
| Adjacent trusted verifier | `ce40f573b7c397d1f00c1c224b7e2c37c9c78a9166ba166b355e51fd42b440f6` |

The source revision bound by the package is
`e08115b50fb0ee37fba1f923b377985dc3f1bc94`. Archive compression can differ between
.NET runtimes; use the hash of the actual delivered ZIP, not a locally rebuilt ZIP.
The package verifier also now normalizes short-form Windows paths and trailing
separators before checking containment. The packaged historical verifier bytes
remain unchanged and bound by their original receipt.

## Exact optional operator commands on the dedicated VM

Nothing needs to be rerun to accept this milestone. For a new extraction and GUI
launch later, paste this into the VM's PowerShell. The destination below is fresh
and distinct from the completed extraction. A second invocation refuses overwrite.

```powershell
$ErrorActionPreference = 'Stop'
$handoff = 'C:\AIW-Desktop-Distribution-e08115b'
$tool = Join-Path $handoff 'desktop-package-archive.ps1'
$verifier = Join-Path $handoff 'verify-desktop-package.ps1'
if ((Get-FileHash -LiteralPath $tool -Algorithm SHA256).Hash.ToLowerInvariant() -cne '561f45aaf0a18ad3517964968e78564b2ed9e1413630892ba85906ffe54dd684') { throw 'Archive helper identity mismatch' }
if ((Get-FileHash -LiteralPath $verifier -Algorithm SHA256).Hash.ToLowerInvariant() -cne 'ce40f573b7c397d1f00c1c224b7e2c37c9c78a9166ba166b355e51fd42b440f6') { throw 'Verifier identity mismatch' }
& $tool -ArchivePath (Join-Path $handoff 'aiw-desktop.zip') `
  -ArchiveSha256 013b5aa1bd9c96c08baa284c1f13dc151da1421e38b1657b74d803a126f4ffbb `
  -ReceiptSha256 be54677224b29ff608f7a222d27c463d06e205ac224d680b0a96c2619acab492 `
  -SourceRevision e08115b50fb0ee37fba1f923b377985dc3f1bc94 `
  -OutputDirectory C:\AIW-Desktop-Operator-e08115b
```

Expected result: structured success and a complete package at
`C:\AIW-Desktop-Operator-e08115b`. To open it after successful verification:

```powershell
Start-Process -FilePath C:\AIW-Desktop-Operator-e08115b\aiw-desktop.exe -Verb RunAs
```

Opening the GUI starts no Sandbox. Preparation, full recipe review, explicit
approval, and separate Start remain required. Use the exact input/retained-run
instructions in the linked acceptance document; do not repeat installation to
inspect retained reports.

## Validation

Both package-schema fixtures passed export, extracted-package verification,
portable sidecar-tool use, and Windows PowerShell 5.1 extraction. Negative controls
rejected wrong archive/receipt/source identities, altered executable bytes,
missing files, duplicate entries, path traversal, existing destinations, and
reparse ancestors. Rejections left no published destination or owned stage.
The actual dedicated-VM round trip adds real package/PowerShell proof; the
fixture tests do not claim application compatibility or publisher authenticity.
