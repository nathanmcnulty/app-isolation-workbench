# First real application MSIX lifecycle

This is the next repackaging milestone after the accepted Sandbox bundles.
Produce a reproducible, signed Notepad++ package, then install, activate, edit/save
and uninstall that exact output on a fresh disposable worker. Research results
remain separate from production assessment reports until their authority and
observation contracts are integrated.

## Closed first recipe

- Input: official Notepad++ 8.9.8 x64 portable ZIP, 8,232,940 bytes, SHA-256
  `b269383239464a945d17cfabfccf53935b83d80d907922310fdfd50d80274c66`.
- [Upstream release](https://github.com/notepad-plus-plus/notepad-plus-plus/releases/tag/v8.9.8).
  Keep upstream binaries and licenses intact; this is a packaging experiment,
  not a Nathan-authored Notepad++ executable or a public application release.
- Tool: Microsoft-signed x64 MakeAppx 10.0.26100.7705, SHA-256
  `00fff202b71c1266b8c3899701e42b5468ea153b2b33a0a47215fe27695f16d0`.
  Tool drift stops assembly; inspect it before approving a different pinned tool.
- Identity: `AIWResearch.NotepadPP`, version `8.9.8.0`, x64, Windows 11 24H2+.
- Publisher: `CN=Nathan McNulty, O=Nathan McNulty, L=Soldotna, S=Alaska, C=US`.
  Use the existing personal Artifact Signing profile outside the application worker.
- Delivery: `containedMsix`; runtime: `mediumIlFullTrust`. The manifest declares
  `packagedClassicApp`, `mediumIL` and `runFullTrust`. This is a delivery baseline,
  not AppContainer isolation or a replacement for the Sandbox profiles.
- Explicit adaptation: remove only `Application/doLocalConf.xml` to select
  per-user configuration rather than the immutable installation directory.
  Preserve its source hash and complete before/after inventories.
- Assembly never launches Notepad++, installs MSIX, grants capabilities, changes
  host policy or creates signing keys. Partial output is preserved; terminal
  `assembly.json` is published last. The scripts are not a production adapter.

The recipe follows [Microsoft's manual packaging guidance](https://learn.microsoft.com/en-us/windows/msix/desktop/desktop-to-uwp-manual-conversion).
The [package publisher must match the signing certificate subject](https://learn.microsoft.com/en-us/windows/msix/package/sign-msix-package-guide).

## Required final trial

Before launch, independently verify the signed package, full manifest/payload,
publisher subject, timestamp, package hash and fresh worker state. Record the exact
operator, package identity, source and adaptation; preexisting registration or a
running application stops the trial. Do not uninstall an unrelated package.

| Function or observation | Acceptance |
|---|---|
| Driver control | Project-owned process control verifies held handle, stdout/stderr, exit, deadline and cleanup before application trial |
| Install | Exact signed MSIX installs under the recorded interactive operator; capture registration, package full name, family name and manifest |
| Activation | Activate the declared package application, observe the target process and verify its actual package identity, image hash and non-elevated medium token |
| Document workflow | Open a fresh project-owned UTF-8 document, edit/save/close; independently compare exact final bytes and hash |
| Configuration | Observe the actual per-user configuration location; installation payload remains unchanged; missing evidence stays unmeasured |
| Uninstall | Remove only the exact installed package registration after process closure; verify registration absent and record supported user-data behavior |
| Cleanup | No owned process/registration remains; preserve input, output, failure and lifecycle evidence |
| Isolation | Full-trust package identity is measured; AppContainer, network denial, outer host containment and broader compatibility remain unmeasured |

The minimum boundary claim for this baseline is measured packaged, non-elevated
medium-integrity execution. It makes no denied-access or AppContainer claim.
Update, reboot, arbitrary installers, plugins, updater and shell integration are
unsupported lifecycle/functions for this first recipe, not implicit successes.
A failed function is attributed to packaging only after the driver and ordinary
application control establish the relevant comparison.

## Current evidence

The first unsigned package assembled with the pinned tool. Two subsequent fresh
assemblies passed independent archive payload hashing and semantic inventory
equivalence, retained licenses, the explicit removed-file contract, tampered-input
rejection before output and existing-output refusal. Unsigned MSIX hashes differed;
semantic payload/manifest equivalence, not byte identity, is the reproducibility
claim. MakeAppx's OPC entry `notepad%2B%2B.exe` maps to physical `notepad++.exe`;
the verifier uses exact per-segment URI encoding rather than skipping that file.
The first verifier's literal-path failure is retained separately.

Host evidence pointer: `%TEMP%\aiw-msix-proof-root.txt`.
`assembly-checks-r2/checks.json` and both assembly records retain exact identities.
No Notepad++ executable or application installer ran on the host.
Signing and the final worker lifecycle are **not yet verified**.
`notepad-msix-research.yml` is a manual owner/main-only assembly/signing workflow;
it has no public-release permission and never installs or executes the application.

## Feedback into assessment

The completed trial must inform shared assessment without introducing a second
verdict engine: distinguish source application identity from delivery package
identity, requested trust level from observed token/package identity, installation
paths from observed user-data paths, and uninstall registration cleanup from data
deletion. Preserve the explicit adaptation and before/after inventories. A package
or SDK error is a delivery/driver result, not application incompatibility. Reuse
the existing protected intake, approval/session binding and receipt-last evidence
publication when promoting this research into a production path.
