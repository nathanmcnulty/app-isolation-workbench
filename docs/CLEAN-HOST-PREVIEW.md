# Clean-host preview handoff

This is the release-candidate handoff for the first supported administrator
preview. It prepares one immutable, verifiable archive for a second operator on
a separate supported host. It does not itself close the clean-host gate.

## Build the handoff

Build only from a clean committed checkout. Supply the exact retained guest and
validated profile that passed the public-entry replay:

```powershell
.\scripts\build-preview-package.ps1 `
  -OutputDirectory <new-package-directory> `
  -ArchivePath <new-versioned-zip-path> `
  -GuestAgent <retained-aiw-guest-agent.exe> `
  -GuestAgentSha256 <independently-retained-guest-sha256> `
  -LaunchProfile <validated-launch-profile.json> `
  -LaunchProfileSha256 <independently-retained-profile-sha256>
```

Archive mode rejects a dirty source tree, a missing replay profile, a locally
substituted guest, profile/project/scenario/guest drift, non-x64 guest bytes, or
a guest with a dynamic Visual C++ runtime. The package records its source
revision, Workbench version, Rust toolchain, target, CLI and guest identities,
profile identity, fixed installer identity, supported host, provider protocol,
and unsigned-preview status in `release.json`.

The builder verifies the completed directory, creates the ZIP, then writes a
companion `<archive>.json` distribution manifest containing the exact archive
SHA-256, receipt file SHA-256, canonical package receipt SHA-256, and verifier
SHA-256. The archive and companion manifest are immutable handoff artifacts.
Publishing over an existing path is rejected.

## Integrity and authenticity boundary

The package receipt detects missing, extra, renamed, reparse, size-changed, and
hash-changed files. `verify-preview-package.ps1` requires the package receipt
SHA-256 supplied independently from the extracted package. The operator first
checks raw `receipt.json` and verifier hashes against the companion distribution
manifest, then runs the verifier as described in the package `README.txt`.

These hashes do not authenticate the publisher. This preview remains unsigned;
code signing, a signed release manifest, timestamping, SBOM publication, and a
trusted publication channel remain production release work. Do not describe
this artifact as signed or publisher-authenticated.

## Supported target and input

- Windows 11 24H2 x64, build 26100 or later.
- Microsoft Windows Sandbox Store package compatible with recorded protocol
  `windowsSandboxCli/v0.8.107.0`.
- Exact Notepad++ 8.9.8 x64 MSI SHA-256
  `c29cbe1a9aaef322cc3f316ceeabe8a8071b18441a5e3c3ec348069739e59e80`.
- One profile-bound fixed install/open/edit/save/close workflow with ephemeral
  local settings and the required guest standard-user ACL control.

The installer is not bundled. Acquire it through the organization's approved
software source and verify the exact SHA-256 before starting. Changed bytes are
unsupported; AIW records that result and does not guess a replacement recipe.
AIW detects Sandbox readiness before protected intake and never enables Windows
features or stops another operator's session.

## Second-operator acceptance record

The clean-host gate closes only after a second operator, without a coding
assistant, performs all of these steps on a separate supported host:

1. Record the archive, distribution manifest, receipt, CLI, guest, profile, and
   installer hashes.
2. Extract to a new local directory and pass exact package verification.
3. Record OS build, architecture, Windows Sandbox package/provider identity, and
   readiness diagnostics.
4. Run the package-local `aiw.exe admin assess` command from an interactive
   terminal with a deliberate evidence directory and visible operator identity.
5. Review the complete recipe and type the exact displayed approval.
6. Preserve `report.json`, `report.md`, execution/status evidence, and the safe
   outcome of one missing-prerequisite or unsupported-input control.
7. Confirm the retained run is terminal with cleanup verified and the provider
   reports no active session.

A successful fixed workflow can still be `insufficientEvidence` for broader
isolation. Cross-host success does not waive the report's missing independent
host, descendant, network/UI/IPC, persistence, or effective-backend evidence.

## Current state

Package construction and same-host public-entry replay are demonstrated. A
clean-source candidate was assembled from revision
`492c7c91a34635a5eb4df142f4d3f1c235fb1f74` as
`AppIsolationWorkbench-0.1.0-alpha.1-x64.zip` with these independently checked
identities:

- archive SHA-256
  `a793f579cbc5e87ed5dbf689f55a51c8a1bc1f3dd0a8a591e4b20f04459979e0`;
- receipt file SHA-256
  `cff687a78dbd30c9a761f5249155c41aa3d839977c2b5cf2d70d2658d111ce55`;
- canonical package receipt SHA-256
  `e0c09fa0fd5ed6234f476eb3b326c30752bad01149a9f7132c5106a6541e0cf7`;
- verifier SHA-256
  `d178ec6033c9084f31949e869969ae840f5698bdde2146377c3ed971222dd6b4`.

Fresh extraction verified all nine payload files, the clean source marker,
version, target, static-CRT guest, profile, provider protocol, and package-local
administrator help. The candidate and companion manifest are retained under
`%LOCALAPPDATA%\Temp\aiw-clean-host-preview-5762ba64ddb44558adf2c7187062854d`.
They are unsigned and have not been published.

The separate-host, second-operator acceptance record above is still required.
Do not copy same-host evidence paths to the target or count archive construction
as a clean-host trial.
