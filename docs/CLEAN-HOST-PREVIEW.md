# Clean-host preview handoff

This is the release-candidate handoff for the first supported administrator
preview. It prepares one immutable, verifiable archive for a second operator on
a separate supported host. It does not itself close the clean-host gate.

## Current separate-host trial

The Azure clean-host VM `aiw-clean-host-0921` in subscription
`43babb60-9e73-4dc8-b769-4401c01aad73` has a staged, assessment-only v6
package at `C:\AIW-Trial-v6`, a separate installer input at `C:\AIW-Input-v6`,
and an empty evidence parent at `C:\AIW-Evidence-v6` as of 2026-09-26. The
operator's desktop launcher is `Run AIW Assessment v6.cmd`. The exact package
inventory verified on the VM, and its compiled local-settings scenario is
v0alpha10/v0alpha2 with a fixed 300-second MSI install deadline.

The v6 source revision is `3e04f1ba520f8b516fa2c1a00ced282d8c8b89dc`;
archive SHA-256 is
`4acab6d323b8b846aee2552720f8277035af2ba432689ceea8a931c4e0890520`;
package receipt SHA-256 is
`d979af8894d628d04d022b6c6d5c29c57a4532085ac2ed3e6d45ba6642bad353`.
The CLI and guest SHA-256 values are respectively
`109d7cc4ac62ff58299349d697df9d7b3447f0087e2435ea58d76d83b79ff503`
and `3820362b4ab8f1c5c85456cc4f2531b251d28041c62373e17b2190e527de1999`.
The installer still matches the supported hash below. This assessment-only
package has no validated launch profile; a successful v6 workflow will test the
new timing bound but will not alone close the profile-bound release gate.

The preceding v4 run `admin-1790038437201088600` reached the guest install
stage and failed when the fixed guest process timed out at 120 seconds. Its
terminal failed report and verified exact-session cleanup are retained under
`C:\AIW-Evidence-v4` on the VM and in the separately preserved evidence archive.
The timeout does not establish application incompatibility or prove that a
longer deadline will succeed. Preserve that run when evaluating v6.

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

## Earlier same-host candidate

Package construction and same-host public-entry replay are demonstrated. A
clean-source candidate was assembled from revision
`42d2b4273abd1eee2738abe1f073b936aab45341` as
`AppIsolationWorkbench-0.1.0-alpha.1-x64.zip` with these independently checked
identities:

- archive SHA-256
  `c8e6b4c1c6f33d0e85e96d94807a095e597c319e0cf0f862d28ceee22edecc93`;
- receipt file SHA-256
  `7e5cdd5432d8800cb31563b5cb871f1eac605a54f1b27f6b206440801a162a92`;
- canonical package receipt SHA-256
  `9160c6f7bfc4d1b4cb22b5ec64432aafa7c987937c5e6c659129f61b14431f89`;
- verifier SHA-256
  `d178ec6033c9084f31949e869969ae840f5698bdde2146377c3ed971222dd6b4`.

Fresh extraction verified all nine payload files, the clean source marker,
version, target, static-CRT guest, profile, provider protocol, and package-local
administrator help. The candidate and companion manifest are retained under
`%LOCALAPPDATA%\Temp\aiw-clean-host-preview-2c9bbb1faa454791a9c8d4c683a4e45c`.
They are unsigned and have not been published.

The separate-host, second-operator acceptance record above is still required.
Do not copy same-host evidence paths to the target or count archive construction
as a clean-host trial.
