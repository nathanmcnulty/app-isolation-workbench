# Clean-host preview handoff

This is the release-candidate handoff for the first supported administrator
preview. It prepares one immutable, verifiable archive for a second operator on
a separate supported host. It does not itself close the clean-host gate.

## Current separate-host trial

The Azure clean-host VM `aiw-clean-host-0921` in subscription
`43babb60-9e73-4dc8-b769-4401c01aad73` ran the assessment-only v6 package
from `C:\AIW-Trial-v6` with separate installer input at `C:\AIW-Input-v6` on
2026-09-26. The second operator used the desktop launcher and typed the displayed
plan hash after reviewing the recipe. The exact package inventory was verified
on the VM; its compiled local-settings scenario is v0alpha10/v0alpha2 with a
fixed 300-second MSI install deadline.

The v6 source revision is `3e04f1ba520f8b516fa2c1a00ced282d8c8b89dc`;
archive SHA-256 is
`4acab6d323b8b846aee2552720f8277035af2ba432689ceea8a931c4e0890520`;
package receipt SHA-256 is
`d979af8894d628d04d022b6c6d5c29c57a4532085ac2ed3e6d45ba6642bad353`.
The CLI and guest SHA-256 values are respectively
`109d7cc4ac62ff58299349d697df9d7b3447f0087e2435ea58d76d83b79ff503`
and `3820362b4ab8f1c5c85456cc4f2531b251d28041c62373e17b2190e527de1999`.
The installer matched the supported hash below. This assessment-only package
has no validated launch profile, so this successful workflow does not close the
profile-bound release gate.

Run `admin-1790455699199696400` completed with process exit code 0. Its
receipt-bound report records all nine stages passed: installation returned 0,
Notepad++ launched in the recorded standard-user context, the fixed document
opened, saved with the expected SHA-256
`55666bc7399b14c1cdb77f1e0261e3b6f09e49aec11cda7de1685d73b8a7c9fc`,
and closed. The required guest file ACL control passed. The report records
`recordedCleanupVerified: true` and outcome `insufficientEvidence` for broader
isolation. A fresh `aiw.exe run status` call from the original RDP operator
context returned terminal status, evidence root
`c2e2d001a03dc2f9ddd47bd04ee6ab54f1dac70485650454b3db3a370469df66`,
and Sandbox state `cleanupVerified`. The provider's raw session list was empty
after the run. The full evidence archive is retained on the VM at
`C:\AIW-Retained\clean-host-evidence-admin-1790455699199696400.zip` and locally
at `E:\aiw-artifacts\clean-host-evidence-admin-1790455699199696400.zip`
(SHA-256 `b3b2376ca832eb4d8c012211227a429ccbce46f5a9703db03ef8e9da90d0c98e`),
with a private Azure handoff copy. Local verification matched the guest, MSI,
scenario result, evidence journal, completion receipt, and saved-document hashes.

One unsupported-input control used the package README as `--installer` in a
separate evidence parent `C:\AIW-Negative-v6`. It returned
`AIW_ADMIN_UNSUPPORTED_INSTALLER` at `adminInstallerInspection`, run
`admin-1790456937602758500`, and retained `installer-rejection.json`. No
protected intake or Sandbox session was acquired. This control did not execute
an installer.

The preceding v4 run `admin-1790038437201088600` reached the guest install
stage and failed when the fixed guest process timed out at 120 seconds. Its
terminal failed report and verified exact-session cleanup are retained under
`C:\AIW-Evidence-v4` on the VM and in the separately preserved evidence archive.
The timeout did not establish application incompatibility. The v6 run shows the
fixed workflow can finish with the 300-second bound on this host; it does not
isolate the timing change as the only cause. Preserve both runs.

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

This earlier profile-bound candidate has not been replayed by the second
operator. Its profile is bound to an earlier guest and scenario identity, so the
successful v6 assessment does not validate that candidate on the clean host.
Do not substitute same-host evidence paths for a clean-host trial.

## Current bound development candidate

A new unsigned candidate was assembled from clean revision
`08ab4406efaeb5c3a674d70db724b106048682a8` using profile SHA-256
`16da5a97a7cab5018b1712265aa4d82f25c885cf3cc47a8b827b46711493ca98`.
The archive is retained at
`E:\aiw-artifacts\AppIsolationWorkbench-profile-08ab440.zip`, with its
companion distribution manifest at the same path plus `.json`:

- archive SHA-256: `0ff27fe2d0a2f283a02bb2806b29b5e23000aca2e2bc6314b61baad8e4ae6f19`;
- receipt file SHA-256: `fc99d0fb7d45ccf081773dab09bb051989cff3606dd94e79f9dd9c81be1d5272`;
- canonical package receipt SHA-256: `d5d9687daad50f1f5ec72ffcb08bd25baca879ec2f73ae2443e4077b08d6454f`;
- verifier SHA-256: `21d06626a01a063162704a0129a981c3815b3efa69881b7841c4631dc341b88b`.

Fresh extractions on the build host and dedicated VM verified the exact nine-file
inventory. The VM copies are `C:\AIW-Preview-08ab440.zip` and
`C:\AIW-Preview-08ab440`; the short-lived Azure handoff blobs were removed.
An agent-run packaged public-entry smoke test on that VM produced
`admin-1790480009430263000` under `C:\AIW-Evidence-Profile-v1`. The retained
report records the bound profile, fixed document save with matching hashes,
standard-user file ACL denial and positive control, and verified cleanup.
Operator-bound `run status` was terminal with `cleanupVerified`, and the
provider session list was empty. The broader result remains
`insufficientEvidence` for effective isolation. This is development evidence,
not the independent second-operator acceptance record above; that gate remains
open for the current package.
