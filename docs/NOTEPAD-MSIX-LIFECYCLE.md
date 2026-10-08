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
  Hosted assembly obtains this identical Microsoft-signed binary from the fixed
  `Microsoft.Windows.SDK.BuildTools` 10.0.26100.7705 NuGet archive (22,582,767 bytes,
  SHA-256 `48a81375752f9f1ff56a34062084b426bfe412a5a8072e1c99b6a4be0e774841`).
  The archive is verified before extraction and the tool is independently held,
  hash-checked and publisher-verified before execution. A supplied tool path does
  not admit a different executable identity.
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
Signing and installed payload verification are complete. The required
non-elevated lifecycle is **not yet verified**; the first activation stopped at
the token check, before document editing.
PR #95 merged at `9c25780` after exact-head review and all required checks passed.
The first hosted signing research run `37710593027` stopped before assembly or
signing because the runner's installed SDK differed from the approved tool. The
fixed NuGet archive provides the same approved tool without accepting runner drift;
SDK mismatch diagnostics now include the observed hash and version.
`notepad-msix-research.yml` is a manual owner/main-only assembly/signing workflow;
it has no public-release permission and never installs or executes the application.
Owner gates require both the original `github.actor` and the current
`github.triggering_actor` on assembly and signing, including reruns. The existing
personal signing control and desktop candidate use the same direct signing gate;
desktop publication also checks the triggering actor. See [GitHub's actor context
semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts).

### Signed package and first worker result

PR #96 merged the pinned SDK supply at `bcf6f8243334c4478f06ee825b8ef20867c9da38`.
Research signing run [37711841372](https://github.com/nathanmcnulty/app-isolation-workbench/actions/runs/37711841372)
assembled and signed that exact source. The signed `application.msix` is
8,641,353 bytes, SHA-256
`2ae3a7c685e811eb34479980bff41d1442b023578074e19f4dca8fc676070437`.
Host and dedicated-worker verification independently checked its valid personal
publisher signature and timestamp. Host verification hashed all 220 signed
payload entries against the hosted assembly inventory and bound the source,
assembly and signing records. Local and hosted raw manifests differed only by
eight CRLF sequences; this was explicitly recorded, while the raw signed manifest
was still verified against its hosted inventory. The producer now emits LF
regardless of checkout format; the assembly test exercises actual LF and CRLF
script copies. This change does not change the identity of the already signed output.

On the dedicated disposable VM, the project-owned process control passed before
installation. The signed package installed as
`AIWResearch.NotepadPP_8.9.8.0_x64__q1fhfzcjv9wt6`; all 220 installed payload
entries matched. Package activation returned PID 8072 in interactive session 2.
Its observed package identity and executable hash matched, but its actual token
was elevated, high integrity (`S-1-16-12288`), and not AppContainer. The recorded
`aiwoperator` SID ends in RID 500: the renamed built-in Administrator. The visible
editor also displayed `[Administrator]`. The driver stopped at activation and
retained the failure before editing. A manifest declaration of `mediumIL` did
not establish the required non-elevated execution observation.

The exact owned editor was closed. A SYSTEM-context removal targeting the recorded
operator SID returned but left registration pending removal. That failed cleanup
check remains preserved. Removal in the actual operator's context then completed;
fresh independent readback found no current-user or all-user registration, no
Notepad++ process, and no package-private configuration directory. Configuration
had previously appeared in `LocalCache/Roaming/Notepad++` under the package's
per-user directory. Neither the accepted cross-user command nor early configuration
creation proves the required completed lifecycle.

Under the host proof root, `signed-artifacts-bcf6f82/signed-verification.json`,
`vm-msix-lifecycle-readback.json`, `vm-msix-recovery-inspection.json` and
`vm-msix-recovery-final-readback.json` preserve these distinct observations.
The worker's original `lifecycle-evidence` directory retains the failure and both
cleanup results. Document edit/save, post-workflow immutable payload and normal
uninstall remain open. The next trial must first prove a fresh standard user's
profile, medium non-elevated token and visible owned control, then install the
same verified package with new evidence. Do not weaken the token gate or change
the VM's UAC policy to pass this trial.

### Standard-user research control

The `aiw-windows-platform` example `msix_standard_user_control` is compiled only
with the explicit `research-msix-control` feature. Default production builds
exclude it. It accepts no command or path arguments and requires the native
Sandbox operator name plus a fresh `C:\AIW-Msix-Control-Output` mapping.
It calls the production `StandardUserSession` and `GuestProcess` implementations:
fresh account/profile/environment, one-use credentials, suspended-child token
and session validation, exact-SID desktop grant/access preflight, owned handles
and job. Its only child is a fixed project-owned GUI control, not Notepad++.
It retains process/token/window/profile observations, a child transcript,
pre-cleanup PID inventory and post-cleanup job readback before a terminal result.
Cleanup and evidence-export failures preserve the primary operation error.
The account and desktop grant live only in the disposable Sandbox and require
disposal of that exact owned session. A passing control is a prerequisite for
the application trial; it is not install or compatibility proof.

The first control-only Sandbox (`b316e9ee-19be-4eab-b25a-663ac96d08ff`)
opened but never entered its PowerShell file bootstrap. Guest inspection observed
`Restricted` execution policy; an explicitly attributed diagnostic reproduction
retained the script-disabled `SecurityError`/`UnauthorizedAccess` rejection.
No application ran. The exact session was stopped in its recorded operator's
context, and a fresh provider readback was empty. The failed stage remains intact.
The corrected research launch uses the fixed compiled control directly, with its
input held read-only against host replacement throughout the connected session.
It does not change execution policy. Missing control receipts remain an
unaccepted trial; provider start/connect alone cannot prove process completion.

This diagnosis also exposed a monitoring boundary: SYSTEM/session-0 provider
inventory was empty while the interactive operator's exact Sandbox was visibly
running and appeared in that operator's provider inventory. Readiness and cleanup
observations must retain the querying identity/session; a different actor's empty
list cannot establish that the owned interactive worker is absent.

The fresh direct-launch control (`146a783d-9856-43fe-9798-082ea65143f3`)
retained a standard-user profile context, then failed before child creation with
`CreateProcessWithLogonW` error 87. Independent readback verified the input lock
denied write access. The control command exceeded that API's documented 1024
character limit. The shared launcher now checks the actual quoted UTF-16 buffer
before launch side effects, using a conservative limit including its terminator;
tests cover ASCII and supplementary Unicode boundaries. The shortened fixed
control has a separate test against the same quoting and native limit. These
checks do not prove a successful live standard-user control or application trial.

The next fresh control, built from `965b07ac71c11c2acc2e727f976886043714f885`,
passed in owned Sandbox `3b6428bd-28e0-4bf1-8b87-9b6d911dd6ee`. Independent
readback bound the held input hash
`2487c7cf42ab250ecec8fd480fc66e434a21e56e815140520e046d55500da88b`
to the recorded source and worker. Child PID 6736 had the context's exact SID,
medium integrity and no elevation. Its GUI was visibly observed over RDP;
the retained window observation matched the PID. The child result recorded
the same SID/profile, guest session 1 and completed GUI loop. Exit was zero;
normal cleanup and evidence export had no errors, with zero job processes
before and after cleanup. The terminal research result explicitly says the
application trial was not run.

The exact worker was subsequently stopped in its recorded operator SID/session;
native exit zero and the operator's empty provider inventory were independently
read back. The dedicated VM remained running and its RDP desktop remained
accessible. Under the host proof root, `vm-msix-control-short-readback-r2.json`
and `vm-msix-control-short-final-readback.json` retain these observations. The VM
stage `AIW-MSIX-Control-0a335285792644c1a35de52ece073974` retains the complete
control output and ownership/provider records. This proves the narrow launcher
prerequisite, not MSIX installation, editing or isolation. Independent outer
driver process/stream/deadline supervision and the real application lifecycle
remain required before accepting that trial.

## Feedback into assessment

The completed trial must inform shared assessment without introducing a second
verdict engine: distinguish source application identity from delivery package
identity, requested trust level from observed token/package identity, installation
paths from observed user-data paths, and uninstall registration cleanup from data
deletion. Preserve the explicit adaptation and before/after inventories. A package
or SDK error is a delivery/driver result, not application incompatibility. Reuse
the existing protected intake, approval/session binding and receipt-last evidence
publication when promoting this research into a production path.

The first worker result already demonstrates two reporting requirements: token
claims need observations of the actual application process, and uninstall success
needs registration readback rather than command acceptance. An unsuitable worker
operator is a trial prerequisite failure, not evidence that the application is
incompatible. Existing assessment standard-user controls remain the implementation
to reuse; this research does not introduce a separate compatibility verdict.
