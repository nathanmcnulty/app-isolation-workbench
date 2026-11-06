# Isolation selection for the real-application assessment

Reviewed 2026-11-05 (America/Anchorage), without building or executing MXC.
The proposed workflow is the Windows x64 7-Zip installer followed by fixed local
archive creation, archive testing, extraction and independent content verification.
The application workflow and boundary controls need separate observations.

## Source identities and availability

The latest official release observed through GitHub's release API is
[MXC SDK v1.0.1](https://github.com/microsoft/mxc/releases/tag/v1.0.1), published
2026-10-17, commit `fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2`. It retains the
stable `1.0.0` request schema. Its `mxc-release-binaries.zip` asset is 542051775
bytes; the API advertises SHA-256
`0e832239454ba7fcd338ff56218a287eef4c0a01c1484084b869f55feff8abe9`.
This is an acquisition identity, not a local download, signature verification,
complete native/dependency inventory, or execution acceptance.

Current main was independently observed at
[`40df784b2c32e764eaed51899a10ee936a2d7c0c`](https://github.com/microsoft/mxc/tree/40df784b2c32e764eaed51899a10ee936a2d7c0c),
committed 2026-11-05. Development behavior must not be attributed to v1.0.1.
AIW still pins `c4a3ab668e85b221b2c77e5e43876ed4e40598ad`,
`0.8.0-alpha`, in `third-party/mxc-pin.json`; its adapter is planning-only.
Neither research nor these release identities advances that pin.

Microsoft's [platform support guidance](https://learn.microsoft.com/en-us/windows/apps/develop/mxc/platform-support)
distinguishes backend availability from V1 SDK operation support. Its stated
v1.0.0 Windows creation set is ProcessContainer, IsolationSession and WSLc;
WindowsSandbox, MicroVM and Hyperlight are experimental and excluded from V1
creation. Persistent lifecycle support is limited to IsolationSession and WSLc.

| Family | Current availability and fit for this assessment |
|---|---|
| Process isolation | ProcessContainer is the relevant MXC candidate for a Windows command-line file workflow. Its effective tier and request-specific policy support must be measured; an accepted request is not proof of enforcement. |
| Session isolation | IsolationSession separates Windows identity/session state. Its stable contract rejects filesystem and UI policies and requires unrestricted egress, ingress and loopback. It cannot supply this assessment's proposed file-denial policy. |
| Micro-VM | Experimental, with separate guest/runtime requirements. Current main's NVX MicroVM path runs Linux commands on Windows x64; Hyperlight runs guest-runtime source in a unikernel. Neither is a Windows 7-Zip installer environment. |
| Linux containers | WSLc runs Linux workloads and requires WSL 3.0.3+, the WSLC client/runtime and an image. A Linux 7-Zip trial would change the application and environment, so it would not compare the selected Windows installation/workflow. |

Sources: [stable policy](https://github.com/microsoft/mxc/blob/fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2/docs/containment-policy/1.0.0/policy.md),
[current NVX requirements](https://github.com/microsoft/mxc/blob/40df784b2c32e764eaed51899a10ee936a2d7c0c/docs/backends/nvx/nvx.md),
[release Hyperlight requirements](https://github.com/microsoft/mxc/blob/fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2/docs/backends/hyperlight/hyperlight-backend.md),
[current WSLc requirements](https://github.com/microsoft/mxc/blob/40df784b2c32e764eaed51899a10ee936a2d7c0c/docs/backends/wslc/wsl-container-getting-started.md).

## Exact OS and runtime questions

The [v1.0.1 OS matrix](https://github.com/microsoft/mxc/blob/fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2/docs/backends/process-container/os-version-support.md)
lists the following Windows 11 servicing floors:

| Release | ProcessContainer | IsolationSession |
|---|---|---|
| 24H2 | 26100.9278 | 26100.9550 |
| 25H2 | 26200.9278 | 26200.9550 |
| 26H2 | 26300.9550 | 26300.9550 |
| 26H1 | 28000.2804 | 28000.3086 |

The retained VM107 control record binds host `10.0.26300.9711` and Sandbox guest
`10.0.26100.9711`. Both exceed their published floors. This is a comparison with
historical evidence, not a fresh runtime observation or proof that MXC works
inside Sandbox. Request-aware probing, tier selection, native feature availability,
policy translation, process/child identity and exact cleanup remain untested for
MXC on this worker. A DLL export alone cannot close them. Denial capture has its
own runtime requirements; release and current-main fallback behavior differ.

Before adoption, follow [the pin review](MXC-PIN-UPDATE.md), including side effects,
native assets/signatures, closed request semantics, inherited environment/handles,
host-DACL fallback and recovery ownership. The stable policy defaults
`fallback.allowDaclMutation` to true; an AIW trial must explicitly refuse that
fallback rather than accidentally widening host authority. Deny-and-record and
permissive learning are separate modes.

Current main also changes the telemetry contract: the development request can
collect Required diagnostics, whereas published contracts retain opt-in/consent
behavior. Preserve that distinction in acquisition and approval disclosures.
See [source-pinned telemetry policy](https://github.com/microsoft/mxc/blob/40df784b2c32e764eaed51899a10ee936a2d7c0c/docs/telemetry.md).

## Candidate decision

Use classic AppContainer first for the fixed Windows 7-Zip comparison, inside the
existing disposable Sandbox worker. This recommendation follows the already
measured native file/registry/child controls and the current production approval,
custody and cleanup foundation. It is not an MXC unsupported verdict. Require
measured target tokens, zero capability SIDs, fixed read/input and write/output
grants, the predeclared canaries and verified cleanup. Application success and
effective controls must remain separate; a broken baseline cannot become an
isolation incompatibility. Network restrictions remain unmeasured without an
independent network control, even with outer Sandbox networking disabled.

Keep MXC ProcessContainer as the next bounded investment against the same
workflow after exact-release adoption and disposable controls. Record its actual
tier; BaseContainer/PSEC must not be relabeled classic AppContainer. Do not
silently switch providers or grants to turn a failure into success.

Keep MSIX alongside this work when packaging is useful. A full-trust MSIX alone
provides no AppContainer verdict, and reusing Windows Sandbox as an outer worker
does not prove application-level isolation. This selection does not close
Benchmark 2, W4/W5, broad application compatibility or production acceptance.
