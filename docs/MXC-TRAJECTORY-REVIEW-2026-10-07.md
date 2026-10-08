# Containment trajectory review — 2026-10-07

## Decision

Keep the administrator-led **Assess -> Adapt -> Package -> Validate** product and
its disposable-worker execution boundary. Finish the current signed Notepad++
MSIX lifecycle slice, then prioritize one measured real-application isolation
comparison over more packaging recipes. Complete the real classic AppContainer
comparison using the existing control foundation, then evaluate current MXC
ProcessContainer against the same workflow if its controls pass. Source/SDK review
can proceed independently of the classic comparison. Do not require every MXC
backend or turn AIW into an agent harness.

This is a roadmap decision, not runtime acceptance. Reviewed AIW source:
`8979c6e4d91af170d69fd694b81b845511228319`, including `aiw-provider-mxc`,
[roadmap](ROADMAP.md), [threat model](THREAT-MODEL.md),
[control evidence](CONTROL-FIXTURE.md), and [MSIX lifecycle](NOTEPAD-MSIX-LIFECYCLE.md).
Our MXC adapter still only generates plans for commit
`c4a3ab668e85b221b2c77e5e43876ed4e40598ad`, contract `0.8.0-alpha`.
It disables learning mode and DACL fallback; its capability-probe plan explicitly
warns of possible recovery mutation. No MXC binary was run for this review.

## What Microsoft's guidance changes

The [October 7 announcement](https://blogs.windows.com/windowsdeveloper/2026/10/07/microsoft-execution-containers-policy-driven-containment-for-ai-agents/)
usefully separates containment, identity and management, and recommends process,
session, WSL and experimental MicroVM configurations for different workloads.
Its policy-authoring modes distinguish enforced denials from permissive observation.
It describes MXC and Windows 365 support as generally available; Intune process
policy and Entra/Agent 365 attribution are future capabilities. Treat these as
vendor statements, not measured AIW capabilities.

The [current repository](https://github.com/microsoft/mxc/tree/7cd00d1ee6af9208322c924ef64e5113f6704639)
also lists Windows Sandbox, LXC, Bubblewrap, Seatbelt and Hyperlight. Its README
marks the Windows Sandbox, MicroVM and Hyperlight Windows paths experimental.
The versioned Rust/.NET/Node SDK surface warrants review before retaining our
external development-contract adapter. GA branding does not establish equivalent
policy semantics across those backends.

The upstream documentation snapshot used here is commit
`7cd00d1ee6af9208322c924ef64e5113f6704639` (October 7), **not a new AIW runtime pin**.
Recheck source and release artifacts before implementation. This review sampled
consumer/backend documentation; it is not a full security audit of that commit.

The first adoption candidate should be the [v1.0.0 release](https://github.com/microsoft/mxc/releases/tag/v1.0.0),
published October 7, at peeled tag commit
`7bf210247986cb73b1b314df60c2f1109c479c0b`. The release and latest-main research
snapshot are distinct; do not adopt `1.1.0-alpha` features through a stable-version
claim. Review the exact SDK package/native-asset inventory, hashes, signatures,
dependency/SBOM availability and provenance before choosing official assets or a
source-built executor. Release artifact signatures have not been verified here.

Microsoft's [Copilot integration description](https://commandline.microsoft.com/local-models-sandboxed-tools-github-windows/)
is especially useful for defining coverage: shell/local servers can be contained,
while built-in file tools rely on harness checks and remote MCP remains outside
the local process sandbox. Therefore “uses MXC” cannot support a whole-agent
containment claim. AIW should record the boundary of each adapter and broker.

## Backend selection and scenario coverage

These priorities are AIW decisions. Backend names are not a security ranking;
select against the declared threat, resources and required functions.

| Option | Scenario to consider | AIW priority and acceptance boundary |
|---|---|---|
| Existing Windows Sandbox / checkpointed VM | Installer execution, package capture, risky application trials | Retain the outer disposable boundary. Our direct Store-provider proof does not transfer to MXC's experimental Sandbox adapter. |
| Classic AppContainer | Windows application function comparison with narrowly granted resources | Existing control proves classic AppContainer, not LPAC. Complete its real-application comparison first; LPAC is a separately declared future candidate. An MXC BaseContainer result need not have an AppContainer token. |
| MXC ProcessContainer | Low-latency fixed tool/plugin or application workflow | First MXC feasibility candidate. Compare the same workflow and allowed/denied controls; require exact effective tier and policy support. |
| MXC IsolationSession | Long-lived Windows desktop automation separated from the operator | Conditional on a desktop requirement. Current policy rejects filesystem/UI settings and requires unrestricted network; unsuitable for the least-privilege file/network comparison. Test actual session separation and exact account/session teardown. |
| MXC WSLC | Linux-first development tools | Conditional on a Linux workflow. Networking is all-allow or all-deny; its proxy is cooperative. Bind Windows mounts, image acquisition and persistent state; host pulls lie outside container policy. |
| MicroVM (Nanvix) | Selected higher-risk Linux workloads | Experimental research. Current constraints include 256 MB RAM, no working directory or denied-path policy, snapshot/copyback semantics and coarse networking; broad Linux compatibility is unproven. |
| Hyperlight | Specialized virtualization-backed workloads | Separate experimental candidate. Verify supported guest payload/toolchain, host-call surface and resource lifecycle; neither Nanvix compatibility nor native Win32 GUI support transfers to it. |
| Bubblewrap / LXC / Seatbelt | Linux or macOS consumers | Track as portability options; defer implementation until there is a supported non-Windows workflow and its own acceptance environment. |
| MSIX / Win32 app isolation / App Silo | Delivery and Windows application adaptation | Continue delivery work separately. Full-trust MSIX is not containment; app-isolation preview/fallback needs its own effective-boundary proof. |

## Ordered work and closure gates

1. **Close the existing delivery slice.** Finish the exact signed MSIX install,
   activation, document/configuration and uninstall checks already specified in
   [NOTEPAD-MSIX-LIFECYCLE.md](NOTEPAD-MSIX-LIFECYCLE.md). Record packaged medium-IL
   execution only; this cannot close Benchmark 2. Do not add another converter.
2. **Review one proposed MXC integration revision without executing it.** Start
   with the exact v1.0.0 tag/package inventory above, independently of completing
   the classic comparison. Follow
   [pin review](MXC-PIN-UPDATE.md); compare stable SDK and native wire contracts,
   license/dependencies, runtime asset provenance, schema defaults and unknown
   fields, probes, fallback, elevated helpers and recovery side effects. Decide
   SDK versus external adapter from the required capabilities and authority
   boundary. Unsupported requested controls must fail before workload execution.
3. **Run project-owned controls in a disposable environment.** Verify driver
   handles/exit, captured output, deadlines and exact cleanup first. Then test
   allowed access and denied access, child inheritance/breakaway, cancellation,
   collector failure and wrong/unsupported backend. Record requested/effective
   tier, OS servicing build, feature support, runtime hash and policy hash. If
   Sandbox cannot reproduce the required semantics, use a checkpointed VM and
   document why. No host installers or automatic host preparation.
4. **Close one real classic AppContainer baseline/candidate comparison first.**
   Integrate the existing control evidence and choose a real workflow explicitly.
   Use matching app/input bytes, driver, worker image and account context, with
   declared candidate differences. Retain an unsupported result if necessary;
   baseline/driver failure prevents attributing failure to containment. Complete
   two fresh comparable repetitions and approved replay before broader coverage.
   Then run MXC ProcessContainer against that same workflow if its controls pass,
   reporting its effective tier separately. Do not replace an unsupported classic
   result with MXC success or treat the two configurations as equivalent.
5. **Make policy refinement reviewable.** Add receipt-bound deny-and-record
   diagnostics only if they answer that workflow's failures. A proposed grant
   must explain purpose, scope and evidence, require fresh bound approval, and
   rerun affected functions and canaries. Add session/WSLC/VM adapters only when
   one of the scenarios above demonstrates a need.

The [Windows support table](https://github.com/microsoft/mxc/blob/7cd00d1ee6af9208322c924ef64e5113f6704639/docs/backends/process-container/os-version-support.md)
now gives servicing-build floors: for 24H2, process `26100.9278` and session
`26100.9550`. These are upstream requirements, not proof that the existing AIW VM
qualifies. “Windows 11 24H2+” and an exported function alone are inadequate;
record runtime feature support for the complete request.

## Security and evidence gates to add to Benchmark 2

- **Independent authority:** policy, approval, helpers and collectors stay outside
  workload control. Test policy replacement, widened grants, inherited handles,
  writable executables/configuration, reparse/hardlink aliases and child escape.
  Retain the current fixed typed commands; an SDK's generic command interface
  must not become AIW's public execution contract.
- **Filesystem and secret boundaries:** project-owned controls reproduce writable
  repository/output, read-only configuration and inaccessible unrelated data.
  Include secret-like files, environment inheritance, pipes/IPC and credential
  broker access without using real credentials. Successful legitimate reads and
  denied writes must be measured separately. Local identity is not Entra identity.
- **Network boundaries:** controlled endpoints test egress, ingress and host
  loopback separately, including required children and proxy bypass. Bind proxy
  identity/configuration and endpoint observations. The current [network guide](https://github.com/microsoft/mxc/blob/7cd00d1ee6af9208322c924ef64e5113f6704639/docs/backends/process-container/networking.md)
  excludes durable DNS-name rules and arbitrary transparent TCP/UDP proxying from
  ProcessContainer GA scope; it also records a bidirectional loopback limitation.
  Do not turn a numeric rule or working HTTP proxy into a domain allowlist or
  general network-isolation claim.
- **UI and brokers:** test requested GUI permission independently from clipboard,
  synthetic input and cross-process interaction. [UI policy](https://github.com/microsoft/mxc/blob/7cd00d1ee6af9208322c924ef64e5113f6704639/docs/backends/process-container/UIPolicy_Schema.md)
  has distinct controls; a usable window does not prove desktop separation.
  Inventory external helpers, services and COM/MCP brokers, identifying which
  accesses are OS-enforced and which rely on a trusted broker's checks.
- **Diagnostics are incomplete evidence:** bind actionable JSON, verbose sibling
  and retained trace to exact process generations, mode, policy and run. Preserve
  loss, truncation, unsupported events, decoder failures and missing artifacts.
  The [denial guide](https://github.com/microsoft/mxc/blob/7cd00d1ee6af9208322c924ef64e5113f6704639/docs/logging-access-denied.md)
  distinguishes blocked capture from allow-and-record, with backend selection and
  bounded outputs. Empty denial lists are not proof of no access; observed access
  is not proof of necessity. Protect resource paths and evidence confidentiality.
- **Lifecycle ownership:** preserve exact provisioned identity, bounded stop,
  deprovision and physical/process absence, including interruption/recovery.
  [SDK lifecycle guidance](https://github.com/microsoft/mxc/blob/7cd00d1ee6af9208322c924ef64e5113f6704639/docs/container-lifecycle.md)
  uses opaque container identities; a display label must never regain authority.
  Account, registration, ACL, trace and persistent-state cleanup need separate
  records when the selected backend creates them.

## Guidance we will not adopt without qualification

The announcement's broad compatibility language is not sufficient. The sampled
[Nanvix guide](https://github.com/microsoft/mxc/blob/7cd00d1ee6af9208322c924ef64e5113f6704639/docs/backends/nanvix/nanvix.md)
documents constrained memory, policy and copyback behavior. The separate
[Hyperlight guide](https://github.com/microsoft/mxc/blob/7cd00d1ee6af9208322c924ef64e5113f6704639/docs/backends/hyperlight/hyperlight-backend.md)
must inform its own supported-workload decision. Virtualization alone does not
establish function compatibility or safe host integration.

The [IsolationSession policy matrix](https://github.com/microsoft/mxc/blob/7cd00d1ee6af9208322c924ef64e5113f6704639/docs/development/architecture/backends/isolation-session/oneshot.md)
requires all-allow networking and rejects filesystem/UI settings; account/session
separation is a different boundary from ProcessContainer's resource policy.
The [WSLC guide](https://github.com/microsoft/mxc/blob/7cd00d1ee6af9208322c924ef64e5113f6704639/docs/backends/wslc/wsl-container-getting-started.md)
describes coarse networking, cooperative proxying and host-side image acquisition.
Use approved digest-bound cached/local images for offline trials; never silently
enable egress to fetch an image. Verify these sampled-main limits again for the
actual adopted release. A shared policy field must not imply shared enforcement.

Permissive/audit mode cannot validate containment. If needed for policy research,
use a separately approved trusted project-owned workload inside the outer
disposable boundary; preserve its relaxed mode in reports and exclude it from
enforced candidate acceptance. Never automatically apply generated grants.

Do not silently accept a different tier or full-trust fallback. A compatible
alternative can become a separately declared candidate with fresh approval and
its own checks. Do not change system-drive/device ACLs to make a run pass. Current
[host-preparation guidance](https://github.com/microsoft/mxc/blob/7cd00d1ee6af9208322c924ef64e5113f6704639/docs/backends/process-container/host-prep.md)
includes privileged machine-wide changes for the DACL tier; the new probe is
documented read-only, unlike the warning on our old pin. Verify actual source
semantics before changing probe classification. Any preparation experiment must
be explicitly scoped to a disposable VM and record changes and cleanup limits.

Fleet management, Windows 365, Entra attribution and OpenShell are integration
options to reassess when a concrete administrator need and available contract
justify them. They are not prerequisites or security proof for the local tool.
Keep telemetry disabled by default and preserve local evidence authority.

## Review outcome

The existing provenance, approval, worker and reporting boundaries are the right
foundation. The most valuable next improvement is demonstrated effective
isolation for one useful workflow, with truthful failure/coverage reporting.
Adding backend names or accepting a vendor's suggested policy would not close
that gap. This document supplies gates; implementation and live proof remain open.
