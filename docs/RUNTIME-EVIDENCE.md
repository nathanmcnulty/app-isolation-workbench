# Runtime evidence foundation

This document records the primary-source snapshot and the initial integration contract reviewed on 2026-08-19. It is deliberately dated: all experimental Windows and MXC contracts must be reverified before a pin is advanced.

## What is implemented

AIW now has three non-elevating building blocks:

1. `aiw-golden-probe` queries its own primary access token and emits versioned JSON. It records the user and AppContainer SIDs, integrity SID/RID/class, token and elevation types, elevation state, capabilities, and restricted-SID count.
2. `aiw-provider-wsb` renders a direct `.wsb` configuration but does not launch it. It disables networking, vGPU, clipboard, printer, audio input, and video input; enables Protected Client; maps tools and inputs read-only; and permits exactly one writable output mapping.
3. `aiw-provider-mxc` renders an MXC request and the exact argument arrays for dry-run and execution. It never starts `wxc-exec.exe`. The adapter is pinned to the source revision in `third-party/mxc-pin.json`.

The probe must execute as the target. Launcher-token inspection is not accepted as evidence of the effective boundary.

## Microsoft Create Process in Sandbox snapshot

The current Microsoft Learn contract describes `Experimental_CreateProcessInSandbox` and its AsUser variant as dynamically loaded exports from `processmodel.dll`. The sandbox specification is a FlatBuffer with the `SBOX` identifier and currently requires specification version `0.1.0`.

Important constraints for AIW:

- An identity names the sandbox and affects the token SID. Reusing an identity reuses the corresponding AppContainer profile and derived permissions.
- AppContainer must be enabled for the documented filesystem, capability, and network controls to take effect.
- AppContainer execution forces the secure low-integrity default. The API refuses integrity elevation above the caller.
- Process/thread security attributes and handle inheritance are currently unsupported.
- An AppContainer caller cannot create another sandbox through this API.
- The public header is not available, so consumers dynamically resolve the export and fail closed when absent.

Source: [Create Process in Sandbox](https://learn.microsoft.com/en-us/windows/win32/secauthz/createprocessinsandbox).

## Target token evidence

The probe opens its own process token with `TOKEN_QUERY` and uses `GetTokenInformation` for:

- `TokenType` and, when relevant, `TokenImpersonationLevel`
- `TokenIsAppContainer` and `TokenAppContainerSid`
- `TokenUser` and `TokenIntegrityLevel`
- `TokenElevationType` and `TokenElevation`
- `TokenCapabilities` and `TokenRestrictedSids`

The implementation validates variable-size buffers, rejects disagreement between the AppContainer boolean and SID, sorts capabilities for deterministic output, and confines Win32 FFI to `aiw-token`. The documented identity-level impersonation caveat is addressed by recording token type and only querying an impersonation level for an impersonation token; the current golden probe uses its process primary token.

Source: [GetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation).

## Direct Windows Sandbox contract

Windows Sandbox defaults are unsuitable for hostile installer assessment: networking, clipboard, audio input, and vGPU can be enabled by default. AIW emits every relevant security setting explicitly rather than relying on defaults.

Mapped folders are a deliberate declassification boundary. Every mapping must be strictly below an explicit workspace root. Tools and inputs are read-only. A single output mapping is writable so the target can return evidence; it must exist, be an ordinary directory root, resolve distinctly from other mappings, and be empty immediately before use. Canonical paths are checked again so a reparse root or alias cannot escape the workspace. Returned files remain untrusted. There is an unavoidable time-of-check/time-of-use interval between rendering and launch, so a future runner must revalidate immediately before process creation and retain the directory handle where possible.

The logon command invokes only a measured fixed-function probe or `aiw-guest-agent` with a typed request/output argument. The Store CLI environment must then be explicitly connected to establish the user logon that triggers this command. The planner does not accept arbitrary logon commands, scripts, URLs, or policy fragments.

Source: [Use and configure Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file).

## MXC pin and behavior

AIW currently targets Microsoft MXC commit `c4a3ab668e85b221b2c77e5e43876ed4e40598ad` and its development `0.8.0-alpha` contract. The development schema is not treated as stable merely because AIW can serialize it.

The adapter requires all MXC filesystem policy roots to be strictly below the declared AIW workspace root and uses `--config-base64` so there is no transient config-path substitution or quoting ambiguity. Its output contains:

- the exact source pin;
- canonical compact config JSON and its SHA-256;
- the base64 payload;
- a dry-run invocation containing `--dry-run`;
- a separate execution invocation marked as requiring human approval.

For ProcessContainer, MXC selects AppContainer or BaseContainer at runtime based on host capability. AIW therefore relies on the in-target token evidence, not the requested `processcontainer` label. AIW sets `fallback.allowDaclMutation` to `false`; a host that requires the DACL fallback must fail closed. Network defaults to block and UI/clipboard/input injection are disabled.

The Windows Sandbox backend is experimental, permits one VM per logon session, supports one-shot and state-aware modes, and treats same-user host processes as inside its trust boundary. One-shot teardown is best effort after a launcher hard-kill. State-aware mode has no idle watchdog and therefore is not yet exposed by the AIW planner.

Crucially, `wxc-exec --probe` is not a pure read. At the pinned source revision, `main.rs` performs best-effort recovery of orphaned DACL state before entering the probe fast path. AIW represents that command as a potential host mutation and does not execute it automatically.

Sources: [MXC schema](https://github.com/microsoft/mxc/blob/main/docs/schema.md), [MXC Windows Sandbox backend](https://github.com/microsoft/mxc/blob/main/docs/windows-sandbox/windows-sandbox.md), and the [pinned source tree](https://github.com/microsoft/mxc/tree/c4a3ab668e85b221b2c77e5e43876ed4e40598ad).

## Not yet claimed

This tranche does not prove that either provider can run successfully on a particular host. It does not enable Windows Sandbox, install/build MXC, elevate, create AppContainer profiles, launch a sandbox, collect process descendants, or authenticate an evidence channel. Those operations require an explicit runner design and live test matrix.

The next validation slice should cover:

- direct `.wsb` launch with the golden probe and output-directory revalidation;
- MXC dry-run against the pinned binary, followed by approved ProcessContainer and Windows Sandbox runs;
- AppContainer and BaseContainer differential evidence across supported Windows builds;
- token evidence from child processes plus job/process-tree completeness;
- offline network, host-file, registry, clipboard, sibling-process, and UI canaries;
- cleanup/orphan detection and feedback-bundle export.
