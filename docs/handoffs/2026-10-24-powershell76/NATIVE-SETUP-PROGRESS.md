# Approved native setup progress

Nathan explicitly approved stages A–D under SETUP-AND-ACCEPTANCE.md. This records
observations, not completion of worker acceptance. PR103 remains unmerged.

## Controller VM203

The first elevation attempt was canceled before installation. Nathan requested
another attempt; the approved Microsoft PowerShell 7.6.7 x64 MSI completed with
exit0 at 2026-10-25T04:19:33Z. No reboot was requested. MSI SHA256 remained
`ec575cef9ec56fcd905de0d5eeac9cb7f81a0a65abb87bb5cd0e87fdfe2b8cc0`;
Microsoft Authenticode was valid. Installation used ENABLE_PSREMOTING=0,
REGISTER_MANIFEST=0 and ADD_PATH=0. No application trial ran on VM203.

The actual production guard initially stopped at native Get-CimInstance. In this
official runtime, CimCmdlets exposes Module.Path directly as
`C:\Program Files\PowerShell\7\Microsoft.Management.Infrastructure.CimCmdlets.dll`,
outside the Modules directory. Its implementing assembly has that same path.
The corrected guard admits only Get-CimInstance as a Cmdlet from CimCmdlets with
both exact paths. It does not permit arbitrary PSHOME modules or proxy functions.
All three consumers retain the identical proof block.

The corrected direct proof passed on UUID
`652a575b-a462-418e-95bb-360b28516925`: Core7.6.7, x64, no prerelease or compatibility
session, all 15 native command capabilities, fixed PSHOME and valid Microsoft
executable signature. Executable SHA256:
`fa2c8bb1e35cdd62ad15cd06a1d8f2c5961e9725a9bfa1e7cfd2c322f49e9619`.
Loaded SMA SHA256:
`70701f20afbbf4e763924c2bdd0c0e9a20eec35a0e4eff439e0ccf77f20d6b26`;
assembly version7.6.0.500, MVID `051b7e56-453c-4221-8845-a5cb965cf12f`.
These observations do not prove worker deployment or application behavior.

Original MSI log, install result and runtime receipt remain outside Git under
`C:\AIW-Resume-20261021\powershell76-approved-9ce03fa-20261024`.
The first proof's checkout/blob hash mismatch was diagnosed as CRLF conversion
only; exact Git/raw guard bytes were verified before the capability failure.

## Correction validation

The exact consumer-loop regression accepts the native binary layout and rejects
seven variants: Function, Alias, wrong module name, another module directory,
a module under Modules masquerading as CIM, another implementing assembly and
missing module. Existing runtime/host/configuration/proxy/ACL checks still pass.
Runtime policy passed five rejection cases across 99 launch-graph files.
An independent read-only source review found no actionable findings; it performed
no VM execution. Full logs remain outside Git as `native-cim-*.log`.

## Worker bootstrap and endpoint observations, 25 October 2026

Nathan subsequently approved a one-time Windows PowerShell5.1 remoting bootstrap
exception for the existing operator credential. It installed the exact verified
MSI once on VM107 (exit0) and launched the installed Core executable for endpoint
setup. The exception is complete; subsequent validation and management use only
Core7.6.7 through normal HTTPS. No credentials, key permissions, listener,
TrustedHosts or firewall scope were expanded. VM106 was not contacted.

VM107's direct executable and loaded SMA identities match the controller hashes
above. Actual PowerShell.7.6 WSMan proof observes wsmprovhost.exe, its loaded Core
assembly and the independently launched worker executable. ConfigXML SHA256:
`fa2df1cdacc7487cffe18c45dab3829423112885f410f13cac0643664aea6647`.
The sole initialization parameter is PSVersion7.6. Native Core registration must
omit the PSVersion setter, which throws on Core; its default creates the required
major.minor value. Endpoint SDDL remains
`O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;S-1-5-21-3556347314-2314855617-1438300668-1001)`.

The plugin staging directory needed existing WinRM NetworkService read/execute
on its exact parent/child directory and inherited files. Protected ACLs retain
SYSTEM/Administrators full control and operator/NetworkService read/execute;
the order-independent comparator rejects six unsafe ACL variants. This changes
service file access, not endpoint authentication. Partial setup failures were
retained, inspected and continued only at the missing fixed stage; the MSI was
not replayed. Active HTTPS firewall auditing retains package-bound/inactive rows
without treating them as unbound network grants; six negative controls pass.

The actual asynchronous observer exposed an additional success-stream object
from Task<VoidTaskResult>. All three production observers now suppress only the
awaiter return with `[void]`, retaining exceptions and cleanup. The extracted
real-child regression fails against the former code and passes after correction.
The corrected native proof has exactly one runtime record and same-session copies
in both directions. Proof SHA256:
`f05f23f5bd2614bbad3ac305ef5159f4f62898869ab766184369a39ac2577d11`.
An independent source review found no actionable findings. The initial noisy
proof remains failure evidence, not accepted producer evidence.

After the Core proof, the default Microsoft.PowerShell endpoint was disabled.
Core's Get-PSSessionConfiguration did not enumerate that legacy plugin, so its
failed retirement task made no change. A separately recorded continuation set
only its native WSMan Enabled leaf to false and restarted WinRM. This is the
[documented underlying disable operation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/disable-pssessionconfiguration?view=powershell-7.6).
The continuation result and a fresh production observer confirm disabled legacy
state and normal Core HTTPS access. No fallback session was used.

Private setup evidence remains under
`C:\AIW-Resume-20261021\powershell76-remoting-92b1ab7-20261025`.
All49 guest setup files were accounted for:48 copied and hash/length-verified;
the duplicate MSI is retained as the exact approved controller input. Export
inventory SHA256 is
`64bd78c79fd81d9c0f9361b6293879720a5d2fcd679873f25eefd74474fde0ff`.
All seven terminal setup tasks and only the exact verified setup directory were
removed after export. The production Clean block then passed baseline accounts,
no trial package/process/tasks/raw artifacts, disabled automatic sign-in and the
sole pinned HTTPS listener. These are setup observations, not app acceptance.

## Observed new baseline and remaining acceptance

With no active lease, VM107 was shut down, its exact MAC retained and NIC put
down. Cold snapshot `aiw-msix-worker107-pwsh76-clean-r1` covers OS/EFI/TPM with
no RAM. Both historical snapshots remain intact. Actual reopened snapshot config
SHA256 is `4d0e51d5c13d8ad77c200c5c7a7981cabb96611b761ff1770895b0221037dbb8`.
Provider source selects this name; normalized wrapper SHA256 is
`5d04868891b253b0cf9592ae76f72224813fc0c6c8aa8302e982d2dd8ecd782d`.
Runtime snapshot/config pins are populated from actual provider observation,
not a guessed hash. A subsequent cold rollback recreated all three107 volumes,
then started the guest with its exact MAC connected. The first read-only HTTPS
probe failed during startup; a later normal HTTPS production observer and exact
production Clean block passed on Core7.6.7, including disabled default legacy
endpoint and absent setup directory. Both attempts remain private evidence.
No restore or application dispatch was retried. Exact reviewed provider bytes
were subsequently downloaded from immutable source9dbf4d8, hash-verified and
atomically deployed without changing root-only mode or the forced SSH key verbs.
Existing-key probe confirms the new snapshot/config/provider hashes, running
state and no active lease. This source-test repair does not change those bytes.

The new ignored native harness covers fresh authoritative raw evidence with
missing/partial caches, blocked collection retaining a dirty lease, compatible
older preparation inputs, pre-dispatch incompatible preparation rejection and
delayed interactive readiness before exactly one Control42. Its Queued case is
an injected exact-consumer regression, not a native scheduler queue observation.
It never dispatches application Run or replays a historical preparation.
Compilation/source review do not establish native acceptance.

## Astra review and queued assertion repair

Astra reviewed exact source9dbf4d8 and found one P2 in the native fixture's queued
assertion. Its injected task observation shared an OR guard/error with real
agent/editor processes, so such a process could hide loss of Queued rejection.
The repair injects an empty process result only within that test assertion and
records that isolation in its receipt. It changes no production Collect guard.
The offline regression extracts the actual native assertion and actual Collect
body, supplies an ambient agent, then removes only Queued from the task guard.
The former assertion falsely passed that mutant; the repaired assertion rejects
it. Both original raw-evidence export controls and the new regression pass on Core.
Queued coverage remains injected, never a native queued-task observation.

The9dbf4d8 CI passed all three jobs. Its queued package driver was cancelled
before publication after the Astra finding. Local source validation retains the
initial one-second deadline assertion failure under parallel load and the passing
unchanged focused test. A serial workspace/check pipeline is still in progress;
do not relabel it complete. Neither the new full trial nor bounded native fixture
has run. Exact-source Astra re-review and repaired-checkpoint CI remain gates.

Build a fresh verified package from the repaired coherent clean checkpoint only
after source-review/validation gates. Report full application lifecycle
and bounded fixture execution separately, then export originals before cold
recovery and release. Historical packages/runs remain historical. No trial
account or app execution is claimed here. PR103 remains unmerged; preserve all
exclusions and the remaining stageC/D gates.
