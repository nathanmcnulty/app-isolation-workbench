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

## Remaining approved work

VM107 has not received the prepared bootstrap. Refresh its exact source URL/hash
to this correction before operator use; do not run the old 9ce03fa bootstrap.
The existing restricted SSH key permits provider verbs, not a bootstrap shell.
The human operator must run the fixed native QEMU guest-exec bootstrap once in
the existing pve-r630 root console. Preserve partial attempts; never replay an
installer blindly. No credentials or management access are expanded.

Stages B–D remain uncompleted: normal HTTPS same-session endpoint/worker/copy
proof, legacy endpoint retirement after proof, observed clean baseline and
coherent pins, then a new verified package and fresh acceptance runs. The
9ce03fa package remains historical and must not be presented as this corrected
source or used for migrated acceptance. No new snapshot/provider pins, trial
account or application execution is claimed. VM106 remains excluded; VM203 must
never be restored; historical completed nonces must never be replayed.
