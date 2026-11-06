# MXC capability trial, 2026-11-06

This is a research capability observation, not application compatibility,
effective enforcement, a verified production receipt or native acceptance of the
multi-mode workflow. The host rejected the returned marker's custody check.

## Source and authorization

AIW source `2e77e4f1327bb12af193c1c398dbe2f14c4952ea` embeds capability source hash
`ab06d421702326f7e730848176a598db7128b6db70928675f733ad19aee79098`.
The user approved the pinned Microsoft MXC 1.0.1 runtime only in fresh Sandboxes
on existing VM107 through reviewed Proxmox-console scripts. Parent runtime
installation and VM/host security changes were excluded.

Official MXC release source is
[`fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2`](https://github.com/microsoft/mxc/tree/fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2).
The selected x64 DLL was 6,123,320 bytes, SHA-256
`bd45522f06dc9cc8001dcd5d7320bc2bf303fb08a39bf10f3404bd9a8001812c`,
with Valid Microsoft Corporation Authenticode at acquisition. See the
[selection and provenance limits](MXC-ASSESSMENT-SELECTION.md).

## Execution and retained observations

VM107 parent Windows was `10.0.26300.9711/x86_64`; the fresh Sandbox guest was
`10.0.26100.9711/x86_64`. A non-elevated ordinary parent operator prepared and
approved the exact plan. Only a dedicated ordinary guest user loaded MXC.
The Sandbox was offline, with read-only tools and a separate writable output
mapping. No 7-Zip installation or application execution was requested.

The staged eight-file packet and embedded source were independently verified.
The private launcher's first Prepare failed because a singleton PowerShell
string was splatted into characters. A separately reviewed, create-new launcher
correction used an explicit string array; all five action argument tests passed.
Original files and the failed attempt were preserved.

Corrected Prepare and separate Approve succeeded. The independently reconstructed
plan hash was `8de5274455619a27aae57085ea3c9306110f0177b3dd282a62a7f06845505266`.
Exactly one Start was issued for that plan. Its bounded wait expired because the
host refused the returned marker at `exact-child-entry`: case drift or a
short-name alias. The owned Sandbox stop succeeded and cleanup was recorded
before output inspection. Start returned failure; it was not replayed.

A reviewed read-only capture subsequently preserved the original 12,704 guest
bytes, SHA-256 `4422e0830cb31a83cce4b63196259d9c515478e0e90f092a5f0b46eb01984199`.
An independent lossless audit passed 279 checks, binding these research bytes to
the approved five requests, runtime/helper/source, guest environment and measured
ordinary-user token. The guest reports were:

- All five fixed policy probes returned FFI status 0 and `supportedForRequest`.
- Each reported `base-container`, no DACL augmentation, BFS absent and no warnings;
  deny-path and all requested UI capability flags were present.
- Collection was complete, child exit was 0, the owned child job was empty and
  payload revalidation succeeded.

These are SDK capability reports. No ProcessContainer workload was created and
no filesystem, network, registry, UI or descendant restriction was exercised.
The raw capture does not repair the rejected host custody check or convert this
run into product evidence. Other SDK availability flags do not validate other
MXC isolation families.

A subsequent read-only namespace query observed long name `result.json` and
alternate name `RESULT~1.JSO`, with one link, ordinary archive attributes, and the
same 12,704-byte digest. Thus the short-name refusal is confirmed; case drift was
not observed. No retained file or alias was changed. The exact atomic-rename
contribution still needs a controlled publication experiment.

The retained-only host Read succeeded with `providerCalls: 0`, preserving the
original failed Start, exact approval and verified outer-cleanup observations.
Private raw files, identities, scripts and audit logs remain outside Git under
`C:/aiw/mxc-multimode-20261106`.

## Required continuation

Keep the strict custody check. Validate a corrected publisher
in a fresh owned environment before a new capability or creation trial; never
repair and adopt this run. Then measure actual ProcessContainer creation and
requested restrictions before using it for the automated 7-Zip comparison.

The [multi-mode acceptance map](MULTIMODE-ASSESSMENT.md), fresh comparisons,
application-tree/registry controls, fault/recovery work, desktop Results, exports
and Benchmark 2 mapping remain open. This trial does not complete W4/W5 or broad
production acceptance.
