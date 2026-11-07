# Native process-tree control, 2026-11-06

## Result and scope

Source `191ac27629b187b7f4b8f4a76fb491ef9809816a` completed one fresh,
offline, first-party control trial on existing VM107. The retained result is
**partial; the fixed controls did not pass**. No 7-Zip installer, application or
MXC runtime executed. The installer was transported as an inert pinned input.

The ordinary trace contains six processes: three pinned helper roles and three
observed `C:\Windows\System32\conhost.exe` images. All six have paired create/exit
events, match the independently held ordinary root token boundary except PID,
and reconcile with the exact owned job. The compiled control contract requires
exactly three helper images, so it correctly refuses this observation before
the classic AppContainer control is reached. Do not reinterpret this old run as
a passing control by changing the verifier.

Seven owner-stage captures separately failed when the guest attempted strict
`HeldApplicationFile` reads on the mapped output directory:
`GetFileInformationByHandleEx(FileIdInfo)`, HRESULT `0x80070032` (not supported).
The guest-local WORK trace and root binding were retained. This is a distinct
owner-journal transport defect, not an explanation for the six-process trace.

## Observed facts

- The ordinary trace records 188 debug events and six paired process lifetimes.
  The helper exits are `31`, `32`, `33`; the three console hosts exit `0`.
- Every measured token is primary, unelevated, ordinary, medium integrity
  RID `8192`, with zero capabilities and the same user/boundary as the held root.
- The independently held root PID, full-width creation time, token and pinned
  helper image match the root CREATE observation. The root exits before the
  helper child and before the grandchild's CREATE event.
- The exact owned job reports total `6`, active `0`, limit-terminated `0`.
  Trace gaps are empty; the collector does not require debugger-process exit.
  These facts do not satisfy the separate three-helper fixture contract.
- The observed console-host image is 1,003,520 bytes, SHA-256
  `c86146188b78e484f32cc29e2331689659943b47689a85570342044f499938ac`.
  Its creation cause and suitability for a future allowed-role policy have not
  been established by this trial. A filename alone is not trusted provenance.
- Owned outer Sandbox cleanup passed. The original marker's identity, size and
  digest match before/after cleanup and during retained Read. Read reports zero
  provider calls and `retainedObservationsMatch=true`. No recovery or replay ran.
- The owned console, transfer browser tab and two loopback helpers were closed.
  Prior VM107 runs, the reused installer input, new package/transfer roots and
  this trial's records remain preserved. Unrelated VM106 and user apps were not
  changed.

The missing owner records prevent independent reconstruction of the guest
launcher cleanup/context from those records. Candidate/profile controls were
not reached. No application compatibility, effective isolation, registry,
chain-reset-negative, broker/all-host completeness or production acceptance
claim follows from this run.

## Source, environment and custody

The host is `10.0.26300.9711/x86_64`; the approved and observed guest is
`10.0.26100.9711/x86_64`. Actions used the existing non-elevated operator's
machine PowerShell Core `7.6.9`, through reviewed Proxmox-console scripts.
Prepare, independent proposal review, exact approval, one-shot Start and Read
were separate actions. The native marker never authorized another Start.

The initial dev artifacts imported external CRT DLLs. They and their inert R1
package were preserved and excluded from transfer. R2 was rebuilt offline and
locked for `x86_64-pc-windows-msvc`, release, with
`-C target-feature=+crt-static`. Independent PE review found no external CRT,
delay or direct vendor imports in either R2 image. It does not prove binary
reproducibility or enumerate later/transitive OS loads.

The seven-file R2 package used a six-member reduced transport. The omitted
installer was copied only from its exact existing input path under held,
no-follow, single-link, read-only custody; size/hash/EOF and source identity
were revalidated. No prior Trial or evidence directory was adopted.

| Item | SHA-256 |
|---|---|
| Shared source, 16 frames | `ecf8b0d284ea5879ee99bf4abe4fe08c2ee4498511e18ffded250fc57a15caab` |
| Host source, 37 outer frames | `0504c39d37a74645d5e00bd252731dadd0fd5aa92c5ef4cc98b96f11b08fd5ee` |
| R2 helper, 1,169,920 bytes | `7b96b5275808fb999921551f0e077d6d7c1c964aba7ed509c0ba7f7120eefefa` |
| R2 host, 3,439,104 bytes | `9286cda68d5f03d24e33a68f664196e276cb156f6a0cdb6237fc25458768a677` |
| Full package, 3,243,510 bytes | `b95c102ade0fba78e0fb21b609c19de7956c8516eb2b926e2319f34fe85b235b` |
| Reduced transport, 1,600,096 bytes | `798f5ed1ec3d86ad5f87bab0313cf2943ce27af6a3d9c287d4b3b5090b5f8407` |
| Manifest | `e3c896c2b9480de9ac52c6008ec71b83d7ecdedad82955222485cf7bf758a10b` |
| Approved plan | `4ce17be598a51e31813de74639bf810c0e9776fa33ef8feab0d25660183be06e` |
| Rendered config | `1d2d1931f30679c4367611f865c8b64d4cb08c5e71b75d3193ce92fc683fb7f4` |
| Original marker, 11,866 bytes | `e77112ded6d95ff8bf62e56875c29c48005dfeb6ffb96eac3f3a35aa3a0d4533` |
| Start received envelope | `919b367459968bcb28dd186d8c368d7057fdbede2c1fa151a946e0ea121f50fa` |
| Read received envelope | `c71a3f14e3f5af2a5a301c42fe89f33ea903b06caa2e37dd66081e63c6cec4e4` |
| Independent outcome audit | `5425c315b461e5d10e054b2b75ad92a2e140ca33c176f88d8bea3914c7dc427e` |
| Independent partial-trace audit | `a516108a74bcc60bfb739cc96cd8bc5ea6d1090aa287962f9b2f0c4e29397993` |

Raw marker bytes, full-width process/file identifiers, source/PE/package reviews,
frozen lossless auditors, received envelopes and original marker remain outside
Git at `C:/aiw/sevenzip-tree-20261106`. Do not audit their numeric identifiers
through ordinary JavaScript numbers or rewrite the original bytes.

## Required correction and remaining acceptance

Keep strict intake/file-identity checks unchanged. The owner journal needs a
fresh protected guest-local directory, with durable local publication before
terminal snapshot. Standard-user and candidate code must not receive write
access to those owner records.

The reviewed direction keeps the current launch semantics and retains every
observed process. Define a bounded console-support role using independently
held System32 code identity, bytes and Windows provenance before launch, then
compare actual event images and enforce the declared token policy. No medium
or non-AppContainer support process may silently bypass the candidate boundary
check. A detached-only fixture would not validate the unchanged application
launcher. Any revised policy needs a fresh source-bound proposal and native
proof. Do not silently allow extra images by filename, reduce actual application
coverage, or grant wider permissions to obtain a passing result.

Fresh positive and deliberate chain-reset-negative native proof, actual 7-Zip
process-tree/registry wiring, repeat comparisons/archive investigation,
new-source faults/recovery, desktop multi-mode Results and retained sanitized
exports remain required by the [acceptance map](MULTIMODE-ASSESSMENT.md).
Benchmark 2 target-application descendant coverage and broad W4/W5/production
acceptance remain open.
