# Native tree-control correction, 2026-11-06

## Result and scope

Source `f27dda809a23ecd25934b2f74d6f8617d378e307` completed one fresh,
offline first-party trial on existing VM107. The result remains **partial;
the fixed controls did not pass**. The protected local owner journal was
retained successfully, and the ordinary journal-read denial probe passed.
The ordinary process trace then failed the new exact console-object binding.
The classic candidate and its profile were not reached; their measurements and
profile cleanup remain unmeasured, rather than failed cleanup observations.

No vendor installer, application or MXC runtime executed. The official installer
was transported as an inert pinned input. This is a new source and contract;
it does not reinterpret the [191ac276 trial](SEVENZIP-TREE-NATIVE-20261106.md).
That historical exact-three-helper failure and its missing owner records remain
unchanged. No recovery or Start replay ran in either trial.

## Retained partial facts

- All seven fixed owner records were retained from the protected guest-local
  SY/BA-only journal. The start record binds the expected Windows environment,
  helper and inert installer; the standard context and launcher token agree.
- The ordinary journal probe exited `0`, did not time out, reported an empty
  owned job and captured exactly `owner-journal-denied-code5`. Its full token
  matches the held ordinary root boundary after normalizing only process ID.
  This measures read denial; it is not a general tamper-proofing verdict.
- The ordinary trace contains **182 debug events and six paired process
  lifetimes**, comprising three pinned helper roles and three console-support
  images.
- All six creation-time tokens match the independently held ordinary root
  boundary except process ID: primary, unelevated, ordinary, medium integrity
  RID `8192`, zero capabilities. Root PID/time/token/helper hash and size match
  the root CREATE observation. No parent edges are inferred from event order.
- Helper exits are `31`, `32`, `33`; console-support exits are `0`. Root exit
  precedes both the helper child's exit and grandchild's CREATE event.
  Create/exit sequences are paired, ordered and unique.
- Exact job accounting reports total `6`, active `0`, limit-terminated `0`;
  trace gaps are empty and the collector's complete flag is true. These facts
  do not override the separately failed console-object classification.
- The workflow exited `1`. Retained guest launcher cleanup reports an empty
  owned job and no cleanup error; helper bindings remained unchanged.
  The terminal driver result is false. Candidate journal denial, candidate
  tracing and profile cleanup are not measured by this result.

The retained workflow error is exactly:

```text
console support differs from independently held image or exit
```

All three debug-event console images match the independently opened support
image's path, SHA-256 and size (1,003,520 bytes), and each exits `0`. However,
**both legacy `volumeSerialNumber` and `fileIndex` differ** from the separately
held expectation. The full preheld HAF identity and independently queried
legacy identity are retained separately in private evidence. Debug events do
not supply an invented 128-bit HAF identity, and no layout conversion is assumed.

The exact-object contract correctly refuses this observation. Matching bytes or
filenames do not authorize an identity exception. The source of the identity
difference, including any namespace or loader explanation, remains unknown.
No application incompatibility or MXC availability conclusion follows.

## Source, environment and custody

Host: `10.0.26300.9711/x86_64`; approved and observed guest:
`10.0.26100.9711/x86_64`. Separate Prepare, independently audited proposal,
exact approval, one-shot Start and Read used reviewed Proxmox-console scripts
and machine PowerShell Core `7.6.9` under the non-elevated operator.

The correction uses a fresh R2 root/session and `v0alpha2` host/guest envelopes.
It creates the protected local journal before the standard account or worker,
checks the local start record through unchanged strict HAF, and holds journal
ancestry through terminal capture. Mapped output contains only `RESULT.DAT`;
its 19 fixed data/error keys preserve partial observations under byte budgets.
Console support is independently pinned and held before root creation; every
observed support token remains subject to the full intended boundary policy.
The historical `Some(3)` verifier is unchanged. Explicit profile deletion in
the new path suppresses a hidden Drop retry, but this run never reached it.

The offline locked release build used `x86_64-pc-windows-msvc` and static-CRT
flags. Independent PE review found no external CRT, delay or direct vendor
imports; it does not prove reproducibility or enumerate dynamic/transitive loads.
The seven-file package and reduced transport were independently reviewed.
Only the existing pinned installer input was reused under held custody; no
prior Trial, approval or evidence was adopted.

Strict marker custody passed. Original identity, size and digest were stable
before/after verified owned outer Sandbox cleanup and during retained Read.
Read reported zero provider calls and matched retained observations. The original
15,605-byte marker was reconstructed losslessly and preserved unchanged.
The owned console, transfer tab and both loopback services were closed/stopped
under exact ownership guards; their ports were free. Trial roots, packages,
original evidence and unrelated user apps/tabs were preserved.

| Item | SHA-256 |
|---|---|
| Shared source, 19 frames | `132bdb6397cf1679e5df050cd1e8a84d3e026238008e66e0e0e7aa5e199b0586` |
| Host source, 37 outer frames | `93f60d437d770c5f25d1276181cbe074c6030ebc220cea8f0f92d21bc296339d` |
| Helper, 1,195,520 bytes | `bcdd71e023ddd42f7d2e90e01f5a043d4ea8cd51acd84afe35a5ad8abf18d715` |
| Host, 3,518,464 bytes | `90dafba7968252cf28e0d44e027871b7ba127edd0d68cd6b675bbe95f18ae3d6` |
| Inert installer, 1,663,506 bytes | `fd99e86f57d8f429ef5ed045bf98315af962e2309b0f1ba87a147a44c71647d0` |
| Full package, 3,274,101 bytes | `fea9a57a94082eeb7e4e0bf3c4a30391255f6fdc3f19d4612b11c89ed44abc64` |
| Manifest | `3415179cc2da1fb3669f0b2f4add866b61e46f0b4bfce9b22f10a11ac7352a6c` |
| Launcher | `a27c94b53ae59e95006661a014e5d9df2fe0c20176fb196ed995ccbd4aa6bab7` |
| Approved plan | `2ca0e9800c0590020d22bbc989f4e811c2300f502b54d2eff2b442d429c5a9c5` |
| Rendered config | `ef915532cb1ecdedaf68acb56394d5dbc747256f0f8adf4b17ef65465ee6c261` |
| Original marker, 15,605 bytes | `4e0bb6fe1c862bae73a18782cffeaa76594d66805f890f155c3ec4d7aadef698` |
| Start received envelope | `83f94c39e08e92f828d6a1fb8b225998b9cd3592ad82fc2d876c12e21ab6c6db` |
| Read received envelope | `058f9102a962b4e8632190e8eeaeba2c0c10f9d403dfa66c0489ab887f617583` |
| Independent outcome audit | `cb74e3ff245c8870a8a75e7aaf3531153c7aa498b1fae652c70c7bb3b1935daf` |
| Independent partial facts | `dc0aba7f4b1f9b26dbf1a837b8911fb3f1c4ea99238003d4b25e2c8251adcedc` |
| Console identity comparison | `6bea312f46866400f15290faa2be17c4d8c13a6841c284a241062cc7a66f4036` |
| Owned interface/service cleanup | `7ad9b092d6b33e30bbc6d4dbb3ee4d09e1fe5ecb273b670809dc4084b351b775` |

Private originals, lossless auditors, exact identities/times and complete proofs
remain outside Git at `C:/aiw/sevenzip-tree-20261106`. This document omits raw
process/account/file identities. Audit full-width values losslessly; never round
them through ordinary JavaScript numbers or rewrite original bytes.

## Read-only follow-up and next-source contract

A separately reviewed read-only VM107 probe observed the fixed native host
System32 console image. Both hashes, before/after metadata and named reopen
agreed, with no API errors. Its path, code hash, size and legacy volume matched
the prior console events; its legacy file index did not. It observed two links
on that host file. This diagnostic did not change HAF's single-link rules or
establish a common physical backing object. The trial's verdict remains failed.

The original diagnostic is 2,477 bytes, SHA-256
`a275d5c7e6ba612e6dacbdc2f2744fe83ca2ba6a9ba9dfbb002e8315443a58ee`.
Its independent lossless comparison is
`host-console-identity-comparison-f27dda8-r1.json`, SHA-256
`23a2ff3c159a6e9a8440c5ddba311d071ac2456d324ef8340601426149272814`.
Both remain private. Microsoft documents
[shared immutable OS files](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-architecture);
that general architecture does not explain these particular identity differences.

Two independent design reviews recommend a new explicit executable-content
contract, retaining observed object identities separately and leaving physical
equivalence unproved. This is not implemented or accepted yet. For the fixed
control fixture, every CREATE image must match its independently approved
path/hash/size before normal debug continuation, and the same event file handle
must undergo bounded identity/content revalidation. Unknown code, missing
handles, token drift or measurement failure must stop the owned job and preserve
the failure. The current collector measures descendants before continuation but
classifies helper/support content afterward; that producer gap must be fixed.
Microsoft defines the event's
[`hFile` as the process image handle](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-create_process_debug_info).
Neither this seam nor a code hash proves loaded-memory integrity or complete DLL
provenance.

Keep strict local intake/custody, all-process token checks, source/approval/session
binding, watchdogs and exact owned cleanup unchanged. The new contract requires
fresh schemas, substitution/mutation/continuation negatives, independent review
and a fresh source-bound native trial. Neither old trial may be replayed or
reclassified. Further physical-object diagnosis is optional; it must not replace
progress into actual 7-Zip measurements.

Fresh positive and deliberate chain-reset-negative native proof, actual 7-Zip
process-tree/registry wiring, repeated three-mode comparisons, archive investigation,
new-source faults/recovery and desktop Results/provider-zero retained export remain
required by [the acceptance map](MULTIMODE-ASSESSMENT.md). Application compatibility,
effective restrictions, MXC, brokers/all-host completeness, broad Benchmark 2,
W4/W5 and production acceptance remain open.
