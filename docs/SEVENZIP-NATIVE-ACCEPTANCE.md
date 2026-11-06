# 7-Zip native acceptance and limits

## Production desktop comparison at 593281a

On 2026-11-06 (America/Anchorage), the exact `593281a64dda9b233a25e3f3262d7e1751c01a6b`
package completed run `sevenzip-1793956275430444300` through the native desktop on
VM107. The operator reviewed plan
`cafe360c6947ac3e74ed795baaa7d72a24d72f0da9f16f7fda58e7b14261d3b3`,
approved that exact hash, then used the separate Start action. Host and guest
were x64 builds `10.0.26300.9711` and `10.0.26100.9711`. This validates the fixed
product workflow for those bytes and environments, not broad production acceptance.

| Measurement | Receipt-bound production observation |
|---|---|
| Driver and installation | Known exit/output and deadline/empty-job controls passed before installation; installer exit 0, no timeout, empty owned job; scoped inventory contains 107 files |
| Create / test / extract | All three exit 0 in each mode, no timeout, empty owned jobs; held root process tokens bind the same standard user |
| Target boundary | Baseline primary tokens are medium integrity and non-elevated; candidate primary tokens are low-integrity AppContainer with the intended package SID and zero capabilities |
| Verify content | Both modes match all four expected names, sizes and SHA-256 hashes, totaling 4,170 bytes; input inventories remain unchanged |
| Selected controls | Baseline reads the exact outside-grant bytes; candidate outside read, input write, file delete and input-directory delete opens each return Win32 access denied (5) |
| App code and inner cleanup | Executable and DLL identities agree across installation/use; candidate profile deletion and all recorded process-job cleanup pass |
| Outer cleanup | Kernel transaction reaches `cleanupVerified`; exact owned-session stop and subsequent empty provider lists are retained |
| Reporting | Typed evidence is verified, fixed comparison is `workflowCompared`, selected controls verified; generic kernel outcome remains `insufficientEvidence` for broader claims |

Both production archives are **579 bytes**, with distinct hashes:

- Baseline: `e3c8a02855b706299ea2184dd5abd42267a43a3c6af1a51fb769bad580c7bab6`.
- Candidate: `ea6060c4dca17cda1738e3a5d689bc8c45e5b7baaa017e85e5e44ff17a915fe1`.

The cause of that byte difference was not measured. The content verification
passes independently; it does not assert archive byte equality.

Independent offline audit passed 482 checks against the transferred private
record: 138,668 bytes, SHA-256
`0c6b0d85f2989eb0c1eee978f08232008fd965fa700ac4274db350bff3d3b978`.
It reconstructed the hardened configuration and request/profile/plan hashes,
verified the approval and six-event journal chain, four session-transaction
snapshots and cleanup transition hashes, completion artifact hashes, and exact
evidence-event/result equality. The original inventory has 32 files, 43 entries
and 12,283,755 bytes. Twenty-eight small raw files were independently rehashed;
the four large installer/agent payloads are represented by the original held
digests. These private copies are not importable original protected identities.

Actual Results opened the original retained selection twice. The two JSON exports
are byte-identical: 3,296 bytes, SHA-256
`61d1572522c084ff5cb4d3270899af8e65dfb21d59a55b34d843dca31b81c271`.
The Markdown export is 1,996 bytes, SHA-256
`1c020c22f7a4e75664ac6a868ec74947bad7ac48bdf3438511f8adbdb3e76af4`.
Privacy checks found no private paths, SIDs, run IDs or account identifiers.
Before/after inventories preserve all 32 files, 43 entries and 12,283,755 bytes,
including unchanged provider diagnostics. The reader has no execution/provider
route; no assessment was repeated to reopen or export these results.

Evidence is retained under `C:/aiw/sevenzip-assessment-20261105`:
`production-independent-audit-593281a.json`,
`production-export-verification-593281a.json`,
`vm107-production-results-integrity-593281a.json`, the before/after native
inventories, and `verified-exports-593281a`.

The native Markdown contains the legacy heading `Failure evidence: verified`
on this successful workflow. A later presentation-only correction uses
`Evidence status`; it is not part of these exact native bytes or export hashes.
The later required guest-version label likewise does not change this record.
A separately derived wording-only copy, `sevenzip-summary-corrected.md`, is
1,995 bytes, SHA-256
`4d622cdb69c807a6440ec555c34a75eafbe3063855cbc101e10c4ca566c6341c`.
`production-report-wording-provenance-593281a.json` records the single heading
replacement and source `5c12df0`; it is not a native export from that later source
and adds no measurements. The original native Markdown remains unchanged.

This is one sequential pair sharing one installation/worker. Raw archive and
extracted payload bytes were not retained for independent rehashing; content
claims are receipt-bound native observations. Application descendant tokens,
registry/system changes, inner network/IPC/UI restrictions, GUI/shell workflows,
update/uninstall/reboot, repeatability and ordinary endpoint equivalence remain
unmeasured. This completed run requires no recovery. See the separate cancellation
record below and the [criteria mapping](SEVENZIP-ASSESSMENT.md#coverage-limits-and-acceptance).

## Native owned cancellation at 593281a

A separate fresh native run, `sevenzip-1793960096774082900`, used the same
`593281a` package on VM107. Its independently reviewed plan hash was
`e06f27420e5ba4c2c2391550c2cf1afa99ce9d4ce5a5757191355c36d086b8fa`.
The operator separately approved that exact plan, started once, and selected
Cancel after the owned Sandbox boot window appeared. The desktop reported
`EvidenceAbsent`, operation cancelled and outer cleanup `Some(true)`.

Independent offline audit passed 304 checks. It verified the exact plan,
profile, protected installer import, workspace, rendered configuration and
reconstructed request commitments; approval and cancellation artifact hashes
in the eight-record journal; committed journal heads; and four durable session
snapshots with bound transition hashes. Provider diagnostics contain one start
of the preselected session, one stop of that exact owned ID, and two subsequent
empty-list observations. No start replay is present. The final transition is
`cleanupVerified`; the kernel outcome is `cancelled`, evidence root is null
and cleanup is complete.

The transferred audit is 80,750 bytes, SHA-256
`668d3d34e2d825be0158cbd26c32721c20557c192082eab112b1607837d3915c`.
Its inventory commits 32 files, 43 entries and 12,240,227 bytes; all 28 small
raw files were independently rehashed. Four large executable files remain
represented by original held digests. Private records are retained beside the
success audit as `vm107-cancellation-after-593281a.json`,
`cancellation-readback-files-593281a` and
`cancellation-independent-audit-593281a.json`. Copied records are not importable
original protected workspace identities.

There is no completion marker or retained application evidence. This proves
owned cancellation and exact cleanup for the recorded run; it does not prove
that installation/application execution never began, add function observations,
or indicate candidate incompatibility. Neither this run nor the successful run
needs recovery. Recovery bindings and regression tests remain distinct from
native forced-fault recovery, which was not exercised. Broad Benchmark 2,
W4/W5 and production acceptance remain open.

## Historical research pair

Observed 2026-11-05 (America/Anchorage), source `b7f17cf`, inside one disposable
Windows Sandbox on VM107. Host build `10.0.26300.9711`, guest build
`10.0.26100.9711`, x64. This is research feasibility, not production Results
acceptance. [Workflow and provenance](SEVENZIP-ASSESSMENT.md) remain authoritative.

The protected proposal hash was
`254dea4984a0bb03ba378c7134ede79be840a90036e6b8891221411abbd4cdaf`.
Independent review reconstructed its typed hash and rendered configuration before
separate exact-hash approval and a single Start. No recovery or retry ran.

| Measurement | Observed result |
|---|---|
| Installer and process-driver controls | Installer exit 0; known exit/output control and deadline/empty-job control passed |
| Baseline create, test, extract | All exit 0, no timeout, empty owned jobs; held same standard-user medium-integrity primary tokens |
| Candidate create, test, extract | All exit 0, no timeout, empty owned jobs; held same-user low-integrity AppContainer primary tokens, zero capabilities |
| Content verification | Both modes match all four expected names, lengths and SHA-256 hashes, totaling 4,170 bytes |
| Selected boundary canaries | Baseline reads the outside-grant file; candidate outside read, input write, file delete and input-directory delete opens return Win32 access denied (5) |
| Installed files | Scoped inventory contains 107 files; held executable/DLL hashes agree across installation and use records |
| Cleanup | Candidate profile deleted, launcher cleanup observed, outer exact-session cleanup verified |

Archive bytes differ: baseline 578 bytes, candidate 579 bytes, with different
hashes. The cause was not measured. Equivalent extracted content does not imply
identical archives. No normalization was applied to hide that difference.

The private retained archive is
`C:/aiw/sevenzip-assessment-20261105/vm107-research-readback.zip`, 23,921 bytes,
SHA-256 `f23223aaada52f33cc354aca47201c924b75b6f3a983157b21f6c4556017f9c4`.
Bounded extraction and independent review verified all 32 manifest records and
57,548 uncompressed bytes. Three absent optional failure/not-reached records are
reported as missing, with no collection errors. The guest completion marker says
`productionEvidence: false`; host execution and cleanup errors are null.

The inventory audit checks retained observations against the fixed fixture; raw
archives and extracted payloads were not retained for independent rehashing.
One sequential pair shares one installation in one Sandbox. GUI/shell use,
uninstall, registry/system changes, network/IPC/UI, every descendant token,
repeatability and ordinary endpoint equivalence remain unmeasured. Installation
alone does not demonstrate application isolation.

These observations established feasibility and remain separate from the later
production receipt record above. The earlier six-control/29-file Results
milestone is reused without execution; neither historical trial closes broad
Benchmark 2, W4/W5 or production acceptance.

## First production desktop attempt

Source `614bb0e`, run `sevenzip-1793950517554284900`, was prepared in the native
desktop on VM107, independently reviewed, approved by the exact plan hash
`536730befc447df29c16c6da55a234ee115722e784592961a6e219c51890dc02`, and started
once. The product retained `DriverIncomplete` and verified outer cleanup.
Installation, tokens, controls and all four application functions are unmeasured
in the retained result. This is neither candidate incompatibility nor production
acceptance. The earlier successful research observations remain separate.

The old fallback discarded private error text; its all-null result cannot
establish whether failure occurred before installation or during final typed
validation. The cause remains unknown. Follow-up source `593281a` adds bounded, receipt-bound
private failure text (excluded from sanitized exports) and accepts only casing
and Win32 verbatim spelling differences for the same fixed executable paths.
Historical records omit the new optional field and retain their original bytes.
The old approval and workspace must not be reused for another Start.

The actual Results view reopened this incomplete run and exported a new sanitized
JSON summary: 3,186 bytes, SHA-256
`95a0d53fd0a9a1527b2e4ab6fd36018e7e0cf109a8723f499dfb108c80489b58`.
All 26 retained files remained unchanged. The export contains no private paths,
SIDs, run IDs or account identifiers. Source review confirms the reader has no
execution/provider route, and retained diagnostics were unchanged. This proves
read/export behavior for the incomplete result; it adds no application measurements.

The later successful `593281a` run above does not establish the cause of this
older failure. Its retained evidence and approval remain preserved.
