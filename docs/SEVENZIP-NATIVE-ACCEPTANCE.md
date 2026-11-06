# 7-Zip native research acceptance

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

The observed application functions and selected boundary checks advance Benchmark
2 feasibility. Production approval/session receipts, cancellation/recovery,
desktop entry, verified retained comparison and sanitized Results export still
require integration and native validation. Broad Benchmark 2, W4/W5 and
production acceptance remain open. The earlier six-control/29-file Results
milestone is reused without execution.

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
validation. The cause remains unknown. A follow-up fix adds bounded, receipt-bound
private failure text (excluded from sanitized exports) and accepts only casing
and Win32 verbatim spelling differences for the same fixed executable paths.
Historical records omit the new optional field and retain their original bytes.
The old approval and workspace must not be reused for another Start.
