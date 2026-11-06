# Results Explorer and paired-controls evidence audit

Audited 2026-11-05, America/Anchorage. Implementation source:
`3d60960bb1f957c446c477978ec4a390df5565b4`, based on main
`53c02c8dfd367b7b12ff4c167e99fd03b9e1dcf1` including PR #103.
Documentation commits after this source do not change the staged binaries.
The full goal remains incomplete: positive native six-case acceptance is unproven.
Full Benchmark 2, production acceptance and W4/W5 remain open.

## Original Results requirements

| Requirement | Implementation and retained evidence | Disposition |
|---|---|---|
| Dedicated Results view; explicit bounded retained selection; existing verification | `gui/src/results.rs` loads strict 1–32-entry selections with a 1 MiB limit through `report_application_assessment`; `gui/ui/results.js` provides the dedicated view. Sources are held explicitly; no recursive discovery or verdict engine. | Implemented; retained backend/UI tests and native safe-fixture demonstration. |
| Multi-run application/workflow/functions/outcomes/gaps; filters and failure/reference drill-down | Backend-owned closed projection, existing function/stage/report-set verifiers, inert hash references and application/outcome/function/control filters. Mixed MSI/Bambu/paired examples are explicitly synthetic. Native desktop proof uses one reviewed MSIX profile plus duplicate/missing/tampered selections. | Implemented. Mixed-application coverage is synthetic, not new application trials. |
| Historical cleanup separate; failed/not reached/unmeasured distinct; no general compatibility/isolation inference | Separate historical cleanup field, closed stage/function/case outcomes and explicit gaps. A passed stage does not promote an unmeasured function. Native failures retain six unmeasured cases. | Implemented and covered by projection, prefix and UI checks. |
| New local JSON/Markdown files outside retained inputs; minimal allowlist; no overwrite | `ResultsStore::export` serializes its stored summary using the current snapshot token; exclusive writer holds the destination parent and excludes retained locations. Raw artifacts, credentials, account/run IDs, tokens, absolute private paths and private driver diagnostics are omitted. | Implemented; real exports, determinism, collision/containment/IO-failure tests and native Save dialogs. |
| Empty/unavailable/tampered/duplicate/partial/unsupported handling; Results never runs, recovers, cancels or modifies a run | Strict input/reader failures and unavailable rows preserve uncertainty. Cancelled/failed opens retain the previous view. The Results command path contains only load/export; execution/cancellation/recovery are separate workflow commands. | Implemented; retained byte snapshots and boundary checks. No systemwide native UI call counter is claimed. |
| Hostile text/input limits; repeated clicks/out-of-order loads; keyboard/focus | Rust schema/size/path/allowlist tests; Node text/bidi and single-flight/epoch tests; transition focus tests. Native Tab/Enter, dialogs, outcome filter, table and disclosure checks completed. | Covered by source-scoped tests and native UI proof below. |
| Existing offline Rust/Node checks, formatting/lint; independent review | Broad baseline plus focused model/diagnostic/transport records below. Consequential source and generated-helper reviews used the independent `results_review` agent. | Completed for their recorded source/scope; unchanged suites were not rerun. |
| Reviewable implementation, exact commits/diff, demonstration, test results, limitations and draft PR; no publication | This audit, linked source records, local full diff/commit list, demonstration artifacts and `PAIRED-DRAFT-PR.md`. | Local artifacts available. Native acceptance limitation remains explicit. No push/PR/publication/merge/release. |

## Production path and where execution evidence ends

| Path | Current implementation | What was actually exercised |
|---|---|---|
| Desktop/CLI preparation and exact approval/Start gates | `aiw-admin-workflow/src/paired.rs` → protected runner preparation → immutable plan/review → approval → separate approved Start. Both exact host/guest Windows tuples and current source/agent commitments are bound. | Native preparation, approval and one Start per earlier fresh run; coupled fake-provider complete/gate/drift cases. Current3d package was staged, but no current3d preparation record was retrieved. |
| Native dispatch and owned outer cleanup | Existing runner/kernel/provider lease, fixed WSB configuration, request/receipt/journal/session binding and exact owned cleanup. | Real VM107 provider and guest entry, bound driver failures and verified exact outer cleanup on earlier source snapshots. Latest executed source938 exited1/66984ms; journal6/cleanupVerified. |
| Native guest intake | `aiw-windows-platform/src/guest_paired_controls.rs` validates native origin, fixed agent path/elevated WDAG token and exact guest Windows before `FixedPairedInputs::open`. | Earlier native runs reached these guards. Source3b localized unsupported extended FileIdInfo on the first mapped agent input. Source938 refused ancestry acquisition with sharing status0xc0000043; exact AIW/Tools component was unknown. |
| Current mapped input repair | `guest_document/paired_inputs.rs`: closed Agent/Fixture/Launcher; read-only directory access, READ\|WRITE sharing with no DELETE; role SHARE_READ; supported basic identities, exact byte commitments, full held/named revalidation and bounded copying. Generic HAF is unchanged. | Six local inert-file/fault tests and source review. Current3d Sandbox mapping/directory/role capability is **not** established by those tests or staging. |
| Local staging and baseline/candidate controls | Fresh protected local copies → unchanged strict `HeldApplicationFile` → standard-user broker → ordinary file/64-bit registry/child baseline and zero-capability classic AppContainer candidate → held token/progress/resource checks. | No native six-case success. Complete comparison, failure prefixes, token/binding rejection and inner cleanup evidence were supplied through explicitly synthetic/fake-provider seams. Local metadata/copy tests never execute control images. |
| Interruption/cancellation/recovery | Existing durable owned cancellation and exact recovery services; historical source may be reported/recovered under its rules but not restarted. Synthetic records cannot acquire native recovery. | Fake process/lease tests cover interrupted dispatch, exact recovery, copied-layout/provider rejection and duplicate/out-of-order receipts. No new explicit native recovery or cancellation was performed in the diagnostic/model/transport attempts. |
| Retained reading and safe summary export | Existing report-set verifiers → actual desktop `ResultsStore` projection → exclusive JSON/Markdown export. | Recorded native guest-driver failures loaded twice with deterministic summaries, explicit29-file snapshots unchanged at those observations, private fields excluded and zero reader execution/provider calls. Native UI additionally verified the safe archive flow. |

Neither a fake success nor outer cleanup proves native case/token/inner-cleanup
acceptance. Current3d must still produce six verified cases, exact bindings,
complete driver and verified inner/outer cleanup before its fixed-profile comparison
can be accepted. This would still not establish general compatibility or isolation.

## Reused validation and demonstration records

- Baseline source `e2e44fe2bf3ca98113618131f4f6d8700354219f`: workspace678 passed /
  27 opt-in ignored; desktop20 / 4 opt-in ignored; Node28. Logs and resolved initial
  cancellation-race failure: [implementation handoff](PAIRED-IMPLEMENTATION-HANDOFF.md).
- Host/guest model source `f68f9e5db6b1dd80bc09129227fd9314d8314cdf`: affected Rust53,
  desktop22 / 4 opt-in ignored, Node7, workspace/desktop Clippy, format/governance.
  Record `C:/aiw/paired-host-guest-validation.json`. Results UI/admin/report files
  are unchanged between that source and3d; retained results remain scoped records,
  not a claim that the complete workspace suite ran again at3d.
- Mapped transport source938: five module tests plus probe3 and workspace Clippy;
  original failed compile/directory-growth checks were retained and corrected.
  Record `C:/aiw/paired-mapped-validation.json`.
- Directory-sharing source3d: six affected module tests, workspace all-target
  Clippy with warnings denied, formatting/governance and independent review.
  Record `C:/aiw/paired-directory-sharing-validation.json`; current adapter hash
  matches its reviewed/tested hash. No unchanged suites rerun during this resume.
- Native Results UI at source3b:
  `C:/aiw/paired-native-results-ui-b12be912-8a77-4a8b-b12a-92373809bc0e`.
  `native-ui-checks.json` and screenshots cover the native dialogs/keyboard flow.
  JSON SHA-256 `3e872cd0342d991c044b617f2845fc8539af0ab97f3e026a8a6666d4c7579c6d`;
  Markdown `4938480eb7a84c9a2cb45235ec004dfb1a0511fb1bbdad1659db5fce7b80d188`.
  Both matched prior verified summaries byte-for-byte. On this resume, all three
  local input hashes and both exported hashes still match the retained proof.
- Mixed-application labeled synthetic preview and real archive fixture exports:
  `C:/aiw/results-explorer-160bf207-6a83-48be-b235-07f37d20b6c9`.
  Production does not import the synthetic report DTO. No application trial reran.
- Full implementation diff and exact commit list through3d:
  `C:/aiw/paired-results-3d60960.diff` and
  `C:/aiw/paired-results-3d60960-commits.txt`.
  Documentation commits following this checkpoint must be included in the final
  generated diff/list; these two files preserve the executed/staged source boundary.

## Current native limitation and remaining work

Resume checkpoint:
`C:/aiw/paired-resume-20261105-8b64bda5-f002-4e52-8c3d-9f58f15bd0aa/checkpoint.json`.
The local3d package was freshly reverified: exact14 files and receipt
`4978d8980456958ef662206be94cc8bdae78b20936c29f3c0dc33058c1c00875`.
VM107 staging was last observed at `2026-11-01T00:36:43Z`; its current state is
unobserved. No current empty/ready state is inferred from that old record.

The existing remoting certificate
`BC14DCC4E37F83161EBB55AF8624E36A79E19256` expired
`2026-11-05T08:49:10Z`. No renewal, validation bypass, remoting connection or access
change was attempted. The available official computer-use JS tool failed before
initialization with `failed to write kernel assets: The system cannot find the
path specified. (os error 3)`, including after its normal reset. Workspace, Temp
and the configured bundled Node runtime/module directories exist. No JS/UI/native
action ran through that failed tool. No alternate automation protocol was built.

When an authorized access route is operational, continue with fresh VM107 identity,
runtime/provider/package and destination checks. Then prepare once with the pinned
guest tuple, retrieve actual nine documents and plan/profile hashes, independently
review the closed generated helper/scope, present the concrete scope, and perform
one Start under standing authority. Preserve every old run; no blind retry or
historical recovery. After settlement, verify six cases and both cleanup layers,
then read/export the exact retained run with unchanged-input/determinism checks.
No new3d plan ID/hash or native result is invented here.

A human screen-reader study, real production data selection, positive current
native paired acceptance, full Benchmark 2 and production acceptance remain
unproven. Publication, new application trials and broader W4/W5 closure stay outside
this work's authorized scope.
