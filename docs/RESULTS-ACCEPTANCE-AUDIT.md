# Results Explorer and paired-controls evidence audit

Audited 2026-11-05, America/Anchorage. Implementation source:
`3d60960bb1f957c446c477978ec4a390df5565b4`, based on main
`53c02c8dfd367b7b12ff4c167e99fd03b9e1dcf1` including PR #103.
Documentation commits after this source do not change the staged binaries.
Results-only correction source is `53ed71f6c204c4b64a909086ce10d7dc66162702`;
it does not change the executed agent, cases, policy or native retained inputs.
The authorized Results/fixed-controls milestone is demonstrated: the current3d
native pair is verified as `fixedControlsObserved`, with all six cases and recorded
inner/outer cleanup. Full Benchmark 2, production acceptance and W4/W5 remain open.

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
| Desktop/CLI preparation and exact approval/Start gates | `aiw-admin-workflow/src/paired.rs` → protected runner preparation → immutable plan/review → approval → separate approved Start. Both exact host/guest Windows tuples and current source/agent commitments are bound. | Current3d fresh preparation, nine actual document hashes, independently reviewed helper/scope, one approval and one Start on VM107. Fake-provider gate/drift cases remain separately labeled. |
| Native dispatch and owned outer cleanup | Existing runner/kernel/provider lease, fixed WSB configuration, request/receipt/journal/session binding and exact owned cleanup. | Current3d Start PID12888/session1 exited0/123755ms; exact session `d01f3d0e-2144-975c-151f-9ec08f17980b`, journal6/cleanupVerified. No cancellation/recovery/retry. |
| Native guest intake | `aiw-windows-platform/src/guest_paired_controls.rs` validates native origin, fixed agent path/elevated WDAG token and exact guest Windows before `FixedPairedInputs::open`. | Current3d native worker measured guest10.0.26100.9711 against separately committed host10.0.26300.9711. Earlier3b extended-ID and938 ancestry-sharing refusals remain preserved. |
| Current mapped input repair | `guest_document/paired_inputs.rs`: closed Agent/Fixture/Launcher; read-only directory access, READ\|WRITE sharing with no DELETE; role SHARE_READ; supported basic identities, exact byte commitments, full held/named revalidation and bounded copying. Generic HAF is unchanged. | Six local inert-file/fault tests and source review, followed by the actual3d mapped transport and strict local custody path into six measured controls. This proves this pinned mapping/profile, not every provider/filesystem configuration. |
| Local staging and baseline/candidate controls | Fresh protected local copies → unchanged strict `HeldApplicationFile` → standard-user broker → ordinary file/64-bit registry/child baseline and zero-capability classic AppContainer candidate → held token/progress/resource checks. | Native baseline file29 bytes/fixed hash, registry64 REG_BINARY29 bytes/fixed hash and medium child success; candidate fileRead/openKey denial5 and low AppContainer child success/zero capabilities. All six held/self tokens and jobs verified; profile deletion and unchanged resource/ACL/fixture/launcher bindings recorded. Failure-prefix/token-rejection branches remain fake/synthetic checks. |
| Interruption/cancellation/recovery | Existing durable owned cancellation and exact recovery services; historical source may be reported/recovered under its rules but not restarted. Synthetic records cannot acquire native recovery. | Fake process/lease tests cover interrupted dispatch, exact recovery, copied-layout/provider rejection and duplicate/out-of-order receipts. No new explicit native recovery or cancellation was performed in the diagnostic/model/transport attempts. |
| Retained reading and safe summary export | Existing report-set verifiers → actual desktop `ResultsStore` projection → exclusive JSON/Markdown export. | Current successful native pair independently verified as eligible/fixedControlsObserved; two deterministic loads and new safe JSON/Markdown exports, 29 retained files unchanged, private markers absent, zero reader execution/provider calls. Earlier failures and native archive-dialog/keyboard proof remain retained. |

The current native retained verifier establishes the fixed-profile comparison.
The generic core outcome remains `insufficientEvidence`: application functions,
general compatibility/isolation and production acceptance remain unmeasured.
Inner jobs/profile and exact outer cleanup are recorded; individual removal of
guest account/canary/control-directory residue is not separately certified.

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

## Current native milestone and remaining limits

After the user restarted the controller and updated Codex, official computer
control worked again. The existing browser at
`https://pve.wombat-universe.ts.net/` provided VM107's existing console. Fresh UUID,
SID/nonadmin session1, network, Core/runtime, exact OS/provider/basic IDs and14-file
package checks passed. Existing noVNC clipboard transported reviewed helpers and
hash-verified readbacks; the separate expired remoting certificate was unused.
No authentication, certificate, VM, security or access change was made.

Actual run `paired-1793931286787802700`, canonical plan
`bdea70e96abec6c66a0c5be8c14ff381de09a76b1df7c9f6f9bd3939a96bf02c`,
profile `84e547dcec7d3a123595cf23307f2e401fbe42eb10a6597e9abec41156dc8e4e`.
Full pins/effects/limits and independent source/evidence reviews:
[native record](PAIRED-NATIVE-APPROVAL.md). Private audit:
`C:/aiw/paired-directory-sharing-native-65b084f3-5d85-4dda-83a1-12754bbda14f`.
`native-terminal-readback.json` retains actual records. Initial exports in
`native-results-export.json` exposed a display defect: nonchild cases copied the
separate child token. Source53ed limits descendant fields to child cases, with
four focused Rust tests, desktop all-target offline Clippy/format, independent
review and corrected desktop/reader builds passed. No native assessment repeated.
`native-results-export-corrected.json` records the corrected actual ResultsStore
verification against the original VM107 run, two deterministic loads, new exclusive
`Exports-Corrected` outputs and the same29-file snapshot unchanged across both
export sessions. Corrected summary JSON SHA256
`89595a81dbfc4eac7cccb5a0e42f3267ef91cec99dc3bb6aa857f6538c7c6b6e`;
Markdown `1d480982f1154ba77b73f9bc41b8787b823eefb737b9a4458a3510fd40382729`.
File/registry descendant fields are false/null/unmeasured; both child rows retain
their own tokens. Initial summaries remain preserved as historical review evidence.

Independent review also fixed private diagnostic helpers before their use:
bounded same-byte locator/document reads with leaf no-follow, accurate parent-owner
labeling, and capped Results output drains with a shared60s observer deadline.
Six focused inert-file checks passed. Creating a leaf symbolic-link fixture
required unavailable privilege, so that check was not claimed; no security change.
The production source and previously completed Rust/Node suites were unchanged.

A human screen-reader study and real production-data selection remain unperformed.
Full Benchmark 2 still requires its declared real-application candidate and broader
measurements. No new application trial, PR #103 repeat, W4/W5 closure or production
acceptance is claimed. Publication remains separate.
