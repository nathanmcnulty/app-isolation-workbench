# Fixed paired-control desktop workflow

Status: local implementation and offline validation complete; see the final
[handoff](PAIRED-IMPLEMENTATION-HANDOFF.md) for exact results. Native acceptance,
Benchmark 2 and remaining W4/W5 work remain open. No general application
compatibility or effective-isolation verdict is established by these controls.

## Product path

Select **Fixed paired controls** in the desktop workflow. The product accepts no
installer, document, executable, script or policy input. It uses a compiled
project and the enrolled shared guest agent, with fixed file, registry and child
cases. Preparation imports the typed paired action into the existing protected
workspace, journal and session kernel. Paired preparation uses static trusted identity inspection and makes no provider
invocations. Runtime protocol, feature and session checks remain deferred until Start.

The desktop presents the immutable recipe, plan and proposed approval. Literal
approval of the displayed plan hash records approval; a separate Start challenge
is still required. Start rechecks the original workspace and current project,
agent, control-source, provider and preparation commitments. Neither opening a
retained run nor viewing Results grants approval or starts an assessment.

Progress comes from the existing worker service. During execution the cancel
button requests cancellation in the original journal. The leased kernel owns
cleanup. The button cannot directly stop a provider or claim cleanup succeeded.
Terminal observation clears pending cancellation. Unknown cleanup prevents a new
workflow and prevents closing the desktop; the explicit recovery button can only
reconcile the cached, original owned session and cannot replay an assessment.
Repeated cancellation/recovery clicks and foreign workflow IDs are rejected.

Opening a retained paired product run reads only its explicit workspace/run and
adjacent `paired-workflow.json`. The locator is not authority: its hashes, paths,
original protected workspace identity and persisted plan must agree. Recovery and
cancellation retain the original held workspace; changed application/project
inputs do not require reconstructing a new run. Synthetic records cannot acquire
a native recovery provider.

Results remains the read/export-only comparison surface. Inner paired outcomes,
comparison eligibility and evidence gaps remain separate from historical outer
cleanup. Application functions stay unmeasured. JSON/Markdown summary export
continues through the bounded field allowlist and exclusive new-file writer.

## Agent enrollment

Existing packages remain readable without the optional manifest property
`guestAgentControlSourceSha256`. Starting this new workflow requires it to match
the current compiled control-source commitment, as well as the enrolled agent
byte hash. Absence or drift fails before creating a run or acquiring a provider.

The preview/desktop package scripts accept an optional
`GuestAgentControlSourceSha256` only with an explicit agent artifact and its
independently retained SHA-256. The read-only CLI command
`aiw provider paired-control-identity` prints the compiled source commitment; it
accepts no execution arguments. This metadata is the producer's enrollment
assertion, not a static proof that arbitrary supplied binary bytes were compiled
from that source. The native guest independently validates the typed request.
No package was built, signed or published as part of this slice.

## Offline evidence and remaining work

The shared runner tests use inert fixture bytes, fake process/lease transports
and explicitly synthetic receipts. Protected fixture tests exercise actual
retained report services and verify unchanged input bytes and zero provider
calls on reads. Additional regressions cover the original recovery binding,
copied layouts, provider/hash substitutions and synthetic native-recovery refusal.
Admin service tests cover its closed compiled project and failure before either
gate/dispatch; controller tests cover exact gates, backend-owned metadata bounds,
single-use cancellation/recovery, stale failures and unresolved-close behavior.
Node tests cover paired input omission, repeated clicks, stale polling, explicit
cancel/recovery commands and terminal controls, alongside preserved Results tests.

A fresh Results demonstration was generated at
`C:/aiw/results-explorer-160bf207-6a83-48be-b235-07f37d20b6c9` using the
existing opt-in Rust demo. `verified-summary.json` and `.md` use the actual
ResultsStore exporter. A real browser keyboard preview entered Results, opened
the selection, expanded/collapsed a synthetic Bambu failure with focus preserved,
then moved focus by Tab to the next selection. Filtering showed exactly two
Bambu rows. `keyboard-failure-preview.png` records failed/not-reached stages
alongside unmeasured application functions and separate historical cleanup.
This preview has no execution backend; it exercises the preserved Results path,
not the complete new paired workflow.

The coupled coordinator/kernel rehearsal described below now extends these
checks. The paired-workflow keyboard/focus preview,
final validation and consolidated source-pinned native proposal remain required.
Native held-file inspection through Sandbox Tools mappings still needs separately
authorized disposable-worker proof; fail closed rather than weakening intake.

## Slice validation (2026-10-30)

- `cargo test -p aiw-admin-workflow -p aiw-cli -p aiw-runner --locked --offline`:
  247 passed, zero failed, 17 opt-in tests ignored. Log:
  `C:/aiw/paired-desktop-services-tests.log`.
- Corresponding all-target Clippy with warnings denied: passed;
  `C:/aiw/paired-desktop-services-clippy.log`.
- Desktop library tests: 19 passed, two opt-in tests ignored;
  `C:/aiw/paired-desktop-lib-tests.log`. Desktop all-target check and Clippy passed.
- `node --test gui/tests/*.cjs`: 25 passed;
  `C:/aiw/paired-desktop-node-tests.log`.
- Root/desktop formatting, diff whitespace and governance: passed.
- Preview package verifier fixture contract: passed;
  `C:/aiw/paired-preview-verifier-tests.log`. Desktop package verifier and archive
  round-trip/refusal controls passed (`C:/aiw/paired-desktop-verifier-tests.log`).
  Four packaging scripts parsed.
- Explicit preserved Results demo: one passed;
  `C:/aiw/paired-results-preview-generation.log`.
- Independent source review covered the admin/project, recovery bindings,
  desktop controller/handlers/UI and enrollment scripts. Earlier findings were
  fixed; follow-up found no additional consequential issue. Review performed no
  builds, edits or provider calls.

These are slice checks; the active goal still requires the remaining work above.

## Paired Results service demonstration

The two fresh retained selections emitted by `paired_protected_` tests are:

- `C:/Users/labadmin/AppData/Local/Temp/aiw-w1-runner-15776-1/paired-assessment-selection.json`
- `C:/Users/labadmin/AppData/Local/Temp/aiw-w1-runner-15776-2/paired-assessment-selection.json`

They contain inert bytes, synthetic readiness/receipts and fake provider calls;
no real provider, application or control is executed. The producer's existing
whole-workspace byte snapshot verifies report/report-set reads do not change
retained inputs. Marker `synthetic-demo.json` records origin, zero real calls,
fake boundary count and whether cleanup was deliberately unknown.

The ignored `results::demo::demonstrate_paired_results` test accepts exactly two
explicit selections through JSON `AIW_PAIRED_DEMO_SELECTIONS`, requires those
markers, bounds every manifest read, checks original workspace containment and
rejects an output parent inside a source fixture before creating files. It then
uses the actual ResultsStore loader/exporter for the four selections (two
originals and two duplicates), verifies one eligible case comparison and one
cleanupUnknown comparison, unchanged selection manifests, deterministic reload,
exclusive JSON/Markdown export, and zero new execution paths. It does not call
the admin preparation/gate coordinator.

A successful service demonstration and real browser preview are retained under
`C:/aiw/results-explorer-2d01aa1d-5314-46cb-9754-503e839094b5`. Files
`verified-summary.json` and `.md` were exported by Rust outside the retained
fixture trees. `paired-keyboard-preview.png` shows the explicit synthetic scope.
Keyboard entry/open/expand preserved focus; the paired detail showed the six
fixed cases, held/self/descendant token facts and hash-only evidence references.
The eligible filter showed exactly one of four selections, excluding unknown
cleanup and duplicates. Application functions remained unmeasured.

The preview script now escapes the demonstration's own scope in its notice,
so a paired-only demo cannot inherit the older ten-row application's description.
Browser preview has no execution backend. This is a paired Results integration
demonstration, separate from the coupled admin-gate/fake-kernel rehearsal below
and from native acceptance. Producer log: `C:/aiw/paired-retained-demo-generation.log`.
Service log: `C:/aiw/paired-results-service-demo.log`; post-review rerun:
`C:/aiw/paired-results-service-demo-final.log`.

Post-review paired demo validation: two tests passed, zero failed; desktop
all-target Clippy passed with warnings denied; all 25 Node tests passed; preview
script syntax and diff whitespace passed. Independent follow-up source review
verified the containment/bounded-read fix and found no remaining consequential
issue in that delta. Logs: `paired-results-service-demo-final.log`,
`paired-results-demo-clippy.log`, `paired-results-demo-node.log` under `C:/aiw`.

## Coupled admin-service rehearsal

The opt-in runner feature `offline-rehearsal` is default-off. The admin crate
activates it only as a dev dependency. Shared inert preparation/readiness and
receipt helpers were factored from the existing tests; the harness calls the
same kernel, journal, approval, receipt reader and exact recovery code. It creates
only fresh synthetic workspaces, accepts no existing workspace/executable/script,
and uses a strict fake process/lease boundary. Fake calls must match the full
planned executable, arguments, configuration, UUID and order. Recovery cannot
Start or connect. Repeated dispatch relies on the real kernel's rejection rather
than a harness-only duplicate guard.

The actual `run_prepared_with_gate` coordinator is now exercised with a compiled
fixed project, persisted locator/plan, exact approval, separate Start and the
fake kernel. Cases cover declined/stale approval, no Start, direct unapproved
kernel refusal, valid pair, project/input/provider drift, missing baseline and
candidate resources, malformed denial code, duplicate/out-of-order evidence,
driver failure/tampering, unknown cleanup and exact recovery, interrupted Start,
running cancellation and no replay. A bounded pause at durable StartIntent lets
a scoped test thread call the actual owned cancellation service. A whole-owned
fixture byte snapshot across the actual retained read proves it is unchanged.

The first full seven-test matrix passed (`C:/aiw/paired-coupled-service-tests2.log`).
Eight non-matrix tests, including the actual cancellation service and 2048-character
Start-error diagnostic, passed after final harness changes
(`C:/aiw/paired-coupled-gates-final2.log`). These are nine distinct coupled tests;
the two logs overlap. Initial failures exposed fake connect/stop response mistakes,
which were fixed; they are not native results. Independent review fixed the weak
fake invocation matching, and the follow-up found no further consequential issue.

The valid coupled run emitted
`C:/Users/labadmin/AppData/Local/Temp/aiw-paired-service-2292-1/paired-assessment-selection.json`.
A prior equivalent coupled fixture under `aiw-paired-service-6156-2`, combined with
the previously retained unknown-cleanup fixture, passed the actual ResultsStore
load/export/determinism/duplicate checks. Output:
`C:/aiw/results-explorer-401abd2d-d5b2-4ec8-a96c-42df8364ca5a`;
log `C:/aiw/paired-coupled-results-demo.log`. These are explicitly synthetic,
zero-real-provider/application/control-call records, not production acceptance.

The coupled tests also exposed hidden Start errors when an absent-evidence report
was available. The service now retains a bounded operation error and the desktop
shows the cause with exact-run preservation/recovery guidance. This local text is
not added to the Results export allowlist. Desktop checks: 20 library tests passed,
three opt-in tests ignored, and all-target Clippy passed. Logs:
`paired-coupled-desktop-tests.log` and `paired-coupled-desktop-clippy.log`.

## Static provider identity and deferred runtime checks

Paired preparation, import and verification now use static trusted Store/package,
cache-only catalog, held file hash/size/file ID and exact OS inspection. The
`WindowsSandboxStaticIdentity` type contains no runtime protocol, Sandbox feature
or session-availability fields. It does not construct an artificial supported
readiness result and does not launch `--version`, `list`, or another provider command.
Full readiness reuses the static inspection prefix before its existing runtime
checks; only the separately approved Start path reaches that full leased preflight.

New paired preparation receipt v0alpha8 has
`providerProtocolObservation: requiredAtStartNotObserved`, no provider version,
and the static identity schema. Its `providerProtocol` is the required pinned
protocol, not an observed runtime result. Approval disclosure explicitly says
protocol, feature readiness and current sessions are unmeasured until Start.
Original v0alpha7 receipts keep their observed-protocol semantics and unchanged
serialization; historical reporting and exact recovery remain independent of
current static inspection. No retained record was rewritten or upgraded.

Dedicated paired import/verification entrypoints reject non-paired metadata
before inspection. Caller-owned inspection modes prevent tampered metadata from
selecting legacy runtime probing. Native Start uses unconditional static inspection
before validating approval; after approval it acquires the existing native lease,
then checks every static identity commitment, required observed CLI protocol,
feature/virtualization/architecture, exact OS and empty sessions before dispatch.
Legacy generic preparation/import behavior remains explicitly separate.

The real preparation body is tested with an inspector that panics on any runtime
request. It stages fixed roles, verifies, imports and reopens with four static
inspections, zero runtime requests, no approval and no session transaction. The
test exposed a live staging-writer/read-only reopening conflict: preparation now
closes the verified writer, takes protected relative read-only custody, compares
the staged hash/size and holds/revalidates both agent handles through role copying
and receipt publication. No sharing or intake protection was relaxed.

Static/runtime identity and receipt-mode mutation tests reject provider, package,
catalog, file-ID, protocol, feature, virtualization, session and OS drift. Two
focused static tests and 15 paired runner regressions passed. Ten admin paired
checks passed against the new receipt (the evidence matrix was already exercised
and is reserved for final validation). The existing offline platform suite passed
173 tests, with 10 live/opt-in tests ignored; no provider/application/control trial
was run. All-target Clippy, desktop compilation, formatting and 25 Node tests pass.
Independent source review found no remaining consequential issue in identity
binding, version compatibility, handle transition or caller-owned mode routing.

Logs under `C:/aiw`: `paired-static-tests4.log`, `paired-static-regression.log`,
`paired-static-admin-tests.log`, `paired-static-platform-tests.log`,
`paired-static-clippy.log`, `paired-static-clippy2.log`,
`paired-static-desktop-check.log`, `paired-static-node-tests.log`.

Still required: paired-workflow keyboard/focus preview, final review/validation
against final commits, exact diff/PR handoff and consolidated source-pinned future
native acceptance proposal. Native provider availability, guest Tools mapping
semantics and native control behavior remain untrialed; Benchmark 2 and W4/W5
acceptance remain open.

Additional extraction regressions: 13 paired runner tests and the strict-fake
negative test passed. Admin/runner all-target Clippy passed with warnings denied.
Logs: `C:/aiw/paired-coupled-runner-regression.log`,
`C:/aiw/paired-coupled-fake-negative.log`, `C:/aiw/paired-coupled-clippy.log`.


## Final UI replay slice

The opt-in `workflow_demo::demonstrate_paired_workflow` test reads only an explicit
retained synthetic coupled-service fixture. It uses the actual Controller for
idle, preparation, review, approval, running and completed snapshots and the actual
ResultsStore for load/export. The review now uses the same production recipe
builder as native preparation. The replay has no provider backend and writes no
new approval; browser clicks replay these recorded states only.

Fresh controller/review/export output is under
`C:/aiw/paired-ui-replay-2e4e835e-c9c9-435d-b042-b64a5eaf229a`.
The original keyboard proof is under
`C:/aiw/paired-ui-replay-eb704d10-26ea-40e5-b00d-ff9278f35e84`:
`separate-start-keyboard.png`, `running-focus.png`, `results-keyboard.png`.
Each preview carries a persistent SYNTHETIC/UI REPLAY/NO PROVIDER BACKEND banner.
Controller DTOs contain local review details and are test artifacts, not safe
summary exports. Only `verified-summary.json` and `.md` use the export allowlist.

Browser keyboard checks verified literal approval does not Start, separate Start,
progress and terminal focus, entering Results, opening the bounded selection and
expanding fixed file/registry/child evidence and hash-only references. Actual
product focus moves on phase/error transitions and preserves steady editing.
Paired application-wide gaps are labeled beyond fixed controls; fixed-case gaps
remain independently exposed. Human summaries distinguish denied/missing/errors
and avoid counting unmeasured fallback records as measurements.

Preview servers bind loopback only, use fixed asset routes, enforce exact Host
and same-origin requests and set CORP/CSP/no-store headers. They expose no file,
execution or recovery API. Independent source review found and resolved a preview
cross-origin privacy gap and an overbroad measured-prefix label; final review found
no remaining consequential issue. Source review did not execute native behavior.
28 Node tests pass (`C:/aiw/paired-final-node.log`). The final workspace validation
and consolidated native-acceptance proposal are recorded separately in the final
handoff, without upgrading any native acceptance claim.


## Final workspace cancellation rehearsal finding

The first final workspace attempt at `b7af36f` exposed a test-only race:
WaitForOwnedCancellation read the lock-free journal while the actual cancellation
service was publishing its intent/artifact/commit, yielding
`AIW_ARTIFACT_UNJOURNALED` and an inconclusive result. The fake now waits for a
bounded atomic handshake after the actual service returns and a stable committed
cancellation observation succeeds, then verifies durable cancellation again.
Start readiness is published after durable StartIntent assertions. A negative
observer check cannot signal an uncommitted cancellation. No production journal,
reader, approval or provider behavior changed. Independent source review accepted
the fix; final validation is rerun against the corrective code commit.


## Final disposition

The code at `e2e44fe2bf3ca98113618131f4f6d8700354219f` passed the final
workspace suite: 678 passed, 0 failed, 27 opt-in ignored. Workspace all-target
Clippy, formatting and governance passed. Desktop: 20 passed, 4 opt-in ignored,
all-target Clippy/format and offline binary build passed; Node: 28 passed.
Structured workspace result: `C:/aiw/paired-final-root-fixed.json`.
The exact review bundle, safe exports, demo scope, independent source review,
initial failed run and remaining limits are in the final handoff. Earlier
remaining-work notes above describe historical checkpoints and are superseded
by this disposition. Native trials and production acceptance remain open.

## Bounded private driver diagnostics after the native unmeasured driver failure

The console run `paired-1793435382044001000` reached the native provider and
agent, then published a receipt-bound `driverIncomplete` with no case progress.
Exact outer cleanup was verified; the failing stage, internal actions and inner
cleanup remain unknown. The error had only been printed to logon
stderr, which that launch path did not retain; it cannot be recovered afterward.

New failed-driver artifacts use `aiw.dev/paired-controls-driver-failure/v0alpha2`
with an optional private `diagnostic`, sanitized by the existing guest helper:
at most 2,048 Unicode scalars (at most 8,192 UTF-8 bytes), no control characters.
The host enforces the same bound. Only an actual collector/driver error is attached; no
process/token/case/cleanup observation is invented. The same two artifacts and
receipt-last publication bind the field through the existing evidence verifier.
No new artifact route, verdict, executable selection, policy grant or case gate.

Legacy v1 remains readable with no diagnostic field. Absent values serialize by
omission, preserving historical payload hashes; v1 with a diagnostic and unknown
schemas are rejected before binding normalization. Event/result equality also
rejects an unexpected explicit null field or changed diagnostic. Existing
progress/token provenance checks still run. The desktop field allowlist never
copies diagnostic text to the view/JSON/Markdown summary; privacy regressions
include private-path, credential and hostile-text sentinels with six unmeasured
cases. Retained raw engineering records remain private and are not safe exports.

Affected offline validation passed: provider88, guest11, paired-runner15 and the
new desktop privacy regression, workspace and desktop all-target Clippy, formats.
Independent source review found no consequential issue. Unchanged broader suites
retain their recorded source/scope and were not rerun. The source fingerprint
changes with these producer/protocol files: every follow-up dispatch needs new
agent/package/source/plan pins. Never edit or replay the old retained failure.

## Separate exact host and guest Windows commitments

The later native a033 run retained the exact failing guard: the observed guest
version differed from the approved profile. That profile was formed from the
host version and reused as both host and guest commitment. This identifies a
model defect; it does not reveal either unretained guest tuple or the old v1
run's failing stage. Diagnostic-only source `4f82f0b` retains both exact tuples
on mismatch while continuing to refuse before control setup. Its verified
package is retained; no fresh native plan has run from it yet.

New fixed-profile revision `aiw.dev/paired-file-registry-child/v0alpha2` requires
`expectedHostWindows` and keeps `expectedWindows` as the exact guest commitment.
Preparation records the statically observed host; receipt consistency and Start
readiness compare that host field. The guest equality guard and result verifier
still require the approved guest field exactly. Both tuples enter the existing
profile/request/run-plan hashes and approval review. There is no new verdict
engine, observed-version adoption, wildcard version or relaxed drift check.

CLI `admin prepare-paired --guest-windows major.minor.build.revision` and the
desktop's optional paired-only version field use the same bounded canonical
four-component parser (each component at most 65535, fixed x64). Invalid input
fails before workflow creation. An omitted value commits the host tuple as the
guest expectation, preserving the former strict behavior; a measured different
guest tuple requires a new explicit plan. The numeric commitment does not assert
that the guest has already been observed or that any case has passed.

Historical v1 profiles omit the new host field, retain their exact hashes and
continue to bind their original single tuple for both environments. Reporting
and exact recovery use historical validation. New dispatch requires the current
revision/source and cannot reuse an old profile. Synthetic protected preparation
and kernel fixtures deliberately use different host/guest tuples. The actual
guest tuple and positive native six-case acceptance remain unverified.

Validation for this model repair: admin13 / CLI2 / probe3 / provider9 / runner15 /
guest11 unique affected Rust tests, desktop22 passed / 4 opt-in ignored, Node7;
workspace and desktop all-target Clippy, formats and governance passed. The first
runner drift fixture assigned1 when the newly distinct host already had revision1;
it was corrected to increment the observed host, with separate host/guest
approval-tamper cases. Focused reruns passed, including actual legacyv1-shaped
fake recovery and guest-versus-host substitution rejection. Completed slow
workflow checks were reused rather than repeated unchanged. Logs:
`C:/aiw/paired-host-guest-*`. Independent source/docs review: no actionable finding.

The model-fix reader also loaded the actual retained native v1 and v2 failures;
both previous JSON/Markdown summary pairs were byte-identical. Each29-file
explicit retained snapshot and selector remained unchanged, private fields were
excluded, and zero provider/assessment calls were made. Audit:
`C:/aiw/paired-host-guest-reader-53e67253-1b0f-4aaf-8010-e6461177db3d`.
This is historical reading/export evidence, not native control acceptance.

## Native file-identity blocker and diagnostic localization

The 4f diagnostic retained host `10.0.26300.9711` versus guest
`10.0.26100.9711`, both x64. A new f68 profile explicitly committed both tuples
and reached a subsequent file operation, then retained unsupported
`GetFileInformationByHandleEx(FileIdInfo)` / `0x80070032`. All six cases remain
unmeasured. Exact outer cleanup was verified; inner cleanup and the precise
failed open are unknown. The bare error can come from mapped inputs, copied
local roles or launcher observation; do not infer the first Tools open failed.

The next diagnostic-only patch labels fixed role paths and setup/open/revalidate
stages. A failed strict role open also triggers one read-attributes-only open at
the same fixed path and one basic metadata query. Raw attributes, volume/index,
link count and size (or unavailability) are explicitly diagnostic/not custody;
they can describe a later object, and partial/zero values are not interpreted.
The original error always propagates. There is no content read, write, process,
identity conversion, transport fallback or acceptance branch. All existing
check conditions, successful copy/execution path, policy/verdicts and outer
receipt/cleanup deadlines remain intact; metadata IO has no hard-cancellation
claim.
Current completed tests are reused; platform Clippy and independent review cover
the changed diagnostic adapters, with formatting/governance checked separately.
Every diagnostic dispatch still requires fresh source/agent/package/plan pins.

Microsoft documents [read-only mapped-folder permissions](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file)
and warns that [file metadata may be partial or unavailable depending on the filesystem/server](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle).
Neither contract proves support for a particular identity API on this object.
Do not fabricate a 128-bit identity, silently fall back in generic
`HeldApplicationFile`, or drop its local-volume/stream/reparse checks.

If the localized failure is the read-only Tools transport, a separately reviewed
closed-role transport design may retain fixed handles, require supported identity
and exact bounded bytes, and copy through those handles into fresh protected
guest-local files before applying unchanged strict local execution custody.
The host's original NTFS agent/control handles remain retained across native
Start/cleanup. Unsupported transport metadata must remain fail-closed; no such
adapter is implemented or accepted yet. Existing path-reopening/unbounded role
copying must not become a bypass. No native positive case acceptance follows.
