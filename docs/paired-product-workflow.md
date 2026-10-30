# Fixed paired-control desktop workflow

Status: local implementation, offline validation in progress. Native acceptance,
Benchmark 2 and remaining W4/W5 work remain open. No general application
compatibility or effective-isolation verdict is established by these controls.

## Product path

Select **Fixed paired controls** in the desktop workflow. The product accepts no
installer, document, executable, script or policy input. It uses a compiled
project and the enrolled shared guest agent, with fixed file, registry and child
cases. Preparation imports the typed paired action into the existing protected
workspace, journal and session kernel. It does not acquire a provider.

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

These checks are not yet a complete coupled admin-service-to-fake-kernel product
rehearsal. That demonstration, a paired-workflow keyboard/focus preview, final validation
against final commits, and the consolidated source-pinned future native acceptance
proposal remain required by the active goal. Native held-file inspection through
Sandbox Tools mappings still needs separately authorized disposable-worker proof;
fail closed rather than weakening protected intake.

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
  `C:/aiw/paired-preview-verifier-tests.log`. Four packaging scripts parsed.
- Explicit preserved Results demo: one passed;
  `C:/aiw/paired-results-preview-generation.log`.
- Independent source review covered the admin/project, recovery bindings,
  desktop controller/handlers/UI and enrollment scripts. Earlier findings were
  fixed; follow-up found no additional consequential issue. Review performed no
  builds, edits or provider calls.

These are slice checks; the active goal still requires the remaining work above.
