# Offline Results Explorer

The desktop **Results** view opens an explicit JSON selection using the existing
`application-assessment-input/v0alpha1` contract documented in [REPORT-SETS.md](REPORT-SETS.md).
There is no disk search, execution entry point, verdict engine or report-JSON import.
The original report-set and retained evidence verifiers determine results and duplicates.
PR #103's completed native trials are unchanged and were not repeated.

The separately approved VM107 paired attempt later stopped during provider
preflight, before dispatch. Its actual retained Results backend/export check
correctly shows six unmeasured cases, with committed approval distinguished from
missing dispatch. Exact artifacts and limitations are in the
[native attempt record](PAIRED-NATIVE-ATTEMPT.md). This supplies real incomplete
retained-input coverage, not a successful native control or GUI demonstration.

Select **Results → Open selection…**, choose a manifest, filter by application,
recorded outcome, function and function result, and expand a selection to inspect
failed/not-reached stages, failure-evidence status and hash references. The view
shows the manifest's original selector ID locally; exports use anonymous selection
numbers. Rows follow the existing service order (Sandbox, production MSIX, reviewed
MSIX research), preserving each group's input order. Export always includes every
loaded row, even if a filter hides it. Empty filters have an explicit no-match state.

Functions are passed/failed only when the existing function matrix says so. Null
remains **unmeasured**, even when individual stages passed. Stage failure and its
not-reached suffix are separate observations. Unavailable/duplicate rows never
inherit successful functions. Shared gap categories and the Bambu profile's fixed
missing-evidence categories survive a closed allowlist. Cleanup is a separate
historical receipt observation; it says nothing about current worker state.
General compatibility and effective isolation remain unmeasured.

## Boundaries

- Selection JSON is limited to 1 MiB and the existing strict 1–32-entry validation.
  Unknown schemas, profiles/fields, invalid hashes/IDs, duplicate IDs and parent
  traversal are rejected. Missing sources become unavailable without being sent
  to a retained reader. Missing and tampered archives share the existing
  `evidenceRejected` reason; the UI does not pretend to diagnose tampering.
- Paths must use a local fixed/removable/RAM drive. The reader checks actual drive
  type and holds explicit ancestors from root to leaf without following reparse
  points. No recursive enumeration is introduced. Reparse/network paths fail
  closed; inaccessible ancestors can reject the selection as a whole.
- The loaded snapshot holds selected sources and their ancestors without delete
  sharing, preventing a retained directory from moving past an export exclusion.
  These read handles are released when another selection replaces the snapshot or
  the application closes. Viewing never executes, recovers, cancels or writes a run.
- A failed/cancelled open preserves the previous view. UI busy guards suppress
  repeated clicks; request epochs reject stale completions. The backend rejects
  overlapping Results operations. Exports require the current backend token and
  serialize the backend-owned projection, never caller-provided report content.
- JSON/Markdown export uses exclusive new-file creation and requires an existing,
  fully held local parent outside every selected retained location. Missing source
  locations conservatively exclude their nearest held existing ancestor. Existing
  files, directories, named streams, reparse paths and unavailable parents fail.
  A write/flush failure reports failure and warns that a partial new file may remain;
  retry requires a new name. No overwrite, automatic cleanup or retry occurs.
- The export allowlist contains schema/scope, anonymous selection number, fixed
  application/workflow labels, outcome/reason, closed function/stage observations,
  closed gap labels, historical cleanup and SHA-256 references. It omits selector
  and run IDs, original report text, raw artifacts, credentials, account identifiers,
  token records, worker identity and absolute private paths. Local labels and the
  snapshot token are outside `Summary` and never exported. Hash references identify
  evidence; they are inert text and never open or execute an artifact.

Native buttons/selects/disclosures support keyboard operation. View navigation
moves focus to the Results heading; dialog completion returns it to the initiating
control. Filters keep focus, status changes are announced, column headers/caption
name the table, and its horizontal scroll region is keyboard focusable. All report
text uses `textContent`; control/bidi characters are bounded and sanitized.

For a developer check without a GUI connection, build the read-only
`gui/examples/export-retained-results.rs` example with installed/cached dependencies:

```powershell
cargo build --manifest-path C:\aiw\app-isolation-workbench\gui\Cargo.toml --example export-retained-results --locked --offline
```

The example requires three explicit paths: an existing selection manifest and two
new JSON/Markdown summary destinations under existing local parents. It calls the
same ResultsStore twice to compare summaries, then its normal safe exporters.
It creates no directories or approval/run artifacts and has no execution/provider
route. If a later export fails, an earlier/partial new output may remain; preserve
it and choose new paths for any separately justified retry. This is backend
verification, not native dialog/focus acceptance.

## Reproducible safe demonstration

From `C:\aiw\app-isolation-workbench`:

```powershell
cargo test --manifest-path C:\aiw\app-isolation-workbench\gui\Cargo.toml --locked --offline
$env:AIW_RESULTS_DEMO='C:\aiw'
cargo test --manifest-path C:\aiw\app-isolation-workbench\gui\Cargo.toml --locked --offline results::demo::demonstrate_results -- --ignored --exact --nocapture
```

The opt-in test creates a **fresh UUID child** of that existing parent and prints
`DEMONSTRATION=...`. It copies the pinned safe reviewed archive
`fixtures/msix-lifecycle/worker107-r5.zip`, plus a deliberately corrupt copy. Its
`selection.json` explicitly selects the real fixture, a duplicate, a missing file
and the corrupt copy. `verified-summary.json` and `.md` come from the real Rust
ResultsStore exporter. Repeated loads must match, retained bytes stay unchanged,
and retained-location/overwrite attempts must fail. Nothing is executed.

`gui/tests/fixtures/results-synthetic-report.json` supplies clearly marked
**SYNTHETIC** MSI/Bambu failures, an export success, absent/rejected failure evidence
and an incomplete VM record for projection/UI demonstration. Production never
imports this file. Generated `demo-summary.json`/`.md` and `demo-view.json` combine
these examples with fixture rows and label the entire demonstration accordingly.

An optional read-only browser preview uses installed Node only:

```powershell
node C:\aiw\app-isolation-workbench\scripts\preview-results.cjs C:\aiw\results-explorer-<printed-UUID>
```

Open its printed loopback URL, choose Results, then Open selection. This preview
has no execution backend and deliberately declines native export; use the generated
Rust exports or the native desktop's dialogs. It serves only fixed preview assets,
binds to loopback, uses a restrictive CSP, and does not expose arbitrary files.
The preview is a UI demonstration, not a retained assessment or native acceptance.

## Validation and scope

Validation completed locally on 2026-10-29 with installed tools and cached dependencies:

| Check | Result |
|---|---|
| `scripts/check-local.ps1 -Check Workspace,Clippy,Format,Governance` | Passed; workspace tests 637 passed, 0 failed, 27 opt-in tests ignored |
| `cargo test --manifest-path gui/Cargo.toml --locked --offline` | 14 passed, 0 failed; 2 opt-in tests separately exercised |
| Explicit junction rejection test | 1 passed using a local junction fixture; no privilege changes |
| Explicit fixture/export demonstration | 1 passed; fresh outputs in the local handoff |
| `node --test gui/tests/*.cjs` | 21 passed, 0 failed |
| Node syntax checks for Results UI/tests/preview | Passed; no separate JS linter is configured |
| Desktop all-target Clippy, locked/offline, warnings denied | Passed |
| Workspace and desktop formatting, final governance, `git diff --check` | Passed |
| Desktop locked/offline build | Passed |
| Native Workbench open + JSON and Markdown dialogs | Both new exports byte-identical to deterministic backend exports |
| Independent source review | Findings fixed; final review found no material blockers |

The local handoff retains full logs and exact artifact locations. Results UI tests
record only `open_results` and `export_results` calls; stale/repeated requests never
reach execution routes. The backend calls the existing read-only retained reader;
no execution/provider calls or new native worker trials occurred in this flow.
The added tests cover deterministic real-fixture loading/export, unchanged inputs,
missing/corrupt/duplicate evidence, strict input limits, hostile text, mixed functions,
source-specific gaps, failed/not-reached stages, partial runs, export collision and
I/O failures, root/case containment, retained rename prevention, backend overlap,
repeated clicks, reversed loads, cancellation, filters and focus. An explicit local
junction negative test runs separately without changing privileges or security.

Real production Sandbox/MSIX retained workspaces were not selected during this
feature validation. The pinned reviewed archive is real historical fixture evidence;
mixed application failures are synthetic examples. There is no new application,
VM, provider, installation, authentication or native worker trial. Screen-reader
behavior is supported by semantic markup and accessibility-tree inspection; a
human screen-reader usability study was not performed. W4/W5 and production
acceptance remain open.

## Draft PR text

**Title:** Add an offline desktop Results Explorer for retained assessments

The desktop now opens bounded explicit assessment selections in a dedicated Results
view, using existing retained report-set verifiers. Users can compare fixed workflow
functions across runs, filter outcomes, and inspect failed/not-reached stages,
evidence gaps and hash references while keeping historical cleanup separate.

JSON and Markdown summary exports use a minimal closed projection, current-snapshot
binding and exclusive file creation outside held retained locations. Viewing has no
execution/recovery/cancellation route. Missing, rejected, duplicate, partial and
unsupported inputs stay explicit. General compatibility and isolation remain
unmeasured.

Validation: offline workspace and desktop Rust tests, Node UI tests, Rust formatting,
Clippy with warnings denied, governance, pinned-archive demonstration, labeled
synthetic mixed-application examples, native dialog verification and independent
source review. Exact totals and any limitations are in the local handoff. No new
application/VM trials, push, publication, merge or release; this does not close W4/W5
or claim production acceptance.
