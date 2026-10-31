# Pinned paired-controls attempt and retained Results

Observed 2026-10-30, America/Anchorage. This records a **pre-dispatch refusal**,
not a successful fixed-control assessment or Benchmark 2 acceptance.

## Approved scope and exact execution

The user approved the proposed PR-readiness milestone, including the single
[pinned native assessment](PAIRED-NATIVE-APPROVAL.md). Publication remains separate.
The controller checked the clean local checkout, VM107 identity, normal HTTPS/Core
runtime, unchanged VM configuration/no VM lease, exact package inventory, provider
and catalog bytes, unchanged retained plan/tool records and pending approval.

- Execution package source: `d370ec8cd5bcaa6915ac24801789070dd0040e3b`.
- CLI SHA-256: `0dccb24c04f895a22e647af10b7ce0d72b70902c328e59b4b2329013cb5a111a`.
- Guest/fixture/launcher SHA-256: `b5cd415894b5d142215ae9b71f8d619d43404eb2511eb9304ad63f53db097512`.
- Worker: VM107, UUID `e5cecc90-35c2-4831-bf9c-424be23f7d4e`.
- Run: `paired-1793425345541054400`.
- Canonical plan hash: `b0d2e739ce45e7c9bbb0a0ed9651905cefcd0dfaae53c4e06450c1108035f234`.
- Approval recorded: 2026-10-30 22:01:55 America/Anchorage
  (`2026-10-31T06:01:55Z`), `AIW\labadmin`, exactly the retained trust deltas.
- Start issued **once**, VM107 CLI process PID 9284; no retry or re-preparation.

Audit directory:
`C:/aiw/paired-native-assessment-9fbf14ab-776c-42ed-8ee6-8b8a8009fca0`.
The fixed controller and durable progress/intent records are retained there and
under `C:\AIW-Paired-d370ec8-20261030` on VM107.

## What actually happened

The CLI terminated after 22 seconds with exit 1, `AIW_WSB_START_REJECTED`.
Provider authority acquisition failed at the required native **list** operation:
`AIW_WSB_CLI_TIMEOUT`, elapsed 15039 ms, child PID 10800. Captured stdout/stderr
were empty for that operation; stream completion was true and deadline/early/
final cleanup-error fields were null. The fixed deadline was not extended.

This happened before the shared execution kernel could commit a Sandbox dispatch
transaction. Post-attempt read-only status reports **Ready**, journal sequence 3,
with committed approval and no bound Sandbox session transaction. There is no run
result, guest request, guest output or related running process in the observed
state. No Sandbox Start/guest/control invocation was reached. Ready is not a
successful attempt, permission to retry, or a cleanup certificate. The failed
provider list does not establish global Sandbox session availability.

No cancellation or recovery was issued: there was no bound dispatched session to
recover. No foreign resource was adopted/stopped, VM restored, security setting
changed, application trial run, or PR #103 trial repeated.

Independent source review found no proven source defect explaining the timeout.
The native provider uses the caller's Windows token/session and does not switch
to the active console session. Remote context is therefore a plausible **unverified
hypothesis**, not an established cause. Do not bypass list, change identity/grants,
relax isolation, extend deadlines, or repeat Start to turn this into a pass.

A subsequent read-only observer was in Windows session 0 while the labadmin
console was active in session 1. Bounded existing AppModel-Runtime/Admin and
TWinUI/Operational records for 06:01:45–06:02:35Z returned no matching events.
No logs were enabled, and no extra provider query ran. This does not establish
the past child's session or the timeout's cause (`context-diagnostics.json`).

Authoritative records: `native-progress.jsonl`, `post-attempt-state.json`, and the
original `Native-start.stderr.txt` retained on VM107. The CLI diagnostic remains
engineering evidence; it is not promoted into a trusted control result.

## Safe offline improvement and actual Results backend

Source commit `2ec65edfe749b73a13ddf0c923db973de1292fc8` distinguishes these retained
states using already verified journal/transaction provenance:

- Approval unavailable: no execution evidence accepted.
- Approval recorded, dispatch not committed: fixed cases remain unmeasured.
- Committed approval and dispatch: unchanged existing evidence verification.

Both incomplete states still refuse output evidence before verification. No verdict
engine, recovery route, provider gate, guest policy, or execution behavior changed.
The desktop export allowlist preserves only the new fixed labels and still drops
private diagnostic text. The old combined label remains accepted for older inputs.

The new developer example `gui/examples/export-retained-results.rs` calls the
actual desktop ResultsStore twice, verifies deterministic summaries and uses its
existing token-bound, exclusive, outside-retained JSON/Markdown exporters. It has
no approval, Start, cancellation, provider or recovery entry point. Its debug build
(9629184 bytes) has SHA-256
`c5523a8cd81b99145f3b30fd216dc92f384adb83ed5da1b1e7868f558cbef113` and was staged
to VM107's new `ReviewTools-2ec65ed` sibling, without replacing the execution package.

The exact read-only command executed on VM107 was the following. Its outputs now
exist; **do not replay it expecting overwrite**:

```powershell
& 'C:\AIW-Paired-d370ec8-20261030\ReviewTools-2ec65ed\export-retained-results.exe' 'C:\AIW-Paired-d370ec8-20261030\Exports\selection.json' 'C:\AIW-Paired-d370ec8-20261030\Exports\summary.json' 'C:\AIW-Paired-d370ec8-20261030\Exports\summary.md'
```

The exact selection is `C:\AIW-Paired-d370ec8-20261030\Exports\selection.json`.
It references only the actual typed locator for this run, without disk discovery.
The example completed on VM107 with exit 0 and no stderr. It produced:

| New export | SHA-256 |
|---|---|
| `Exports\summary.json` (7105 bytes) | `5d6d97e2f40018e23dfffc6a14be234f4de5dc51d21c40a722bd8096a636441a` |
| `Exports\summary.md` (3026 bytes) | `448c3b6f5198ff94b913865d41660a6877a9db45732180907d3ceac125d35502` |

The report is available but **partial**: all six baseline/candidate cases and all
application functions are unmeasured; no comparison is eligible, no observations
verified and historical cleanup is null. It preserves the fixed approval-without-
dispatch gap. A planned request hash is an inert reference, not executed evidence.

Further actual-backend checks passed: repeated new JSON/Markdown files are
byte-identical to the first exports; attempts to overwrite those first files and
to export into retained storage fail without changing them or creating refused
targets. A bounded snapshot of every file in the explicit retained tree (17 files,
including project/locator/review, roles, journal heads and existing lock record)
matches before/after. Summary checks find no absolute Windows path, operator SID,
account/run ID or credential/password marker. All six cases remain unmeasured.
Record: `vm107-results-validation-v2.json`. Two earlier validation scripts stopped
before any export operation because their explicit snapshot list omitted the
existing `runs/.locks` directory; the final list includes that source-defined
coordination directory. No retained file was deleted, repaired or changed.

This is actual retained-reader/export-backend validation, **not native GUI
validation**. The console browser connection timed out twice during this turn;
no current GUI screenshot, filter/focus test or native dialog result is claimed.
Earlier labeled fixture/UI evidence remains applicable only to its recorded scope.

## Validation and remaining milestone

Focused checks passed: two protected paired-reader/kernel regressions, one shared
function-matrix regression, one desktop fixed-gap/privacy regression, affected
runner and desktop all-target Clippy, formatting and the offline example build.
Independent source review found no consequential issue in the reporting/example
delta. Unchanged broad Rust/Node suites and prior review evidence were reused.
Logs under `C:/aiw`: `paired-predispatch-report-tests.log`,
`paired-predispatch-functions-test.log`, `paired-predispatch-results-test.log`,
`paired-predispatch-runner-clippy.log`, `paired-predispatch-desktop-clippy.log`,
`paired-retained-export-example-build.log`. Current live backend record:
`vm107-results-export.json` in the audit directory.

The positive six-case native demonstration remains incomplete. Before another
assessment attempt, separately review a bounded diagnostic of the timeout and
update execution authority for the exact target/context/source; this request's
single Start must not be replayed. Preserve the existing approved run and its
diagnostics. Full Benchmark 2 still needs its declared real-application candidate;
W4/W5 closure, publication and production acceptance remain open.

Final read-only status still shows Ready/sequence 3, no transaction/result/output
or related process. The fixed Proxmox metadata probe matches its initial VM
configuration/checkpoint/provider hashes and no-lease state exactly. No extra
Sandbox provider query was used for that final check. Documentation review's two
factual corrections (execution-package source versus reporting source, and VM107
CLI PID versus controller PID) were fixed. Final governance/format/diff evidence
is retained under `C:/aiw/paired-attempt-final-governance.json` and the local audit.
