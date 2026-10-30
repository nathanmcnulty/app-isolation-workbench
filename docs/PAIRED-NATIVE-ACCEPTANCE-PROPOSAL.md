# Proposed native acceptance — not executed or authorized here

Implementation source: `b7af36f0baa16982c8c0d20e8269acc5a586f1b9` on
`codex/paired-controls`, descendant of main `53c02c8` including merged PR #103.
A later documentation/test-only commit may follow; any control-source change
requires fresh pins and a fresh plan. This proposal does not authorize execution.
Do not repeat PR #103 trials or recover/replay completed historical runs.

## Pinned local inputs

- Control revision: `aiw.dev/paired-file-registry-child/v0alpha1`.
- Source commitment (length-prefixed exact UTF-8 bytes from the 13 sources in
  `crates/aiw-probe/src/paired_controls.rs`):
  `95201a1b89182f699358f2641e8ec47de7a45e2ed56c7fdc1b55418227803f49`.
- Fixed policy: `classicAppContainerNoCapabilitiesFixedChildOutputGrant`.
- Locally built, unexecuted x64 debug/static-CRT guest agent:
  `C:\aiw\app-isolation-workbench\target\guest-agent-static\x86_64-pc-windows-msvc\debug\aiw-guest-agent.exe`.
- SHA-256: `b5cd415894b5d142215ae9b71f8d619d43404eb2511eb9304ad63f53db097512`.
- Build/PE verification record: `C:/aiw/paired-final-agent-build.json`;
  compiler output: `C:/aiw/paired-final-agent-build.stderr.log`.
  Built with installed tools/cached dependencies; not signed, packaged or run.

These pins identify local bytes. They do not independently enroll a release or
prove native behavior. No independently supplied future desktop package receipt
hash or provider enrollment was available for this new source. Therefore no
copy/paste native launch command is supplied with invented package hashes.

## Prerequisites for a separately authorized disposable-worker session

Obtain the independently reviewed desktop package and receipt hash for the exact
source/agent/source-commitment above (or regenerate every pin for reviewed final
bytes). Enrollment must include `guestAgentControlSourceSha256`; never add it to
an old package merely to bypass a refusal. Independently verify trusted Store
provider package/catalog/file identity and exact OS. No supplied credentials, host security grants or application installers are
required by this fixed workflow. The guest creates its own fresh worker-local
standard account; that behavior remains part of native acceptance.
Do not weaken local held-file intake if Sandbox Tools mappings cannot meet it.

First prove native driver viability inside a fresh disposable worker: mapped
agent/fixture/launcher custody and hashes, suspended process/token observations,
output capture, bounded deadlines, descendant jobs, registry/file fixture
integrity, profile deletion and exact worker cleanup. A mapping/driver failure
must leave the comparison inconclusive with its valid prefix retained. This is
the specific untrialed native risk; offline mocks cannot settle its semantics.

## Proposed product procedure after prerequisites and separate authorization

1. Use the verified desktop package's **Fixed paired controls** choice, no
   installer/document inputs. Choose a new local evidence parent outside all old
   runs. Preparation must create a fresh owned workspace and display its typed
   locator/immutable plan; runtime protocol/features/sessions remain explicitly
   unmeasured. Observe zero provider process calls during preparation/viewing.
2. Check exact OS/user, source/executable/provider commitments, baseline/candidate
   fixed cases and permitted policy difference. Approve only the displayed
   literal plan hash. Confirm approval alone leaves the worker unstarted.
3. Invoke separate Start once. Runtime leased preflight must reject any drift or
   occupied session before dispatch. Never retry an ambiguous Start. Derive run
   ID, workspace, session UUID and recovery context from the newly retained
   `paired-workflow.json`, plan and session transaction; never guess an ID or
   adopt an old/foreign lease.
4. Verify ordinary-user file and 64-bit registry reads and child launch, then
   classic AppContainer no-capabilities fixed cases with held/self/descendant
   token evidence. Error 5 is denied; 2/3 is missing; timeout/failure/unmeasured
   stay distinct. Broken baseline/driver or incomplete cleanup is inconclusive.
   Effective isolation and general application compatibility remain unmeasured.
5. Exercise cancellation only on that owned running workflow. For interrupted
   dispatch or unknown cleanup, preserve every record and use its exact-session
   recovery action once; never replay Start or recover a synthetic record.
6. In Results, open only the newly emitted bounded assessment selection. Compare
   fixed case/token/evidence facts with cleanup in its historical column. Export
   JSON and Markdown to two new files outside retained sources. No editing task
   or document round-trip applies to these fixed controls; ordinary application
   functions must remain unmeasured. If future app trials are proposed, their
   exact inputs/editing tasks need separate source-pinned authorization.

Use fresh UUID destinations, then exclusive new-file exports. The following
read-only local pin check is safe now and is not a native trial:

```powershell
$ErrorActionPreference = 'Stop'
$pairedAgentPath = 'C:\aiw\app-isolation-workbench\target\guest-agent-static\x86_64-pc-windows-msvc\debug\aiw-guest-agent.exe'
$pairedAgentExpected = 'b5cd415894b5d142215ae9b71f8d619d43404eb2511eb9304ad63f53db097512'
if ((Get-FileHash -LiteralPath $pairedAgentPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pairedAgentExpected) { throw 'Agent drift: stop and regenerate independently reviewed pins' }
$pairedFutureEvidence = Join-Path 'C:\aiw' ('paired-native-evidence-' + [guid]::NewGuid())
$pairedFutureJson = Join-Path 'C:\aiw' ('paired-native-summary-' + [guid]::NewGuid() + '.json')
$pairedFutureMarkdown = Join-Path 'C:\aiw' ('paired-native-summary-' + [guid]::NewGuid() + '.md')
foreach ($pairedFuturePath in @($pairedFutureEvidence,$pairedFutureJson,$pairedFutureMarkdown)) {
    if (Test-Path -LiteralPath $pairedFuturePath) { throw 'Destination collision' }
}
# Names only: does not create an evidence root, start a provider, or export files.
@{ evidenceParent=$pairedFutureEvidence; json=$pairedFutureJson; markdown=$pairedFutureMarkdown }
```

Acceptance evidence must include exact enrolled package/provider/agent/source
hashes, fresh typed run records, driver outputs, all six case observations,
cleanup and recovery receipts, untouched input hashes and the safe exports.
Failure remains evidence, not a compatibility verdict. Keep live Benchmark 2,
W4/W5, release and production acceptance open.
