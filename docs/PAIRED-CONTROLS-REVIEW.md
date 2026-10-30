# Paired backend source review checkpoint

Scope: local `codex/paired-controls` descendant of `edf4139`; fixed paired request,
preparation/import, runner lifecycle, native guest setup/collector and publication.
The independent `results_review` agent read source without editing, building,
executing providers or running native tests. Admin/desktop/retained Results
integration remains outside this checkpoint and requires subsequent review.

Resolved findings:

- Canonical profile/request hashing now uses the shared evidence writer. Exact
  agent-copy role hashes and sizes are checked at every typed boundary.
- Registry scope/view/value and native stage are validated before flattening;
  denial requires native error 5, missing requires 2 or 3.
- Historical source commitments remain readable/recoverable; new preparation,
  Start and guest dispatch require the current fixed source identity.
- Two lost-separator guest path literals were replaced with named absolute paths
  and fixed-path regressions.
- Fixed-role copies cannot enter normal request dispatch through Windows casing,
  verbatim or unknown aliases. Normal dispatch explicitly requires the Tools
  agent; missing executable identity fails closed.
- A late malformed case no longer erases the previously validated prefix. Each
  prospective case is checked before commit, with only its held process and an
  unmeasured observation retained if self/descendant output is malformed.
- Partial evidence carries measured launcher provenance, excludes PID aliases,
  binds users, and rejects success without completed held/self/child evidence.
  Late resource/full-result failures retain independently valid progress.
- Raw normalization clears incoming self-token fields and accepts them only from
  a parsed report matched to the held token. A pure prefix regression caught and
  verified this correction without running a fixture.
- Complete observations must match all six recorded cases. Partial observations
  cannot confer comparison eligibility or production acceptance.

The reviewer found no remaining material source blocker in the reviewed native
slice after these fixes. This is source review, not evidence of native operation.
Sandbox Tools mappings may have virtual/remote volume semantics rejected by the
existing held intake reader. Keep this fail-closed and validate it only during
subsequent separately authorized disposable-worker acceptance; do not weaken
host intake or run a native trial to complete this offline task.

Focused logs: `C:/aiw/paired-contract-tests.log`, `paired-runner-tests.log`,
`paired-preparation-tests.log`, `paired-guest-tests.log`, `paired-prefix-tests.log`
and `paired-core-clippy.log`. Read each log for the actual recorded result; none
is the final full-product acceptance run. No Benchmark 2/W4/W5 closure follows.

Recorded incremental results for this checkpoint: 6 provider contract tests, 8
runner lifecycle tests, 1 preparation test, 5 guest dispatch/publication tests and
1 pure prefix-retention test passed. Component all-target Clippy, including the
native platform crate, passed with warnings denied. Formatting and diff checks
passed. These checks did not execute native control paths, providers or apps.

## Retained reader and Results review

The independent reviewer also reviewed the paired retained reader, private
historical validation path, shared report-set routing and Results projection,
filters and exports. Two findings were fixed: pending ApprovalIntent artifacts
are not committed approval, and requested native-worker origin alone is not a
verified native observation. Regression tests cover both. Missing/rejected
records contain no copied measurements or eligible comparison. Historical
cleanup remains separate, and application functions remain unmeasured.

The test-only protected-workspace rehearsal was reviewed as truthful: inert
files, synthetic provider/guest provenance, real fresh protected file bindings,
actual shared runner with fake process/lease, followed by the actual retained
reader/report-set services. No production authority check was weakened. Tests
verify unchanged fixture bytes, duplicate identity handling and zero additional
provider-boundary calls on reads. The separate unresolved-cleanup case remains
inconclusive and viewing performs no recovery. Native behavior is still untested.

Incremental logs: paired-retained-snapshot-tests (1), paired-historical-preparation-
tests (1), paired-report-service-tests (8), paired-report-set-tests (4),
paired-protected-fixture-tests (1), paired-protected-unknown-cleanup-tests (1),
paired-results-rust-tests (5), paired-results-projection-tests, paired-results-node-
tests (10), paired-report-clippy and paired-results-clippy under `C:/aiw/`.
Read the actual logs for their recorded source state; full-product final validation
and actual desktop keyboard preview have not occurred.


## Final product source review disposition

Subsequent independent source review covered admin/desktop gates, exact owned
recovery, static provider identity and staged custody, coupled offline harness,
Results/exports, keyboard focus and loopback replay. Findings were fixed; final
review found no remaining consequential issue. The cancellation publication
handshake correction is test-only and preserves production fail-closed reads.
See [final handoff](PAIRED-IMPLEMENTATION-HANDOFF.md) for completed validation and
limits. The earlier incomplete checkpoints above remain historical evidence;
source review and synthetic rehearsals are not native behavior acceptance.
