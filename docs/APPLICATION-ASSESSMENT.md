# Application-neutral assessment and replay

Implementation boundary for the first useful slice of
[issue #108](https://github.com/nathanmcnulty/app-isolation-workbench/issues/108).
Execution and native acceptance are in progress. A schema accepting an operation
does not mean execution implements it.

One intake, plan, review/approve, Start, execution, retained-report and package
path must accept two different external applications without engine changes.
Names, fixture membership and compiled vendor hashes never select behavior.
Payloads and generated packages remain outside the repository and AIW distribution.

## First capability

Stage an exact portable manifest into an offline disposable Windows worker and
run reviewed x64 entry points as a fresh ordinary user or zero-capability classic
AppContainer under that user. Code is separate from mutable work data. Grants
are explicit and limited to owned guest resources; no weaker fallback is allowed.

Existing project/scenario data compiles with versioned settings: scenario and
candidate, explicit relative cwd, exact inputs, process/total deadlines, bounded
captures and declared exit/work-file assertions. Staging, bounded
launch-to-completion, expected exit and file observation are the first typed
operations. Other mechanisms and verbs remain precise capability blockers.
Unknown fields and verbs fail closed. This first capability uses a bounded ASCII
Windows-relative path domain and refuses ambiguous device/stream/traversal names
and aliases instead of claiming general filesystem normalization.

Portable intake also rejects short-name aliases observed during directory
enumeration, including aliases assigned by Windows to otherwise ordinary long
filenames. This inherited policy can block an administrator's source before any
application runs. Choose supported source names as explicit run inputs and
reinspect their actual filesystem metadata; a filename that looks like 8.3 is
not proof of admission. Changing a source name changes its manifest and requires
fresh preparation and approval. Do not remove aliases or change volume policy to
reuse an old approval.

The compiler validates the whole manifest and resolves entry points to exact
content. A semantic workflow hash excludes display labels, host roots and the
selected policy. It aids comparison, not execution authority. Full approval binds
project, compiled plan, protected intake, inputs, agent, provider, workspace,
session and rendered configuration. Start remains separate.

## Worker and evidence

A fixed first-party agent reads a bounded read-only request. Source and fixture
mappings are read-only. An elevated guest collector stages code/data, establishes
a fresh ordinary user and launches each application directly with that user's
token. Collection stays in the elevated process. No secondary ordinary-user
observer or application-selected helper runs. Before dispatch, all fifteen
individual directory/progress-file mutation opens must return access denied under
the application user. Sharing violations and unknown results block dispatch.
Mapped host ACLs are never changed to manufacture this boundary.

The collector holds images, creates processes suspended, measures their token,
image, full-width lifetime and exact owned job, and flushes a pre-resume creation
record before resume. Progress records survive missing final completion; retained
reports project them separately as diagnostics. A creation record alone does not
prove application code ran. Final receipt publication is atomic and last.

Retain actual image identity, full-width lifetime, root token, raw exit bits,
capture prefixes/completeness/overflow, declared file facts and independent
cleanup errors. Missing observations stay absent. Exit, token or outer Sandbox
boundary alone cannot become application success or an enforcement verdict.
Full descendant token/image, DLL/memory, registry and network-denial coverage
remain unmeasured; plans requiring unavailable evidence are blocked explicitly.

Retain failed and partial observations. Strict request/artifact admission precedes
report projection. Cleanup, functional assertions and driver completeness stay
distinct. Cancellation and exact-session recovery never replay an application.
Retained reopen/export never acquires a provider or executes an application.

## Package and comparison

Replay packaging consumes the same validated plan, payload manifest and inputs.
Transporting reviewed external bytes to an explicitly selected administrator
destination does not make them AIW distribution assets. Require closed inventory,
held copies and manifest-last publication. Import revalidates and recompiles the
same semantics, then creates fresh preparation, review, approval and Start.
Packages carry no reusable approval, session or compatibility credit. Assessment
must remain useful when packaging has a capability gap.

The first replay format is a protected directory with exactly `package.json`,
`payload/` and `inputs/`. It contains the same project and compiled workflow,
external application bytes and exact input files. Export uses held copies and
publishes the manifest last. Verification checks the complete inventory and
recompiles the project against actual payload/input hashes. It does not bundle an
agent, provider, runtime installer, approval or an executable launcher.

Comparison admits independently verified source, inputs, workflow, user model,
executor and comparable fresh environments, with only declared policy differences.
Failed baseline, incomplete capture, lost evidence or unknown cleanup cannot be
attributed to isolation. Content agreement and identical container bytes remain
separate claims.

## Acceptance

Prove the driver with project-owned controls before vendor trials. Exercise an
unchanged engine with stateless JSON and stateful database external run data.
Retain provenance and source-pinned stage results. Test plan/payload drift,
unsupported operations, unsafe paths, capture overflow, timeouts/cancellation,
interrupted or missing publication, non-replaying recovery, cleanup conflicts,
package round-trip and retained read/export without execution. Complete applicable
checks and independent review before delivering the draft PR.

This slice does not complete the seven-fixture/holdout matrix, every installer or
backend, generic MSIX authoring, W4/W5 or production acceptance. Preserve legacy
receipts and readers; retire superseded execution after equivalent generic
coverage transfers.

## CLI service path

All new commands consume administrator-supplied run data; no application recipe
registry or vendor asset manifest selects execution:

- `application plan-assessment`: inspect held portable metadata and return the
  compiled plan or capability blockers, with zero provider calls/executions.
- `application prepare-assessment`: protect the exact source, inputs and enrolled
  AIW agent; import the hash-bound plan and return review data. The input map is a
  JSON object from reviewed input IDs to source files.
- `run review-approval` (or the existing explicit approval-record API), followed
  separately by `run start`: reuse the original approval and exact-session
  transaction, cancellation and recovery path.
- `application report-assessment` and `application compare-assessments`: read
  protected retained records, admit receipt/result/progress together, and project
  assertions, coverage and historical cleanup without acquiring a provider.
- `application export-assessment-package`, `verify-assessment-package` and
  `prepare-assessment-package`: copy/verify the same external data and prepare
  fresh review. Import never reuses execution authority.

Use `schema assessment-settings`, `compiled-assessment`,
`application-assessment-guest-request`, `application-assessment-result`,
`verified-assessment-evidence` and `generic-application-run-report` for the closed
versioned contracts. Application metadata and exact argv are private run inputs;
sanitized reports omit raw captures, paths, process IDs, SIDs and free-form native
diagnostics. Those remain in protected evidence for diagnosis.

Typed Windows Sandbox preparation failures retain their existing category and
stage through the generic CLI path. Public details are static and omit native
error text; direct service failures do not infer a run ID. Other unclassified
admin failures can still return the generic CLI error. A category identifies the
failed requirement, not its native cause or whether cleanup completed.

The monotonic workflow budget includes setup and prevents late application
dispatch. Synchronous filesystem/profile/native calls can overrun that budget;
the separate outer Sandbox watchdog bounds worker lifetime. This is not a hard
real-time I/O cancellation guarantee. Desktop intake and general installer/GUI
automation remain separate work; current native acceptance is still pending.
