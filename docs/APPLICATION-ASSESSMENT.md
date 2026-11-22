# Application-neutral assessment and replay

Implementation boundary for the first useful slice of
[issue #108](https://github.com/nathanmcnulty/app-isolation-workbench/issues/108).
The portable CLI slice has the sampled native evidence below. Broader acceptance
remains open; a schema accepting an operation does not mean execution implements it.

One intake, plan, review/approve, Start, execution, retained-report and package
path must accept two different external applications without engine changes.
Names, fixture membership and compiled vendor hashes never select behavior.
Payloads and generated packages remain outside the repository and AIW distribution.

## Review a machine MSI install

On Windows, use the existing `application import --kind msi` command to create
protected intake. Preserve download metadata with `--archive-download-metadata`
when present. In a v0alpha2 project, declare an x64 MSI with the reviewed
SHA-256, blocked networking, and a scenario containing exactly one `install`
step. Then preview the selected scenario:

```powershell
aiw application plan-msi-install --project <project.json> --scenario <scenario-id> --import-receipt <receipt.json> --timeout-seconds 300
```

The command reopens the protected intake and binds the current receipt, payload
size and SHA-256 to the project revision. The preview describes a fixed elevated
guest Windows Installer operation requesting machine scope, quiet install and no
reboot. It accepts 1–300 seconds and up to 128 MiB. Custom properties, transforms,
other installer mechanisms, signer requirements, reboot and update/uninstall
flows are outside this capability. MSI success requires additional worker
observations. Package architecture, actual registration, dependencies, custom
actions and application entry points remain unmeasured in this preview. The
preview creates no run, approval, installer invocation or provider session.

### Installer diagnostics

Preview v0alpha2 specifies flushed, guest-local Windows Installer logging and
an 8 MiB diagnostic read limit. The retained raw log stays private. To inspect
a captured log without writing out its text:

```powershell
aiw application summarize-msi-log --log <private-install.log>
```

The summary recognizes a small set of English log records. It reports observed
client and server records, server-side package policy verification, a matching
allow record for the same package and server thread, the last recognized action
records, and separate log engine return codes. It skips unknown records and an
unfinished final line. Use independent client exit, matching transaction
events, and machine-context registration for the exact MSI ProductCode to
verify installation.

In fresh offline Windows Sandboxes, the 120-second client deadline expired
during package trust verification for both the repository control and the
external holdout. For the control, the trace recorded offline certificate
revocation checks (`0x80092013`), then `WinVerifyTrust` returned success
after 121.4 seconds and App Control recorded a matching allow.

At the existing 300-second maximum, the control exited successfully in 173.5
seconds. Matching transaction events, machine-context registration and two
installed executable candidates were observed. The holdout progressed into
Windows Installer actions and reached the deadline without a client exit or
machine registration. The reviewed deadline covers Windows trust processing
and the install. The actual completion evidence determines the result.

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

Current generic plans use version 4 and preparation receipts use `v0alpha4`.
They approve the fixed signed collector channel, workflow and the closed
`sandboxSystemNoninteractive` context: collector token/process session 0,
fresh standard-user application session 0 and desktop policy
`noninteractiveLogonDefault`. The application never runs as SYSTEM. This
CLI-only context uses an explicit empty desktop string with CreateProcessAsUserW;
Windows chooses the connection under its
[documented process connection rules](https://learn.microsoft.com/en-us/windows/win32/winstation/process-connection-to-a-window-station).
The [process-creation contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
requires same-session handle inheritance and describes temporary use of assigned
privileges. No rights grant,
session reassignment, desktop ACL repair or interactive fallback is permitted.

Classic makes the single AsUser call inside the existing checked standard-user
impersonation scope, so Windows uses the target user's caller context for lookup.
The effective SID and deadline are checked immediately before creation. Ordinary
creation remains direct. Reversion is fail-stop; both returned handles are owned
immediately, and restored collector identity is checked before either success or
assignment-failure publication. The owned job contains the suspended process
before full dispatch/custody revalidation and token/PSS checks permit Resume.
`collectorUnimpersonated` describes checked collector boundaries, excluding the
deliberate profile/query/Classic-creation scopes; it is not continuous thread history.

Classic launch diagnostics query the profile folder and image/cwd access under
the collector and the fresh standard user before the single process-creation
attempt. Profile lookup follows the caller's identity as documented by
[GetAppContainerFolderPath](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-getappcontainerfolderpath).
Only the owned user's Packages subtree may be opened; other returned paths are
hashed without traversal. Diagnostic handles close before dispatch, and identity,
protection, image, cwd and deadline gates are checked again. On API failure, a
bounded ASCII `ctx1` suffix records HRESULTs, access results and file IDs in the
signed launch error. It does not replace that error or retry the application.
Successful launches retain no diagnostic suffix; queries can warm OS state, so a
later success does not identify the cause of an earlier failure.
An `unheld` folder result does not distinguish missing from denied ancestor
access. `outside` leaves access to that returned folder unmeasured, including
when the SYSTEM lookup selects another profile tree.

Collector protection `v0alpha5` records the held primary token's `TOKEN_OWNER`
separately from its user SID. For process/thread security and the primary default
DACL only, Owner Rights resolves to the measured SYSTEM or Administrators owner,
which must be absent from the application user and every application token group.
An individual NT SERVICE SID is recognized only when its complete canonical SID
is present in the held collector groups and absent from that application user and
all of its groups, regardless of group attributes. This recognizes inherited OS
service principals within the trusted collector environment; it does not grant
permissions, change ACLs, or establish protection from those services or brokers.
All 15 file and 14 process/thread denial measurements remain required. Missing
owner/group facts or an unrecognized trustee prevent application creation.
Protection v4 retains its stricter trustee rules and historical results remain
read-only under those rules. Source tests alone do not qualify the v5 path.
Requests use `v0alpha3`; channel bindings/bootstrap use `v0alpha2`. The signature
envelope and progress protocol retain their existing bytes and meaning.
These contracts passed the sampled native controls and workflows below; broader
native acceptance remains open.
Their exact typed Sandbox CLI protocol is part of plan hashing and approval;
preparation selects it from the verified Store package without claiming a live
version observation. Start must observe the same held provider version before
listing or starting sessions. The exact adapters are `0.8.107.0` and
`0.8.114.0`; ranges, mixed tuples and fallback are rejected. Protocol selection
does not establish native lifecycle qualification. Recovery additionally
requires committed approval and the same persisted plan/session protocol before
querying or stopping anything. Historical generic version-1/version-2/version-3 plans remain
readable with their original hashes but cannot acquire mutation authority,
including locked cleanup/discard. Preserve those runs and prepare a fresh
versioned plan; do not relabel or reuse an earlier approval.

## Worker and evidence

A fixed first-party agent reads a bounded read-only request. Source and fixture
mappings are read-only. The fixed elevated WDAG bootstrap holds the request and
agent and creates one fresh local SYSTEM ServiceAccount task with no triggers,
restarts or session override. A protected create-only intent binds one shared
monotonic deadline; the application also retains its stricter declared total
timeout. Only the unchanged, positively idle task can be deleted. Unknown or
active tasks remain for exact owned outer Sandbox cleanup, without Stop or replay.
The SYSTEM collector independently measures its primary identity and token/physical
session 0 before collecting. It stages code/data, establishes
a fresh ordinary user and launches each application directly with that user's
token. Collection stays in the elevated process. No secondary ordinary-user
observer or application-selected helper runs. Before dispatch, all fifteen
individual directory/progress-file mutation opens must return access denied under
the application user. Sharing violations and unknown results block dispatch.
Collection and signing stay in a protected guest-local directory outside every
mapping. Process/thread rights and the creator's primary-token default DACL must
also pass the closed trustee and native denial gates before process creation.
Mapped output is hostile transport. Mapped host ACLs are never changed to
manufacture this boundary.

The collector holds images, creates processes suspended, measures their token,
image, full-width lifetime and exact owned job, and flushes a pre-resume creation
record before resume. Progress records survive missing final completion; retained
reports project them separately as diagnostics. A creation record alone does not
prove application code ran. A final signed terminal, published after all four
raw artifacts are closed, authenticates the complete journal/result/evidence/
receipt against the immutable public local Start anchor. Imported signatures
without that independent anchor establish internal consistency only. See the
[channel requirements and qualification gates](ASSESSMENT-EVIDENCE-CHANNEL.md).

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

### Sampled native evidence

On source `315391e`, the same pinned CLI, guest agent and common assessment harness
completed two external workflows in fresh Windows Sandboxes on existing VM107.
Application names, payloads, SQL/arguments and assertions stayed in external run
data; there were no production-code changes or application-specific rebuilds
between fixtures. Both used the same intake, replay export/verification,
preparation, separate approval/Start, retained report and comparison services.

| Declared workflow | Ordinary and Classic results |
| --- | --- |
| Stateless JSON transformation | One launch, three steps and two assertions passed; complete 20-byte stdout, empty stderr |
| Initialize a supplied empty database, insert rows, query in a separate process | Two launches, six steps and five assertions passed; complete 25-byte query output, empty stderr and an 8,192-byte database |

Independent admission verified 29/30 signatures for the JSON runs and 36/37 for
the database runs. Actual root images and Medium standard-user/Low AppContainer
tokens were measured. Every passing trial verified empty owned jobs, account
cleanup, owned AppContainer-profile cleanup where applicable, exact Sandbox stop
and two final empty provider lists. Both retained comparisons admitted identical
project/content/semantic identities with only declared policy selection differing.
Database full-file hashes and extents matched; complete database bytes were not
retained for direct byte comparison.

The first database baseline failed opening its initially absent file. Versioned
CLI source inspection and success with a declared empty seed support an
initial-condition explanation; no native file-open error trace was collected.
That authenticated failure remains retained, without an isolation-incompatibility
claim. A new explicit zero-byte input condition, with
the same executable/SQL/protection options, required fresh plans and approvals.
It did not rewrite or replay the failed run. This demonstrates both truthful
failure reporting and correction through run inputs alone.

Project-owned positive controls passed in both policies. Separate overflow and
timeout controls authenticated incomplete outcomes without workflow success and
verified cleanup. Repeated retained Read returned matching full-report hashes and
lengths for the four passing external runs. Six production sanitized JSON reports/comparisons
were exported from admitted retained bytes without application/provider calls.
This qualifies the declared CLI/root-token scope, not every restriction, native
desktop operation, installer family or arbitrary application. Private raw evidence
and payloads remain outside Git.

### Broader exit criteria

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
automation remain separate work; the sampled CLI results do not close broad
native, Benchmark 2, W4/W5 or production acceptance.
