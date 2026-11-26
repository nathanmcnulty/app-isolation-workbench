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

### Approved MSI installation and discovery

A project can declare one `install` step for an x64 MSI and ask
`aiw run prepare-wsb-msi` to bind protected intake to a fresh plan. The
install-discovery profile requires the measured Windows Sandbox 0.8.114.0
protocol. Its plan discloses machine installation with an elevated worker
installer, an offline disposable Sandbox, buffered verbose logging and a
300-second installer deadline. The plan binds the source hash, receipt,
agent, provider, workspace and compiled scenario. Use
`run import-prepared-wsb` and `run review-approval` before `run start`.
Reviewing a preview alone grants no authority.

Start stages an exact verified copy on the guest's local disk. The worker
reads the package ProductCode before launch and requires a fresh machine
state. A successful install-only result requires a natural exit code 0 and
the same ProductCode registered as installed in machine context. The host
checks the exact-session cleanup and revalidates the completion-verified
result against the matching evidence record.

Inspect `scenario.installDiscovery` in the Start or retained JSON report.
The candidate scan queries registered local file key paths for components
in the reviewed MSI. Each candidate includes the component GUID, an
executable path relative to `C:\Program Files`, size and held-file SHA-256.
`candidateScanComplete` describes this bounded key-path scan. Shortcuts,
non-key-path files and other installation roots are outside this scan.
After inspecting the list, rerun the same retained report command with
`--select-entry-point <relative-path>` to return exactly one candidate and its
source run, receipt, evidence and package identities. Use the relative path
as printed, including its case. Selection is read-only and carries no launch
approval. Worker observations describe the measured installation. An elevated MSI's custom
actions share the guest boundary, and the result establishes no effective
application isolation.

### Launch a reviewed MSI entry point

For the next run, use the same installer and a new scenario. Declare these
steps in order: install, launch the exact selected relative executable with no
arguments, wait for that executable's window, request graceful close, and
expect exit code 0. Use a new run ID. Pass these additional options to
`aiw run prepare-wsb-msi`:

```text
--reviewed-entry-point <relative-path>
--selection-source-root <completed-install-only-run-directory>
--selection-source-run <completed-install-only-run-id>
--selection-source-project <install-only-project.json>
--selection-source-agent-sha256 <source-run-guest-agent-sha256>
```

Preparation reopens the retained install-only evidence; it cannot use a loose
selection JSON or a previous launch as the source. Review and approve the
fresh plan separately. The new Sandbox reinstalls the exact MSI, checks the
registered component and its executable bytes, and opens the held image as a
standard user. Success records that its own window appeared, it closed on
request with the expected exit code, its process job was empty, and the
provider cleaned up. A changed executable or missing window fails this run.
This is a launch smoke check, not an interaction test, isolation verdict, or
packaging result.

### Keep a reviewed MSI window open for an operator

Use the same verified install-only selection and separately approved fresh
plan. In the scenario above, replace the graceful-close step with the typed
operator wait. For example:

```yaml
- type: waitForUserClose
  timeoutSeconds: 120
```

Choose 30 to 600 seconds. The clock starts only after AIW observes the
launched application's own visible window and checks its standard-user token.
Set the outer Start timeout to cover installation, window readiness, and this
session. Interact inside the Sandbox and close the application normally;
AIW does not send a close message in this mode. An expired wait is an
unsuccessful attempt, and the process job and Sandbox are cleaned up.
There is no host file, network or clipboard access. Scratch data stays in
the Sandbox and is discarded with it.

Use `run report-wsb-msi-run` for the retained report. A successful
`interactiveSession` proves the window, the standard-user context, natural
exit, and cleanup. It does not prove which controls someone used, establish
an isolation verdict, or produce a package.

### Installer diagnostics

Preview v0alpha3 specifies guest-local verbose Windows Installer logging and an
8 MiB diagnostic read limit. It uses flushed logging by default. Add
`--buffer-install-log` to review Windows Installer's buffered verbose mode.
A buffered log can lag the worker's actual stage while the process is running.
The retained raw log stays private. To inspect a captured log without writing
out its text:

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
external holdout. Traces for both packages recorded offline certificate
revocation (`0x80092013`) during trust processing, then `WinVerifyTrust`
returned success in about 121–122 seconds and App Control recorded a matching
allow.

At the existing 300-second maximum, the control exited successfully in 173.5
seconds, with matching transaction events, machine-context registration and
two installed executable candidates. The holdout reached `InstallValidate`
with flushed logging and `ProcessComponents` with buffered logging. Both
holdout runs reached the deadline without a client exit or machine
registration. The reviewed deadline covers Windows trust processing and
installation. The actual completion evidence determines the result.

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
  Add `--include-replay-provenance` to `application report-assessment`
  for a `replayProvenance` field. A `matched` receipt comes from the
  retained evidence directory and matches the validated run and plan. It
  shows the recorded package manifest digest. The original package is
  needed to verify its bytes independently. Other statuses are `missing`
  for an absent receipt, `mismatched` for a failed identity, format or binding
  check, and `unavailable` when a receipt check cannot be completed.
- `application export-assessment-package`, `verify-assessment-package` and
  `prepare-assessment-package`: copy/verify the same external data and prepare
  fresh review. Import never reuses execution authority.
- Add `--format review` to `verify-assessment-package` for a compact, read-only
  JSON review bound to the exact `package.json` SHA-256. It shows declared
  inputs, ordered steps, requested run conditions and expected outputs.
  Launch steps show an argument count. Verification reads the package in place.
- `application compare-assessment-packages --baseline <package> --candidate <package>`
  verifies both packages in place and reports manifest identities and changed
  declaration categories. Changes to ordered steps include argument and exit
  expectation changes. The output describes the plans, with no runtime findings.
  Add `--include-candidate-review` to see the candidate's declared inputs, steps,
  requested run conditions and expected outputs alongside the change summary.
  Use `candidateReview.packageManifestSha256` to pin preparation to the candidate
  shown in that combined review.
- In the desktop Workflow view, choose a candidate under **Review a replay
  package** for the same in-place verification and compact review. A baseline
  adds the change summary. **Prepare from PowerShell** generates a command
  that carries the reviewed package path and manifest pin into
  `prepare-assessment-package`. Supply the trusted CLI path, the enrolled
  agent path and its independently recorded hash, the evidence parent and
  your operator identity. Run the command manually in PowerShell 7.6 or
  later. Preparation returns a plan for separate approval and Start.
- To require the exact previously reviewed `package.json` bytes, pass the
  review or comparison's `packageManifestSha256` as
  `--expected-manifest-sha256 <sha256>` to `verify-assessment-package` or
  `prepare-assessment-package`. Preparation checks the pin before it writes
  the workspace. A manifest-only edit requires a new review hash. Pinned
  preparation returns the run locator and `receiptRetention`. A value of
  `retained` means `replay-package-preparation.json` contains the run ID, plan
  hash and verified manifest digest. A value of `failed` means preparation
  completed and the original locator remains usable. This invocation could
  not publish the receipt. If the receipt is required, prepare again
  with the reviewed digest. The existing approval and Start steps still apply.

### Verify the replay handoff before a live trial

Desktop review and optional baseline comparison are read-only. A fresh
candidate review supplies the exact manifest SHA-256 for the preparation
command. A changed candidate must pass a new review before it can be prepared
with a new pin.

AIW preparation requires x64 Windows build 26100 or later, available
virtualization, and one trusted x64 `MicrosoftWindows.WindowsSandbox` Store
registration for the same Windows account that will run AIW. The generic
portable assessment accepts CLI versions `0.8.107.0` and `0.8.114.0`.
The MSI discovery profile requires `0.8.114.0`. AIW verifies the exact
provider file and its Store catalog. Supply the measured AIW CLI, the
independently enrolled guest agent and its recorded SHA-256, the reviewed
package, and an existing local evidence parent.

Check registration from the intended operator account with a read-only query.

```powershell
Get-AppxPackage -Name MicrosoftWindows.WindowsSandbox |
    Select-Object Name, Version, Architecture, Status
```

If the registration is missing, use Microsoft's documented optional-feature
installation and Store upgrade process on an authorized lab host. Check the
resulting version against the AIW versions above before preparing. A newer
Store version needs explicit AIW support before use.
[Microsoft installation guidance](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-install) ·
[Microsoft Store upgrade guidance](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-versions)

1. In PowerShell 7.6 or later, set `$aiwCli` to the trusted executable path
   used in the desktop. Prefix the generated command with `$prepareJson = `
   to capture its output, then run it manually. On success, parse the result
   with `$prepared = ($prepareJson -join [Environment]::NewLine) | ConvertFrom-Json`.
   Check that
   `approvalRecorded` and `executionStarted` are false and that
   `run.planSha256` agrees with `proposedApproval.planHash`. For the receipt
   acceptance check, require `receiptRetention` to be `retained`.
2. Reopen the run using `$aiwCli`, the trusted executable path entered in
   the desktop, and the workspace and run ID from the preparation response.

   ```powershell
   $run = $prepared.run
   & $aiwCli run status --root $run.workspace --run-id $run.runId
   & $aiwCli application report-assessment --workspace $run.workspace --run-id $run.runId --include-replay-provenance
   ```

   Confirm `core.status` is `pendingApproval` with the same plan hash, the
   report's `evidenceStatus` is `notRun`, and `replayProvenance.status` is `matched`
   with the reviewed manifest digest and the prepared plan hash.
3. For a separately authorized live trial, review the exact retained plan
   in an interactive terminal. Record approval only after confirming the
   plan and trust changes printed by the CLI. Use the approved operator
   identity from the preparation review.

   ```powershell
   & $aiwCli run review-approval --root $run.workspace --run-id $run.runId --approved-by $prepared.proposedApproval.approvedBy --approved-at ([DateTimeOffset]::UtcNow.ToString("o"))
   ```

   The confirmation is `approve <printed-plan-hash>`. Approval records
   permission for that plan. A separate `run start` supplies the same
   workspace and run ID, `run.projectPath` as the project, and the
   independently enrolled agent hash. Reopen the report after the trial to
   check the observed workflow, evidence gaps and recorded cleanup.

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
real-time I/O cancellation guarantee. In-desktop preparation and approval,
general installer/GUI automation, broad native acceptance, Benchmark 2 and
W4/W5 remain open.
