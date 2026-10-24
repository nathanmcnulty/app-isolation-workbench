# WSMan host and loaded-engine identity correction

Source baseline: owning PR #103 branch `codex/new-vm-handoff-20261021` at
`73a9fd6dedcaa9b9fa977088ff59609147cccbca`. This corrects the P1 in
[Dot's independent review at 7cd7bf3](https://github.com/nathanmcnulty/app-isolation-workbench/blob/7cd7bf3b4e35f02354ebea56b662cfa8c327ec51/docs/handoffs/2026-10-24-powershell76/INDEPENDENT-MIGRATION-REVIEW.md).
The documentation branch was read, not adopted as the implementation branch.

## Production behavior

Remote proof observes the actual System32 wsmprovhost.exe process, actual
PSSenderInfo.ConfigurationName, Registry64 ConfigXML, registered/loaded plugin,
fixed startup redirects and native command origins with no compatibility session.
Configuration parsing rejects DTDs, foreign namespaces, RunAs/custom startup,
wrong resource/architecture/version and shared-process configurations. The
SupportsOptions check belongs to the singular Resource element.

The loaded System.Management.Automation assembly contributes its actual fixed
path, held-file SHA256, AssemblyVersion and loaded MVID, compared to the held
file's PE metadata. AssemblyVersion follows the engine's major/minor contract;
it is not assumed equal to the runtime patch. Registered plugin bytes must match
the fixed PSHOME plugin, and its actual loaded module path must match registration.

That endpoint independently starts the fixed machine pwsh.exe with the same
direct proof via bounded stdin, output and deadline. Preparation and requests
bind the distinct endpoint and worker identities. Dispatch compares both with
both prepared and requested values before operations. Same-session Copy-Item,
normal HTTPS and explicit PowerShell.7.6 remain required. Relevant files remain
held through the session; endpoint configuration is rechecked before successful
receipt publication. Direct local, SYSTEM and standard-user proofs still require
the fixed pwsh image and engine. Worker receipts compare the worker identity;
cold-clean verification and independent report readback additionally compare the
endpoint identity. No endpoint process is substituted into worker receipts.

Historical absent engine/endpoint fields remain omitted, preserving original
serialized bytes and hashes. Old records remain readable, including completed
cold-recovery readback. Missing bindings cannot authorize fresh execution.
Approved assets, raw-evidence/completeness logic, no-replay rules and deployed
historical provider pins are preserved.

## Offline validation and evidence limits

Local checks use the existing bundled Core 7.6.5 and Rust/Cargo 1.99.1 on Windows
10.0.26300.9711. No runtime was installed and no VM was contacted. Logs are outside
Git at `C:\AIW-Resume-20261021\wsman-*`.

The production PowerShell proof is identical across native guard, observer and
transport. Its inert regression executes actual configuration parsing, loaded
engine capture, native-command-origin checking, held-file handling and binding
comparisons. Results: ten direct-binding rejections, 25 host rejections,
18 endpoint/worker drift rejections and 18 configuration rejections; implicit
proxy, linked-image and sharing violations rejected. Protected ACL-at-creation,
existing ACL preservation and all 61 retired entries remain covered. Synthetic
legitimate WSMan observations distinguish host and worker; actual loaded-engine
capture uses the existing bundled runtime. This does not establish that a real
worker endpoint accepts the proof.

Rust regressions cover legitimate distinct identities, invalid engine/configuration,
endpoint/worker drift, worker-only receipt comparison, exact old request/binding
serialization and no new execution authority. A command-line budget regression
keeps the direct guard within the Windows native command-line limit.

Completed local checks: workspace/all-target check and Clippy with warnings
denied; formatting; 22 probe/model tests; 16 MSIX recovery/export/readiness tests;
three generated worker tests; three direct-proof/subprocess tests; five independent
report tests; final governance including runtime policy and endpoint regressions.
Two generated-script checks initially expected the superseded diagnostic string;
their corrected assertions and actual parser checks passed on rerun. Earlier
failure logs remain separate. No tests were ignored in these focused selections.
The full prior migration suite is not relabeled as a new local full-suite run.
Fresh hosted CI and the clean-source unsigned worker/desktop package are reported
with the final checkpoint and actual build/test revisions outside this source
record, avoiding a self-referential commit hash.

## Independent source review

A separate read-only review agent examined the production models, shared proof,
observer/transport, Windows held runtime, recovery/report comparisons and
regressions against the prescribed contract. Review corrections were incorporated
before checkpointing, including RunAs rejection, StrictMode-safe held-handle
retention, bounded child cleanup and Resource SupportsOptions placement.
The final source review reported no remaining blocking finding. The reviewer
did not execute the suites or conduct native acceptance; test results are producer
evidence and hosted CI is reported for its actual checked-out revision separately.

## Blocked acceptance

Stages A–D and merge remain blocked. No MSI, endpoint registration, WinRM restart,
firewall/security change, baseline provisioning, VM107 connection, application
execution or Sandbox trial is part of this correction. VM106 remains excluded.
The [consolidated plan](SETUP-AND-ACCEPTANCE.md) now describes the exact closed
registration shape this proof accepts. Real Invoke-Command/same-session Copy-Item,
SYSTEM/standard-user lifecycle and fresh cold-clean evidence still require the
separate approved setup and acceptance stages. Historical completed nonces must
never be replayed. PR #103 remains unmerged.
