# Administrator packaging component

Goal: select a Notepad++ installer, analyze its identity and available supported
recipes, select the isolation/workflow option, assemble a reusable package, then
validate that package in a disposable worker. Analysis, assembly, approval and
execution remain distinct actions.

## Implemented service

`aiw-admin-workflow::packaging` exposes Windows-only read-only installer analysis
and protected bundle creation. Analysis cross-checks the existing source inspector
against held file identity, streams, size/hash and embedded signature status, and
fixed scenario compiler, offering only packaged recipes whose MSI hash matches:
local-settings assessment and interactive document. Windows Sandbox is the
available runtime through a closed offline preset; custom grants and other isolation modes are unsupported.
Unknown signature/compatibility/isolation observations remain unknown. Recipe
choices describe data/workflow behavior; they do not represent different measured
isolation strengths.

Creation takes the selected typed recipe plus the analyzed installer and packaged
project hashes. It reloads the packaged project and fixed compiler, reopens the
installer with held-file authority, revalidates its hash and imports protected
bytes with download provenance. The existing exporter publishes the closed bundle
manifest last; the ordinary verifier checks the result before a durable success
record is saved. Assembly does not run an installer or acquire a Sandbox session.

Source intake, selection and result are retained under a fresh evidence child.
Bundle output uses a distinct fresh child even when evidence and output share a parent.
Post-intake failures retain a failure record and identify the evidence location;
partial output must be preserved and retries use fresh locations. Destination
creation, closed inventory and overwrite/reparse protections reuse the existing
[bundle contract](SANDBOX-BUNDLES.md), rather than a new file-copy implementation.

## Remaining acceptance

The desktop now has installer selection, Analyze, the closed isolation preset and
workflow choices, and Create package. Output defaults to the existing Workbench
evidence parent; both outputs use distinct fresh children, and a different output
folder is optional. A changed installer clears analysis and disables creation.
Native analysis/assembly share the controller operation lock with trial execution;
window closure cannot abandon stage publication. Package result and independently
retainable manifest hash are shown separately from compatibility results. Complete
analysis and package records are optional advanced details.

Prepare package validation imports the closed bundle using its displayed manifest
hash into fresh protected intake. Both verified and imported recipes must equal
the installed fixed profile before preparation can proceed. The ordinary review,
exact approval and separate Start still apply. Interactive packages have their
own text-input picker. Auxiliary analysis/creation preserves any completed trial
and its verified export authority; failed creation clears the prior package card.

The service contract tests use inert source/agent fixtures, not actual application
execution. They cover both recipe bindings, input/project drift, unsupported
runtime selection, network-grant rejection and failed publication. They cannot
establish real Notepad++ compatibility.

- Validate the new desktop Analyze -> selection -> Create package flow using the
  actual installer on the dedicated VM. Unit controls are not native acceptance.
- Validate package import and replay through the desktop using the displayed
  manifest identity and retained bundle-import stage; assembly is not a
  compatibility pass.
- Build and stage a new development package on the dedicated VM. Use the actual
  supported Notepad++ MSI, retain identities and negative controls, create the
  bundle through the new flow, and complete fresh package-bound worker validation.
- Obtain exact-code independent review and required hosted CI at integration,
  then commit/push/merge and verify the merged tree. Keep signed public-alpha
  acceptance separate; this development component has not been publicly released.
