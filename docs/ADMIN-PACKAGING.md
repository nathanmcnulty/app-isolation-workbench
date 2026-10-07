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

### Development VM checkpoint (2026-10-07)

Exact source `e881c59f328f6aab2b8c1ce70881b298dacc72a2` passed independent
review after four desktop findings were corrected. Local checks passed: 31
service tests, 7 controller tests, 10 UI tests, both warnings-as-errors Clippy
suites, formatting and governance. The Windows release/static-CRT desktop built.

Native RDP acceptance on the dedicated VM selected the real Notepad++ MSI,
analyzed its identity, selected the offline local-settings recipe and created
`bundle-package-1791358312403859600`. Its manifest SHA-256 is
`315de78af896740f66679c5d1b1574e17028d7ea765a8e33bdc6b8371385408e`.
The original MSI still hashes to
`c29cbe1a9aaef322cc3f316ceeabe8a8071b18441a5e3c3ec348069739e59e80`;
the retained selection records `executionStarted: false`. The launch control
observed an empty provider before launch and compared all nine copied product
files. Desktop SHA-256:
`db656757baf1fee5e62ae50cb40bc837bfde5970c235f76b4ceb31bcb8336d0f`.

Host evidence is under the directory named by
`%TEMP%\aiw-public-alpha-proof-root.txt`, in `package-ui-build-identity.json`,
`package-ui-vm-setup-retry2.json` and `package-ui-created-read.json`. The initial
setup failure and transport diagnostic are retained separately. VM package
evidence is under the operator Workbench Evidence folder in
`package-1791358312403859600`; launch proof is
`C:\AIW-Package-GUI-Proof-e881c59`.

Native inspection found horizontal overflow in the result card. `f6746b8` fixes
that display issue; corrected native acceptance and package-bound execution
remain pending. This checkpoint proves package assembly, not compatibility.

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
