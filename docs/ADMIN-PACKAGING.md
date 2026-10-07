# Administrator packaging component

Goal: select a Notepad++ installer, analyze its identity and available supported
recipes, select the isolation/workflow option, assemble a reusable package, then
validate that package in a disposable worker. Analysis, assembly, approval and
execution remain distinct actions.

## Administrator path

This flow is in the current source; signed alpha `desktop-alpha-6c7873c4e80c`
predates it. Use a verified desktop build containing the packaging component.

1. Under **Build a Notepad++ Sandbox package**, choose the supported Notepad++
   8.9.8 x64 MSI and press **Analyze installer**.
2. Choose **Windows Sandbox · offline and ephemeral** and either **Fixed assessment
   with local settings** or **Interactive document · input selected at launch**.
3. Press **Create package**. Keep the displayed package folder and manifest hash;
   creating a package does not install or execute the application.
4. Enter your **Operator identity** below. For an interactive package, use its
   **Text input for this validation** picker. Press **Prepare package validation**.
5. Review execution, access and data lifetime; full records are under technical
   details. Approve the exact displayed literal, then press **Start** separately.
6. The fixed assessment completes automatically. For interactive validation,
   edit the document in Notepad++, save and close the editor. Read the verified
   function and cleanup result, then export needed output explicitly to a new file.

Only the installed fixed recipes and supported installer bytes are accepted.
This produces a reusable Sandbox bundle, not an MSIX or AppContainer package.
The compatibility result belongs to the verified workflow; assembly and signing
do not establish broader isolation.

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

## Acceptance and integration

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
that display issue. The rebuilt desktop, SHA-256
`097925729a320134079e90a509b27a23b692c17a03662b6695740f6cfc6f218d`,
created a readable result card and fresh `bundle-package-1791358586319474200`.
Its manifest SHA-256 is
`a6de6c053562fa16554b820581ab676cbc7e2d93e402e995ada8b84dd7e888fd`.

That package was imported through the desktop into fresh protected intake for
run `admin-1791358675396046500`. After full recipe review, exact plan approval
`b9020827e028bc609bcf50e6497d8765a7c6609f6556c84b64795eeb07bbac09`
and separate Start, the disposable Sandbox completed the fixed workflow.
The native result displayed installation, visible launch, document opening,
editing/saving, graceful close and recorded cleanup as passed. The retained
report identifies the original MSI and installed recipe revision
`16ccfae035f215296b3a8f1bb76fa34a4bbad19658e3290846d2a1ff5807d2ea`.
Its SHA-256 is `b4e112dea4aef38a773e40531a3b3f482e033cae425c4870dd45e7013713678e`;
the completion receipt SHA-256 is
`917af8e3bba9a437342944d89b49522feda5eb38912a11d3af7256db30033f87`.
Broader isolation remains `insufficientEvidence`; this is a fixed workflow result.

Host evidence adds `package-layout-build-identity.json`,
`package-layout-vm-setup.json`, `package-layout-preparation-read.json`,
`package-replay-recipe.json` and `package-trial-result-compact.json`. The corrected
provider query ran from the installed provider directory and returned an empty
session list; the initial query's working-directory failure is retained.
Full recipe transport used two hash-checked pages after the bounded initial
attempt refused oversized output. The original MSI hash remained unchanged.

The existing package report command independently reverified the bundle, import
record and terminal run under the operator account. Manifest identity matched;
the replay intake receipt SHA-256 is
`14f9e49a6652c8cfe23d1cb400d5401b0b48244b2ed9013f85b0abb8aaa9ab1a`.
The resulting bundle-bound report SHA-256 is
`03f20baf09f868a16e0844c519590d87d4818e28cb32b4024d9477d4eb354fc9`.
VM evidence: `C:\AIW-Package-Reverify-1791358675396046500`;
host transport: `package-operator-reverify-read.json`. The preceding SYSTEM
attempt was rejected by the workspace owner/ACL check and is retained.

The same native desktop also assembled interactive package
`bundle-package-1791359797373095100`, manifest SHA-256
`d3172837706da6ee8f2224a05978d0be636326509c5223a62596be7990ae2dc6`.
The retained result binds the interactive recipe, ephemeral scratch contract,
original installer hash and size. Host record:
`package-interactive-assembly-read.json`. No interactive worker was started.
Creating it preserved the completed fixed assessment. That exercise exposed
an unwanted scroll back to the old assessment; `b61e0a7` keeps the new package
result visible, with UI tests covering both recipe selections.

The rebuilt `b61e0a7` desktop (SHA-256
`669ed9710429216f492468f0ecff709be4fa6162a36c0eb99ecbf62d4eb03641`)
passed that native regression check: the new package result remained visible
while the completed assessment remained retained. It created fixed bundle
`bundle-package-1791360440476210900`, manifest
`e53629fb35ede4e43cbfd1c0557a6b16381eaa1238d5d4e8b1c4fb95ddbc2da4`.
Host records: `package-scroll-build-identity.json`,
`package-scroll-vm-setup.json` and `package-scroll-assembly-read.json`.

### Interactive package acceptance (2026-10-07)

That desktop created `bundle-package-1791360541664326800`, manifest SHA-256
`4799a686906b1073cc6ebfaeb382b44a09f88f65fca1266a35bd78bcee96f1a4`.
Its own input picker selected the unchanged 180-byte document, SHA-256
`3e266d6a75e56727e3ab1703230fc0a6566e6410c57aa13f871fcc0bfb4aaa4c`.
The package was imported into fresh protected intake for
`admin-1791360654757886700`. The full hash-checked recipe was reviewed before
exact approval of plan
`b00535d73001a31b766cab24c26794bd894b713b94d753ecdbe49aaa6b5129c3`,
then the separate Start action launched Sandbox. Installed recipe revision:
`73845e0301522a8471b3bcf854e96fe9814bca9b5d81e925e0ad281cac3a2742`.

Authorized computer use observed Notepad++ open the standard-user document,
typed `AIW package replay edited by Codex.` followed by CRLF, saved, and closed
the application. This was automated native acceptance, not a new human trial.
The verified session retained 217 bytes, SHA-256
`b95b0dae76a7ea5776cf9f52dafbdd020fae58ae0fd2fcbd5fa9e1f821fe4cb8`.
The report SHA-256 is
`eae8ac93d509fcadaf1fdf5a2f393c44b58642d3ec1bcf2c9f4d38b8d6759a73`;
completion receipt SHA-256:
`8ca31a0aeb274b7e9ad12c164e37dd66475b65e17e8ee25d0241088ef992acee`.
The process ran at medium integrity without elevation or AppContainer; recorded
cleanup verified and the provider session list was empty. These observations
do not establish broader isolation.

Explicit GUI export created fresh
`C:\AIW-Package-Interactive-1791360654757886700.txt`. Read-only verification
matched its size, hash and exact content to the retained output and intended
native edit; source input and installer hashes remained unchanged. A second
export to the same path was refused, preserving the verified result and bytes.
The existing package report command independently reverified bundle/import/run
association under the operator account. Its report SHA-256 is
`fee230082588346092dfe011ec2d271fc86ecb85d14d97ab7f1b73811e7678af`;
replay import receipt SHA-256:
`2151fb9ae570bbf78a0adfc0b8a227e7b1480a720cddc199f37d8757ec0a3891`.
VM proof: `C:\AIW-Package-Reverify-1791360654757886700`. Host records include
`package-interactive-replay-recipe.json`, `package-interactive-result-read.json`,
`package-interactive-reverify-setup.json` and `package-interactive-final-read.json`.

### Integration checks

The local workspace suite and full warnings-as-errors Clippy passed in diagnostic
run `aiw-local-checks-b6831e1e-218d-40f0-a568-aa9ba67d8f5b`. Earlier local
test-storage AccessDenied failures remain retained; no publication or ACL checks
were weakened. All three hosted checks passed at `46cdab5` in CI `37591119932`,
including the normal parallel workspace suite. All three final checks passed at
`a7714f1` in CI `37594030722`. PR #90 merged at
`08dcc310aa30ea9c0bc4b68deb46ac09337ea012`; main's tree matches the tested
PR tree `421227ad1ea6472e8570a03a6d2c399d6fb6e26e`.

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

- Both fixed recipes have native assembly and fresh package replay acceptance;
  interactive replay also has explicit export and overwrite-refusal acceptance.
- Obtain exact-code independent review and required hosted CI at integration,
  then commit/push/merge and verify the merged tree. Keep signed public-alpha
  acceptance separate; this development component has not been publicly released.
