# 7-Zip application assessment

Active implementation, selected 2026-11-05 (America/Anchorage). The declared
experiment completed its [native research trial](SEVENZIP-NATIVE-ACCEPTANCE.md).
Production integration is in progress; that trial alone does not establish a
supported desktop feature or broad isolation verdict.
Start from [working state](WORKING-STATE.md); the [candidate review](MXC-ASSESSMENT-SELECTION.md)
records the current MXC research and why classic AppContainer is selected first.

## Application and acquisition

7-Zip 26.05 x64, released 2026-10-21. Follow the project's
[download page](https://www.7-zip.org/download.html), which links to the official
[`ip7z/7zip` release](https://github.com/ip7z/7zip/releases/tag/26.05).
The selected EXE is the vendor's recommended installer form. No winget display
name or search result is acquisition authority.

| Observation | Selected bytes |
|---|---|
| Asset | `https://github.com/ip7z/7zip/releases/download/26.05/7z2605-x64.exe` |
| Size | 1,663,506 bytes |
| SHA-256 | `fd99e86f57d8f429ef5ed045bf98315af962e2309b0f1ba87a147a44c71647d0` |
| Independent comparison | Local hash matches the digest retrieved separately from GitHub's release API |
| Embedded identity | Product `7-Zip`, file version `26.05` |
| Authenticode | `NotSigned`; no publisher-signature assertion |

Acquisition records and inert installer are retained at
`C:/aiw/sevenzip-assessment-20261105`. Inspecting PE metadata or hashing does not
execute the installer. Installation and all vendor application processes are
limited to a fresh offline Windows Sandbox within VM107. Preserve VM106 and all
existing VM107 packages, retained results and unrelated files.

## Fixed workflow and measurements

First validate the process driver using a project-owned child with known output
and exit status, then a deliberately sleeping child that must hit its deadline
and leave an empty owned job. Driver failure prevents installation. Record each
completed stage durably; inspect those stages after interruption before any new
trial, rather than blindly installing again.

Install once as the elevated Sandbox account into the fixed guest-local app
directory. Hold the installed console executable and DLL while exercising the
workflow as the same verified standard user. Retain the scoped installed-file
inventory, hashes and actual process observations. This is not a complete
machine/registry installation-change collector.

Create the same fixed inputs for each mode: text, binary bytes, an empty file,
and a Unicode filename within a directory containing a space. Run the compiled
create, test and extract commands. Independently compare extracted names, lengths
and SHA-256 hashes with the expected input inventory. Exit zero alone cannot pass
content verification. Retain failures and not-reached functions. A failed baseline
prevents attributing a candidate difference to isolation.

The ordinary baseline is inside the disposable worker. It is not proof of normal
execution on every administrator endpoint. The candidate is classic AppContainer
with zero capability SIDs and explicit code/input reads and candidate-output
writes. No broad capability, host grant, policy widening or ordinary-process
fallback is permitted to obtain success. Measure held suspended target tokens
for all three console invocations and check their user, integrity, AppContainer
SID and capabilities before resuming them.

Declare a project-owned readable canary outside candidate grants: the ordinary
user must read the exact bytes; the candidate must report native access-denied
code 5. Verify the candidate profile is deleted and every owned job is empty.
The existing six-case control evidence remains separate: it cannot substitute
for missing observations on this application or its children.

## Research versus the supported product

The default-off `research-sevenzip` platform examples establish native feasibility
before adapting the production runner. The fixed host driver prepares protected
inputs and a proposal, records exact-hash approval, and requires a separate Start.
It persists a preselected-session intent before provider mutation and uses the
existing held Store provider, exclusive lease and exact-session cleanup. It never
installs 7-Zip on the parent VM or development host. Guest records are untrusted
research observations, not production receipts and not importable verified Results.

Before calling the path supported, integrate the fixed application request with
the existing production preparation/approval/session kernel, cancellation and
owned recovery. Bind app bytes, workflow revision, environments, user and allowed
candidate-policy differences. Use receipt-last publication and the existing
verified assessment/reporting services. The desktop must start that supported
workflow without internal JSON authoring, reopen explicit retained results without
execution, and export allowlisted sanitized JSON/Markdown through Results.

The native proof and production integration need independent review and focused
negative tests, including input/policy drift, partial or altered output, missing
baseline measurements, failure prefixes, cancellation and cleanup uncertainty.
Retained reads must preserve source bytes and make zero execution/provider calls.

## Coverage limits and acceptance

The initial workflow automates local console archive operations. GUI archive
manager interaction, Explorer shell extensions, encrypted or adversarial archives,
updates, uninstall, reboot, network, registry dependencies, IPC/UI controls and
every descendant's token remain outside this workflow. An administrator can
identify additional coverage needs; that feedback cannot silently change this
approved fixed trial. It requires a separately reviewed workflow extension.

Benchmark 2 requires the same approved application workflow, measured target and
required-descendant boundaries, selected denial canaries, verified cleanup and an
explainable baseline/candidate matrix. Missing evidence blocks the relevant
claims. Native research alone does not satisfy production approval/reporting or
desktop acceptance. W4/W5 and broad production acceptance remain open.
