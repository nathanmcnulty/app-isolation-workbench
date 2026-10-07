# Signed second-application packaging acceptance

Public prerelease [desktop-alpha-4e39c787e63a](https://github.com/nathanmcnulty/app-isolation-workbench/releases/tag/desktop-alpha-4e39c787e63a)
was built, signed, assembled, attested and published by release run `37695560530`
from exact main source `4e39c787e63a43cbeb07976117288d059be9818e`.
PR #93 passed independent final review and all three hosted checks at `0815cbb`
in CI `37693018289`. The merged tree is identical; main CI `37694385449` passed
all three checks. Later acceptance documentation is not the release's build source.

Downloaded-byte acceptance passed for Bambu and both Notepad++ recipes, including
independent package/run reporting and explicit document export. This candidate is
the tested alpha download; it is not a stable release or a broader isolation claim.

## Public distribution

Fresh host downloads verified all five asset sizes and SHA-256 identities against
the published release. GitHub attestations verified the canonical repository,
exact main ref/digest, release workflow and GitHub-hosted runners. The two handoff
scripts had valid timestamped Nathan McNulty signatures before execution. Archive
extraction verified the closed inventory and receipt, and all six fixed signed
package paths passed Authenticode. No candidate executable or application installer
ran on the host.

| Asset | SHA-256 |
|---|---|
| `aiw-desktop.zip` (12,509,156 bytes) | `702f456af20f4b72f6815089105cbbaefdeecd818ffed075a171742e95721f03` |
| `desktop-package-archive.ps1` | `08f097e2ce930a3ea1e6eaf91aee4e030059f2fb095c2e3cbeb87006e75678a8` |
| `distribution.json` | `e7bbc1a1acf5b0f12e8c801a704c5e6b20ec8ae4f09f4a72d382a2adc18ffdcf` |
| `START-HERE.md` | `f9c0c2dada7fe2cfe1e5f0fd2e4266c92886bdfad64799cc143bc6c707749f2e` |
| `verify-desktop-package.ps1` | `d5fb34b439bc19d43a0a3dccf49b0b15ee6554d6ca60b7eba448df244d749a2c` |

Receipt core: `dfb7b56d70fde8a64d83faee9e3c5e91fc769c49315fe2006d505fe7650fe8ff`.
Desktop: `3f0296c7c920126696bd1f4f0ef42f55041c2681308281c15ae118f325000d00`.
CLI: `a7233418be3e62563c2ebb443c1616f009a0128371c259cc9eb41dd69c09e8ef`.
Guest: `be99c59549d83825b320059ff83a23e3fc27a302799d03a2a6afe185d1bdec8f`.
Origin verification remains separate from application functions and isolation.

The dedicated VM independently downloaded the five public assets and verified
their identities, handoff signatures, closed inventory and receipt. Its fixed
launch driver recorded an empty provider list, a successful captured CLI control,
and the exact desktop process path/hash in RDP session 2 before trial preparation.
Computer use observed the downloaded GUI. VM distribution proof remains under
`C:\Users\aiwoperator\AppData\Local\Temp\AIW-Bambu-Public-4e39c78-1c050deb-r2`.
Host evidence is pointed to by `%TEMP%\aiw-bambu-public-proof-root.txt`.

The actual host operator token is administrator despite the scheduled task's
requested `Limited` run level. The first staging script incorrectly assumed that
request implied a non-admin token and stopped before downloading or launching
anything. Its failure is preserved separately. The fresh retry records the actual
identity/token and verifies the authorized interactive session; it changed no
account membership or Windows security setting. Guest application execution is a
separate standard-user requirement, verified from the trial's retained evidence.

## Fresh Bambu package review

Native supported-installer analysis and package assembly passed for the fixed
429,037,864-byte Bambu Studio EXE, SHA-256
`cd2f8f2c789a22efee1300e993827cfdb047f27cfb0b8f5dd7395fbafadef4c7`.
Package `bundle-package-1791413014481967900` has manifest SHA-256
`d9fbdf4fec09f43ae39a8163c75a8d0a59882b8538a465904e99c02eae7aa99c`.
Assembly did not install the application or start Sandbox.

Fresh package-bound preparation created `admin-1791413194354644600`.
The complete retained recipe, import and package records were read before exact
approval of plan `f80938c6749d520cfbc2f6197bf04e3fef8328b1d1c9011c2de3ff2c5b1c5fd8`.
Independent assertions compare the full fresh intake receipt and compiled scenario,
manifest, project revision, workspace binding, and installed signed guest identity.
The approval action did not start Sandbox; the separate Start action did. Computer
use observed the actual Sandbox window. All five checks passed: install, prepare
the fixed STL, export 3MF, collect 3MF, and verify the fixed four-vertex/four-triangle
geometry. Independent hashing of the retained 9,064-byte artifact matched both
the scenario and report:
`bb46f80e83867633012d862b3828666be5d1fcd8c1cc058abdd2787c138f0f89`.
The application token was medium integrity and non-elevated; the recorded
standard-user context had administrators disabled. Report evidence and recorded
cleanup verified, the terminal result recorded cleanup complete, and the provider
reported an empty session list. Broad isolation remains `insufficientEvidence`.

The initial collector copied an incorrect bundle path from the screen. Its error
is retained; the corrected read-only collector derives the bundle and replay from
unique typed records created after the verified GUI process started. Bounded
readback preserves the complete 22,152-byte review without rerunning assembly or
application execution. The guest metadata's signature status remains `unknown`;
independent distribution signature verification is separate and does not rewrite
that observation.

## Fresh Notepad++ regressions

Both recipes used the 7,806,976-byte Notepad++ 8.9.8 x64 MSI, SHA-256
`c29cbe1a9aaef322cc3f316ceeabe8a8071b18441a5e3c3ec348069739e59e80`,
and the downloaded guest identity listed above. Native analysis and separate
package assemblies passed. Each complete retained recipe, fresh import receipt,
manifest, project revision and canonical plan was independently checked before
literal approval as `AIW automated validation` and a separate Start action.

| Recipe | Bundle manifest SHA-256 | Run | Approved plan SHA-256 |
|---|---|---|---|
| Fixed local settings | `26a92eb433018425b24863cc3841c4a1badfa3101f5e7a00bc4ef54e83c14734` | `admin-1791414783770782800` | `93be380f3428a4554b4a50704804fdb174123b9f1cd2ea56f5c84751dd722cc0` |
| Interactive document | `c7c39aacedee82a12481444ba00436dac60e4223f5c066d4e9a054e0bcc0bed8` | `admin-1791415311231448600` | `524d0e45b9dbf273e0f0a545a0bbbc10a5984c7dcb4cc5e51a23411d77becb4d` |

The fixed trial passed all GUI checks and all nine retained stages. Its expected
and observed saved-document hash matched
`55666bc7399b14c1cdb77f1e0261e3b6f09e49aec11cda7de1685d73b8a7c9fc`.
The application token was medium integrity and non-elevated, administrators were
disabled, and the protected ACL negative control verified access denied (error 5).
The signed CLI independently reverified the exact bundle/import/run association
in the RDP operator context (PID 4752, exit zero, empty standard error). Its report
SHA-256 is `00f4c28e6f456e9eb886aa86b5ddd97586c84356c10e2b3a501e119c3084ae7c`.
The VM control record, current CLI identity and unchanged report digest were
copied into host evidence as `signed-msi-fixed-control-readback.json`.
The administrator MSI flow publishes `report.json`; the separate read-only CLI
check produced `report-bundle.json`. A collector initially expected that second
filename too soon. Collection was corrected without repeating application execution.

For interactive preparation, the reusable scratch recipe is intentionally
recompiled into the fixed document-transfer recipe using the selected input.
Verification checked the raw bundle digest, prepared scenario digest, full receipt
and the closed compiler transformation, including its installation log and deadline;
it did not discard differing fields to force equality.
Computer use observed Notepad++ open with the approved 180-byte input, appended
`AIW validation` and a CRLF, saved it, confirmed the saved editor state, and closed
Notepad++. The original instruction text mentioning Nathan remained input text;
this fresh edit was performed by automated validation, not Nathan.
Clipboard paste was disabled as requested, so physical key events entered the edit.
The verified 196-byte retained output and explicit GUI export matched exact text
and SHA-256 `fd3715b740ad7837ab7c91e79e42ebc5131c65b086a38ab5832495e339117e90`.
A second export to the same path was refused. No existing file was overwritten.
The interactive report binds input/output sizes and hashes, successful process
closure, the approved plan and guest identity, standard-user context and cleanup.
Both MSI terminal results record cleanup complete and an empty provider list.
Broad isolation remains `insufficientEvidence` for all three application trials.

The signed CLI independently reverified the interactive bundle/import/run
association as the RDP operator (PID 12208, exit zero, empty standard error).
Its bound report SHA-256 is
`a7d462d09a520f59121ae308cd8f4973e5d5abec47fa8d4edf08289a67bd3933`.
Final independent readback compared the original input, retained output and export
bytes after the overwrite refusal. Output and export equal the original input
plus the exact 16-byte edit, with the report's hash and size. The provider remained
empty. The initial reporting helper used `Start-Process` and observed a null exit
code despite captured output; its files remain preserved. A fresh read-only helper
used a held process handle, asynchronous output capture and a bounded deadline.
It did not repeat installation or application execution.

Both owned staging task registrations were removed after their exact wrapper
actions and terminal results were verified (initial failure 1, fresh retry 0).
Fresh readback verified the registrations absent and retained all evidence.
No VM power action or unrelated task/session cleanup was performed.

Full host evidence includes `signed-msi-fixed-terminal-complete.json`,
`signed-msi-interactive-terminal-complete.json` and their complete pre-approval
review records. Canonical plan, receipt and scenario checks are retained in
`verify-signed-canonical-bindings.py`, `assert-signed-interactive-terminal.py` and
`assert-signed-interactive-final.py`; full final readback is
`signed-msi-interactive-final-complete.json`.
Failed collectors and reporting helpers remain preserved separately.
