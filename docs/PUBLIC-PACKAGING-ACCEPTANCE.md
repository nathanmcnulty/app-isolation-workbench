# Signed packaging alpha acceptance

Public prerelease [desktop-alpha-08dcc310aa30](https://github.com/nathanmcnulty/app-isolation-workbench/releases/tag/desktop-alpha-08dcc310aa30)
was built, signed, assembled, attested and published by release run `37595331022`
from exact main source `08dcc310aa30ea9c0bc4b68deb46ac09337ea012`.
PR #90's final three checks passed at `a7714f1` in CI `37594030722`;
the merged tree is identical. Main CI `37595301328` also passed.
Later acceptance documentation is not this release's build source.

## Public distribution

Fresh host downloads verified all five asset sizes, SHA-256 identities and GitHub
attestations against the canonical repository, exact main ref/digest, release
workflow and GitHub-hosted runner. The two handoff scripts had valid timestamped
Nathan McNulty signatures before execution. Archive extraction verified the closed
inventory and receipt; the six fixed signed package paths passed Authenticode.
No application installer or candidate executable ran on the host.

| Asset | SHA-256 |
|---|---|
| `aiw-desktop.zip` (12,449,027 bytes) | `f1015e3bea862c2f0a9e8aa60476e2b41248afe494fea09e2b1a51f23b0dcb28` |
| `desktop-package-archive.ps1` | `1c39d2220fdf867ce72e135d653ea5cde4468d29f627f1f6c43d717fb7cf41d2` |
| `distribution.json` | `e318a87af3aa2bba986248076e7f540f239a28c8ecfda80559a0b37c43d7bb54` |
| `START-HERE.md` | `48554354205148acc504461cbae105d98cc6ce058374cbd0a740d12a687a4dfe` |
| `verify-desktop-package.ps1` | `297b6be110f0b56bf7f3749b2741db3b9808a70cdfc56b87d3ce330c7997b288` |

Receipt core: `2974700af7c9efbd92ceec80834178ff6117135ec8002c385f39f4f65ff1761a`.
Desktop: `32b575c25699cc02910e92a66a5ecae358dc6078d0f1204b621ecc5e66025285`.
CLI: `f82048a594469b1564e5803a69fdb3aef871a6da8adafb268f8b1d6b3e257009`.
Guest: `be87259ffded7ebf6526ed4fbbe14cb76e5cc88a7449ec28896ceaf9d6f6a1d0`.
Provenance and signing establish origin, not application compatibility.

The dedicated VM independently downloaded the public assets into
`C:\AIW-Public-Handoff-08dcc31` and extracted `C:\AIW-Desktop-Alpha-08dcc31`.
Durable distribution proof is `C:\AIW-Public-Distribution-Proof-08dcc31`.
The fixed launch driver recorded an empty provider list, native CLI control,
operator session, exact binary identity and GUI process handle under
`C:\AIW-Public-GUI-Proof-08dcc31`. Computer use observed the actual downloaded
desktop running as `aiwcleanhost\aiwoperator` in the RDP session.

## Package assembly and fixed replay

Native installer analysis used Notepad++ 8.9.8 x64 MSI, SHA-256
`c29cbe1a9aaef322cc3f316ceeabe8a8071b18441a5e3c3ec348069739e59e80`.
Both supported recipes were assembled through the GUI. New package results
remained visible and preserved the earlier completed assessment.

Fixed bundle `bundle-package-1791363618451200500` has manifest
`32bab2748faeda3317f3b2408ea877d0bb107fe83cb7c6136813f0af4f0033fb`.
Run `admin-1791363728884366700` imported that bundle into fresh protected intake.
The complete hash-checked recipe was read before approving plan
`c2c1a8ad1d466183161ac09ffcad6c8d68165d6890283fb756d17bf8dd0801d1`.
Approval did not start Sandbox; Start remained a separate native action.
The fixed driver verified install, visible launch, document open, edit/save and
graceful close. The actual Sandbox window was observed; the brief automatic
Notepad++ window was not captured independently. Cleanup verified and a subsequent
provider list was empty. Document export was correctly disabled for this mode.

Report file SHA-256:
`b4c23394107741f7e3e00df7360030f3a0e4aa358b8af8ac5c4ea92a9f165097`.
Receipt: `577893c6666c30ca628a2536bcdd354c40a387115578f02e6eab07395a0a66e5`.
The operator-context CLI independently reverified bundle/import/run association;
its report is `1171d4d315a657d7ec4baa19e63e3a6297195e5b11f97493fc06211c429bf019`,
replay import receipt `2e6c081d1c17c75e042ab5e737628e2e88a4b5e7e1f65582d0cbe415711ebd62`.
VM proof: `C:\AIW-Package-Reverify-1791363728884366700`.
Broader isolation remains `insufficientEvidence`.

## Interactive replay and explicit export

Interactive bundle `bundle-package-1791364470924715200` has manifest
`ba1a836251795299bf4c6e896f026b90e1d48d315b9298cf56fa79a9f4f16bd1`.
Its own text picker selected the 180-byte fixture, SHA-256
`3e266d6a75e56727e3ab1703230fc0a6566e6410c57aa13f871fcc0bfb4aaa4c`.
Run `admin-1791364558757379700` used fresh protected intake and full recipe
review before exact approval of plan
`4d52ec435bf1309202f2709546a054446622cad798cc0c77cb372b6511398254`
and separate Start. Recipe file hash:
`f0b013872b09aa4c99f8c4d7657fb3079fccb0d91c5e612ed3f5e6158c39720e`.

Computer use observed the actual standard-user Notepad++ document, appended
`AIW signed package replay edited by Codex.` plus CRLF with ordinary keys,
saved it and closed only the editor. This is automated native acceptance, not
an independent human trial. The guest token was non-elevated, medium integrity
and not AppContainer. The backend verified 224 retained bytes and cleanup.
Provider sessions were subsequently empty. Broader isolation remains unmeasured.

Explicit GUI export created fresh
`C:\AIW-Public-Package-Interactive-1791364558757379700.txt`.
A second export to the same destination was refused while preserving the result.
Independent reads confirmed exact intended text, unchanged source and identical
retained/exported SHA-256
`e37bf22cac9d3cfc8696aa33ed196dab221f47b6c6846bbdc4102edc80c8376f`.
Report file: `8e0ab3ccbdec10315c30ab0eec2e94aba2402233950007f3ee6f6a13407d3c5c`.
Receipt: `50aca95bb5d633f1b118e046e977a6f28df72d1966931a57d719facca6a59db5`.
The operator CLI independently reverified package/run association, report
`908ecb244f4e367331d0f7089188a6501320d5ba9d0c8b4bcfa0475f68806e0c`,
import receipt `03ba29a18df605e92eb302ea8a6954a46de8064324ec713c4664dd27b8cb315c`.
VM proof: `C:\AIW-Package-Reverify-1791364558757379700`.

## Existing Bambu export workflow

Fresh public GUI run `admin-1791365433522265300` reviewed the full hash-checked
recipe, approved exact plan
`be7095b96411c1e9b6c140a8c55c1bc594ee347bd3267f58981e860fe946c145`
and started separately. Recipe file hash:
`73d6026343ccb38bc802c7d1a703a78e2e93ed284b909f549f1353b5070bd3a1`.
The supported Bambu Studio 02.08.02.60 EXE retained SHA-256
`cd2f8f2c789a22efee1300e993827cfdb047f27cfb0b8f5dd7395fbafadef4c7`.
Installation, fixed STL preparation, 3MF export, collection and bounded geometry
verification passed. Install and export exited zero. The application token was
non-elevated, medium integrity, with the fixed standard-user context.
The Sandbox and completed GUI result were observed; this command-line workflow
does not demonstrate Bambu graphical editing. Document export was disabled.

The retained 3MF is 9,063 bytes, SHA-256
`dfb08aa805d60a2e54936396cd7cb251ce72e6715babad5d0d66cc504779d3e6`.
Independent read-only size/hash agrees with both the report and guest scenario;
the report's bounded structural check records four vertices and four triangles.
Report file: `aea4c431481f4f40a62e56c70b20a809ce94fd545d662b5338243703500fbb20`.
Receipt: `6ad6b338d3ac43353c32ad385d97fde52c5edc8d7f4656f6fb8df7d831948860`.
Both the report and terminal result record cleanup. Broader isolation remains
`insufficientEvidence`; slicing, printing, cloud and general EXE compatibility
are not established. Host record: `bambu-terminal-proof.json`.
After all three trials, a separate provider query at `2026-10-07T09:45:42Z`
exited zero with empty stderr and `WindowsSandboxEnvironments: []`.
The original Bambu installer hash remained unchanged. Host record:
`post-trial-provider-read.json`. This current-session observation is separate
from each receipt-bound cleanup result.

## Evidence and limitations

Run records remain under
`C:\Users\aiwoperator\AppData\Local\AppIsolationWorkbench\Evidence\<run-id>`;
each protected workspace is its same-named child. Host proof is at the fresh
root recorded by `%TEMP%\aiw-package-public-proof-root.txt`.
Original public-alpha evidence remains separately recorded in
[the earlier acceptance record](PUBLIC-ALPHA-ACCEPTANCE.md).

Read-only recipe transport failures are preserved: a mistyped run ID, a diagnostic
script replacement that expanded a PowerShell variable, and a Bambu collector
using the MSI recipe shape. Corrected reads used typed manifest or displayed plan
binding, page identity checks and reconstructed recipe hashes before approval.
These failures did not start workers. RDP clipboard text
injection did not reliably reach inputs; ordinary native keys completed the same
documented UI actions without enabling guest clipboard redirection.
An active Bambu diagnostic log refused a read because the running provider held
it open; it was not interpreted as completion or an empty session list. An extra
terminal transport page was safely refused because the complete Bambu record fit
in one page; the first page's compressed hash and raw size verified before use.

These checks establish the two supported Notepad++ reusable Sandbox recipes on
this dedicated VM and exact signed build. They do not establish arbitrary MSI/EXE
conversion, effective host isolation, MSIX/AppContainer authoring, another installer
version or broad deployment compatibility. Assembly, provenance, function results
and isolation measurements remain separate claims.
