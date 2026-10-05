# Signed public alpha acceptance

Public alpha `desktop-alpha-6c7873c4e80c` was built, signed, assembled, attested,
and published by successful GitHub run `37254512259` from exact main source
`6c7873c4e80c889394ec43b27138cc52fc7df1c2`. It remains a prerelease:
[download the release](https://github.com/nathanmcnulty/app-isolation-workbench/releases/tag/desktop-alpha-6c7873c4e80c).
Later documentation commits are not its build source.

## Public distribution proof

Anonymous release readback confirmed the exact source, published prerelease
state, and five assets. Independent downloads passed GitHub attestation verification
for each file: canonical repository, exact main digest/ref, pinned workflow identity,
GitHub-hosted runner, public visibility, and invocation `37254512259/attempts/1`.
Each verified statement names exactly the same five assets and their observed
digests. This provenance proves artifact origin, not runtime compatibility.

| Asset | SHA-256 |
|---|---|
| `aiw-desktop.zip` (12,285,056 bytes) | `b5a34980920720866539a1691b6da0e0d2213b32484a0da6ab18e738a1cffee7` |
| `desktop-package-archive.ps1` | `73455a41e08d4695478b71f094caf58ce2c0ed75b052aacee842926a9b2978b1` |
| `distribution.json` | `3aabca1f07f123ad882f64c1c56852e539db3a6cc4383118a599f531a1c0cd9e` |
| `START-HERE.md` | `6e2c52527fdffcbf12347b5e53091365cbca2ebbde1e3e964464c6a16e6569fe` |
| `verify-desktop-package.ps1` | `704404e58a81905f606a00cc74a84b274fb56a7607623f6194936dc77cedb7ab` |

Both handoff scripts were authenticated before execution. Native Authenticode
checks found valid, timestamped Nathan McNulty signatures on the six fixed
package paths: desktop, CLI, verifier, and three guest-agent copies. The signed
archive helper verified exact inventory and receipt on both host and dedicated
VM under native Windows PowerShell 5.1. No candidate executable ran on the host.

Receipt core SHA-256 is
`b49983a2c24149c36e9a73ab2be172168e5259ce05943a3b6c7f9f4a3a14def4`.
Desktop SHA-256 is
`307cf8d27a286ef61893eada36ca3136d62ae6d4fb5cb25b266a8d50194c1b48`;
CLI SHA-256 is
`53e43af5c997bb0a7727a8dd42719c8deb645b92d194ef1d2077f2fbaab2ae6f`;
guest SHA-256 is
`661d34283a92424c7e7f571e50d20274e2490dd39673d5b8587049248365d3f7`.
Package signature checks cover the documented fixed paths; they do not authenticate
every package file. Public asset attestations are a separate provenance control.

## Dedicated-VM interactive acceptance

The VM downloaded those public assets directly into `C:\AIW-Public-Handoff-6c7873c`
and freshly extracted `C:\AIW-Desktop-Alpha-6c7873c`. Distribution evidence is
`C:\AIW-Public-Distribution-Proof-6c7873c`. The GUI launch driver authenticated
the exact desktop bytes and ran as `aiwcleanhost\aiwoperator`, session 2; RDP
computer use observed the actual interface. Launch/control records are under
`C:\AIW-Public-GUI-Proof-6c7873c`.

Interactive run `admin-1791167847046734900` used the supported Notepad++ 8.9.8
x64 MSI, SHA-256
`c29cbe1a9aaef322cc3f316ceeabe8a8071b18441a5e3c3ec348069739e59e80`.
Its 180-byte input hash is
`3e266d6a75e56727e3ab1703230fc0a6566e6410c57aa13f871fcc0bfb4aaa4c`.
The complete retained recipe was reviewed before approval. A deliberately wrong
confirmation was refused without consuming the review or starting Sandbox;
the exact plan confirmation succeeded, then Start required a separate action.

The actual guest editor opened the correct document. Codex appended `aiw` with
ordinary keys, saved, and closed only Notepad++. Literal text injection did not
reach the nested guest; clipboard-disabled settings were preserved. This is an
automated RDP control, not an independent human trial. The backend verified the
183-byte output and recorded cleanup. The application token was non-elevated,
medium integrity, and the guest runtime context was the fixed standard user.
Broader isolation correctly remained `insufficientEvidence`.

Explicit GUI export created `C:\AIW-Public-Interactive-6c7873c.txt`.
A second export to that existing destination was refused. Read-only byte checks
confirmed the unchanged original, the exact observed three-byte edit, and identical
retained/exported output SHA-256
`18956010f0d7494f5cc9c8f1a04c36b17e07175a003f32e863ede7dd1e5e2cbb`.
Report receipt SHA-256 is
`2dbb2fe07a77abdbb0afff2493263984c3ba155495a4def5b57794f14d45a871`.

Evidence root is
`C:\Users\aiwoperator\AppData\Local\AppIsolationWorkbench\Evidence\admin-1791167847046734900`;
its nested workspace has the same run ID. Full host proof is at the fresh root
recorded in `%TEMP%\aiw-public-alpha-proof-root.txt`, including
`interactive-review.json` and `interactive-terminal-proof.json`.
A SYSTEM-context provider-list diagnostic failed to locate
`WindowsSandboxServer.exe`; its failure is preserved and is not an empty-session
observation. Recorded cleanup and live application results remain separate from
that management-context limitation.

## Fixed Notepad++ assessment

Fresh public GUI run `admin-1791169556266470800` reviewed the complete local-settings
recipe, recorded exact approval, and started separately. Installation, visible
launch, fixed document open, expected edit/save bytes and graceful close all passed.
Document export was disabled for this assessment mode. Typed terminal records
confirm succeeded installation/launch/close, standard-user medium-integrity token,
required guest ACL positive control and protected-read denial (Win32 error 5),
recorded cleanup, and unchanged installer identity. Broader isolation remains
`insufficientEvidence`; the retained missing-evidence list is not suppressed.

Report receipt SHA-256 is
`63a8cd2787edb247fea3c2b606d841666da31f6fff7775e85c4d8063af89fdfe`;
full retained report file SHA-256 is
`7c105c89bb6c95be417d38a0500575c066d5edcdee6d4325a18e741093e04067`.
Evidence root is the same operator evidence parent with this run ID; full source
records remain on the VM. Host `assessment-review.json` and
`assessment-terminal-proof.json` retain the exact reviewed plan and selected
terminal fields with the full report's hash.

## Fixed Bambu export

Fresh public GUI run `admin-1791170118731201300` reviewed the complete retained
recipe, recorded exact approval, and required separate Start. The supplied Bambu
Studio 02.08.02.60 EXE retained SHA-256
`cd2f8f2c789a22efee1300e993827cfdb047f27cfb0b8f5dd7395fbafadef4c7`.
Silent installation, fixed STL preparation, 3MF export, collection and geometry
verification all passed. Installation and export exited zero; the export process
ran as the fixed standard user at medium integrity without elevation. Document
export remained disabled for this mode; no Bambu output was automatically exported.

The retained 3MF has 9,063 bytes and SHA-256
`01117ca03c98a610973653e8148db52b8a4f3545b01cda0e643754445e01eaa0`.
Its bounded structural check verified four vertices and four triangles for the
fixed tetrahedron. Independent read-only hashing agrees with the report and
guest result. Report receipt SHA-256 is
`d799bdb85dfef9c7b964d5080884171b4534fab0b369c7d58180a2019e9d2d95`;
full report file SHA-256 is
`e917b578162231ff9c3f95be29304c5908609725f58011eb168049e917687d38`.
Typed records confirm cleanup and preserve the broader `insufficientEvidence`
outcome. Slicing, printing, cloud and graphical workflows were not tested.
Full evidence remains under the operator evidence parent with this run ID.
Host `bambu-review.json` and `bambu-terminal-proof.json` retain reviewed and
terminal identities. No installation was repeated to obtain these records.

## Scope after acceptance

After all three trials, a fixed read-only `wsb.exe list --raw` control ran as
`aiwcleanhost\aiwoperator` in session 2. At `2026-10-05T03:34:42Z`, it exited zero
with empty stderr, no truncation and `WindowsSandboxEnvironments: []`.
The operator task completed successfully. Its provider SHA-256 was
`247e092b5c5bd37820f225a7dd3ddf10ae37a67e2751a19c24b802c84769c441`
(Windows Sandbox 0.8.107.0). This is a separate current-session observation;
it does not replace the per-run receipt-bound cleanup records. The earlier
SYSTEM-context query failure remains preserved. VM record is
`C:\AIW-Public-GUI-Proof-6c7873c\07-post-trial-provider.json`; host readback is
`post-trial-provider-proof.json` under the same public proof root.

All three supported GUI workflows passed on the dedicated VM using these exact
public signed bytes. The wrong-confirmation and existing-file export controls
also passed. This closes downloaded-artifact acceptance for this narrow alpha;
historical unsigned evidence remains distinct.
Stable promotion, general application packaging, and broader isolation conclusions
are separate milestones. Follow the release's `START-HERE.md` for its exact
verification/extraction/launch commands; keep this package with its retained evidence.
