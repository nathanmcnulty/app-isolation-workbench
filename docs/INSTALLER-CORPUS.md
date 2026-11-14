# Installer corpus

The current corpus follows [issue #108](https://github.com/nathanmcnulty/app-isolation-workbench/issues/108)
and [roadmap R5](ROADMAP.md#r5---prove-generality-and-retire-fixed-execution).
Applications are regression data, never an admission list or product-code roadmap.
Users acquire and pin their own inputs; no vendor payloads belong in this repository
or AIW releases. Listing a fixture is not a download, execution or compatibility result.

## Application-neutral recovery corpus

The manifests below were inspected for #108 at Microsoft's
[winget-pkgs commit 041009ec9ce158c716313f615e940e8564a3d141](https://github.com/microsoft/winget-pkgs/tree/041009ec9ce158c716313f615e940e8564a3d141)
on 2026-11-08. Versions identify that research snapshot, not the latest available
version or authorization to use a later payload. Use x64 initially and validate
actual installed architecture separately from installer-wrapper architecture.

| Fixture / exact WinGet ID | Inspected manifest | Declared first workflow and useful variation |
| --- | --- | --- |
| 7-Zip / `7zip.7zip` | [26.06, EXE and MSI](https://github.com/microsoft/winget-pkgs/blob/041009ec9ce158c716313f615e940e8564a3d141/manifests/7/7zip/7zip/26.06/7zip.7zip.installer.yaml) | Create/list/extract controlled archive, verify contents; CLI and output assertions. Existing 26.05 evidence remains separate. |
| GIMP / `GIMP.GIMP` | [3.2.6, Inno EXE](https://github.com/microsoft/winget-pkgs/blob/041009ec9ce158c716313f615e940e8564a3d141/manifests/g/GIMP/GIMP/3.2.6/GIMP.GIMP.installer.yaml) | Open synthetic image, edit, save/export, reopen; GUI, graphics, profile state, user/machine scope. |
| LibreOffice / `TheDocumentFoundation.LibreOffice` | [26.8.2.2, MSI](https://github.com/microsoft/winget-pkgs/blob/041009ec9ce158c716313f615e940e8564a3d141/manifests/t/TheDocumentFoundation/LibreOffice/26.8.2.2/TheDocumentFoundation.LibreOffice.installer.yaml) | Writer open/edit/save and PDF export; multiple entry points and declared VC runtime dependencies. |
| Firefox / `Mozilla.Firefox` | [159.0, Nullsoft EXE](https://github.com/microsoft/winget-pkgs/blob/041009ec9ce158c716313f615e940e8564a3d141/manifests/m/Mozilla/Firefox/159.0/Mozilla.Firefox.installer.yaml) | Fresh profile, project-owned local HTML/assets, navigation/close; multiprocess and first run. |
| Chrome / `Google.Chrome` | [157.0.8103.39, enterprise MSI](https://github.com/microsoft/winget-pkgs/blob/041009ec9ce158c716313f615e940e8564a3d141/manifests/g/Google/Chrome/157.0.8103.39/Google.Chrome.installer.yaml) | Repeat local-content browser workflow; another engine/process model. Installer-created components are not all tested functions. |
| VLC / `VideoLAN.VLC` | [3.0.24, EXE/MSI/portable ZIP](https://github.com/microsoft/winget-pkgs/blob/041009ec9ce158c716313f615e940e8564a3d141/manifests/v/VideoLAN/VLC/3.0.24/VideoLAN.VLC.installer.yaml) | Play/seek/close synthetic local media; include portable-directory input and observable playback checks. |
| Notepad++ / `Notepad++.Notepad++` | [8.9.9, EXE/MSI/portable ZIP](https://github.com/microsoft/winget-pkgs/blob/041009ec9ce158c716313f615e940e8564a3d141/manifests/n/Notepad%2B%2B/Notepad%2B%2B/8.9.9/Notepad%2B%2B.Notepad%2B%2B.installer.yaml) | Open/edit/save/reopen controlled text; regression transfer from the separately pinned 8.9.8 reference. |

The matrix must exercise actual MSI, reviewed EXE, portable, multiprocess and
GUI/operator-assisted capabilities. Attempt every fixture through the same path,
retain useful failed/blocked results, and do not require every isolation candidate
to succeed. A matrix made only of blockers does not prove a useful engine.
Choose an additional holdout after implementation is fixed and complete a declared
normal-use workflow without product-specific production changes or a rebuild for
identity. See [release gates](RELEASE-GATES.md#first-generic-assessment-release).

### Acquisition and test boundary

Record package ID/version, source/manifest revision, final URL, architecture,
locale, installer type/scope, payload SHA-256, signature observations, dependencies
and input-fixture hashes. WinGet supplies acquisition metadata, not execution
permission. Review resolved install behavior; do not trust a manifest command
string, silently install dependencies or enable network access. Chrome's rolling
URLs require exact hash verification; drift requires a newly reviewed record.

Keep acquisition separate from offline execution and record actual payloads from
bootstrappers. Stage portable archives safely into a validated directory; archive
availability does not mean the executor already supports it. Use project-owned
images, documents, HTML and media. No personal accounts or proprietary user data
are required for these initial workflows.

Internet browsing, account sign-in, updates, downloads, printing, extensions,
plugins, shell integration, long-running services and physical devices are separate
coverage. Do not disable browser/application sandboxes to obtain a pass. Existing
Bambu evidence is a regression asset, not another required production product path.
Earlier VS Code/device/bootstrapper interests below remain potential generic data
scenarios; they do not justify new app adapters or restore the old profile sequence.

## Historical local inventory and plans

The remainder preserves the 2026-09-07 inventory and later scoped observations.
Its profile sequencing and later future-tense instructions are historical; the
recovery corpus above and current roadmap set implementation order.

Read-only inventory on 2026-09-07 of the user-supplied `%USERPROFILE%\Downloads\installers` folder. No installer was executed, downloaded, unblocked, copied, or modified. These are candidate fixtures, not supported application profiles or successful installation results. Passive fingerprints below are not protected intake receipts.

Subsequent [Bambu feasibility trials](BAMBU-STUDIO-PROFILE.md) and [signed public acceptance](BAMBU-PUBLIC-ACCEPTANCE.md) supersede the inventory's original untested status. Approved standard-user local STL-to-3MF export, reporting, package assembly/replay and cleanup have retained acceptance evidence. The original installers were not executed on the host.

| File | MiB | Observed classification | Proposed coverage |
|---|---:|---|---|
| `Bambu_Studio_win-v02.08.02.60.exe` | 409.16 | Large EXE; bundled payload candidate, offline install unverified | Local model import/slice/save workflow first; printer/cloud integration separate |
| `ChatGPT Installer.exe` | 1.37 | Microsoft Store Installer wrapper | Store/download acquisition case; installed application not present in this file |
| `DriveManager-C3.2.0-windows-installer-x64.exe` | 24.68 | SK hynix signed EXE; offline install unverified | Install/UI/close and hardware-unavailable reporting; not a normal-user positive control |
| `npp.8.9.8.Installer.x64.exe` | 6.63 | Notepad++ EXE | First EXE-profile candidate using the existing document scenario |
| `npp.8.9.8.Installer.x64.msi` | 7.45 | Notepad++ MSI; matches existing live payload hash | Known MSI control |
| `Signal Private Messenger Installer.exe` | 0.78 | Microsoft Store Installer wrapper | Acquire direct desktop payload for an offline install/UI test; linking/messaging separate |
| `vs_BuildTools.exe` | 4.25 | Visual Studio 2022 bootstrapper | Pinned workload/layout acquisition and dependency-heavy installation later |

## Planned addition: Visual Studio Code

Requested 2026-10-11. VS Code is distinct from the Visual Studio Build Tools
bootstrapper above; no VS Code payload has been acquired or accepted by this record.
Microsoft supplies [user/system installers and ZIP archives](https://code.visualstudio.com/docs/setup/windows)
and documents [portable mode](https://code.visualstudio.com/docs/setup/portable).
Pin one x64 release and its exact payload/signature before any disposable-worker trial.

First compare an offline ZIP baseline with a user-install scenario: open a tiny
project-owned folder, edit/save a UTF-8 file, close/reopen and verify exact bytes,
settings location, process tree and cleanup. Keep portable and installed modes
separate because they place user data differently. Run as an observed standard
user; preserve Chromium sandboxing and record unsupported launch behavior.
Then add one fixed project-owned integrated-terminal command to test child
inheritance, deadlines and closure. Marketplace extensions, account sign-in,
Settings Sync, remote development and agent workflows require separate scenarios.
This candidate follows the current MSIX lifecycle and isolation-comparison gates;
it does not replace the existing comparison workflow or establish VS Code support.

## Installer distinctions

Signal and ChatGPT both expose `Store Installer` / `StoreInstaller.exe` version resources and Microsoft signer identities. Their small files are acquisition wrappers; installed app bytes and versions must be measured after acquisition. Signal's [official download page](https://signal.org/download/) offers direct Windows and Microsoft Store routes. Its [desktop installation guidance](https://support.signal.org/hc/en-us/articles/360008216551-Installing-Signal) requires linking to a phone for actual use. An install/first-window test must not imply messaging was tested, and no personal account linking or message sending is part of the initial fixture.

The DriveManager file is signed by SK hynix. Its [C3.2.0 manual](https://ssd.skhynix.com/download/driver_manager/Drive_Manager_Easy_Kit_Manual_C3.2.0_ENG.pdf) describes SSD monitoring, firmware updates, and drive erase, and requires administrator access for installation and use. Installation/window/close may be small tests, but physical-device functionality is a separate dependency. Missing hardware or denied device access in a worker must be reported explicitly. Physical host disks, firmware changes, erase, and hardware passthrough are outside this fixture's scope.

Bambu's accepted local export is a richer offline workflow. Slicing, cloud login,
printer discovery and hardware interactions remain separate unmeasured functions.

Visual Studio supports explicit workload selection and an offline layout, documented by [Microsoft](https://learn.microsoft.com/en-us/visualstudio/install/create-an-offline-installation-of-visual-studio?view=visualstudio). Pin the acquired payload/workload set rather than treating the bootstrapper hash as the final application identity. This inventory does not create that layout.

Every inspected EXE's PE wrapper header reports x86 (`0x14c`), including files named x64. That is the installer/loader architecture, not proof of installed application architecture. Payload architecture must be measured separately.

## Intake behavior exposed by this corpus

The initial native `application inspect` path accepted only `vs_BuildTools.exe`, including a cache-only embedded signature observation. It rejected the other six before signature inspection because their named streams violated the then-current unnamed-stream-only policy. All six contain `SmartScreen`; the two Notepad++ files and Signal also contain `Zone.Identifier`. Stream names do not establish that their contents are authentic or safe.

Separate passive Windows version-resource/signature observations reported valid signatures for Bambu (Shanghai Lunkuo Technology), DriveManager (SK hynix), and the Signal/ChatGPT/VS wrappers (Microsoft). Those observations do not satisfy AIW's protected intake authority or bind the eventual downloaded payload. Raw stream contents, referrer URLs, and browsing history were not exported.

### Validated metadata intake (2026-09-08)

All seven originals subsequently passed `application inspect`, explicit `application import --archive-download-metadata`, and independent `application verify-import`. The [download metadata policy](DOWNLOAD-METADATA-INTAKE.md) archives exact supported stream bytes as protected sidecars, binds them in the receipt, and creates a normalized unnamed-stream payload for later approved Sandbox execution. The six affected files produced v0alpha3 receipts; the streamless VS bootstrapper retained v0alpha2.

Before/after inspection confirmed unchanged source file identities, payload hashes, metadata names, lengths, and hashes for every original. Raw metadata bytes are retained only in local protected sidecars; reports contain hashes, not origin URLs. This establishes intake, not installer execution or application compatibility. Unknown streams remain rejected, and default import still requires unnamed-stream-only sources.

The local proof is `aiw-download-intake-20260907-235847` under the testing user's temporary directory: `summary.json`, per-file external receipts and inspections, and protected `intakes/fixture-00` through `fixture-06`. No installers were downloaded for this validation.

## Profile sequence

1. Establish the standard-user MSI baseline now that source metadata intake is implemented. Add the Notepad++ EXE path to isolate installer-profile changes while reusing the document workflow.
2. Add DriveManager install/UI/close as an elevation/device-dependency case; add Bambu's bounded local-file workflow as the richer positive candidate. Neither is assumed compatible with AppContainer.
3. Acquire and pin a direct Signal desktop payload for install/first-run coverage. Treat authenticated messaging as a separately declared scenario requiring dedicated test identities.
4. Add Store-wrapper and Visual Studio acquisition profiles after the offline worker path. Acquisition and application execution are separate stages with separate network policies and payload identities. A downloader blocked offline is not evidence that the application is incompatible.

## Observed payload fingerprints

Rehash and perform authoritative intake verification before any future approved execution. Filenames and passive version resources are descriptive only.

| File | SHA-256 of unnamed data stream |
|---|---|
| `Bambu_Studio_win-v02.08.02.60.exe` | `cd2f8f2c789a22efee1300e993827cfdb047f27cfb0b8f5dd7395fbafadef4c7` |
| `ChatGPT Installer.exe` | `7ff5d38df475749e8b311d8e465b8777638ecd9fc53686385a68d89a10a58a58` |
| `DriveManager-C3.2.0-windows-installer-x64.exe` | `c5f5c82e52612562ba5d06dff7b8d4cb7939ae5fcddcfdbd06432225ae45fb41` |
| `npp.8.9.8.Installer.x64.exe` | `7b2a949bf460fb37a3888c9048698f43222a185a48323023df1c51e78a3ca1c2` |
| `npp.8.9.8.Installer.x64.msi` | `c29cbe1a9aaef322cc3f316ceeabe8a8071b18441a5e3c3ec348069739e59e80` |
| `Signal Private Messenger Installer.exe` | `d27d55012c906a2b9c684b25e991c421e4505486defdcefc0d5e8cb184aab988` |
| `vs_BuildTools.exe` | `ce7bb977accae1748191233d05ee6832a4b61a319419627bfcdbd818de5bfd68` |
