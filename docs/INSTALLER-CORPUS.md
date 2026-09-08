# Installer corpus

Read-only inventory on 2026-09-07 of the user-supplied `%USERPROFILE%\Downloads\installers` folder. No installer was executed, downloaded, unblocked, copied, or modified. These are candidate fixtures, not supported application profiles or successful installation results. Passive fingerprints below are not protected intake receipts.

| File | MiB | Observed classification | Proposed coverage |
|---|---:|---|---|
| `Bambu_Studio_win-v02.08.02.60.exe` | 409.16 | Large EXE; bundled payload candidate, offline install unverified | Local model import/slice/save workflow first; printer/cloud integration separate |
| `ChatGPT Installer.exe` | 1.37 | Microsoft Store Installer wrapper | Store/download acquisition case; installed application not present in this file |
| `DriveManager-C3.2.0-windows-installer-x64.exe` | 24.68 | SK hynix signed EXE; offline install unverified | Install/UI/close and hardware-unavailable reporting; not a normal-user positive control |
| `npp.8.9.8.Installer.x64.exe` | 6.63 | Notepad++ EXE | First EXE-profile candidate using the existing document scenario |
| `npp.8.9.8.Installer.x64.msi` | 7.45 | Notepad++ MSI; matches existing live payload hash | Known MSI control |
| `Signal Private Messenger Installer.exe` | 0.78 | Microsoft Store Installer wrapper | Acquire direct desktop payload for an offline install/UI test; linking/messaging separate |
| `vs_BuildTools.exe` | 4.25 | Visual Studio 2022 bootstrapper | Pinned workload/layout acquisition and dependency-heavy installation later |

## Important distinctions

Signal and ChatGPT both expose `Store Installer` / `StoreInstaller.exe` version resources and Microsoft signer identities. Their small files are acquisition wrappers; installed app bytes and versions must be measured after acquisition. Signal's [official download page](https://signal.org/download/) offers direct Windows and Microsoft Store routes. Its [desktop installation guidance](https://support.signal.org/hc/en-us/articles/360008216551-Installing-Signal) requires linking to a phone for actual use. An install/first-window test must not imply messaging was tested, and no personal account linking or message sending is part of the initial fixture.

The DriveManager file is signed by SK hynix. Its [C3.2.0 manual](https://ssd.skhynix.com/download/driver_manager/Drive_Manager_Easy_Kit_Manual_C3.2.0_ENG.pdf) describes SSD monitoring, firmware updates, and drive erase, and requires administrator access for installation and use. Installation/window/close may be small tests, but physical-device functionality is a separate dependency. Missing hardware or denied device access in a worker must be reported explicitly. Physical host disks, firmware changes, erase, and hardware passthrough are outside this fixture's scope.

The Bambu filename/version and large payload make it a useful candidate for a richer offline file workflow; this has not established offline installation or driver requirements. Use a project-owned tiny model for import/slice/save before adding cloud login, printer discovery, or hardware interactions.

Visual Studio supports explicit workload selection and an offline layout, documented by [Microsoft](https://learn.microsoft.com/en-us/visualstudio/install/create-an-offline-installation-of-visual-studio?view=visualstudio). Pin the acquired payload/workload set rather than treating the bootstrapper hash as the final application identity. This inventory does not create that layout.

Every inspected EXE's PE wrapper header reports x86 (`0x14c`), including files named x64. That is the installer/loader architecture, not proof of installed application architecture. Payload architecture must be measured separately.

## Intake behavior exposed by this corpus

The current native `application inspect` path accepted only `vs_BuildTools.exe`, including a cache-only embedded signature observation. It rejected the other six before signature inspection because their named streams violate the current unnamed-stream-only policy. All six contain `SmartScreen`; the two Notepad++ files and Signal also contain `Zone.Identifier`. Stream names do not establish that their contents are authentic or safe.

Separate passive Windows version-resource/signature observations reported valid signatures for Bambu (Shanghai Lunkuo Technology), DriveManager (SK hynix), and the Signal/ChatGPT/VS wrappers (Microsoft). Those observations do not satisfy AIW's protected intake authority or bind the eventual downloaded payload. Raw stream contents, referrer URLs, and browsing history were not exported.

Next intake work must distinguish read-only source inventory from execution/import eligibility. Define a bounded provenance policy for download metadata, retain original files and origin information, and record any deliberate transformation in the external receipt. Do not silently strip streams or broadly allow arbitrary named streams. Until that work is implemented, these six originals remain rejected by protected intake.

## Profile sequence

1. Establish the standard-user MSI baseline and address source metadata handling. Add the Notepad++ EXE path to isolate installer-profile changes while reusing the document workflow.
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
