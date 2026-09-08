# Notepad++ 8.9.8 intake fixture

This fixture records a local, non-executing intake proof performed on 2026-09-01. The installer binaries are not redistributed by this repository.

## Source identities

| Kind | File | Size | SHA-256 |
|---|---|---:|---|
| EXE | `npp.8.9.8.Installer.x64.exe` | 6,953,384 bytes | `7b2a949bf460fb37a3888c9048698f43222a185a48323023df1c51e78a3ca1c2` |
| MSI | `npp.8.9.8.Installer.x64.msi` | 7,806,976 bytes | `c29cbe1a9aaef322cc3f316ceeabe8a8071b18441a5e3c3ec348069739e59e80` |

Windows Authenticode inspection outside AIW reported both originals as validly signed by `NOTEPAD++`. AIW's held-file, cache-only whole-chain verification independently reported `signatureStatus: available` for both working copies. AIW does not yet record signer identity or timestamp.

## Negative source proof

The downloaded originals contained the unnamed data stream plus `Zone.Identifier` and `SmartScreen`. AIW rejected both before import because application source authority currently requires only the unnamed data stream. The originals were not changed and remain negative fixtures.

## Positive intake proof

Separate working copies were made outside the repository. Only `Zone.Identifier` and `SmartScreen` were removed from those copies. Their sizes, SHA-256 hashes, and external Authenticode status remained unchanged.

AIW then completed protected receipt-last imports and independent read-only verification:

| Kind | Intake ID | Receipt SHA-256 | Result |
|---|---|---|---|
| EXE | `npp-898-exe-20260901` | `afe58a59c8d686f3899122da64ee64fa854b1680dcf1a7c0e008aefc5e72db51` | `verified: true` |
| MSI | `npp-898-msi-20260901` | `4f97ad60d7282b71c7699322ed1a987f58f71230005965c3bdb5903fa5905cc6` | `verified: true` |

The protected payloads retained the source hashes and received only the explicitly recognized semantic SmartLocker extended-attribute sets, which are bound into their import receipts.

## Stabilization refresh — 2026-09-07

The downloaded originals still match the identities above and still carry `Zone.Identifier` and `SmartScreen`; they remain unchanged negative fixtures. New unnamed-stream working copies were created in a separate local temporary directory, retaining identical file content. AIW reports embedded signature availability for both copies; no installer was launched.

Delayed verification exposed a Windows kernel file-hash cache appearing after import. File and portable intake receipts now use `v0alpha2`: native EA sets are validated, then only `$KERNEL.PURGE.SEC.FILEHASH` is excluded from canonical intake authority. Other metadata and content checks remain exact. Old `v0alpha1` receipts are rejected and require fresh import.

| Kind | Fresh intake ID | v0alpha2 receipt SHA-256 | Result |
|---|---|---|---|
| EXE | `npp-v2-exe` | `1c9d8964dd585e642c45fd9a1c7b9cd2dff99241aefb030bd13939d648bd57e4` | Immediate and delayed (over eight minutes) independent verification passed. |
| MSI | `npp-v2-msi` | `41427fe2d10e57d4fd1005d4e9c328704c8b17880083d9e9a4a3cd6dac9e06c7` | Immediate and delayed (over eight minutes) independent verification passed. |

Machine-local working copies, external receipts, and verification JSON are retained under `%TEMP%\aiw-health-fixtures-176e3524e9f04ef28902716f28811d3d`. Use `exe-v2-import.json` and `msi-v2-import.json`; earlier experimental receipts in that directory are preserved diagnostic artifacts, not current intake authority. Reverify before any later approved execution.

The existing fixed golden probe also passed a separate live Sandbox cleanup-before-result recovery canary. That proof did not install or exercise these applications. The approved MSI scenario was subsequently exercised as recorded below.

## Interpretation and remaining evidence

- The EXE outer PE image is x86. This does not establish the architecture of the product payload selected by the installer.
- MSI package architecture, product properties, signer identity, and timestamp are not yet recorded.
- The intake observations above were non-executing; the subsequent MSI test below ran only inside Windows Sandbox.
- No compatibility, containment, or safety conclusion follows from successful intake.
- Baseline comparison, EXE execution, and independent containment measurements remain pending.

## Approved MSI Sandbox proof — 2026-09-07

The ignored `live_imported_msi_install_observe_close_and_cleanup` test exercised the public preparation/import/approval/start APIs using the retained v0alpha2 MSI intake. It passed in 159.58 seconds. Installation returned 0; launched PID 1396 had a visible window, received WM_CLOSE, and exited with 0. Completion verification and exact cleanup succeeded, the request was removed, and no Sandbox sessions remained. The terminal assessment remained `insufficientEvidence`.

| Binding | Measured value |
|---|---|
| Run ID | `aiw-msi-live-10380-1788811934450793200` |
| Sandbox ID | `e162c72b-5b43-a08b-945a-397f85bf8a17` |
| Static guest SHA-256 | `785663fa6a08d017065cda5feb38f482a4900709a459ba9b629d5d36cbe0aa1c` |
| Request SHA-256 | `e25b5484687af661690d8e44dad95e7456bffddb862f387bd1bf322f81cbcfb4` |
| Completion receipt SHA-256 | `055bd17b27b9c06b3bedb1a063ad84af23426fe5d08b8271375cc76b94f3a179` |
| Evidence root | `f6ee6887eb8639e83008f4b3f1431387d60d0ebc0f405ced5bf526549cb16471` |

The machine-local prepared workspace, journal, result, and guest artifacts remain under `%TEMP%\aiw-msi-live-10380-1788811934450793200`. A separate negative fixture, `%TEMP%\aiw-msi-live-13140-1788811878424248900`, passed staged MSI tamper rejection before request or session creation. Both tests also verified that the golden-only API rejects the MSI profile. No installer ran on the host. No new CI run was triggered.

## Candidate token snapshot — 2026-09-07

The v0alpha2 compiled profile passed a fresh approved MSI install/observe/close run in 113.81 seconds. The held launched-process token snapshot and scenario result both identify PID 5780. The guest reported a primary, high-integrity token (RID 12288), elevated with default elevation type, no AppContainer SID, no capabilities, and zero restricted SIDs. These are guest-local observations; the Windows Sandbox VM boundary is distinct from AppContainer token isolation. No ordinary baseline or independent containment conclusion is claimed.

| Binding | Measured value |
|---|---|
| Run ID | `aiw-msi-live-19192-1788819016541089200` |
| Sandbox ID | `b7ae18a6-9bfc-70bb-c13a-ff9faff3a9c2` |
| Static guest SHA-256 | `8ccc5d79a707214726f94eab4dd4f53885aaa70391e1affec4652c7fd93eedcc` |
| Request SHA-256 | `e7fdbe8e2de00b1b1bf094ab23b708b9f4f1d1f8f341517c26b1c8b475049e23` |
| Scenario SHA-256 | `65471de6d43328e8752e7adfceef96229420860ebc895fad816c28f5ed1189ea` |
| Completion receipt SHA-256 | `b3ce6b293c399fabdea44049fd5f427ae053f71da022626d3a69b361c661464f` |
| Evidence root | `6533bbd868701d13610911ea31fab6a98c8bf1805eda9e7c29c398580f066c0c` |

Installation and launched-process exit codes were both zero. The host verified the receipt, reverified the token event's evidence root and request/PID bindings, and returned execution v0alpha2 with `applicationToken`. Exact cleanup succeeded, request removal was verified, no Sandbox sessions remained, and assessment stayed `insufficientEvidence`. The prepared workspace remains under `%TEMP%\aiw-msi-live-19192-1788819016541089200`; the log is `%TEMP%\aiw-msi-token-live.log`. No installer ran on the host and no CI was triggered.

## Functional document and file-change benchmark — 2026-09-07

The approved v3 MSI scenario passed a live Windows Sandbox run in 82.52 seconds. Notepad++ opened the fixed text document, exposed the expected initial content, accepted the replacement text and Enter key, exposed the expected edited content, saved the exact expected bytes, and closed with exit code zero. Installation also returned zero. Exact Sandbox cleanup completed, the request was removed, and the host session inventory was empty. The terminal assessment remains `insufficientEvidence` for containment; these are guest-reported functional observations.

The three bounded snapshots were complete: zero files before installation, 215 after installation, and 222 after use. The retained report identifies 215 installation additions and seven use-time additions under guest roaming application data: `config.xml`, `contextMenu.xml`, `langs.xml`, `plugins/Config/converter.ini`, `session.xml`, `shortcuts.xml`, and `stylers.xml`. There were no reported modifications/removals or incomplete roots. This identifies installed payload versus initial user-state files to investigate for packaging; registry changes and dependencies outside the fixed roots were not captured.

Evidence identity:

- Run/workspace: `%TEMP%\aiw-msi-live-15696-1788832809534382900`
- Session: `294bca6c-eee3-19e0-0c32-a4b1027acdf3`
- MSI SHA-256: `c29cbe1a9aaef322cc3f316ceeabe8a8071b18441a5e3c3ec348069739e59e80`
- Static guest SHA-256: `1afe4be4b5e5cba5169c14e7d569b25895a5d26289c466f09947aadad2768188`
- Request SHA-256: `8c750c075b62c451e64f690b58a363dcc44bb36fd91832ff7899d39a7cebed0f`
- Completion receipt SHA-256: `24fabe898970dbb20f40f0be58965af7838eba6d89295d7f0554cfeedc0addb1`
- Evidence root: `ecd05c392be9508d42b32d0328f71601f7e70445ed83081f8b431ecf002610c4`
- Expected/observed saved-document SHA-256: `55666bc7399b14c1cdb77f1e0261e3b6f09e49aec11cda7de1685d73b8a7c9fc`
- Live log: `%TEMP%\aiw-behavior-live-v4.log`
- Retained-report verification: `%TEMP%\aiw-behavior-retained-report-test.log`

Three preceding development attempts failed without accepted evidence and verified cleanup. One exposed a startup message timeout; bounded readiness retries resolved it. Subsequent diagnostics showed that Scintilla ignored control characters sent as `WM_CHAR`: the editor had the 46 printable bytes but no CR/LF. Sending Enter through the normal key-message path produced the expected 48 bytes. The harness now independently checks editor content before Save and the retained file afterward. This was a test-driver issue, not evidence of application incompatibility.

Independent review also led to per-message PID checks, retained document ancestry, and bounded capture/read diagnostics. Synthetic tests verify that normal atomic saved-file replacement works while a Scenario-directory rename is blocked. The v2 retained report remains readable with new observations absent; the v3 report passes repeated deterministic output and unchanged-workspace checks. No installer or application was executed on the host, and no hosted CI run was scheduled for this benchmark.

## Stage-progress benchmark — 2026-09-07

The updated static guest passed a fresh approved Windows Sandbox run in 80.09 seconds. All nine native stages reported passed: before-install capture, installation, after-install capture, document preparation, process launch, document open/verification, edit/save/byte verification, graceful close/job cleanup, and after-use capture. The run verified exact Sandbox cleanup and no remaining host sessions. The scoped file report again contained 215 installation additions and seven use-time additions, with complete roots.

- Workspace: `%TEMP%\aiw-msi-live-14964-1788843480881488100`
- Approved guest SHA-256: `c0b7ad637af79981623756d5226d5885395f59e738f9de43f5bde9c7f0490b2e`
- Request SHA-256: `cbaf8f6b2cccc3802c200a9dbc042a12cd6286e36a3916a5573de9f7ac2a44a4`
- Receipt SHA-256: `e37f44f76fc239929f46a0fc884cbac2ffa40f3353e8ce91256cd66924398453`
- Evidence root: `2f915cf32c6c401100054a116706f3d11545951679ed2e3df275c84707e780c1`
- Sandbox ID: `1ce01ef1-b168-3b46-2203-b9b29dc36f82`
- Local readable/JSON exports: `%TEMP%\aiw-notepad-stage-assessment.md` and `.json`.

The current report and the previous v3 report without a stage event both passed retained-workspace repeatability, wrong-binding, unexpected-output, and unchanged-inventory checks. The earlier failed editor fixture also passed the unsuccessful-report regression. Caught-failure stage progress was tested locally using synthetic failed receipts, including tampered evidence, contradictory successful status, unexpected files, and failure at every stage; no new live application failure was induced. One live Sandbox run and no hosted CI runs were used for this slice.

## Original-download intake to report benchmark — 2026-09-08

The supplied original MSI, including `SmartScreen` and `Zone.Identifier`, passed explicit metadata archiving and protected intake verification without modifying the original. Its v0alpha3 import receipt supplied the normalized payload to the existing approved Sandbox scenario. The live test completed in 140.75 seconds with all nine stages passed, matching saved-document bytes, exact-session cleanup, and no remaining Sandbox sessions.

The v0alpha4 assessment reports `downloadMetadataPolicy: archiveForSandbox`. Markdown states that the tested payload has no named streams and the run does not test the original download's Mark-of-the-Web or SmartScreen handling. This remains an elevated-in-worker application exercise with insufficient evidence for an isolation verdict; a standard-user baseline and application-level boundary comparison are still required.

- Original MSI SHA-256: `c29cbe1a9aaef322cc3f316ceeabe8a8071b18441a5e3c3ec348069739e59e80`
- Intake proof: `%TEMP%\aiw-download-intake-20260907-235847`
- Workspace: `%TEMP%\aiw-msi-live-23956-1788851283228469600`
- Approved guest SHA-256: `c0b7ad637af79981623756d5226d5885395f59e738f9de43f5bde9c7f0490b2e`
- Request SHA-256: `70abd9a150fe8b4be147dcc552edd5a8d0e47d42bc3715c44da935080c1181e8`
- Receipt SHA-256: `cdc5939af92315d15f6340326992ad5eeb0d0526d069facba58d18674979ca1a`
- Evidence root: `35efc73d5ecc34c61327706cda4adc2b7aaed3d7a798df054c1cb0eb020ea6aa`
- Sandbox ID: `122ea952-52c8-64f5-6532-5e900cf4b8f0`
- Local exports: `%TEMP%\aiw-download-assessment.md` and `.json`.

The previous completed v0alpha3 report still verifies with its original receipt serialization. CLI, probe, runner and native suites passed, including source/ADS writer exclusion, metadata bounds, sidecar replacement/removal/addition/hardlinks, and schema downgrade. The extended-only Windows path regression, workspace Clippy, Rust 1.85 all-target check, formatting and governance checks passed. This slice used one live Sandbox run and no hosted CI.
