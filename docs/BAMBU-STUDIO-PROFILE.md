# Bambu Studio local-file profile

The second application profile targets the supplied Bambu Studio 02.08.02.60 EXE. It has a typed, non-executing compiler and a project-owned STL fixture. It is not yet accepted by preparation, approved start, guest-agent execution, or retained report sets. Compilation returns `executionSupported: false`; it cannot produce an application compatibility verdict.

```powershell
cargo run -p aiw-cli -- provider compile-bambu-scenario --project .\examples\bambu-studio-info.json --scenario local-file-info
cargo run -p aiw-cli -- schema compiled-bambu-scenario
cargo run -p aiw-cli -- schema bambu-scenario-compilation
```

The compiler reads project metadata only. It does not open or execute the installer. Source paths may vary, but source bytes must match the reviewed SHA-256. Protected intake verification remains a separate prerequisite for eventual execution.

## Fixed workflow

| Input or operation | Bound value |
| --- | --- |
| Application | Bambu Studio 02.08.02.60, EXE, x64 installed application |
| Installer SHA-256 | `cd2f8f2c789a22efee1300e993827cfdb047f27cfb0b8f5dd7395fbafadef4c7` |
| Staged installer | `C:\AIW\Tools\application.exe` |
| Installer arguments and deadline | `/S`, 300 seconds |
| Application entry point | `C:\Program Files\Bambu Studio\bambu-studio.exe` |
| Application arguments and deadline | `--info C:\AIW\Scenario\fixtures\aiw-tetrahedron.stl`, 60 seconds |
| Expected application exit | 0 |
| Fixture | [Four-triangle unit tetrahedron](../fixtures/bambu-studio/aiw-tetrahedron.stl) |
| Fixture SHA-256 | `2cb47e4cd9e465a162b4e60e6f15708f4ee15ef28477737c807283176a057450` |

The example declares `Install -> Launch -> ExpectExitCode(0)`. Empty project launch arguments select the fixed profile arguments above. There is no graceful-close step for a CLI operation that should exit itself. Caller-supplied arguments, MSI sources, changed hashes, reboot/update/uninstall semantics, secrets, network access, host resource access, and modified compiled commands are rejected. Git pins STL line endings because its exact bytes are part of the contract.

The profile is separate from Notepad++ MSI. MSI ProductCode queries, editor message driving, document-save expectations, and Notepad++ registry roots do not apply to Bambu. Existing MSI preparation and report contracts retain their meaning.

## Why this workflow

The [upstream CLI manual](https://github.com/bambulab/BambuStudio/wiki/Command-Line-Usage) documents `--info` with positional STL input. This provides a small offline model-loading experiment without selecting printer, process, and filament profiles. Slicing, project export, printing, cloud login, hardware discovery, and graphical editing are separate functions and remain unmeasured.

The supplied [02.08.02.60 release](https://github.com/bambulab/BambuStudio/releases/tag/v02.08.02.60) has a valid Shanghai Lunkuo signature and NSIS markers. [NSIS documents uppercase `/S`](https://nsis.sourceforge.io/Docs/Chapter4.html) for silent installation; that packaging convention alone does not prove this particular installer completes silently or without reboot. Live feasibility must establish those facts before integration.

## Disposable-worker feasibility, 2026-09-09

Protected intake re-verification succeeded for the supplied payload (receipt SHA-256 `6cbb034da1117a8cadc713cd1e5a0a8d67005a7a60e6abaccc0e8ba117681c74`). Two fresh Windows Sandbox trials used the recorded installer bytes, networking and device redirections disabled, read-only research inputs, and a dedicated writable output folder. No installer or application was run on the host.

Both silent installations exited 0 and produced the expected entry point, SHA-256 `e5675c12d45b5598cf245492285529e6c9907117a0f936e5511bf7667299cf24`. The first PowerShell research driver lost its application exit-code observation. The second retained process handles before waiting and captured exit 0 for `--info` under `AiwBambuResearch`, a separate local user whose driver reported no administrator role and its own user profile. Both exact Sandbox sessions were stopped and absence verified.

This is exploratory feasibility, not an approved production scenario result or token-bound assessment. The research fixture path was `C:\AIW\ResearchUser\aiw-tetrahedron.stl`, with the same fixture hash as the compiled profile. Driver identity, paths, and deadlines differ from the intended production adapter. These observations must not be inserted into retained assessment sets or counted as the completed second-application benchmark.

The Windows [GUI-subsystem wrapper](https://github.com/bambulab/BambuStudio/blob/v02.08.02.60/src/BambuStudio_app_msvc.cpp) loads adjacent `BambuStudio.dll` and forwards CLI arguments. It tries to attach to the parent console and reopens console streams; ordinary redirected stdout/stderr were empty in these trials. The [`--info` implementation](https://github.com/bambulab/BambuStudio/blob/v02.08.02.60/src/BambuStudio.cpp) uses model information written to that console. Empty redirected streams therefore remain a capture gap, and exit 0 alone is not a verified model-information result.

The third fresh Sandbox trial exercised a separate local export:

```text
bambu-studio.exe --export-3mf C:\AIW\ResearchUser\aiw-tetrahedron.3mf C:\AIW\ResearchUser\aiw-tetrahedron.stl
```

The installer, standard-user driver, and application each exited 0. The artifact was 9,061 bytes, SHA-256 `56511b82a0f9a10c4d10e60aa87e6074a182063acc14c3927f6b706e14fb2355`. After exact-session cleanup, host inspection opened the archive without extraction, bounded its entries and expanded sizes, and parsed model XML with DTDs and external resolution disabled. It found ten ZIP entries and one four-vertex, four-triangle mesh. The vertex coordinates matched the input tetrahedron translated by `(-0.5, -0.5, -0.5)` and its four faces matched the expected topology. This supports an exploratory STL-import/project-export observation; it is not a complete 3MF conformance check, slicing result, graphical workflow, or isolation verdict. The artifact hash records this output only, not expected byte-for-byte reproducibility.

All three trials used Windows build 28000 and Sandbox CLI 0.8.107.0. Cleanup was verified after each trial. The third research workspace is `%TEMP%\aiw-bambu-feasibility-cd492ff4-47bf-4af8-a9df-5fc96edc897a`; it retains the configuration, guest script, host journal, result, artifact, and inspection. Its result JSON hash is `b0b3d6b85cfdfeba418da0dbdfb56da0eeab54237753efd927a9f0c87e20c9ba`. These local research records are outside the production receipt/evidence chain and are not redistributed as verified reports.

**Roadmap consequence:** prefer a separate approved STL-to-3MF export profile for the first Bambu functional report. Verify bounded model geometry and package references, not an output hash or empty redirected console text. Keep the current information-query compiler available as metadata-only research intent; its fixed arguments do not silently become the export command. No slicing, cloud account, printer, or additional downloaded runtime was required for this exploratory export.

## Integration requirements

Promote the profile only after the exact installer and fixed CLI workflow have a repeatable disposable-worker proof. Then add an EXE request and preparation path with an explicit payload-size limit sufficient for this 429,037,864-byte source; do not raise the MSI limit or rename old schemas to fit it.

Reuse the existing approval, held-file integrity, session ownership, receipt-last publication, cleanup/recovery, and standard-user launch mechanisms. Add bounded model-information observations that distinguish install completion, target launch, model processing, output capture, and cleanup. Exit 0 alone must not become a model-loading or isolation claim. Retain failed stages and unavailable output independently.

Extend reporting around application-neutral verified observations when there are two concrete consumers. Keep Bambu model processing and Notepad++ editing as distinct function columns; missing functions stay unmeasured. Research scripts and raw exploratory output are not production evidence and cannot be imported as successful retained runs.
