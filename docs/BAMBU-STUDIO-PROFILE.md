# Bambu Studio local-file profile

The second application profile targets the supplied Bambu Studio 02.08.02.60 EXE. It has a typed, non-executing compiler and a project-owned STL fixture. It is not yet accepted by preparation, approved start, guest-agent execution, or retained report sets. Compilation returns `executionSupported: false`; it cannot produce an application compatibility verdict.

```powershell
cargo run -p aiw-cli -- provider compile-bambu-scenario --project .\examples\bambu-studio-info.json --scenario local-file-info
cargo run -p aiw-cli -- schema compiled-bambu-scenario
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

## Integration requirements

Promote the profile only after the exact installer and fixed CLI workflow have a repeatable disposable-worker proof. Then add an EXE request and preparation path with an explicit payload-size limit sufficient for this 429,037,864-byte source; do not raise the MSI limit or rename old schemas to fit it.

Reuse the existing approval, held-file integrity, session ownership, receipt-last publication, cleanup/recovery, and standard-user launch mechanisms. Add bounded model-information observations that distinguish install completion, target launch, model processing, output capture, and cleanup. Exit 0 alone must not become a model-loading or isolation claim. Retain failed stages and unavailable output independently.

Extend reporting around application-neutral verified observations when there are two concrete consumers. Keep Bambu model processing and Notepad++ editing as distinct function columns; missing functions stay unmeasured. Research scripts and raw exploratory output are not production evidence and cannot be imported as successful retained runs.
