# Bambu Studio local-file profile

The second application profile targets the supplied Bambu Studio 02.08.02.60 EXE. A separately typed STL-to-3MF export now uses protected preparation, approved Sandbox execution, standard-user launch, artifact verification, and retained JSON/Markdown reporting. The original information-query compiler below remains metadata-only (`executionSupported: false`). Neither profile produces an application compatibility or effective-isolation verdict. [Mixed application report sets](REPORT-SETS.md) combine both production reporting profiles.

## Approved export and retained reporting

Use [the export project](../examples/bambu-studio-export.json) with a protected intake receipt for the exact installer bytes listed below. Build the guest agent with `scripts/build-guest-agent.ps1` and retain its independently computed hash.

```powershell
cargo run -p aiw-cli -- provider compile-bambu-export-scenario --project .\examples\bambu-studio-export.json --scenario local-file-export
cargo run -p aiw-cli -- run prepare-wsb-bambu --run-id <run-id> --project .\examples\bambu-studio-export.json --guest-agent <static-guest-agent> --guest-agent-sha256 <agent-sha256> --workspace-parent <parent> --created-at <timestamp> --import-receipt <protected-intake-receipt> --scenario local-file-export
```

Import the prepared workspace with `run import-prepared-wsb`, approve its exact plan using the existing approval workflow, then use `run start-approved-wsb`. Preparation alone does not authorize execution. The golden-probe-only start rejects this profile. The EXE has a separate 512 MiB staging limit; MSI limits and contracts retain their meaning.

The fixed export command is:

```text
bambu-studio.exe --export-3mf C:\Users\AiwStandardUser\AppData\Local\AIW\Scenario\aiw-tetrahedron.3mf C:\Users\AiwStandardUser\AppData\Local\AIW\Scenario\aiw-tetrahedron.stl
```

The installer runs privileged inside the disposable worker. The application runs under the established standard user, with its suspended process token checked and its job assigned before execution. Networking remains disabled. Four stages are recorded: install, prepare fixture, export, collect artifact. The guest publishes its scenario result and bound evidence event, then publishes the completion receipt last. A failed attempt records a stage prefix and a bounded diagnostic, with no successful artifact identity; its output slot is an empty placeholder.

After exact-session cleanup, the host verifies the approved request, completion receipt, evidence chain, result identity, and 3MF bytes. ZIP entry counts and compressed/expanded byte sizes are bounded; XML entities and ambiguous paths are rejected. The verifier follows the package relationships, component/build references and transforms, and requires the fixture's four vertices and four triangles. Artifact hashes identify that run's output; exports need not be byte-identical. This is a deliberately narrow fixture verifier, not a general 3MF validator.

```powershell
cargo run -p aiw-cli -- run report-wsb-bambu-run --root <retained-workspace> --run-id <run-id> --project <original-project> --guest-agent-sha256 <original-agent-sha256> --format json
cargo run -p aiw-cli -- run report-wsb-bambu-run --root <retained-workspace> --run-id <run-id> --project <original-project> --guest-agent-sha256 <original-agent-sha256> --format markdown
cargo run -p aiw-cli -- schema bambu-run-report
```

Reporting reopens retained authority and evidence without starting Sandbox or changing the workspace. A successful run requires reverified artifact evidence; changed output is rejected. Failed/cancelled runs distinguish verified failed evidence from absent or rejected evidence. `recordedCleanupVerified` describes the retained transaction, not a fresh provider query. Successful export still has outcome `insufficientEvidence`: baseline/candidate comparison, descendant isolation/canaries, filesystem/registry changes, and slicing/printer/cloud functions remain unmeasured.

The Markdown report opens with an administrator overview for the exact installer and fixed export workflow. Its function table marks stages passed only when the retained scenario evidence is verified; absent or rejected evidence remains unmeasured, and geometry verification is shown separately. The overview records the standard-user observation and historical cleanup status, states the broader isolation gap, and gives a next action based on the retained result. The JSON report remains the detailed machine-readable record.

## Production validation, 2026-09-09

The approved export passed in one fresh Sandbox: install and export exited 0, all four stages completed, and the exact session's cleanup was verified. The launched process token was medium integrity, not elevated, not AppContainer, with a matching standard-user profile and no enabled Administrators group. The 9,062-byte 3MF contains the expected referenced four-vertex/four-triangle tetrahedron. This demonstrates the fixed workflow inside an outer Sandbox, not an inner isolation candidate.

Retained workspace: `%TEMP%\aiw-bambu-live-10628-1789017156910616800`; the original project and exported reports are sibling `.project.json`, `.report.json`, and `.report.md` files. The production guest agent SHA-256 is `c9e4de9eaaedeb80ee6189badd90548111d702fab38818530ab2547eea83957e`; completion receipt SHA-256 is `a24acdd0d16952c259b1664df90b9318b872db50c3a471e0dbe1a97f50e0f1c0`; evidence root is `e546979313fc03bd248e823cfd565afe3a27cd49c5ee5501390d7a39bcf4b3a7`; artifact SHA-256 is `19a461fea05b8c7f75d0c8a53e08f2d7bf2557ddb2b832d559c4599c40a3eca5`.

The live harness checked golden-only start rejection, approved execution, cleanup, repeatable retained JSON, wrong agent-hash rejection, and artifact-drift rejection/restoration. The final host verifier was also exercised against the retained production output after review tightened XML hierarchy and qualified-attribute checks. Local provider/orchestrator/runner/guest and CLI tests passed, along with Clippy, Rust 1.85 compatibility, formatting, and governance. Existing successful MSI and mixed failed/legacy MSI report fixtures passed retained regression checks without another installation. No hosted CI run was requested for this slice.

To recheck reporting without an installation, set `AIW_BAMBU_REPORT_WORKSPACE`, `AIW_BAMBU_REPORT_PROJECT`, and `AIW_BAMBU_REPORT_GUEST_SHA256`, then run `cargo test -p aiw-runner --test live_bambu retained_bambu_report --locked --offline -- --ignored --exact`. The harness writes exported reports beside the retained workspace. Fresh execution is a separate ignored test requiring `AIW_RUN_LIVE_WSB_BAMBU=1`, `AIW_LIVE_GUEST_AGENT`, `AIW_LIVE_GUEST_AGENT_SHA256`, and `AIW_LIVE_BAMBU_RECEIPT`.

## Metadata-only information query

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

## Separate-host administrator trial, 2026-09-27

The independent operator approved the visible fixed recipe for unsigned package
source `ee8eb34055d86bce6c68fee78f9e62423b4c65e2` on the dedicated
`aiw-clean-host-0921` VM. Its archive SHA-256 was
`4b76e12a6dfdfc184149fd3643c7b9be46f70b3848c9bbb2a1106c992c1a3f2e`;
the extracted eight-file package verified against receipt
`aaaaa53e479c61f41378b54c82777bd9e09196e0971c32e128a41c7db7eb1e88`.
The separate installer on that VM matched the fixed
`cd2f8f2c789a22efee1300e993827cfdb047f27cfb0b8f5dd7395fbafadef4c7`
hash. Run `admin-1790501499861166000` is retained at
`C:\AIW-Bambu-Evidence-ee8eb34` on the VM.

The approved worker started and connected, but the fixed guest installer
process reached its 300-second wait limit. The retained result has
`failedStage: install`, no completed stages or installer exit code, and no
application-token or export evidence. The zero-byte 3MF is the required
failure placeholder, not a produced model. The verified failure report
(`failed-report.json` SHA-256
`ace27e64405f1cff7fc50c6bd1e8412d827712055df283abcb094a5e986a9f4a`)
records `recordedCleanupVerified: true`; the provider diagnostic records the
exact session stop, and a fresh provider list was empty. This does not establish
whether the installer was still progressing, blocked, or incompatible on this
host. Do not count the export as tested or rerun blindly. The remaining gate is
a bounded diagnosis of installer progress and a new operator-approved trial.

## Agent-observed separate-host diagnostic, 2026-09-28

An agent used the dedicated VM's open RDP session to run the staged unsigned
`d7b92918887c6a5614f22e9dfd027eebb50b9fe2` package. The eight-file
package verified against independently supplied receipt SHA-256
`d692312e949142438cf2317425fa4eec53dfea520757a592b5e5d4c315e342d6`.
Run `admin-1790624935080973000` is retained at
`C:\AIW-Bambu-Agent-Evidence-d7b9291` on `aiw-clean-host-0921`.
This is development diagnosis, not a successful independent operator trial.

The visible Sandbox worker opened and later closed without an installer dialog.
The receipt-bound failure report (`failed-report.json` SHA-256
`e9b55fdb4775041efce49aee00e119bd2bdcc57b959953ba18cd2fc117512d9a`)
records `failedStage: install`, no completed stages, and verified cleanup. Its
new diagnostic records installer PID 6648, elapsed wait 300021 ms, four
processes remaining in the job, and the fixed Bambu entrypoint present as a
regular 159776-byte file. A fresh provider `list --raw` returned an empty
session list. Installation made observable progress, but the installer job did
not finish by the bound. No standard-user export or compatibility result was
measured. Identify the remaining job processes and their completion behavior
before revising the wait contract or repeating an acceptance trial.

The packaged verifier's documented `-PackageRoot .` invocation failed because
it resolved `.` against the process working directory rather than PowerShell's
current location. Absolute-path verification succeeded, and source commit
`fae693b` fixes relative resolution with a regression check in both PowerShell
7 and Windows PowerShell 5.1. The staged `d7b9291` package retains its original
verifier bytes; this source fix needs a new package before distribution.

## Separate-host installer-process diagnosis, 2026-09-28

The unsigned `449f615` package added bounded job-process image diagnostics and
fixed the packaged verifier's relative-root behavior. Its archive SHA-256 is
`5643941259037d1614a9395452e6e40b66b0a4b2d76e5b9f87c4402f73c37019`;
the eight-file receipt is
`383ea00a4e296102bbf79395dcc0ad01b9a585616b3c15145c4be9606c97a2e5`.
The archive was independently verified on `aiw-clean-host-0921`, including
`-PackageRoot .` under Windows PowerShell 5.1. These are agent-owned development
runs, not independent operator acceptance.

Run `admin-1790634384041089400` at
`C:\AIW-Bambu-Agent-Evidence-449f615` again timed out after 300 seconds in the
fixed install stage. Its receipt-bound failed report records verified cleanup,
the 159,776-byte Bambu entrypoint, and four live job members:
`application.exe`, two `vcredist2019_x64.exe` processes, and
`VC_redist.x64.exe`. No export stage ran.

Run `admin-1790634916825655000` at
`C:\AIW-Bambu-Agent-Inspect-449f615` repeated the exact approved recipe only
to inspect the stalled child processes in the disposable worker. Its verified
failed report SHA-256 is
`7e17132057ccc8015e1f38021153e155b6cb9adc640d3f73e2fa14403a39446e`;
cleanup was verified and a fresh provider list was empty. The guest inspection
showed installer PID 6676 and a child chain of bundled
`vcredist2019_x64.exe` (including PID 3576, launched with `/s`) and Microsoft's
`VC_redist.x64.exe` (PID 2216, launched in quiet mode). Those redistributable
processes had accumulated under one second of CPU each late in the wait. The
guest produced three `dd_vcredist_amd64_*.log` files under its local temp
directory, but they were not retained before normal worker cleanup. Their
contents and the precise wait condition remain unknown. A subsequent targeted
diagnostic must retain bounded setup-log evidence before changing the installer
deadline or claiming the export works on this host.

The next development source adds guest-only, bounded VC log excerpts to the
existing failure diagnostic. Its focused Windows test passes; it needs a new
static guest build and exact-source separate-host run before the log contents
can inform any installer change.

## Remaining integration

Mixed report sets now combine the two concrete reporting consumers. Keep Bambu export and Notepad++ editing as distinct function columns; missing functions stay unmeasured. Research scripts and raw exploratory output are not production evidence and cannot be imported as successful retained runs. Add clean repetitions and control-fixture coverage before declaring the broader repeatability benchmark complete.
