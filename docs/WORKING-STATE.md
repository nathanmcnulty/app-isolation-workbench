# Working state

Updated 2026-11-16 (America/Anchorage). Effective goal #108 is one application-neutral
assessment and packaging path, demonstrated with two behaviorally different
administrator-supplied external fixtures through unchanged production code.
Legacy #111 and its evidence are preserved and paused.

Checkout: `C:\aiw\app-isolation-workbench-108`, branch
`codex/application-neutral-assessment`, draft PR #112. Base main:
`04be2cefb9e9e4ffff73408e960efee6d30ea9d8`. Start with `scripts/work-status.ps1`,
[scope](REPOSITORY-SCOPE.md), [migration](APPLICATION-AGNOSTIC-MIGRATION.md) and
[release gates](RELEASE-GATES.md).

## Current slice

The generic offline x64 portable CLI path covers protected intake, compilation,
preparation, separate approval/Start, ordinary-user or classic AppContainer
execution, signed retained reporting/comparison and data-only replay. Names,
payloads and operations are run inputs. See [assessment](APPLICATION-ASSESSMENT.md)
and [channel design](ASSESSMENT-EVIDENCE-CHANNEL.md). Installers/GUI automation,
full descendants/registry/network/DLL/memory coverage, the wider fixture matrix,
W4/W5 and production acceptance remain open.

Source 93eded3 closes the seven-role signed transport boundary while preserving
strict generic intake. Full affected suites passed: provider 146, runner 163
(9 ignored), platform 222 (10 ignored); Clippy, governance and independent reviews
passed. Actual CNG/filesystem fixtures observed all seven short aliases. The
later owner-bound publication tests observed no aliases and do not replace those
proofs. A native symlink fixture required unavailable privilege and remains
unmeasured. Test-only commit 24b6349 passed all three jobs in CI 43860384530;
raw workspace passed=true, exit 0, 488.97 seconds. Tested merge 5b5cc441 has the
same tree 25fae8047dfdaa1409ad7a26783df8fcde46b950.

R9 used exact source-93eded3 tools. Complete signed publication and retained Read
now authenticate against the trusted local Start. Independent original admission
verified 23 signatures, raw artifact hashes, 15 file denials and 14 process/thread
denials. The application was not created: the collector's actual logon trustee
was outside the protection-v1 allowlist. Outcome remains NotRun/insufficientEvidence.
One exact owned Start/connect/stop completed; final two lists were empty and
outer cleanup was recorded complete. Retained Read exited 0; a subsequent private
QA projection accessed an absent property, independently preserved as a harness
bug. Original request bytes were removed during cleanup; its descriptor commitment
was recomputed without claiming custody of the absent original file.

The current provenance correction measures the exact collector primary-token
logon SID and proves absence from the held standard token's complete group list.
It retains/revalidates both token handles and collector token identity before
application creation. Only trustee policy gains that exact v2 exception; owner
policy, all 29 denial checks and historical v1 rules remain unchanged. Independent
native and cross-boundary source reviews passed. The first freeze passed 535
affected unit tests (19 ignored), Clippy and governance. A reviewed followup keeps
v1 wire fields closed even for null provenance and excludes the standard user SID
itself from the logon-trustee exception. Final provider 149, native protection 4
and signed-host 5 tests plus all-target Clippy passed. CI 43867287965 at f7b55485
passed all three jobs; actual workspace passed=true / exit 0 / 472.6 seconds,
with the same tested tree 9596f436708a87451a34b3c8e6fb8a367bd2a9bc.

R10 independently admitted 34 originals, 25 signatures and all 29 denials.
Protection v2 passed: the collector logon SID was absent from the actual standard
token groups, and retained Read records collectorKeyProtected=true. Portable
staging completed, but CreateProcessAsUserW returned privilege error 1314 before
an application process was created. Outcome remains NotRun, not incompatibility.
One exact owned Sandbox was stopped, with final empty lists and recorded cleanup.
Application-job cleanup remains unmeasured. Preserve this consumed Start.

R11 used exact source-3c8f317 tools. Independent admission checked 42 originals
(111,552 bytes), 25 signatures, all 29 denials and the complete local Start chain.
The signed held-token snapshot measured AssignPrimaryToken absent, IncreaseQuota
present/attributes 0 and Impersonate present/attributes 3. CreateProcessAsUserW
again failed with 1314 before creating an application. Retained Read authenticated
with collectorKeyProtected=true; the owned Sandbox was stopped and final lists
were empty. Account cleanup is historical; application-job cleanup is unmeasured.

Authorized SSH now drives separately reviewed, one-shot InteractiveToken/LUA
tasks in session 1. Actual before/after actors were Medium, limited, non-elevated
and matched the exact operator SID. Prepare and committed approval were separately
admitted before Start. No terminal UI input or administrator SSH assessment was
used for R11. Each phase preserves original CLI bytes and removes its idle task.

The current launch candidate uses CreateProcessWithTokenW with the same held
token, startup attributes, job and identity checks. A suspended PSS audit requires
the three actual stdio objects and absence of one excluded inheritable canary;
checked cleanup and a post-publication deadline guard precede Resume. This grants
no privileges or desktop permissions. Source 1726c6c passed independent reviews,
153 provider tests, 230 platform tests (10 ignored), Clippy, format and governance.
All three CI jobs in run 43905819003 passed; the tested merge has the same tree.
Fresh R12 completed separate Prepare, approval, Start and retained Read. Independent
admission verified 42 originals (111,527 bytes), 25 signatures, all 29 denials and
the complete Start chain. CreateProcessWithTokenW returned error 87 before creating
a child. Read authenticates as NotRun. No Resume, suspended audit or application
code ran. Owned Sandbox cleanup passed; application-job cleanup is unmeasured.
The rejected parameter remains unresolved. Preserve this consumed Start.
Created-but-unresumed failures remain DriverIncomplete/Unmeasured and cannot
confer application compatibility.

A separate unsigned, suspended-only research diagnostic completed two fixed
CreateProcessWithTokenW cases differing only in CREATE_NO_WINDOW. Both returned
87 before creating a child; account cleanup reported success and owned Sandbox
cleanup completed.
Removing that flag does not fix this diagnostic tuple. This is not signed
assessment evidence, a PSS audit or application qualification. The rejected
parameter remains unknown; ordinary/classic positive controls remain blocked.

## Storage and next gates

Use only `C:\aiw\environment-probe-20261114\target-static-r1`. Normal builds
require explicit cache selection, reject unsafe overrides, disable incremental
and debug symbols, and require at least 10 GiB free with cache <=8 GiB.
Source 1726c6c consecutive dev builds measured 2,873,857,828 bytes / 3,499 paths
both times; pass two compiled nothing and kept identical image hashes. Release
ended at 3,115,819,164 bytes. All 21 actual compiler commands and three exact-source
AMD64 static-CRT images passed independent admission. Keep one immutable
30,285,312-byte three-tool set, not copied trees. Totals sum file lengths and may
count Cargo hard-link aliases twice. Volume-free samples measure actual space.
Linker/backtrace PDB files are
measured separately; disabling full compiler symbols does not mean zero PDBs.

Earlier audited cleanup recovered 8.41 GiB of idle GUI output and 6,857,707,520
bytes of verified idle compiler metadata. Policy-blocked incremental cleanup
was never retried. One mistaken direct check omitted target/static flags and was
stopped after about 25 MB of extra metadata in the same bounded cache. After
tests settled, 45 audited single-link metadata files totaling 24,367,136 bytes
were removed while the cache was idle under exclusive Cargo locks; observed free
space increased 24,453,120 bytes. Independent cleanup admission passed. Corrected
validation uses storage preflight and the normal builder's explicit target/flags.
Do not create retry caches or blindly remove current artifacts.

Preserve all consumed controls R6/R7/R8/R9/R10/R11/R12. Qualify ordinary/classic positives,
negative controls, interruption/exact recovery and stable provider-zero reads
before the two external fixtures. Their exact payloads/provenance remain private
run inputs and have never executed. Use the authorized VM107 SSH/SCP route for
data transfer and the reviewed limited interactive task route for execution. No additional
privilege/runtime/VM/security change follows from a setup refusal.
