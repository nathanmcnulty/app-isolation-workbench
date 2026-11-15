# Fresh Sandbox environment observation

The default-off `research-environment` feature is a first-party prerequisite
measurement for the private multi-mode assessment. A fresh worker's Windows
version and dependency observations must precede a new application plan after
host servicing changes. It is not an application assessment or MXC support test.
The first native host inspection failed; fresh guest execution is pending.

Source `404c837` passed all three [hosted CI jobs](https://github.com/nathanmcnulty/app-isolation-workbench/actions/runs/43654996049).
Independent reviews covered the execution boundary, fixes, static builds, direct
and delay imports, source framing, and actual transport packet. The host's pure
identity output matches the independently reconstructed source commitment
`1cc0f6677c60c34846f9e2e9d88208e864af761d86c47b3128d5b5158e6e8b68`.

| Artifact | Bytes | SHA256 |
|---|---:|---|
| Static guest helper | 436,224 | `8a647447a50a5d67b06b9abb5b78cbdf40ea707e88c7ee84d81f09114f28f56b` |
| Static host helper | 3,108,864 | `2f3aaa905bfc5266f571d953edd262c750562082f854be91c89a88939ef6bd18` |
| AIW-only transport ZIP | 1,181,413 | `d2f0a590f71e5ebdae4e5d1bd432b907d5738ac8fe947c853119ae3b1509cb41` |

Both PE images are AMD64 with no external CRT, vendor or delay imports. All 487
tracked source files matched before/after each build and the reviewed checkout.
This establishes build/source consistency, not reproducibility or native loading.
The first data receiver timed out after acknowledging five of seventeen parts.
A separately reviewed continuation held and verified that prefix before accepting
only parts 5–16, then rehashed all 17. The data-only stager verified the complete
archive and five members before publishing its receipt. Original failures and
parts remain retained; this was an explicit data continuation, not execution
recovery or an application replay.

The static host helper's first native `--inspect-host` invocation on VM107 exited
with signed code `-1073741819` (`0xc0000005`). The root exit was observed without
timeout or watchdog kill. Both retained output streams are complete, settled and
zero bytes. No provider acquisition, Sandbox or application execution was
requested. Descendant cleanup remains unmeasured. Output begins only after the
inspection operations, so empty output does not locate the failing call or prove
entry. Source review identified no proven cause; a COM factory/apartment lifetime
hypothesis remains untested. Do not infer an isolation incompatibility, loader
result or successful prerequisite observation.

A bounded read of existing Application Error events, limited to the failed
image's path, PID and time window, returned no matching facts with a generic
query-error/no-records state. A refined read retained bounded stage/exception
facts: native module resolution and its guard passed, and the cmdlet returned
`NoMatchingEventsFound` for that same fixed query. This supplies no faulting
module, offset or cause and makes no claim about other logs or time windows.
The helper has not been rerun. Private originals are under
`C:\aiw\environment-probe-20261114`:

| Record | Original bytes | SHA256 |
|---|---:|---|
| `native-prefix-audit-original-r2.json` | 1,911 | `d5a04dbe8800208b1e1d08394276f1e4b2f67c5a341a2e0cc02434e379c93ada` |
| `native-stage-receipt-original-r1.json` | 715 | `411162be231ecb5f43f73489252066373fb3acdc26f9b5219fab84dd279d147b` |
| `native-inspection-metadata-original-r2.json` | 1,417 | `0ef35225d56ca4260a9edf67b6c54b12e77283a4356aa1a770bcf9c735ccc297` |
| `native-inspection-stdout-original-r2.bin` and `native-inspection-stderr-original-r2.bin` (each) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `native-application-error-events-original-r1.json` | 1,495 | `c2c6dbcd0ff8ba517e70c83fb5eaaadfc3013ca43e3a665077b22adea25f443b` |
| `native-application-error-events-original-r2.json` | 2,446 | `dd471d7d6cb9ba889f6d090c9bc36dd295d6a85ec3c8e3c686710253d2000a5e` |

Original JSON and stream bytes were captured from bounded native clipboard
output (with Base64 frames decoded) and matched separately observed native
length/digest markers. They were not reserialized. The staging digest
transcription refusal was resolved by
reobserving the marker and admitting the unchanged quarantined bytes, without
rerunning staging. The complete-transfer observation has separate admission
`native-transfer-completion-admission-r2.json`, SHA
`9c0268422ac8bca78cdd6500f991d843c9a8b1848aa0663a9acc19f42d8cc684`.

The provider accepts only `environment_probe.exe`, its fixed output argument,
one read-only tools mapping and one writable output mapping. This feature does
not enable the older MXC or application publication roles. The guest makes no
installer, vendor-code, runtime-load, account or ACL-grant requests. The host
creates a fresh protected owned workspace; it does not alter existing ACLs or
VM security settings.

The guest helper requires an x64 static CRT build, its exact image path and the
native elevated primary `WDAGUtilityAccount` token (canonical local RID 504).
It records the observed Windows API version, native system directory and a
bounded, held, read-only file observation of the fixed system CRT dependency.
Each fallible measurement carries either a value or a bounded error. A refused
file measurement remains unknown. File presence and a digest do not establish
loader compatibility; loader compatibility and isolation enforcement remain
explicitly unmeasured.

The host example is a closed transaction for the existing approved research VM,
ordinary operator, exact session and fresh root. Its source commitment combines
the existing application source frame with the environment, custody and lifecycle
sources. A separately reviewed guest binary hash must be enrolled at host build
time. Both helpers require static CRT builds for execution. Build provenance and
direct/delay PE imports must be reviewed before native dispatch; a compiler flag
alone is insufficient evidence of the resulting dependencies.

`--inspect-host` observes the host API version and static provider identity
without acquiring a provider. Static identity is not CLI protocol proof. Prepare
holds the helper, creates a fresh protected workspace and publishes the complete
proposal. Approve binds its exact hash. Start rechecks source, helper, actor,
host and plan, then durably records intent before provider acquisition and
dispatch. Provider operations have deadlines and only the owned session is
stopped. No global stop operation is used.

Guest output uses held mapping ancestry, create-new temporary publication and
atomic non-replacing final publication. A present invalid final file fails
immediately; it is not treated as an absent file to wait on. Cleanup is recorded
independently before final report publication. Host results preserve partial
observations and execution or cleanup failures.

Read reopens protected records without provider acquisition. A retained match
requires the approved plan, session and durable start/dispatch records, as well
as stable full file identity and typed report validation. Raw marker bytes are
exported from the same held read. Recovery requires dispatch intent and reconciles
only the original session, with a fresh durable recovery intent. It never
replays the helper or application. A start intent alone grants no cleanup claim.

Focused tests cover exact role refusal, partial observations, contradictory
tokens and file facts, canonical SID parsing, retained binding and recovery
authority. CI compiles/tests this feature independently of MXC and application
features and checks its minimum Rust version. These checks do not substitute for
the pending fresh Sandbox run or advance application compatibility, enforcement,
Benchmark 2, W4/W5 or production acceptance.
