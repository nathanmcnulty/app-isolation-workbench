# Updating the MXC pin

AIW's MXC integration is a non-executing external adapter pinned to an August
`0.8.0-alpha` development contract. Current upstream describes GA SDK capabilities
and several experimental backends; neither classification changes our adapter's
acceptance. AIW does not float against its `main` branch. See the
[October 7 trajectory review](MXC-TRAJECTORY-REVIEW-2026-10-07.md).

For every pin update:

1. Fetch the proposed commit without executing its binaries. Start current adoption review with v1.0.0 (`7bf210247986cb73b1b314df60c2f1109c479c0b`), separately from latest-main development research. Record the exact SDK package/native-asset inventory and hashes, verify signatures/provenance where available, and identify dependency/SBOM gaps. Decide official assets versus source build explicitly.
2. Review its license/dependencies, schema, SDK/native contract versions, CLI parser, ProcessContainer tier/request-aware probes, backend policy/lifecycle, denial capture, telemetry and elevated host-preparation/recovery changes. Paths such as `docs/schema.md` and the development schema describe the old pin; locate the corresponding stable contracts at the proposed revision. Compare a versioned Rust SDK integration against retaining the external adapter before selecting an approach.
3. Confirm whether `--probe`, `--dry-run`, or startup performs recovery or other host mutation.
4. For the external adapter, update constants in `aiw-provider-mxc` and `third-party/mxc-pin.json` together. If adopting the SDK, update the locked dependency and native-asset provenance plus source-pin metadata together, with a versioned AIW adapter contract; do not retain misleading external-executor metadata.
5. Regenerate representative plans and compare decoded config JSON field by field. For an SDK adapter, also inspect typed-request/native-policy translation, unknown-field rejection and version dispatch at the selected release.
6. Run AIW unit, Clippy, dependency, and secret checks.
7. Build MXC from that exact commit in a disposable development environment and record binary hashes.
8. Run the approved Windows capability and containment matrix against the exact selected official artifacts or exact source-built artifacts recorded above. Never infer effective isolation from a successful exit code alone.

For the proposed revision, verify exact servicing-build and runtime feature support
for the full request. Record effective tier, SDK/runtime provenance, policy hash,
default/unknown-field handling, inherited environment/handles and child coverage.
Test unsupported controls before application execution. Do not silently weaken
LPAC, filesystem, network or UI requirements when tier selection changes.
Machine-wide preparation and recovery are separate mutating operations, never
implicit readiness checks. Prove their scope only in a disposable environment.

For diagnostics, distinguish enforced deny-and-record from permissive allow-and-record.
Bind modes and all required artifacts/loss indicators into retained evidence;
permissive success is not containment acceptance. Generated grants are proposals
requiring review, fresh approval and affected function/canary checks. Upstream's
claim that a new probe is read-only does not remove the old pin's mutation warning.

A pin must not advance when a new field is silently ignored, a backend degrades without evidence, or a formerly observational command gains an undisclosed side effect.

When the proposed source is available locally, run the non-executing contract check:

```powershell
.\scripts\verify-mxc-pin.ps1 -MxcSourcePath C:\path\to\mxc
```

The script verifies the Git revision, validates both representative AIW configs against MXC's pinned development schema, and checks each base64 payload hash. It does not build or run `wxc-exec.exe`. Update this verifier with any adopted contract change; a pass for the old schema is not acceptance of the current SDK.
