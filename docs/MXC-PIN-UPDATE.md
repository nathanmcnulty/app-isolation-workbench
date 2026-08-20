# Updating the MXC pin

MXC is an external experimental runtime. AIW does not float against its `main` branch.

For every pin update:

1. Fetch the proposed commit without executing its binaries.
2. Review its license, `docs/schema.md`, development schema, CLI parser, ProcessContainer probe, Windows Sandbox policy/lifecycle, and host-preparation changes.
3. Confirm whether `--probe`, `--dry-run`, or startup performs recovery or other host mutation.
4. Update the constants in `aiw-provider-mxc` and `third-party/mxc-pin.json` in the same commit.
5. Regenerate representative plans and compare decoded config JSON field by field.
6. Run AIW unit, Clippy, dependency, and secret checks.
7. Build MXC from that exact commit in a disposable development environment and record binary hashes.
8. Run the approved Windows capability and containment matrix. Never infer effective isolation from a successful exit code alone.

A pin must not advance when a new field is silently ignored, a backend degrades without evidence, or a formerly observational command gains an undisclosed side effect.

When the proposed source is available locally, run the non-executing contract check:

```powershell
.\scripts\verify-mxc-pin.ps1 -MxcSourcePath C:\path\to\mxc
```

The script verifies the Git revision, validates both representative AIW configs against MXC's pinned development schema, and checks each base64 payload hash. It does not build or run `wxc-exec.exe`.
