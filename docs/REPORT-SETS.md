# Retained MSI report sets

`run report-wsb-msi-set` re-verifies a bounded manifest of existing retained MSI workspaces and emits one report-set result. It performs no installation, Sandbox start, cleanup, recovery, comparison, or mutation. Each entry is independently reverified; an entry that cannot be read or verified remains represented as unavailable rather than being omitted.

The manifest uses `aiw.dev/wsb-msi-report-set-input/v0alpha1` and accepts JSON, YAML, or YML through the normal bounded document reader. It contains one to 32 entries with unique explicit IDs:

```json
{
  "schemaVersion": "aiw.dev/wsb-msi-report-set-input/v0alpha1",
  "entries": [
    {
      "id": "notepad-retained-2026-09-09",
      "workspaceRoot": "C:\\AIW\\retained\\aiw-msi-live-123",
      "runId": "aiw-msi-live-123",
      "projectPath": "C:\\AIW\\projects\\notepad-plus-plus-msi.aiw.json",
      "guestAgentSha256": "<independently supplied lowercase sha256>"
    }
  ]
}
```

Run it with:

```powershell
cargo run -p aiw-cli -- run report-wsb-msi-set --input .\retained-msi-report-set.json --format json
cargo run -p aiw-cli -- run report-wsb-msi-set --input .\retained-msi-report-set.yaml --format markdown
cargo run -p aiw-cli -- schema wsb-msi-report-set-input
cargo run -p aiw-cli -- schema wsb-msi-report-set
```

IDs are unique manifest selectors and are retained in the output. Workspace roots and project paths are explicit absolute paths; the project may be outside the current repository. Current v2 project files can be supplied as JSON or YAML and are re-read and validated for each entry. The independently supplied guest-agent hash remains an input commitment for each re-verification.

The report-set output uses `aiw.dev/wsb-msi-report-set/v0alpha1`. It records concise per-entry summaries and unavailable entries, suppresses duplicate selectors and duplicate verified identities according to the runner contract, and preserves each entry's failure reason for review. A report set does not establish comparison eligibility, an isolation pass, a compatibility recommendation, or a general application claim. The underlying workspaces retain the narrower assessment or unsuccessful-attempt semantics documented in [the assessment-report contract](ASSESSMENT-REPORT.md).

Schema generation is smoke-tested by `scripts/verify.ps1`; checked-in schema snapshots are not maintained until an external consumer requires them.

## Retained-fixture benchmark — 2026-09-09

The first set combines the current standard-user success (`aiw-msi-live-15136-1788999221878544900`), the controlled post-install failure (`aiw-msi-live-12864-1788999078887288000`), and the legacy failure (`aiw-msi-live-10356-1788914688885044500`). The success row exposes the five fixed workflow results and observed application token while preserving its insufficient-evidence outcome. Failed rows do not gain function results; verified stages and retained installation captures remain separately visible. Missing or rejected failed-attempt evidence is distinguished in JSON.

The read-only regression passed: repeated output matched, alternate-path duplicate selection was flagged using verified run identity, a wrong guest hash and an unreadable project stayed visible as unavailable entries, and all retained workspace inventories were unchanged. The bounded reader also rejects malformed and oversized project files. CLI JSON and Markdown exports were exercised locally. No Sandbox session or hosted CI run was needed for this reporting slice.

Local review artifacts: `%TEMP%\aiw-report-set-benchmark.input.json`, `%TEMP%\aiw-report-set-benchmark.json`, and `%TEMP%\aiw-report-set-benchmark.md`. These are rebuildable reports, not execution authority or a community compatibility database. Full file/registry metadata remains available through each individual retained-run report; the set carries counts and incomplete scopes to keep output bounded.