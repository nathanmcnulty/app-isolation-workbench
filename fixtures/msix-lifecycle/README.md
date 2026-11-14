# Synthetic lifecycle verifier inputs

`synthetic-receipts.json` contains project-authored unit-test inputs. Its generated
payload names and hashes, placeholder manifest and configuration text, process
IDs and times are synthetic. The fixed historical identity strings and package
hashes exercise the existing closed verifier contract; they do not represent new
measurements, shipped package bytes, or native acceptance evidence.

No third-party application, installer, package or configuration content is
included. These inputs test receipt validation only. They cannot pass the report
reader's independently pinned historical archive gate.

## Optional historical regression checks

The former `worker107-r5.zip` fixture and upstream configuration license file
were removed from the current tree because the archive included third-party XML
configuration content. Git history was not rewritten. Historical text remains in
[the lifecycle record](../../docs/NOTEPAD-MSIX-LIFECYCLE.md).

Historical report success/cleanup, shared assessment, CLI and GUI regressions
are explicitly ignored by default. To run them, supply an independently retained
external archive via the absolute `AIW_MSIX_RESEARCH_ARCHIVE` environment path
and select the ignored tests. The CLI example in
`examples/msix-research-assessment.json` likewise uses an external placeholder
path; edit a local copy to point at your retained archive. The original archive
identity remains unchanged:
SHA-256 `768e9ade771bbc3345067c82745c15f2d7c0ed31c4c8e281d437d14a27c321b3`,
285340 bytes. Missing input fails explicitly. Never replace this digest with a
synthetic or recompressed archive to make a test pass.

The default suite retains synthetic shared-verifier success, failure-marker and
cleanup rejection tests; archive identity rejection; missing-evidence behavior;
and Windows mixed-source rejection. CLI tests exercise missing and same-length
synthetic archives without granting application functions. GUI tests exercise
invalid/missing archives through deterministic loading, stale-token rejection,
JSON/Markdown export, overwrite and retained-location refusal, privacy filtering,
and unchanged input checks. These tests require no historical archive.

Seven historical tests (including one Windows-only mixed-source test) require
external input. The default suite no longer exercises the historical report
success path, accepted-run deduplication, outer native/controller cleanup receipt
mutations, or real-archive GUI/CLI success. No application is installed or executed
by these read-only tests.
