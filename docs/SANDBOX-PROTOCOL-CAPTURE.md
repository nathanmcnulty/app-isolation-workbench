# Read-only Sandbox protocol research

An unknown Store CLI version remains unsupported until its protocol and owned
lifecycle have been reviewed and measured. Do not replace the exact version gate
with a wildcard, relabel old plans, replay a refused run or downgrade a worker.

The opt-in `research-sandbox-protocol` feature adds the
`sandbox_protocol_capture` example. It is excluded from default builds and accepts
no arguments, command strings or provider paths. It uses the existing static
Store/package/catalog verification, holds the provider file, and invokes only
`--version`, `--help`, and `list --raw` through the existing suspended, job-bound
launcher. It never calls start, connect, stop or exec, and leaves existing sessions
untouched. Build it in the selected shared cache after the normal
`scripts/build-storage.ps1` preflight; use the existing target-specific static CRT
setting for a clean worker. Do not create another target directory for research.

The private diagnostic JSON retains stdout/stderr as exact hex bytes with sizes
and SHA-256 hashes, including non-UTF-8 data and nonzero CLI exits. Each command
has a 15-second invocation deadline, the existing cleanup allowance and 64 KiB
per-stream bound. A launcher error stops subsequent commands and marks that
capture incomplete; earlier original records remain. A final held-provider
identity/hash error also retains those records, explicitly marked unverified.
The example writes the diagnostic before returning failure for incomplete capture
or failed revalidation. Zero exit means a complete observation, not compatibility.

This report cannot establish production readiness, mint a lease or approve a
protocol. Catalog trust is the static inspection observation. Successful
provider-managed descendants follow the existing launcher's policy; this capture
does not claim global process cleanup or live session absence. Do not use its raw
list bytes as an admitted session inventory without the matching reviewed parser.

Native capture belongs on the selected validation worker, with exact-source
artifact hashes and retained original output. Keep raw diagnostics private. A new
version still needs explicit plan/receipt/recovery selection, strict raw-response
tests, and fresh first-party exact-ID lifecycle and interruption/recovery proof
before application trials. Historical 0.8.107.0 evidence keeps its original scope.
