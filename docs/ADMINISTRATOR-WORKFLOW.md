# Administrator workflow contract

The supported administrator entry point is `aiw admin assess`. It accepts
exactly three operator values: `--installer`, `--evidence`, and `--identity`.
The packaged Notepad++ local-settings asset manifest supplies the fixed project,
scenario, and guest-agent identity; operators do not provide a project file,
command, guest hash, approval JSON, or profile path.

The command reads only package-root assets beside the current executable. It
records `host-readiness.json`, rejects missing prerequisites and occupied Sandbox
sessions before intake, validates the fixed scenario and exact MSI bytes, then
performs protected intake, preparation, recipe inspection, planning import,
terminal exact-hash approval, execution, and retained JSON plus Markdown report.
Stage files are create-new under a newly created evidence directory. Unsupported
bytes, missing assets, malformed identity, and readiness failures do not acquire,
recover, or stop a Sandbox session. Cancellation writes an explicit cancellation
stage and leaves the imported run pending approval. Failed attempts remain in
their retained stage/workspace state: inspect `aiw run status` and use explicit
`aiw run recover` only if that exact status requires recovery. The workflow never
retries, repairs state, stops another session, or accepts arbitrary commands.
The retained Markdown report is the operator result; its assessment remains
`insufficientEvidence` for broader isolation even when the fixed document
workflow succeeds.

The product package intentionally carries the guest-agent path and expected
identity, while clean-host release assembly supplies the executable. That
assembly and its disposable-worker proof are Packet 5 gates.
