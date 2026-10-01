# Administrator workflow contract

The supported administrator entry point is `aiw admin assess`. It accepts
exactly three operator values: `--installer`, `--evidence`, and `--identity`.
The packaged Notepad++ local-settings asset manifest supplies the fixed project,
scenario, guest-agent identity, and optional approved replay profile; operators
do not provide a project file, command, guest hash, approval JSON, or profile
path. A package without a profile performs the fixed assessment. A package with
the profile and its independent identity performs the profile-bound replay and
revalidates its retained source evidence before Sandbox acquisition.

The command reads only package-root assets beside the current executable. It
records `host-readiness.json`, rejects missing prerequisites and occupied Sandbox
sessions before intake, validates the fixed scenario and exact MSI bytes, then
performs protected intake, preparation, recipe inspection, planning import,
terminal exact-hash approval, execution, and retained JSON plus Markdown report.
The complete escaped recipe, Sandbox configuration, data lifetime, and recipe
hash are displayed before the separate exact-plan approval prompt.
Stage files are create-new under a newly created evidence directory. Unsupported
bytes, missing assets, malformed identity, and readiness failures do not acquire,
recover, or stop a Sandbox session. Cancellation writes an explicit cancellation
stage and leaves the imported run pending approval. Failed attempts remain in
their retained stage/workspace state: inspect `aiw run status` and use explicit
`aiw run recover` only if that exact status requires recovery. The workflow never
retries, repairs state, stops another session, or accepts arbitrary commands.
After the run, the console defaults to a short summary of the verified fixed
functions, recorded cleanup, broader-isolation gap, evidence location, and next
action. `--format json` restores the structured command result and error
envelopes for automation. The retained `report.md` is the detailed operator
view; `report.json` and stage files preserve advanced evidence in either mode.
The assessment remains `insufficientEvidence` for broader isolation even when
the fixed document workflow succeeds. Approval still displays the complete
recipe and exact plan before the operator enters the plan hash; completion
format does not shorten that trust-boundary review.

## Public-entry proof

### Packaged interactive export contract

`aiw admin export-document --workspace <retained-workspace> --run-id <exact-run-id>
--destination <new-absolute-file>` uses the interactive product packaged beside
the executable. The default output is a short summary; `--format json` preserves
the detailed export result. The operator supplies no project path or guest hash.
The package must contain the fixed interactive manifest, matching project and
guest bytes, and no launch profile. The existing runner re-verifies the retained
receipt, transfer artifact, original workspace ownership, and recorded cleanup
before create-new export. Package drift, a wrong run, incomplete evidence,
overwrite, and workspace/reparse destinations must fail closed. This command
does not acquire or recover Sandbox, install anything, or repeat approval.
The lower-level `run export-wsb-msi-document` remains available for advanced use.

The profile-bound preview package completed this exact public route on
2026-09-20. Operator approval was recorded for run
`admin-1789947096248087800`; Windows Sandbox installed the exact supported MSI,
launched Notepad++ as the fixed standard user, opened and saved the test
document with the expected bytes, requested graceful close, and verified exact
cleanup. The retained report records the validated launch profile
`d8d7e4daddda76c535e6da1f897c210fa6b0798275640777747cea3df025d987`,
installer SHA-256
`c29cbe1a9aaef322cc3f316ceeabe8a8071b18441a5e3c3ec348069739e59e80`,
and guest SHA-256
`121daa7e6b93212037813dea948675431d1a1680bbb106cd396a2647454cfee5`.
The retained status is terminal with `cleanup-verified`, and the provider list
was empty afterward. The report truthfully remains `insufficientEvidence` for
the broader isolation assertions that this workflow does not measure.

The complete evidence is preserved under
`%LOCALAPPDATA%\Temp\aiw-admin-public-replay-783a99b8f9a24fcb9c1f6d25cfe90ecf`.
A separate visibility retry created an unapproved preparation under
`%LOCALAPPDATA%\Temp\aiw-admin-public-replay-b7dbd4600bb84ea298bc9045ada6c22c`;
it never acquired Sandbox and is not execution evidence. This distinction is
kept so an operator or reviewer does not mistake a prepared run for the
completed public-entry trial.

The product package carries exact project and guest identities. Its optional
profile path and hash must either both be present or both be absent. Release
assembly supplies the executable bytes and receipt; the checked-in placeholder
manifest deliberately fails closed. Clean-host assembly and disposable-worker
proof remain Packet 5 gates. The same-host public-entry proof above closes the
administrator workflow milestone; it does not close the second-operator,
clean-host distribution gate.
