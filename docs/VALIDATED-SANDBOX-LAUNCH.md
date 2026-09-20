# Evidence-backed Sandbox replay preflight

The first launch profile checks whether a fresh preparation matches the verified
Notepad++ local-settings assessment. It supports the fixed install/open/edit/save/close
workflow, ephemeral settings, and measured standard-user file ACL controls.
It does not enable arbitrary interactive launch or authorize execution.

Create the profile from the retained baseline/candidate/replay selectors used by
`run report-wsb-settings-comparison`:

```powershell
aiw package create-wsb-launch-profile --input report-set-input.json > launch-profile.json
aiw package create-wsb-launch-profile --input report-set-input.json --format markdown
aiw schema wsb-launch-profile
```

Keep the returned `profileSha256` independently of the profile file. Creation
reopens all three retained runs; rendered reports are never accepted as evidence.
Missing OS observations or file ACL controls block profile creation. The profile
binds the comparison, evidence selectors, application, project, scenario, and agent.

Use the existing bundle import and `run prepare-wsb-msi` flow to create a fresh
preparation with the replay project, scenario, and exact agent. Before planning
import and approval, check it:

```powershell
aiw package check-wsb-launch-profile --profile launch-profile.json `
  --profile-sha256 <independently-retained-hash> --root <fresh-preparation> `
  --project <replay-project.json> --guest-agent-sha256 <verified-agent-hash> `
  --format markdown
aiw schema wsb-launch-preflight
```

The command checks the trusted hash before following evidence paths, re-verifies
the retained comparison, and checks the pristine preparation. Changed application,
project, scenario, agent, provider, host OS, required observations, or normalized
Sandbox configuration rejects preflight. Only the verified workspace prefix is
normalized, allowing fresh preparation locations without ignoring other mappings.

The output includes the exact preparation hash and recipe inspection. The nested
recipe retains its standalone inspection wording; the outer preflight supplies
the separate validation association. Neither output is execution authority.
Normal planning import, fresh bound approval, and start still perform their checks.
Do not reuse a preflight result after changing the preparation or environment.

Retained evidence must remain accessible on the same host. The new guest's OS,
workflow, ACL observations, and cleanup must still be verified after execution.
Cross-host deployment, persistent settings, general installer conversion, and
broader containment remain unvalidated. This completes an evidence-backed
preflight slice, not all of Roadmap Benchmark 3 or a general packaging release.

## Development proof

The retained baseline/candidate/replay comparison produced profile hash
`d8d7e4daddda76c535e6da1f897c210fa6b0798275640777747cea3df025d987`.
A fresh preparation passed both JSON and Markdown preflight without launching
a Sandbox. Both output schemas validated; altered application binding was
rejected with `AIW_WSB_LAUNCH_PROFILE_REJECTED`; all 75 retained evidence files
kept their original hashes. The proof and unimported preparation are preserved
under `%LOCALAPPDATA%\Temp\aiw-launch-profile-4f66ac89756542148448c434368f5644`.
The initial generic CLI diagnostic and corrected actionable rejection are both
retained there. Unit checks cover profile/evidence-selector tampering and
application/project/scenario/agent/provider/package/OS/configuration mismatch.
The CLI regression ensures rejection details remain actionable.

Local validation passed 42 CLI tests, 101 runner library tests (four explicit
skips), warnings-as-errors clippy, Rust 1.85, formatting, and governance. The
first runner suite hit native access denied while an existing test created its
run storage, before its scenario; the isolated test and full rerun passed without
code changes. The cause remains unconfirmed. Preserve
`%LOCALAPPDATA%\Temp\aiw-launch-profile-runner-tests.log`, the corresponding
`runner-isolated.log` and `runner-recheck.log`, and
`%LOCALAPPDATA%\Temp\aiw-local-checks-ef92da3b-f935-4c44-8add-dc50da34749e`.
