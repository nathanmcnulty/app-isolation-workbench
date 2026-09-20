# Review and approve a prepared run

After preparation and planning import, an operator can approve the exact persisted
plan without creating an approval JSON file:

```powershell
aiw run review-approval --root <run-storage-root> --run-id <run-id> `
  --approved-by 'Your operator identity' `
  --approved-at ([DateTime]::UtcNow.ToString('o'))
```

For an imported Sandbox preparation, use its workspace as the storage root and
its recorded run ID. The command shows all planned actions, requested permissions,
project revision, plan hash, and approval identity. Inspect the preparation's
recipe first when you need the detailed mappings and data lifetime. Review the
displayed actions and permissions, then type `approve <displayed-plan-hash>`
exactly. Any other response cancels without recording approval. Approval does
not start Sandbox or execute an application; the existing separate start command
still verifies its prerequisites, approval, and any bound replay profile.

Input and the review display must be attached to a terminal. Do not pipe a yes
response or suppress the review. Standard output contains the recorded approval,
or an `approvalRecorded: false` cancellation result. Automation retains the
existing explicit `run approve --approval <record.json>` interface.

The existing approval service checks the current plan again when recording the
decision. A plan change while it is being reviewed cannot receive approval for
the formerly displayed hash. Invalid provenance, a completed/cancelled run, or
an existing approval remains an error; this command cannot override those checks.

This is the first administrator-workflow improvement, not the complete preview
gate. It removes hand-authoring approval records, but the exact-plan display is
still technical. Guided intake, a concise assessment summary, recipe selection,
and clean-host distribution remain in [the release gates](RELEASE-GATES.md).

## Development validation

The 44 CLI tests, clippy with warnings denied, Rust 1.85, formatting, and governance
passed. Focused confirmation/terminal-rejection tests and the CLI build passed
again after final display buffering. The review escapes terminal controls and
Unicode direction overrides; redirected input is rejected without changing run
state. Logs: `%LOCALAPPDATA%\Temp\aiw-local-checks-e65ba41f-40eb-4fa4-b27a-cd58f7ab50af`.

A real terminal control trial cancelled without writing approval, then accepted
the exact displayed hash through the ordinary approval service. Retained status
reports approval ready and no Sandbox session. Control evidence:
`%LOCALAPPDATA%\Temp\aiw-terminal-approval-proof`. This proves the terminal approval
path, not application execution. No installer was run.

An independent Sol high-effort review of exact commit `5766a55` found no
actionable issue. It confirmed exact-hash input, escaped terminal rendering,
terminal-only review, cancellation without mutation, and service-side plan,
provenance, lifecycle, hash, and trust-delta revalidation under the run lock.
There is no automated pseudo-terminal success/cancellation test or forced plan
replacement race harness. Focused unit/service coverage plus the retained real
terminal proof cover those paths; the reviewer did not consider this a blocker.
