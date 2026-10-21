# Prompt for the new Codex session

Continue App Isolation Workbench from branch `codex/new-vm-handoff-20261021`.
Start with `scripts/work-status.ps1`, `docs/WORKING-STATE.md` and
`docs/RESUME-ON-NEW-VM.md`. Read `AGENTS.md`; follow `docs/EXECUTION-PLAN.md`.

The old Azure VM became unavailable when its subscription ran out of funds.
This is the new dedicated VM and Codex instance for the project. Do not recover,
clean up or depend on the old VM/subscription. Inspect this machine's actual
identity/tools before binding a new disposable trial to it.

My objective is to finish the next real repackaging/install/execution milestone
and feed lessons back into assessment. Continue autonomously as far as practical.
I authorize project development, terminal/computer use and testing on this
dedicated VM. Preserve unrelated work and failed evidence; use a disposable
worker/checkpoint for application execution. Commit/push stable milestones;
PR/merge when appropriate after review and required checks. Ask only when you
truly need human input.

It is fine to redo setup and affected controls on the new VM to regain progress.
Prefer a fresh, understandable trial over trying to adopt old machine state.

Last code checkpoint: `5688db4`. This branch preserves its complete history.
Draft release `migration-handoff-20261021` contains hash-bound signed MSIX inputs,
the historical native driver, 15 controllers and 39 selected evidence/log records.
Download/verify using the exact commands and archive hash in the migration guide.

The driver AND archived controllers pin the OLD VM/SIDs/computer/disk/baseline/
paths/hashes. They cannot simply run here. First deliver a narrow reviewed rebind,
rebuild the feature-gated driver, and create fresh account/nonce/preparation/output
records. Preserve checks; do not introduce generic execution or weaken cleanup.

The default SYSTEM Scheduler fixed cmd control passed on the old VM. The latest
reviewed WTS Scheduler wrapper was never dispatched: real standard-user RDP login
did not finish before the preparation window expired. Next prove that fixed native
`vm-launch-control` through the Scheduler route, with real interactive shell/token
binding and exact owned-process cleanup. Then run the full signed Notepad++ MSIX
lifecycle in a fresh disposable trial. Install/payload verification passed
historically; normal non-elevated packaged execution/edit/save/configuration/final
payload verification/uninstall remain unproven. A control pass is not completion.

Keep admin output simple with detailed evidence available. VS Code is planned;
classic AppContainer real-app comparison and reviewed MXC work follow this slice.
Avoid quota spent replaying the entire history. Use one writer and proportional
checks, with independent review for consequential identity/execution/cleanup work.
Follow the execution plan's model guidance; no expensive model is needed for
status reading/polling. Never use device-code auth. Signing uses existing personal
Artifact Signing through pinned CI, not copied private keys. Leave the migration
release draft. Close the milestone only against the full current acceptance proof.
