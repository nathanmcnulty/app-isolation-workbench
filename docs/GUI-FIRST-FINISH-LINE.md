# Working GUI: first finish line

User-authorized on 2026-10-02: finish and validate the desktop workflow without
requiring the user to drive terminals, approve test runs, or edit test documents.
The dedicated Azure VM and its existing RDP session are the disposable acceptance
environment. Agent-driven actions are recorded as automated acceptance, never as
another human operator's proof. Public publisher identity/signing is a separate
distribution decision; it does not block a clearly unsigned development GUI.

## Product outcome

An administrator launches a packaged Windows GUI, selects the exact supported
Notepad++ installer and optional bounded text input, checks readiness, reviews
the complete recipe and plan, explicitly approves that plan, and separately
starts the Sandbox workflow. The app remains responsive during installation and
editing. It presents verified function/transfer and cleanup results separately
from unmeasured broader isolation, offers advanced details, and explicitly
exports a verified document to a new file. No compiler, internal JSON editing,
CLI flags, or assistant is needed to complete that loop.

The supported assessment and interactive document workflows both use the same
existing Rust services as the CLI. This is the first GUI finish line, not a
generic installer converter or a new isolation-provider implementation.

## Architecture and delivery

1. Extract the existing administrator workflow into a shared Rust crate. Keep
   protected intake, fixed package assets, held identities, imported planning,
   authoritative approval, execution, retained reports, and export unchanged.
   CLI terminal confirmation and progress become adapters. Input authority is
   an explicit approval/start gate; progress observers have no authority.
2. Add Tauri 2 with embedded local HTML/CSS/JS, native narrowly typed file
   selection, and Rust-owned one-active-workflow state. No shell, generic file
   access, HTTP, updater, remote navigation, or remote content is exposed.
   Display untrusted strings as inert text. Use a restrictive CSP.
3. Keep one-shot review and start challenges in backend memory. Match the
   workflow, challenge, operator, and literal `approve <plan hash>`, consume
   each response once, and use the existing locked approval validation. Approval
   alone must not acquire Sandbox. Separate Start requires an explicit action.
   GUI closure cancels pending gates; running-workflow closure must preserve
   execution/cleanup and durable evidence rather than abandon a worker.
4. Build an exact identified Windows GUI package with fixed product/guest
   assets and inventory verification. Provide a direct launch entry and retain
   clean-source/build identities. Preserve the existing CLI distribution.
5. Deploy to the dedicated VM and validate through Computer Use. Use project-
   owned process controls before any experimental driver; keep durable stage,
   result, diagnostic, screenshot, and cleanup records. Do not weaken approval
   for tests or inject a generic execution interface.
6. Review consequential service and IPC boundaries independently, fix findings,
   run proportional local tests and required integration CI, PR and merge stable
   milestones, and verify the integrated tree. Finish only after the actual
   GUI acceptance matrix below passes, with limitations explicitly recorded.

## Acceptance evidence

- Fresh GUI assessment: select supported MSI, prepare, review, approve, verify
  approval did not start Sandbox, explicitly start, and obtain truthful function
  results, retained advanced evidence, verified cleanup, and an empty provider.
- Fresh GUI transfer: select MSI and bounded UTF-8 text, approve and explicitly
  start, visibly edit/save/close Notepad++ through RDP, then export through the
  GUI. Independently reverify receipt, output size/hash/content, unchanged input,
  overwrite refusal, and exact cleanup. No terminal approval or export step.
- Negative controls: unsupported installer/type, missing prerequisites or
  occupied provider, invalid/oversized/drifted text, product/guest/project drift,
  cancelled/malformed/stale/duplicate approval, changed plan after display,
  duplicate Start/concurrent mutation, close before approval/Start, failed or
  timed-out execution, rejected/unmeasured evidence, and export before cleanup
  or to an existing/workspace/reparse destination. Use service tests and retained
  fixtures where they establish the claim; use live GUI controls for actual
  interaction and disposable-worker evidence for execution boundaries.
- Render/control checks: untrusted control and direction characters cannot
  disguise approval fields or verdicts; failures name the retained evidence and
  safe next action. Busy UI remains responsive and never invents progress.
- Restart/read-only report viewing never restarts, repairs, recovers, or approves
  a run implicitly. Cached recent-run paths are pointers, not authority.

Detailed proof belongs here or in focused fixtures. WORKING-STATE stays a short
resume pointer. Missing live/rendered evidence means the goal remains active.
