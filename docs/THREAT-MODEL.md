# Threat model

This document describes the boundaries AIW must preserve while evolving from plan-only contracts into Workbench and Studio. A recommendation is not a claim that an application is safe; it is a deterministic statement about observed compatibility and evidence completeness under a named configuration.

## Protected assets

- Host operating system, credentials, user data, network position, and administrative tokens.
- Signing identities, certificate stores, and private keys.
- Integrity and provenance of projects, plans, policies, packages, models, knowledge packs, and evidence.
- Accuracy of effective-backend, token, scenario, canary, trace, and cleanup claims.
- Customer and product evidence confidentiality.

## Untrusted inputs

- Installers, applications, packages, plug-ins, child processes, and worker output.
- Project YAML/JSON, imported bundles, paths, registry values, command-line text, URLs, documents, and window titles.
- Guest evidence when an in-guest target can tamper with the collector.
- AI prompts/completions, retrieved knowledge, models, tokenizers, and rendered Markdown.
- External packaging output, including manually authored Master Packager packages.

## Current guarantees and limitations

The current code provides strict schema/project parsing, safe-relative-path validation, SHA-256 checks, duplicate-ID detection, legal state transitions, canonical integer-only JSON, evidence-chain verification, deterministic allowlisted bundle manifests, conservative denial-canary evaluation, evidence-cited advisory reports, read-only probes, hardened `.wsb` rendering, pinned MXC planning, and run-bound completion-receipt verification. It also contains a fixed-function guest agent and a fake-provider-tested Windows Sandbox transaction kernel covering durable intent, an exclusive lease, exact-session cleanup, bounded receipt waiting, and recovery. The native test boundary pins and holds the Store package provider/catalog identities and has completed a real start/list/connect/receipt/stop/absence proof. A separate Windows primitive creates a new local fixed-volume run workspace with a protected owner-and-SYSTEM-only DACL and holds parent, root, tools, and output handles without delete sharing. It records final handle paths and `FILE_ID_INFO` identities and refuses existing leaves rather than adopting or repairing them.

It does not yet prove imported-application execution or isolation. The private Windows Sandbox runner binds the canonical owner-bound workspace evidence into the approved plan and durable session transaction, revalidates the held and reopened directory identities before mutation and after exact cleanup, and emits the same binding in terminal execution evidence. Production `aiw run start` and Windows Sandbox recovery remain unavailable until recovery is independent of drifted inputs and provider subprocess trees have kill-on-close deadlines; MXC remains planning-only. There is no desktop UI, package authoring, signing, or live canary provisioner. A guest receipt is consistency evidence, not authenticity against an administrator inside the guest, so host-side target/descendant process and token evidence, trace coverage, canaries, and effective-backend validation remain mandatory.

## Required controls

### Intake and paths

- Import MSI, EXE, and portable directories into ACL-restricted workspaces; hash the source and record signer, version, architecture, entry points, reboot behavior, persistence, and compatibility findings without executing it.
- Reject traversal, Windows case collisions, symbolic links/reparse points, unsafe output classes, oversized payloads, canonical workspace escapes, and mapping overlap.
- Revalidate canonical paths, provider identity, input hashes, plan hashes, and empty output directories immediately before a run. Use handle-based checks where a same-host path-swap race is possible.

### Execution and privilege

- Use fresh workspaces and provider leases, shell-free argument arrays, bounded typed scenarios, timeouts, cancellation, crash recovery, explicit reboot continuation, and idempotent cleanup.
- Use only a short-lived elevated helper with owner-bound named-pipe IPC, caller/executable validation, canonical handle-based paths, bounded messages, and fixed verbs. Never expose arbitrary shell, script, process, registry, URL, query, or filesystem verbs and never run a persistent SYSTEM service.
- Imported projects cannot grant permissions, choose real host resources, or encode free-form commands.

### Isolation evidence

- Record requested and effective backend, exact target and descendant tokens/capabilities/integrity/elevation, policy/configuration and provider hashes, process coverage, traces/dropped events, scenario results, run-bound canaries, terminal receipt, and cleanup.
- A canary passes only with a successful baseline control, explicit native denial for the isolated attempt, evidence references for both phases, and verified ordering. Timeout, not-found, missing evidence, and generic errors are indeterminate.
- Any fallback, unsupported API, provider drift, incomplete trace, missing descendant, forged/mismatched receipt, unexpected session/file, or failed cleanup invalidates the isolation conclusion and yields `insufficientEvidence`.

### Packaging and signing

- Use disposable checkpointed Hyper-V authoring workers with pinned tools and allowlisted export channels. Revert/destroy workers after every run and require repeatable captures.
- Treat a full-trust converted MSIX as a compatibility baseline. AppContainer/App Silo, ACP capability proposals, and narrow PSF remediation require explicit approval and complete Workbench revalidation.
- Sign outside the worker from a newly validated staging directory. Never place PFX passwords, access tokens, or private-key material in recipes, command lines, workers, logs, or evidence. Bind the final signed package hash to final install/launch/update/uninstall/canary/cleanup receipts.
- Master Packager is manual export/import only; its output is untrusted and receives the same inspection and validation.

### Evidence, AI, and privacy

- Keep authoritative state inspectable and append-only: immutable project revisions, per-run event/evidence JSONL, content-addressed artifacts, approvals, and terminal receipts.
- Export only allowlisted artifacts through a sanitized diagnostic/bundle path. No automatic telemetry or hidden network reporting.
- The optional local Analyst receives bounded verified evidence, emits cited plain text, and has no tools, credentials, network, execution, signing, deployment, or verdict authority. Model/runtime/knowledge artifacts are separate trust classes.

## Trust-boundary failure policy

AIW fails closed. Unsupported or degraded behavior is not converted into a successful recommendation. A model cannot override deterministic findings; a package cannot inherit a Workbench verdict after mutation; and a launch profile expires or becomes invalid when its application, provider, OS, policy, or evidence binding drifts.

## Explicit non-goals

- Automatically declaring an application safe or automatically converting every legacy installer.
- Learning or applying broad allow rules without review.
- Treating guest telemetry or a guest-authored receipt as tamper-proof.
- General-purpose privileged automation, arbitrary local-AI tool hosting, fleet management, enterprise compliance certification, or background application management.
