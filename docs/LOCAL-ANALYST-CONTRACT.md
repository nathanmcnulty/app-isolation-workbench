# Local analyst report contract

The AIW Analyst turns normalized evidence into a cited explanation for an administrator. It is not an agent with tools and it is not part of the isolation verdict. The current implementation validates a provider-neutral report envelope; it does not run a model.

## Fixed authority boundary

An analyst report can contain a plain-text executive summary, findings, and typed recommendations. Every statement requires one or more citations to exact evidence sequence numbers and record hashes. Validation first verifies the complete evidence chain, then resolves every citation.

The schema has only one authority, `advisoryOnly`, and validation output always sets `contentAuthoritative` to `false`. Unknown fields are rejected. Markdown is not accepted as a trusted rendering format; consumers must render the declared `plainText` as text.

Recommendations are limited to three non-executing actions:

- collect one fixed category of additional evidence;
- propose testing one fixed policy-control category in a new disposable run with human approval;
- escalate to a Microsoft product group, software vendor, or internal security team.

A proposal cannot contain a command, executable, path, registry key, URL, package, policy value, or deployment target. A policy-relaxation proposal is invalid unless both `requiresNewDisposableRun` and `requiresHumanApproval` are true.

## Provenance envelope

The report records the provider and version, model-pack identity and version, requested alias, resolved model-variant ID, model payload root, actual execution provider, runtime artifact root, prompt-template hash, generation-configuration hash, transport, input class, tool access, and external-network access.

This distinction matters for Foundry Local. Its SDK can resolve a model alias to a hardware-specific variant and exposes the selected variant ID. It can also choose and manage execution providers. AIW therefore records both the human-friendly alias and resolved variant, plus the actual execution provider. Sources: [Foundry Local get started](https://learn.microsoft.com/en-us/windows/ai/foundry-local/get-started), [current SDK reference](https://learn.microsoft.com/en-us/azure/foundry-local/reference/reference-sdk-current), and [Rust SDK model API](https://github.com/microsoft/Foundry-Local/blob/main/sdk/rust/docs/api.md).

Foundry Local is a first provider, not part of the contract. The first integration should use an in-process SDK path with no analyst tools and no external network during inference. Catalog/model acquisition happens as a separate, approval-bound supply-chain operation before a run. The exact cached model payload and loaded runtime artifacts must be measured by the trusted host and matched to approved manifests.

## Validate a report

```powershell
cargo run --locked -p aiw-cli -- analyst validate `
  --report .\examples\analyst-report.json `
  --evidence-log .\examples\analyst-evidence.jsonl `
  --model-pack .\examples\model-pack.json
```

Successful validation reports evidence-chain and citation resolution separately from content authority. The validator also requires report provenance to match the model pack's provider, provider version, model-pack identity, resolved variant, model payload root, and approved execution-provider list. The pack must declare `summarizeEvidence`, plus `classifyHypothesis` or `structuredProposal` when the corresponding report sections are present.

## What validation does not prove

The report envelope is still untrusted input. Current validation does not independently measure the loaded runtime, cryptographically verify the model-pack signature, prove that the named model generated the text, detect hallucinations, or judge whether a recommendation is good. Runtime roots, prompt hashes, and generation hashes are checked for shape and consistency but must eventually be injected from host measurements rather than accepted from model output.

The production flow should give the model only the bounded content portion, then have the trusted host add measured provenance, validate citations, and sign or hash the completed advisory artifact. Model output never receives credentials and never invokes the runner. Accepting a recommendation creates a separate reviewed project revision and fresh disposable validation run.

## Current research snapshot

As of 2026-08-19, Microsoft documents Foundry Local for Windows, macOS, and Linux, with SDKs including Rust and an optional OpenAI-compatible REST service. The Windows SDK supports hardware-aware execution-provider management, while the model API exposes aliases, selected variant IDs, cache state, and load state. The repository's release history also shows an actively serviced native runtime. These are reasons to keep provider/runtime provenance explicit and versioned rather than bundling an opaque model directory with AIW.
