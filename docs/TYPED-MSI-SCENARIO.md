# Typed MSI scenario integration

The first typed application slice is a pure compiler for a fixed Notepad++ MSI profile. It accepts a validated project and an exact scenario ID, emits a versioned plan, and provides validated canonical hashing. The CLI exposes it through `provider compile-msi-scenario`; `schema compiled-msi-scenario` describes its wire format.

The CLI wraps the compiled plan with its canonical SHA-256 and the full project revision SHA-256. This separates executable-profile identity from project identity, so future preparation can bind both. `schema msi-scenario-compilation` describes that review output; it is not accepted as an approval or prepared workspace.

Required assessment assertions and descendant coverage remain unchanged in the project and its hash. Compiling an action sequence does not satisfy those requirements. A future assessment must still return insufficient evidence when their measurements are unavailable.

The supported sequence is install, launch, wait for the expected process, graceful close, and require exit code zero. Application and launch arguments must be empty. The compiler resolves the recognized relative entry point to a fixed installed guest path and rejects unsupported steps instead of skipping them. The MSI content hash comes from the project and remains an unverified claim until protected intake verification and staging.

```powershell
cargo run -p aiw-cli -- provider compile-msi-scenario --project .\examples\notepad-plus-plus-msi.aiw.yaml --scenario install-launch-close
cargo run -p aiw-cli -- schema compiled-msi-scenario
```

These commands do not execute the MSI or open its source path. The fixture's provider hash is a planning placeholder. Compilation is neither approval nor proof of application identity, compatibility, containment, or successful installation.

## Required application execution integration

1. Add a distinct imported-MSI preparation profile. Verify the current protected MSI intake, hold its payload, and copy the held bytes to exactly `tools\application.msi`. Bind both the import receipt and the staged payload. Preserve the existing read-only tools mapping rather than mapping Downloads or the intake directory into Sandbox.
2. Persist the compiled scenario and bind its canonical hash, staged MSI hash, intake receipt hash, project revision, provider, guest agent, and workspace into a distinct run-plan action. Import and approval remain separate operations. Existing generic `ExecuteScenario` and fixed golden-probe actions do not authorize application execution.
3. Extend public start to dispatch solely from the imported preparation. It must accept no new application path, arguments, scenario selector, executable, or policy after approval. Revalidate the held workspace after staging the request and immediately before durable start intent.
4. Add a separate strict guest request and a bounded native executor for this profile. Install without reboot, observe the exact launched process, and close that process gracefully with bounded waits. Record failed installation, reboot-required results, early exits, timeouts, and close failures explicitly. Publish a fixed scenario result and evidence log before the completion receipt.
5. Reuse provider lease, session transaction, exact-ID cleanup, request removal, recovery, and completion verification. Extend profile-specific workspace allowlists; do not loosen the private golden-only discard inventory.
6. Validate tampering and approval rejection before provider acquisition, then perform an ignored live MSI canary inside Windows Sandbox using the separately retained local fixture. No installer runs on the host. Correlated guest observations remain insufficient containment evidence until independently measured host evidence is available.

The compiler is implemented; these execution integration steps remain pending. Existing approved start still runs only the fixed golden token probe. This local slice does not schedule additional CI.

## Local validation — 2026-09-07

Provider and CLI coverage passed: 17 provider tests, 13 CLI unit tests, and 19 CLI integration tests (the added command-binding test ran separately after the existing 18-test suite). The assessment-requirement/hash regression passed after review. All-target Clippy with warnings denied, formatting, schema output, and governance checks passed. Independent review found no blocking issue. No new guest agent, MSI execution, or hosted scenario validation is claimed by these checks.
