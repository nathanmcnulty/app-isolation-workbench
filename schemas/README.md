# Generated schemas

The Rust domain types are the canonical source during the v0alpha1 phase. Generate a schema to standard output with:

```powershell
cargo run -p aiw-cli -- schema project
cargo run -p aiw-cli -- schema model-pack
cargo run -p aiw-cli -- schema evidence-record
cargo run -p aiw-cli -- schema assessment-bundle-spec
cargo run -p aiw-cli -- schema assessment-bundle-manifest
cargo run -p aiw-cli -- schema assessment-bundle-verification
cargo run -p aiw-cli -- schema canary-plan
cargo run -p aiw-cli -- schema canary-observation-set
cargo run -p aiw-cli -- schema canary-report
cargo run -p aiw-cli -- schema analyst-report
cargo run -p aiw-cli -- schema analyst-report-validation
cargo run -p aiw-cli -- schema token-evidence
cargo run -p aiw-cli -- schema windows-sandbox-plan
cargo run -p aiw-cli -- schema compiled-msi-scenario
cargo run -p aiw-cli -- schema msi-scenario-compilation
cargo run -p aiw-cli -- schema imported-msi-guest-request
cargo run -p aiw-cli -- schema imported-msi-scenario-result
cargo run -p aiw-cli -- schema msi-runtime-context
cargo run -p aiw-cli -- schema msi-registry
cargo run -p aiw-cli -- schema msi-failed-snapshots
cargo run -p aiw-cli -- schema msi-product-registration
cargo run -p aiw-cli -- schema wsb-msi-report-set-input
cargo run -p aiw-cli -- schema wsb-msi-report-set
cargo run -p aiw-cli -- schema wsb-approved-execution
cargo run -p aiw-cli -- schema run-plan-v0alpha4
cargo run -p aiw-cli -- schema windows-sandbox-cli-lifecycle-plan
cargo run -p aiw-cli -- schema windows-sandbox-completion-expectation
cargo run -p aiw-cli -- schema windows-sandbox-completion-receipt
cargo run -p aiw-cli -- schema windows-sandbox-completion-verification
cargo run -p aiw-cli -- schema mxc-golden-probe-plan
```

Checked-in schema snapshots will be added when the first external consumer is introduced. At that point, schema drift becomes a required review and compatibility test.

`msi-application-token` describes the versioned guest root-process token observation. Compiled MSI profile v0alpha2 requires it; the profile/version is part of the approved scenario hash. Imported MSI execution v0alpha2 includes the verified observation, while legacy v0alpha1 without it remains explicitly missing evidence.

`wsb-msi-assessment-report` describes the read-only retained-run assessment report, including recorded cleanup, original project requirements, guest observations, and explicit missing evidence.

`msi-registry` describes the v5 profile's phase-bound registry metadata observations. It binds the actual runtime SID and represents empty keys, default values, absent roots and incomplete scopes explicitly. See [capture scope and limits](../docs/REGISTRY-CAPTURE.md).

`msi-failed-snapshots` describes the optional receipt-bound v5 failure event. It contains only completed filesystem/registry capture phases and metadata; absent phases remain unmeasured, legacy failed receipts remain unchanged, and `captureContext` identifies the capture account rather than asserting the launched application token.
