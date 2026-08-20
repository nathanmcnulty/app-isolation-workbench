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
cargo run -p aiw-cli -- schema windows-sandbox-cli-lifecycle-plan
cargo run -p aiw-cli -- schema windows-sandbox-completion-expectation
cargo run -p aiw-cli -- schema windows-sandbox-completion-receipt
cargo run -p aiw-cli -- schema windows-sandbox-completion-verification
cargo run -p aiw-cli -- schema mxc-golden-probe-plan
```

Checked-in schema snapshots will be added when the first external consumer is introduced. At that point, schema drift becomes a required review and compatibility test.
