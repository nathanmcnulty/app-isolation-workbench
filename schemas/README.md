# Generated schemas

The Rust domain types are the canonical source during the v0alpha1 phase. Generate a schema to standard output with:

```powershell
cargo run -p aiw-cli -- schema project
cargo run -p aiw-cli -- schema model-pack
cargo run -p aiw-cli -- schema evidence-record
```

Checked-in schema snapshots will be added when the first external consumer is introduced. At that point, schema drift becomes a required review and compatibility test.
