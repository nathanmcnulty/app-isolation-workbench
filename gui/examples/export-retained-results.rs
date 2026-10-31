//! Headless verification of the desktop Results backend for an explicit selection.
//! No execution, approval, provider, cancellation or recovery entry point.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use aiw_desktop::results::ResultsStore;
    use anyhow::{anyhow, ensure};
    use std::path::PathBuf;

    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 3,
        "Usage: export-retained-results <selection.json> <new-summary.json> <new-summary.md>"
    );
    let selection = PathBuf::from(&args[0]);
    let json_path = PathBuf::from(&args[1]);
    let markdown_path = PathBuf::from(&args[2]);
    let store = ResultsStore::default();
    let first = store.load(&selection).map_err(|e| anyhow!(e))?;
    let second = store.load(&selection).map_err(|e| anyhow!(e))?;
    ensure!(
        serde_json::to_vec(&first.summary)? == serde_json::to_vec(&second.summary)?,
        "Retained selection changed between reads; no exports written"
    );
    // Both exports use the same backend-owned projection and its current token.
    // The service validates local held parents, retained exclusions and CreateNew.
    // Failure may leave the first export or a partial new file; never delete/retry.
    store
        .export(&second.token, &json_path, "json")
        .map_err(|e| anyhow!(e))?;
    store
        .export(&second.token, &markdown_path, "markdown")
        .map_err(|e| anyhow!(e))?;
    println!(
        "{}",
        serde_json::json!({
            "schemaVersion":"aiw.dev/retained-results-export-check/v0alpha1",
            "selectedRows":second.summary.rows.len(),
            "deterministicSummary":true,
            "jsonExported":true,
            "markdownExported":true,
            "backend":"desktop ResultsStore; existing retained report verifiers",
            "scope":"Viewing/export only; no provider or execution route"
        })
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("The desktop retained Results backend requires Windows.");
    std::process::exit(1);
}
