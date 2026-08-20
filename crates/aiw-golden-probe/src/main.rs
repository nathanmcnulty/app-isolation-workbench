#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aiw_token::collect_current_process_token;
use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "aiw-golden-probe",
    version,
    about = "Emit evidence from the token of this exact process"
)]
struct Cli {
    /// Format the evidence for human inspection.
    #[arg(long)]
    pretty: bool,

    /// Write to a new file instead of stdout. Existing evidence is never overwritten.
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let evidence = collect_current_process_token()?;
    match cli.output {
        Some(path) => {
            let mut output = create_output(&path)?;
            write_evidence(&mut output, &evidence, cli.pretty)?;
        }
        None => {
            let stdout = io::stdout();
            let mut lock = stdout.lock();
            write_evidence(&mut lock, &evidence, cli.pretty)?;
        }
    }
    Ok(())
}

fn create_output(path: &Path) -> io::Result<std::fs::File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

fn write_evidence(
    output: &mut impl Write,
    evidence: &aiw_token::TokenEvidence,
    pretty: bool,
) -> Result<()> {
    if pretty {
        serde_json::to_writer_pretty(&mut *output, evidence)?;
    } else {
        serde_json::to_writer(&mut *output, evidence)?;
    }
    output.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_create_new_and_never_overwritten() {
        let root = std::env::temp_dir().join(format!(
            "aiw-golden-probe-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should follow epoch")
                .as_nanos()
        ));
        std::fs::create_dir(&root).expect("test directory should be created");
        let output = root.join("evidence.json");
        drop(create_output(&output).expect("new output should be created"));
        assert_eq!(
            create_output(&output)
                .expect_err("existing output must be rejected")
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        std::fs::remove_dir_all(root).expect("test directory should be removed");
    }
}
