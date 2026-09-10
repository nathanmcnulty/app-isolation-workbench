#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use aiw_token::TokenEvidence;
use clap::{Parser, ValueEnum};
use serde::Serialize;
use sha2::{Digest, Sha256};

const SCHEMA_VERSION: &str = "aiw.dev/control-fixture-report/v0alpha1";
const DOCUMENT_NAME: &str = "control-document.txt";
const CANARY_NAME: &str = "canary.txt";
const CHILD_TOKEN_NAME: &str = "child-token.json";
const INITIAL_DOCUMENT: &[u8] = b"AIW control fixture initial document\r\n";
const EDITED_DOCUMENT: &[u8] = b"AIW control fixture edited document\r\n";
const MAX_CANARY_BYTES: u64 = 1024;
const MAX_CHILD_STDOUT_BYTES: u64 = 16 * 1024;
const CHILD_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, ValueEnum, Serialize)]
#[serde(rename_all = "camelCase")]
enum Mode {
    RoundTrip,
    ReadCanary,
    Child,
    Token,
    ExpectedFailure,
    ChildToken,
}

#[derive(Parser)]
#[command(name = "aiw-control-fixture", disable_help_subcommand = true)]
struct Args {
    #[arg(long, value_enum)]
    mode: Mode,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FixtureReport {
    schema_version: &'static str,
    mode: Mode,
    own_process_token: TokenEvidence,
    result: FixtureResult,
}

#[derive(Serialize)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum FixtureResult {
    RoundTrip {
        initial_sha256: String,
        edited_sha256: String,
    },
    ReadCanary {
        outcome: CanaryOutcome,
    },
    Child {
        child_process_id: u32,
        child_stdout_bytes: u64,
        child_token: TokenEvidence,
    },
    Token,
    ExpectedFailure {
        code: &'static str,
        message: &'static str,
    },
    Error {
        code: &'static str,
        message: String,
    },
}

#[derive(Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum CanaryOutcome {
    Success {
        size_bytes: u64,
        sha256: String,
    },
    AccessDenied,
    NotFound,
    Error {
        raw_os_error: Option<i32>,
        message: String,
    },
}

fn main() -> ExitCode {
    let args = Args::parse();
    let own_process_token = match aiw_token::collect_current_process_token() {
        Ok(token) => token,
        Err(error) => {
            eprintln!("could not collect control fixture token: {error}");
            return ExitCode::FAILURE;
        }
    };
    let root = match std::env::current_dir() {
        Ok(root) => root,
        Err(error) => {
            eprintln!("could not resolve fixed fixture directory: {error}");
            return ExitCode::FAILURE;
        }
    };
    let (result, exit_code) = match run_mode(args.mode, &root) {
        Ok(result) => (result, ExitCode::SUCCESS),
        Err(error) => (
            FixtureResult::Error {
                code: "fixedOperationFailed",
                message: error,
            },
            ExitCode::FAILURE,
        ),
    };
    let exit_code = if matches!(result, FixtureResult::ExpectedFailure { .. }) {
        ExitCode::from(23)
    } else {
        exit_code
    };
    let report = FixtureReport {
        schema_version: SCHEMA_VERSION,
        mode: args.mode,
        own_process_token,
        result,
    };
    match serde_json::to_writer(std::io::stdout(), &report) {
        Ok(()) => {
            println!();
            exit_code
        }
        Err(error) => {
            eprintln!("could not serialize control fixture report: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_mode(mode: Mode, root: &Path) -> Result<FixtureResult, String> {
    match mode {
        Mode::RoundTrip => round_trip(root),
        Mode::ReadCanary => Ok(FixtureResult::ReadCanary {
            outcome: read_canary(&root.join(CANARY_NAME)),
        }),
        Mode::Child => child(root),
        Mode::Token => Ok(FixtureResult::Token),
        Mode::ExpectedFailure => Ok(FixtureResult::ExpectedFailure {
            code: "fixedExpectedFailure",
            message: "control fixture deliberately returned exit code 23",
        }),
        Mode::ChildToken => write_child_token(root),
    }
}

fn round_trip(root: &Path) -> Result<FixtureResult, String> {
    let path = root.join(DOCUMENT_NAME);
    write_new(&path, INITIAL_DOCUMENT)?;
    let initial = read_bounded(&path, INITIAL_DOCUMENT.len() as u64)
        .map_err(|error| format!("read fixed initial document failed: {error}"))?;
    if initial != INITIAL_DOCUMENT {
        return Err("fixed control document initial readback differed".to_owned());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .map_err(|error| format!("overwrite fixed control document failed: {error}"))?;
    file.write_all(EDITED_DOCUMENT)
        .map_err(|error| format!("write fixed edited document failed: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("flush fixed edited document failed: {error}"))?;
    let edited = read_bounded(&path, EDITED_DOCUMENT.len() as u64)
        .map_err(|error| format!("read fixed edited document failed: {error}"))?;
    if edited != EDITED_DOCUMENT {
        return Err("fixed control document edited readback differed".to_owned());
    }
    Ok(FixtureResult::RoundTrip {
        initial_sha256: sha256(INITIAL_DOCUMENT),
        edited_sha256: sha256(EDITED_DOCUMENT),
    })
}

fn read_canary(path: &Path) -> CanaryOutcome {
    match read_bounded(path, MAX_CANARY_BYTES) {
        Ok(bytes) => CanaryOutcome::Success {
            size_bytes: bytes.len() as u64,
            sha256: sha256(&bytes),
        },
        Err(error) if error.raw_os_error() == Some(5) => CanaryOutcome::AccessDenied,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => CanaryOutcome::NotFound,
        Err(error) => CanaryOutcome::Error {
            raw_os_error: error.raw_os_error(),
            message: error.to_string(),
        },
    }
}

fn child(root: &Path) -> Result<FixtureResult, String> {
    let child_token_path = root.join(CHILD_TOKEN_NAME);
    let executable = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|error| format!("canonicalize current fixture executable failed: {error}"))?;
    let mut child = Command::new(executable)
        .args(["--mode", "child-token"])
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("launch fixed child fixture failed: {error}"))?;
    let child_process_id = child.id();
    let deadline = Instant::now()
        .checked_add(CHILD_TIMEOUT)
        .ok_or("child timeout overflowed monotonic clock")?;
    let exit = loop {
        match child
            .try_wait()
            .map_err(|error| format!("observe fixed child failed: {error}"))?
        {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                child
                    .kill()
                    .map_err(|error| format!("terminate timed out fixed child failed: {error}"))?;
                let _ = child.wait();
                return Err("fixed child timed out and was terminated".to_owned());
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    };
    if !exit.success() {
        return Err(format!("fixed child exited with {exit}"));
    }
    let child_token_bytes = read_bounded(&child_token_path, MAX_CHILD_STDOUT_BYTES)
        .map_err(|error| format!("read fixed child token failed: {error}"))?;
    let child_token: TokenEvidence = serde_json::from_slice(&child_token_bytes)
        .map_err(|error| format!("parse fixed child token failed: {error}"))?;
    if child_token.process_id != child_process_id {
        return Err("fixed child token PID did not match retained child process handle".to_owned());
    }
    Ok(FixtureResult::Child {
        child_process_id,
        child_stdout_bytes: 0,
        child_token,
    })
}

fn write_child_token(root: &Path) -> Result<FixtureResult, String> {
    let bytes = serde_json::to_vec(
        &aiw_token::collect_current_process_token().map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("serialize fixed child token failed: {error}"))?;
    if bytes.len() as u64 > MAX_CHILD_STDOUT_BYTES {
        return Err("fixed child token exceeded 16 KiB bound".to_owned());
    }
    write_new(&root.join(CHILD_TOKEN_NAME), &bytes)?;
    Ok(FixtureResult::Token)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("create fixed fixture file failed: {error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("write fixed fixture file failed: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("flush fixed fixture file failed: {error}"))
}

fn read_bounded(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>, std::io::Error> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "fixed fixture file exceeded its bound or was not regular",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "fixed fixture file grew beyond its bound while being read",
        ));
    }
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("aiw-control-fixture-{name}-{}", std::process::id()));
        fs::create_dir(&root).expect("temporary fixture root should be created");
        root
    }

    #[test]
    fn round_trip_uses_fixed_new_document_and_exact_readback() {
        let root = temporary_root("round-trip");
        let result = round_trip(&root).expect("fixed round trip should pass");
        assert!(matches!(result, FixtureResult::RoundTrip { .. }));
        assert_eq!(fs::read(root.join(DOCUMENT_NAME)).unwrap(), EDITED_DOCUMENT);
        assert!(round_trip(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn read_canary_distinguishes_not_found_and_bounded_success() {
        let root = temporary_root("canary");
        assert!(matches!(
            read_canary(&root.join(CANARY_NAME)),
            CanaryOutcome::NotFound
        ));
        fs::write(root.join(CANARY_NAME), b"canary").unwrap();
        assert!(matches!(
            read_canary(&root.join(CANARY_NAME)),
            CanaryOutcome::Success { size_bytes: 6, .. }
        ));
        fs::write(root.join(CANARY_NAME), vec![0_u8; 1025]).unwrap();
        assert!(matches!(
            read_canary(&root.join(CANARY_NAME)),
            CanaryOutcome::Error { .. }
        ));
        fs::remove_dir_all(root).unwrap();
    }
}
