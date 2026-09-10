#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FailedControlRecord {
    schema_version: &'static str,
    production_evidence: bool,
    status: &'static str,
    stage: &'static str,
    message: String,
}

#[cfg(windows)]
fn main() -> ExitCode {
    match aiw_windows_platform::execute_fixed_control_appcontainer() {
        Ok(observation) => match serde_json::to_vec(&observation) {
            Ok(bytes) if bytes.len() <= 48 * 1024 => {
                if let Err(error) = std::io::stdout().write_all(&bytes) {
                    eprintln!("could not write fixed AppContainer control result: {error}");
                    return ExitCode::FAILURE;
                }
                println!();
                ExitCode::SUCCESS
            }
            Ok(_) | Err(_) => {
                write_failed("fixed AppContainer control result exceeded the 48 KiB JSON bound");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            write_failed(&error.to_string());
            ExitCode::FAILURE
        }
    }
}

#[cfg(windows)]
fn write_failed(message: &str) {
    let record = FailedControlRecord {
        schema_version: "aiw.dev/research/control-appcontainer/v0alpha1",
        production_evidence: false,
        status: "error",
        stage: "launcher",
        message: message.to_owned(),
    };
    let _ = serde_json::to_writer(std::io::stdout(), &record);
    println!();
}

#[cfg(not(windows))]
fn main() -> ExitCode {
    eprintln!("aiw-control-appcontainer is only available on Windows");
    ExitCode::FAILURE
}
