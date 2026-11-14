//! One-shot first-party environment observation in the authorized existing VM.
#![forbid(unsafe_code)]
#[cfg(windows)]
#[path = "environment_trial/host.rs"]
mod host;
fn main() -> std::process::ExitCode {
    #[cfg(windows)]
    return match host::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}; preserve the exact environment-probe transaction");
            std::process::ExitCode::FAILURE
        }
    };
    #[cfg(not(windows))]
    std::process::ExitCode::FAILURE
}
