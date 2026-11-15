//! Closed, default-off environment observer. No vendor application execution.
#[cfg(windows)]
fn main() -> std::process::ExitCode {
    match aiw_windows_platform::environment_probe::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Environment observation refused: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Fixed Windows disposable-worker role required");
    std::process::exit(1);
}
