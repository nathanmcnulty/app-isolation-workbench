//! Default-off diagnostic role, requiring the fixed standard-user guest identity.
#[cfg(windows)]
fn main() -> std::process::ExitCode {
    match aiw_windows_platform::run_mxc_process_probe() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("MXC request probe refused: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Fixed Windows disposable-worker role required");
    std::process::exit(1);
}
