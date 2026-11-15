//! Default-off fixed probe/creation roles with disposable guest identity guards.
#[cfg(windows)]
fn main() -> std::process::ExitCode {
    match aiw_windows_platform::run_mxc_process_probe() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("MXC fixed research role refused: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Fixed Windows disposable-worker role required");
    std::process::exit(1);
}
