//! Explicit opt-in disposable-worker research. Never run on the administrator host.
#[cfg(windows)]
fn main() -> std::process::ExitCode {
    match aiw_windows_platform::run_sevenzip_research() {
        Ok(code) => std::process::ExitCode::from(code),
        Err(error) => {
            eprintln!("7-Zip research driver failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("7-Zip research requires the fixed disposable Windows Sandbox worker");
    std::process::exit(1);
}
