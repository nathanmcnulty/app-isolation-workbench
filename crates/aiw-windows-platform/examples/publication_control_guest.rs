//! Default-off fixed mapped-output publication control; no application dispatch.
#[cfg(windows)]
fn main() -> std::process::ExitCode {
    match aiw_windows_platform::research_publication::run_control() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Publication control refused: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Fixed Windows disposable-worker role required");
    std::process::exit(1);
}
