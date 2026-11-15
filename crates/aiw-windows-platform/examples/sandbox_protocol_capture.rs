//! Explicit opt-in read-only provider research; no configurable commands or paths.
#[cfg(windows)]
fn main() -> std::process::ExitCode {
    if std::env::args_os().len() != 1 {
        eprintln!("This fixed capture accepts no arguments");
        return std::process::ExitCode::FAILURE;
    }
    match aiw_windows_platform::capture_windows_sandbox_protocol() {
        Ok(report) => match serde_json::to_writer(std::io::stdout().lock(), &report) {
            Ok(())
                if report["allCommandsCaptured"] == true
                    && report["heldProviderUnchanged"] == true =>
            {
                std::process::ExitCode::SUCCESS
            }
            Ok(()) => std::process::ExitCode::FAILURE,
            Err(error) => {
                eprintln!("Cannot write protocol observation: {error}");
                std::process::ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("Protocol observation refused: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Protocol observation requires Windows");
    std::process::exit(1);
}
