#![forbid(unsafe_code)]
fn main() -> std::process::ExitCode {
    #[cfg(windows)]
    match aiw_windows_platform::run_msix_vm_worker() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("AIW_MSIX_WORKER_FAILED: {error}");
            std::process::ExitCode::FAILURE
        }
    }
    #[cfg(not(windows))]
    {
        eprintln!("AIW_MSIX_WORKER_WINDOWS_REQUIRED");
        std::process::ExitCode::FAILURE
    }
}
