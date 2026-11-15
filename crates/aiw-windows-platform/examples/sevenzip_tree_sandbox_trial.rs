//! Closed disposable-worker first-party tree controls. No vendor execution.
#![forbid(unsafe_code)]

#[cfg(windows)]
#[path = "mxc_probe_trial/host.rs"]
#[allow(dead_code)]
mod host;

fn main() -> std::process::ExitCode {
    #[cfg(windows)]
    return match host::run_tree() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}; preserve the exact tree-control transaction");
            std::process::ExitCode::FAILURE
        }
    };
    #[cfg(not(windows))]
    std::process::ExitCode::FAILURE
}
