//! Fixed disposable-worker feasibility driver. Not a production report/provider.
//! This executable never installs or launches 7-Zip on the administrator host.
#![forbid(unsafe_code)]

#[cfg(all(windows, feature = "research-sevenzip"))]
#[path = "sevenzip_trial/host.rs"]
mod host;

fn main() -> std::process::ExitCode {
    #[cfg(all(windows, feature = "research-sevenzip"))]
    return match host::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}; preserve the fixed trial root and inspect the durable transaction");
            std::process::ExitCode::FAILURE
        }
    };
    #[cfg(not(all(windows, feature = "research-sevenzip")))]
    {
        eprintln!("This research example requires Windows and research-sevenzip; no operation.");
        std::process::ExitCode::FAILURE
    }
}
