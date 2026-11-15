//! Fixed disposable-worker feasibility driver. Not a production report/provider.
//! This executable never loads MXC on the host and never installs or launches 7-Zip.
#![forbid(unsafe_code)]

#[cfg(all(windows, feature = "research-mxc-process"))]
#[path = "mxc_probe_trial/host.rs"]
mod host;

fn main() -> std::process::ExitCode {
    #[cfg(all(windows, feature = "research-mxc-process"))]
    return match host::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}; preserve the fixed trial root and inspect the durable transaction");
            std::process::ExitCode::FAILURE
        }
    };
    #[cfg(not(all(windows, feature = "research-mxc-process")))]
    {
        eprintln!("This research example requires Windows and research-mxc-process; no operation.");
        std::process::ExitCode::FAILURE
    }
}
