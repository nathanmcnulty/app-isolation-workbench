//! Fixed disposable-worker publisher control; never loads MXC or an application.
#![forbid(unsafe_code)]
#[cfg(all(windows, feature = "research-mxc-process"))]
#[allow(dead_code)]
#[path = "mxc_probe_trial/host.rs"]
mod host;

fn main() -> std::process::ExitCode {
    #[cfg(all(windows, feature = "research-mxc-process"))]
    return match host::run_publication() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}; preserve the publication transaction; never replay Start");
            std::process::ExitCode::FAILURE
        }
    };
    #[cfg(not(all(windows, feature = "research-mxc-process")))]
    {
        eprintln!("Windows and research-mxc-process are required; no operation.");
        std::process::ExitCode::FAILURE
    }
}
