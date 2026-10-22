//! Closed disposable-Sandbox research control, excluded from production builds.
#[cfg(windows)]
fn main() {
    if let Err(error) = aiw_windows_platform::run_msix_standard_user_research_control() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
#[cfg(not(windows))]
fn main() {
    eprintln!("This control requires Windows Sandbox");
    std::process::exit(1);
}
