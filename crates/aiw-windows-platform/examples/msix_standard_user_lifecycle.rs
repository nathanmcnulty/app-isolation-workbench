#[cfg(windows)]
fn main() {
    if let Err(error) = aiw_windows_platform::run_msix_standard_user_research_lifecycle() {
        eprintln!("Closed MSIX lifecycle failed: {error}");
        std::process::exit(1);
    }
}
#[cfg(not(windows))]
fn main() {
    eprintln!("This research lifecycle requires Windows Sandbox");
    std::process::exit(1);
}
