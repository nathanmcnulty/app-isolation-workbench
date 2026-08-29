#![deny(unsafe_op_in_unsafe_fn)]

use aiw_probe::WindowsSandboxReadiness;

#[cfg(windows)]
pub use windows_platform::{
    CanonicalSandboxId, WindowsSandboxExecutionLease, WindowsSandboxInvocationError,
    WsbConnectObservation, WsbListObservation, WsbStartObservation, WsbStopObservation,
};

#[cfg(windows)]
mod windows_platform;

#[must_use]
pub fn assess_windows_sandbox() -> WindowsSandboxReadiness {
    platform::assess_windows_sandbox()
}

#[cfg(windows)]
pub fn acquire_windows_sandbox(
    expected_provider_sha256: &str,
) -> Result<WindowsSandboxExecutionLease, WindowsSandboxInvocationError> {
    windows_platform::acquire_windows_sandbox(expected_provider_sha256)
}

#[cfg(windows)]
mod platform {
    pub(super) use super::windows_platform::assess_windows_sandbox;
}

#[cfg(not(windows))]
mod platform {
    use aiw_probe::{ReadinessState, WindowsSandboxReadiness};

    pub(super) fn assess_windows_sandbox() -> WindowsSandboxReadiness {
        WindowsSandboxReadiness {
            schema_version: "aiw.dev/windows-sandbox-readiness/v0alpha2".to_owned(),
            supported: false,
            os_build: None,
            process_architecture: std::env::consts::ARCH.to_owned(),
            virtualization: ReadinessState::Unknown,
            sandbox_feature: ReadinessState::Missing,
            provider_binary: None,
            provider_package: None,
            catalog_trust: None,
            provider_file_identity: None,
            cli_protocol: None,
            app_execution_alias: None,
            current_sessions: ReadinessState::Unknown,
            current_session_ids: Vec::new(),
            blockers: vec![
                "AIW_WINDOWS_REQUIRED: Windows Sandbox assessment is only available on Windows."
                    .to_owned(),
            ],
            warnings: vec![
                "Assessment never enables Windows features or installs providers.".to_owned(),
            ],
        }
    }
}
