#![deny(unsafe_op_in_unsafe_fn)]

use aiw_probe::WindowsSandboxReadiness;

#[cfg(windows)]
pub use windows_platform::{
    CanonicalSandboxId, WindowsSandboxExecutionLease, WindowsSandboxInvocationError,
    WsbConnectObservation, WsbListObservation, WsbStartObservation, WsbStopObservation,
};

#[cfg(windows)]
#[doc(hidden)]
pub use windows_platform::{
    WindowsSandboxRecoveryLease, WsbRecoveryDisposition, WsbRecoveryObservation,
};

#[cfg(windows)]
pub use workspace::{HeldRunWorkspace, WorkspaceError};

#[cfg(windows)]
pub use coordination::{
    RunCoordinationError, RunCoordinationKey, RunCoordinationLease, RunCoordinationMode,
    try_acquire_run_coordination,
};

#[cfg(windows)]
pub use discard_intent::{
    DISCARD_INTENT_BINDING_POLICY_VERSION, DISCARD_INTENT_BINDING_SCHEMA_VERSION,
    DiscardIntentBindingEvidence, DiscardIntentEaBinding, DiscardIntentEaEntry, DiscardIntentError,
    DiscardIntentStableId, HeldDiscardIntentPublication, PublishableDiscardIntent,
    ReopenedDiscardIntent, StagedDiscardIntent, reopen_prepared_discard_intent,
    reopen_published_discard_intent, stage_discard_intent,
};

#[cfg(windows)]
pub use discard_checkpoint::{
    DISCARD_CHECKPOINT_BINDING_POLICY_VERSION, DISCARD_CHECKPOINT_BINDING_SCHEMA_VERSION,
    DiscardCheckpointBindingEvidence, DiscardCheckpointError, ExistingDiscardCheckpoint,
    HeldDiscardCheckpointPublication, PublishableDiscardCheckpoint, ReopenedDiscardCheckpoint,
    ReservedDiscardCheckpoint, StagedDiscardCheckpoint, reopen_existing_discard_checkpoint,
    reopen_prepared_discard_checkpoint, reserve_discard_checkpoint,
};

#[cfg(windows)]
pub use depublish_commit::{
    DEPUBLISH_COMMIT_BINDING_POLICY_VERSION, DEPUBLISH_COMMIT_BINDING_SCHEMA_VERSION,
    DepublishCommitBindingEvidence, DepublishCommitError, ExistingDepublishCommit,
    HeldDepublishCommitPublication, LocatedDepublishCommit, PublishableDepublishCommit,
    ReopenedDepublishCommit, ReservedDepublishCommit, StagedDepublishCommit,
    locate_depublish_commit_from_persisted_root, reopen_existing_depublish_commit,
    reopen_prepared_depublish_commit, reserve_depublish_commit, stage_depublish_commit,
};

#[cfg(windows)]
#[doc(hidden)]
pub use exact_dispose::{
    ExactDisposeError, HeldCheckpointBoundWsbRoot, HeldFixedWsbCheckpointSnapshot,
    WsbRootDepublishObservation, WsbRootNamespaceState, classify_checkpoint_bound_wsb_root,
    hold_fixed_wsb_tree_for_checkpoint, observe_fixed_wsb_tree_for_checkpoint,
    reopen_checkpoint_bound_wsb_root, verify_fixed_wsb_tree_inventory,
};

pub use aiw_probe::WindowsFileIdentity as WorkspaceDirectoryIdentity;
pub use aiw_probe::WorkspaceBindingEvidence;

#[cfg(windows)]
mod coordination;

#[cfg(windows)]
mod discard_intent;

#[cfg(windows)]
mod discard_checkpoint;

#[cfg(windows)]
mod depublish_commit;

#[cfg(windows)]
#[allow(dead_code)]
// Private issue #30 benchmark; issue #28 will add the first authority-bearing
// in-crate consumer after its durable intent/checkpoint contract is reviewed.
mod exact_dispose;

#[cfg(windows)]
mod windows_platform;

#[cfg(windows)]
mod workspace;

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
#[doc(hidden)]
pub fn acquire_windows_sandbox_recovery(
    start_provider_sha256: &str,
    persisted_session: CanonicalSandboxId,
) -> Result<WindowsSandboxRecoveryLease, WindowsSandboxInvocationError> {
    windows_platform::acquire_windows_sandbox_recovery(start_provider_sha256, persisted_session)
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
