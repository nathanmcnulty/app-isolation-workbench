//! Native fixed guest setup/collection. No host callers can select executables,
//! scripts, resources, accounts, profile names or policy fragments.
use crate::guest_document::paired_controls::FixedPairedResources;
use crate::guest_msi::GuestProcess;
use crate::guest_standard_user::StandardUserSession;
use crate::{HeldApplicationFile, PairedLauncherAttempt};
use aiw_probe::ControlEvidenceOrigin;
use aiw_provider_wsb::{
    PairedControlResult, PairedControlsRequest, paired_controls::PAIRED_CONTROL_RESULT_SCHEMA,
};
use std::path::Path;
use std::time::Duration;

const AGENT: &str = r"C:\AIW\Tools\aiw-guest-agent.exe";
const FIXTURE_INPUT: &str = r"C:\AIW\Tools\aiw-control-fixture.exe";
const LAUNCHER_INPUT: &str = r"C:\AIW\Tools\aiw-control-appcontainer.exe";
const FIXTURE: &str = r"C:\AIW\Control\aiw-control-fixture.exe";
const LAUNCHER: &str = r"C:\AIW\Control\aiw-control-appcontainer.exe";
const OBSERVATION: &str = r"C:\AIW\Control\paired-launcher.json";

pub enum PairedGuestOutcome {
    Completed(Box<PairedControlResult>),
    DriverIncomplete {
        progress: Vec<aiw_provider_wsb::paired_controls::PairedCaseProgress>,
        launcher_token: aiw_token::TokenEvidence,
    },
}

pub fn execute_fixed_paired_controls(
    request: &PairedControlsRequest,
) -> Result<PairedGuestOutcome, String> {
    request.validate()?;
    request.profile.validate()?;
    // Fail before account, filesystem, registry or process mutations. Synthetic
    // requests are supported by fake transport only, never this native boundary.
    if request.profile.origin != ControlEvidenceOrigin::NativeWorker
        || std::env::current_exe().map_err(|e| e.to_string())? != Path::new(AGENT)
        || !std::env::var("USERNAME")
            .unwrap_or_default()
            .eq_ignore_ascii_case("WDAGUtilityAccount")
    {
        return Err("fixed elevated Sandbox agent and native-worker origin required".into());
    }
    let token = aiw_token::collect_current_process_token().map_err(|e| e.to_string())?;
    if !token.is_elevated
        || token.is_app_container
        || token.user_sid
            != crate::control_appcontainer::fixed_account_sid("WDAGUtilityAccount")
                .map_err(|e| e.to_string())?
    {
        return Err("paired setup requires the elevated guest token".into());
    }
    let windows = crate::observe_windows_version().map_err(|e| e.to_string())?;
    require_approved_windows(&windows, &request.profile.expected_windows)?;
    let inputs = [
        hold_role(AGENT, request)?,
        hold_role(FIXTURE_INPUT, request)?,
        hold_role(LAUNCHER_INPUT, request)?,
    ];
    let user = StandardUserSession::establish().map_err(|e| e.to_string())?;
    let resources = FixedPairedResources::prepare(&user.context().user_sid)?;
    resources.stage_roles()?;
    let roles = [hold_role(FIXTURE, request)?, hold_role(LAUNCHER, request)?];
    for input in &inputs {
        input.revalidate().map_err(|e| e.to_string())?;
    }
    let (launcher, held_token) = GuestProcess::start_standard_user_measured(
        LAUNCHER,
        &["--paired-control-launcher".into()],
        &user,
    )
    .map_err(|e| e.to_string())?;
    let exit = launcher.wait_for_exit(Duration::from_secs(120));
    let cleanup = if exit.is_ok() {
        launcher.verify_empty_after_success()
    } else {
        launcher.cleanup()
    };
    cleanup.map_err(|e| e.to_string())?;
    let exit = exit.map_err(|e| e.to_string())?;
    if exit != 0 {
        return Err(format!("fixed paired launcher failed with exit {exit}"));
    }
    let observation = HeldApplicationFile::open_bounded(Path::new(OBSERVATION), 64 * 1024)
        .map_err(|e| e.to_string())?;
    let bytes = std::fs::read(OBSERVATION).map_err(|e| e.to_string())?;
    observation.revalidate().map_err(|e| e.to_string())?;
    let observation: PairedLauncherAttempt =
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if held_token != observation.launcher_token
        || held_token.process_id != launcher.process_id()
        || held_token.user_sid != user.context().user_sid
    {
        return Err("paired helper self token differs from held launcher token".into());
    }
    aiw_provider_wsb::paired_controls::validate_paired_progress(&observation.progress)?;
    let progress = observation.progress;
    let mut failure =
        aiw_provider_wsb::paired_controls::PairedControlDriverFailure::for_request(request)?;
    failure.progress = progress.clone();
    failure.launcher_token = Some(held_token.clone());
    failure.validate(request)?;
    let Some(observation) = observation.observation else {
        return Ok(PairedGuestOutcome::DriverIncomplete {
            progress,
            launcher_token: held_token,
        });
    };
    let partial_token = held_token.clone();
    let complete = (|| {
        let (resources, file_unchanged, registry_value_unchanged) = resources.observation()?;
        let fixture_unchanged = roles[0].revalidate().is_ok() && inputs[1].revalidate().is_ok();
        let launcher_unchanged = roles[1].revalidate().is_ok() && inputs[2].revalidate().is_ok();
        let result = PairedControlResult {
            schema_version: PAIRED_CONTROL_RESULT_SCHEMA.into(),
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            request_sha256: request.request_sha256.clone(),
            profile_sha256: request.profile.hash()?,
            origin: request.profile.origin,
            windows,
            launcher_id: launcher.process_id(),
            launcher_token: held_token,
            user_sid: user.context().user_sid.clone(),
            package_sid: observation.package_sid,
            baseline: observation.baseline,
            candidate: observation.candidate,
            fixture_unchanged,
            launcher_unchanged,
            file_unchanged,
            file_acl_unchanged: resources.file_dacl_before_sha256
                == resources.file_dacl_after_sha256,
            registry_value_unchanged,
            registry_acl_unchanged: resources.registry_dacl_before_sha256
                == resources.registry_dacl_after_sha256,
            resources,
            profile_deleted: Some(observation.profile_deleted),
            driver_complete: true,
        };
        // This validates all individual native observations but cannot assert the
        // outer Sandbox cleanup, which the host verifies under its execution lease.
        result.compare(request, None)?;
        if progress.len() != 6
            || result.launcher_token != observation.launcher_token
            || !progress_matches_variant(&progress[..3], &result.baseline)
            || !progress_matches_variant(&progress[3..], &result.candidate)
        {
            return Err("full paired observation differs from measured case prefix".into());
        }
        Ok::<_, String>(result)
    })();
    Ok(match complete {
        Ok(result) => PairedGuestOutcome::Completed(Box::new(result)),
        Err(_) => PairedGuestOutcome::DriverIncomplete {
            progress,
            launcher_token: partial_token,
        },
    })
}
fn require_approved_windows(
    observed: &aiw_probe::WindowsVersionObservation,
    expected: &aiw_probe::WindowsVersionObservation,
) -> Result<(), String> {
    if observed != expected {
        return Err(format!(
            "paired guest environment differs from approved profile: expected {}.{}.{}.{} / {}; observed {}.{}.{}.{} / {}",
            expected.major,
            expected.minor,
            expected.build,
            expected.revision,
            expected.observer_architecture,
            observed.major,
            observed.minor,
            observed.build,
            observed.revision,
            observed.observer_architecture,
        ));
    }
    Ok(())
}

fn hold_role(path: &str, request: &PairedControlsRequest) -> Result<HeldApplicationFile, String> {
    let file = HeldApplicationFile::open_bounded(Path::new(path), 128 * 1024 * 1024)
        .map_err(|e| e.to_string())?;
    if file.observation().sha256 != request.agent_sha256
        || file.observation().size_bytes != request.profile.fixture_size_bytes
    {
        return Err("fixed paired executable differs from approved exact agent bytes".into());
    }
    Ok(file)
}

fn progress_matches_variant(
    progress: &[aiw_provider_wsb::paired_controls::PairedCaseProgress],
    value: &aiw_provider_wsb::PairedVariant,
) -> bool {
    progress.len() == 3
        && progress[0].process == value.file_process
        && progress[0].observation.read.as_ref() == Some(&value.file)
        && progress[1].process == value.registry_process
        && progress[1].observation.read.as_ref() == Some(&value.registry)
        && progress[2].process == value.child_process
        && progress[2].observation.child_id == value.child_id
        && progress[2].observation.child_token == value.child_token
        && progress[2].observation.child_stdout_bytes == value.child_stdout_bytes
        && progress[2].observation.outcome == value.child_outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_windows_mismatch_retains_exact_versions_without_accepting_drift() {
        let expected = aiw_probe::WindowsVersionObservation {
            major: 10,
            minor: 0,
            build: 26300,
            revision: 9711,
            observer_architecture: "x86_64".into(),
        };
        assert!(require_approved_windows(&expected, &expected).is_ok());
        for field in 0..5 {
            let mut observed = expected.clone();
            match field {
                0 => observed.major += 1,
                1 => observed.minor += 1,
                2 => observed.build += 1,
                3 => observed.revision += 1,
                _ => observed.observer_architecture = "aarch64".into(),
            }
            let error = require_approved_windows(&observed, &expected).unwrap_err();
            assert!(error.contains("expected 10.0.26300.9711 / x86_64; observed "));
            assert!(error.contains(&format!(
                "{}.{}.{}.{} / {}",
                observed.major,
                observed.minor,
                observed.build,
                observed.revision,
                observed.observer_architecture,
            )));
        }
    }
}
