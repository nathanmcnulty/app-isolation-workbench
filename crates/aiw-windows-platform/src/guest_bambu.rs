//! Bounded native execution for the reviewed Bambu STL-to-3MF export.
//!
//! This is intentionally a profile-specific primitive.  It does not accept a
//! command, executable, or path from the caller and it never runs a guest
//! script.  The provider compiler remains the authority for the reviewed
//! scenario; this module only executes its fixed native stages.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use aiw_provider_wsb::{
    BAMBU_MAX_ARTIFACT_BYTES, BAMBU_STUDIO_EXPORT_OUTPUT_PATH, BambuExecutionStage,
    CompiledBambuExportScenario, StandardUserRuntimeContext,
};
use aiw_token::TokenEvidence;
use sha2::{Digest, Sha256};

use crate::guest_msi::{GuestMsiExecutionError, GuestProcess};
use crate::guest_standard_user::StandardUserSession;

const INSTALLER_PATH: &str = r"C:\AIW\Tools\application.exe";
const INSTALLER_TIMEOUT: Duration = Duration::from_secs(300);
const INSTALLER_ARGUMENTS: &[&str] = &["/S"];
const APPLICATION_PATH: &str = r"C:\Program Files\Bambu Studio\bambu-studio.exe";
const EXPORT_TIMEOUT: Duration = Duration::from_secs(60);
const EXPORT_ARGUMENT: &str = "--export-3mf";
const FIXTURE_RELATIVE_PATH: &str = r"Scenario\aiw-tetrahedron.stl";
const ARTIFACT_RELATIVE_PATH: &str = r"Scenario\aiw-tetrahedron.3mf";
const FIXTURE_PATH: &str =
    r"C:\Users\AiwStandardUser\AppData\Local\AIW\Scenario\aiw-tetrahedron.stl";
const FIXTURE_SHA256: &str = "2cb47e4cd9e465a162b4e60e6f15708f4ee15ef28477737c807283176a057450";
const FIXTURE_BYTES: &[u8] = include_bytes!("../../../fixtures/bambu-studio/aiw-tetrahedron.stl");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestBambuExecutionObservation {
    pub install_exit_code: i32,
    pub launch_process_id: u32,
    pub launch_exit_code: i32,
    pub application_token: TokenEvidence,
    pub standard_user_context: StandardUserRuntimeContext,
    pub artifact_bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct GuestBambuAttempt {
    /// Failed attempts never expose partial artifact bytes.  The guest
    /// dispatcher publishes the required zero-byte model placeholder while
    /// retaining the failed stage and diagnostic in the result.
    pub result: Result<GuestBambuExecutionObservation, String>,
    pub completed_stages: Vec<BambuExecutionStage>,
    pub failed_stage: Option<BambuExecutionStage>,
}

/// Executes the fixed Bambu export profile inside the guest.
///
/// Installation runs under the elevated guest agent.  The application and
/// fixture/export paths are then bound to the fresh standard-user profile;
/// process containment and cleanup are verified by `GuestProcess` before the
/// stage is recorded as complete.
pub fn execute_fixed_bambu_export_attempt(
    scenario: &CompiledBambuExportScenario,
) -> GuestBambuAttempt {
    if let Err(error) = scenario.validate() {
        return failed(None, error.to_string());
    }

    let mut completed_stages = Vec::new();
    let install = match execute_install() {
        Ok(code) => {
            completed_stages.push(BambuExecutionStage::Install);
            code
        }
        Err(error) => return failed_stage(completed_stages, BambuExecutionStage::Install, error),
    };

    let standard_user = match StandardUserSession::establish() {
        Ok(user) => user,
        Err(error) => {
            return failed_stage(
                completed_stages,
                BambuExecutionStage::PrepareFixture,
                error.to_string(),
            );
        }
    };
    let (fixture_path, artifact_path) = match prepare_fixture(&standard_user) {
        Ok(paths) => {
            completed_stages.push(BambuExecutionStage::PrepareFixture);
            paths
        }
        Err(error) => {
            return failed_stage(completed_stages, BambuExecutionStage::PrepareFixture, error);
        }
    };

    let (launch_process_id, launch_exit_code, application_token) =
        match execute_export(&standard_user, &fixture_path, &artifact_path) {
            Ok(observation) => {
                completed_stages.push(BambuExecutionStage::Export);
                observation
            }
            Err(error) => {
                return failed_stage(completed_stages, BambuExecutionStage::Export, error);
            }
        };

    let artifact_bytes = match read_export_artifact(&artifact_path) {
        Ok(bytes) => {
            completed_stages.push(BambuExecutionStage::CollectArtifact);
            bytes
        }
        Err(error) => {
            return failed_stage(
                completed_stages,
                BambuExecutionStage::CollectArtifact,
                error,
            );
        }
    };

    GuestBambuAttempt {
        result: Ok(GuestBambuExecutionObservation {
            install_exit_code: install,
            launch_process_id,
            launch_exit_code,
            application_token,
            standard_user_context: standard_user.context().clone(),
            artifact_bytes,
        }),
        completed_stages,
        failed_stage: None,
    }
}

fn execute_install() -> Result<i32, String> {
    let installer = GuestProcess::start(
        INSTALLER_PATH,
        &INSTALLER_ARGUMENTS
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect::<Vec<_>>(),
    )
    .map_err(|error| error.to_string())?;
    let started = Instant::now();
    let operation = installer.wait_for_exit(INSTALLER_TIMEOUT);
    let wait_diagnostic = operation.is_err().then(|| {
        let entrypoint = match fs::symlink_metadata(APPLICATION_PATH) {
            Ok(metadata) if metadata.is_file() => format!("regular file, {} bytes", metadata.len()),
            Ok(_) => "present but not a regular file".to_owned(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => "absent".to_owned(),
            Err(error) => format!("metadata unavailable: {:?}", error.kind()),
        };
        format!(
            "installer pid={}, elapsedMs={}, jobProcesses={:?}, jobProcessImages={:?}, fixed entrypoint={entrypoint}",
            installer.process_id(),
            started.elapsed().as_millis(),
            installer.active_processes(),
            installer.diagnostic_processes()
        )
    });
    let cleanup = if operation.is_ok() {
        installer.verify_empty_after_success()
    } else {
        installer.cleanup()
    };
    let exit_code = complete_process(operation, cleanup).map_err(|error| {
        if let Some(diagnostic) = wait_diagnostic {
            format!("{error}; {diagnostic}")
        } else {
            error
        }
    })?;
    if exit_code != 0 {
        return Err(format!("fixed Bambu installer exited with {exit_code}"));
    }
    Ok(exit_code)
}

fn prepare_fixture(user: &StandardUserSession) -> Result<(String, String), String> {
    if user.context().user_sid.is_empty()
        || user.context().administrators_enabled
        || !user
            .context()
            .profile_path
            .eq_ignore_ascii_case(r"C:\Users\AiwStandardUser")
        || !user
            .context()
            .local_app_data
            .eq_ignore_ascii_case(r"C:\Users\AiwStandardUser\AppData\Local")
    {
        return Err("standard-user context was outside the fixed Bambu profile".to_owned());
    }
    if hex::encode(Sha256::digest(FIXTURE_BYTES)) != FIXTURE_SHA256 {
        return Err("embedded Bambu fixture hash did not match the fixed profile".to_owned());
    }
    let root = user.document_root();
    let fixture_path = root.join(FIXTURE_RELATIVE_PATH);
    let artifact_path = root.join(ARTIFACT_RELATIVE_PATH);
    user.impersonate(|| {
        fs::create_dir_all(root.join("Scenario")).map_err(|error| {
            GuestMsiExecutionError::Process(format!(
                "create fixed Bambu scenario directory failed: {error}"
            ))
        })?;
        let mut fixture = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&fixture_path)
            .map_err(|error| {
                GuestMsiExecutionError::Process(format!(
                    "create fixed Bambu STL fixture failed: {error}"
                ))
            })?;
        fixture.write_all(FIXTURE_BYTES).map_err(|error| {
            GuestMsiExecutionError::Process(format!(
                "write fixed Bambu STL fixture failed: {error}"
            ))
        })?;
        fixture.sync_all().map_err(|error| {
            GuestMsiExecutionError::Process(format!(
                "flush fixed Bambu STL fixture failed: {error}"
            ))
        })?;
        drop(fixture);
        Ok(())
    })
    .map_err(|error| error.to_string())?;
    ensure_regular_nonreparse(&fixture_path)?;
    let fixture_path = path_string(&fixture_path)?;
    let artifact_path = path_string(&artifact_path)?;
    if !fixture_path.eq_ignore_ascii_case(FIXTURE_PATH)
        || !artifact_path.eq_ignore_ascii_case(BAMBU_STUDIO_EXPORT_OUTPUT_PATH)
    {
        return Err("fixed Bambu paths differed from the compiled export profile".to_owned());
    }
    Ok((fixture_path, artifact_path))
}

fn execute_export(
    user: &StandardUserSession,
    fixture_path: &str,
    artifact_path: &str,
) -> Result<(u32, i32, TokenEvidence), String> {
    let arguments = vec![
        EXPORT_ARGUMENT.to_owned(),
        artifact_path.to_owned(),
        fixture_path.to_owned(),
    ];
    let application = GuestProcess::start_standard_user(APPLICATION_PATH, &arguments, user)
        .map_err(|error| error.to_string())?;
    let launch_process_id = application.process_id();
    let application_token = match application.collect_token() {
        Ok(token) => token,
        Err(error) => {
            let cleanup = application.cleanup();
            return Err(format!("{error}; cleanup={cleanup:?}"));
        }
    };
    if application_token.process_id != launch_process_id {
        let cleanup = application.cleanup();
        return Err(format!(
            "Bambu token process identity differed from launch process; cleanup={cleanup:?}"
        ));
    }
    if let Err(error) = user.context().validate_token(&application_token) {
        let cleanup = application.cleanup();
        return Err(format!(
            "Bambu standard-user token failed validation: {error}; cleanup={cleanup:?}"
        ));
    }
    let operation = application.wait_for_exit(EXPORT_TIMEOUT);
    let cleanup = if operation.is_ok() {
        application.verify_empty_after_success()
    } else {
        application.cleanup()
    };
    let launch_exit_code = complete_process(operation, cleanup)?;
    if launch_exit_code != 0 {
        return Err(format!("fixed Bambu export exited with {launch_exit_code}"));
    }
    Ok((launch_process_id, launch_exit_code, application_token))
}

fn read_export_artifact(path: &str) -> Result<Vec<u8>, String> {
    let path = Path::new(path);
    ensure_regular_nonreparse(path)?;
    let metadata_before = fs::metadata(path)
        .map_err(|error| format!("stat fixed Bambu export artifact failed: {error}"))?;
    if metadata_before.len() > BAMBU_MAX_ARTIFACT_BYTES {
        return Err("fixed Bambu export artifact exceeded the 1 MiB bound".to_owned());
    }
    #[cfg(windows)]
    use std::os::windows::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .read(true)
        // OPEN_REPARSE_POINT keeps the read bound to a regular file and
        // refuses to traverse a link at the final path component.
        .custom_flags(0x0020_0000)
        .open(path)
        .map_err(|error| format!("open fixed Bambu export artifact failed: {error}"))?;
    let mut bytes = Vec::with_capacity(metadata_before.len() as usize);
    std::io::Read::by_ref(&mut file)
        .take(BAMBU_MAX_ARTIFACT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read fixed Bambu export artifact failed: {error}"))?;
    if bytes.len() as u64 > BAMBU_MAX_ARTIFACT_BYTES {
        return Err("fixed Bambu export artifact exceeded the 1 MiB bound".to_owned());
    }
    let metadata_after = fs::metadata(path)
        .map_err(|error| format!("restat fixed Bambu export artifact failed: {error}"))?;
    if metadata_before.len() != metadata_after.len() {
        return Err("fixed Bambu export artifact changed while being read".to_owned());
    }
    ensure_regular_nonreparse(path)?;
    Ok(bytes)
}

fn ensure_regular_nonreparse(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect fixed Bambu path failed: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("fixed Bambu artifact path was not a regular file".to_owned());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("fixed Bambu artifact path was a reparse point".to_owned());
        }
    }
    Ok(())
}

fn path_string(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| "fixed Bambu path was not valid UTF-8".to_owned())
}

fn complete_process<T>(
    operation: Result<T, GuestMsiExecutionError>,
    cleanup: Result<(), GuestMsiExecutionError>,
) -> Result<T, String> {
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(operation), Ok(())) => Err(operation.to_string()),
        (Ok(_), Err(cleanup)) => Err(cleanup.to_string()),
        (Err(operation), Err(cleanup)) => Err(format!(
            "{operation}; containment cleanup also failed: {cleanup}"
        )),
    }
}

fn failed(failed_stage: Option<BambuExecutionStage>, error: String) -> GuestBambuAttempt {
    GuestBambuAttempt {
        result: Err(error),
        completed_stages: Vec::new(),
        failed_stage,
    }
}

fn failed_stage(
    completed_stages: Vec<BambuExecutionStage>,
    failed_stage: BambuExecutionStage,
    error: String,
) -> GuestBambuAttempt {
    GuestBambuAttempt {
        result: Err(error),
        completed_stages,
        failed_stage: Some(failed_stage),
    }
}
