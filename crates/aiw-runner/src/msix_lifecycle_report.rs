//! Read-only projection of a reviewed historical research result, not a live
//! execution adapter or a second lifecycle verdict engine. The independently
//! reviewed archive digest is compiled in; caller-supplied hashes cannot enroll
//! new evidence. Native/controller terminal acceptance remains authoritative.
use crate::ApplicationReportFunctions;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Cursor, Read},
    path::Path,
};

const ARCHIVE_SHA: &str = "768e9ade771bbc3345067c82745c15f2d7c0ed31c4c8e281d437d14a27c321b3";
const BUNDLE_SHA: &str = "105f17f381730592a03414f923d7b17a988d5365398a7a225d61faaf6d193f4c";
const SOURCE: &str = "16ba49bfa399e38d29dfd468b90439deb6a9f4eb";
const NATIVE: &str = "206f439c87a73d7d3bed55dfc90f50834afc5e5ae1442e7b8a6e1732d8d9d4d6";
const NONCE: &str = "72f841670a4a6596636cffa2cd427cb1a765dcdc391a664a634ef22c130781e2";
const UUID: &str = "e5cecc90-35c2-4831-bf9c-424be23f7d4e";
const ROOT: &str = "0/standard-user-lifecycle/";
const STAGES: &str = "0/standard-user-lifecycle/msix-lifecycle/";
const ARCHIVE_BYTES: u64 = 285340;
const MAX_ENTRY: u64 = 4 * 1024 * 1024;
const MAX_TOTAL: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum MsixResearchProfile {
    Worker107NotepadR5,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MsixEvidenceReference {
    pub archive_entry: String,
    pub sha256: String,
    pub bytes: usize,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MsixApplicationIdentity {
    pub name: String,
    pub version: String,
    pub portable_source_sha256: String,
    pub removed_configuration_file: String,
    pub removed_configuration_file_sha256: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MsixPackageObservation {
    pub signed_sha256: String,
    pub publisher: String,
    pub full_name: String,
    pub family_name: String,
    pub install_location: String,
    pub delivery_model: aiw_schema::DeliveryModel,
    pub runtime_boundary: aiw_schema::RuntimeBoundary,
    pub observed_process_id: u64,
    pub observed_user_sid: String,
    pub observed_session_id: u64,
    pub observed_integrity_sid: String,
    pub observed_elevated: bool,
    pub observed_app_container: bool,
    pub identity_verified_before_resume: bool,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MsixConfigurationObservation {
    pub observed_path: String,
    pub retained_evidence: MsixEvidenceReference,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MsixLifecycleReport {
    pub schema_version: String,
    pub profile: MsixResearchProfile,
    pub archive_sha256: String,
    pub source_commit: String,
    pub bundle_sha256: String,
    pub native_sha256: String,
    pub worker_uuid: String,
    pub run_nonce: String,
    pub observed_windows_build: String,
    pub research_only: bool,
    pub lifecycle_completed: bool,
    pub functions: ApplicationReportFunctions,
    pub source_application: MsixApplicationIdentity,
    pub package: MsixPackageObservation,
    pub document: MsixEvidenceReference,
    pub configuration: Vec<MsixConfigurationObservation>,
    pub unchanged_payload_files: u64,
    pub registration_cleanup_verified: bool,
    pub install_location_absent: bool,
    pub recorded_process_job_task_cleanup_verified: bool,
    pub user_data_deletion: String,
    pub edit_method: String,
    pub evidence: Vec<MsixEvidenceReference>,
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Reads from one bounded snapshot of an opened file. No extraction, execution,
/// worker connection or freshness claim. A renamed/recompressed/modified archive
/// is deliberately not the reviewed artifact.
pub fn report_msix_lifecycle(
    path: &Path,
    profile: MsixResearchProfile,
) -> Result<MsixLifecycleReport, String> {
    let file = File::open(path).map_err(|_| "MSIX archive unreadable")?;
    if !file
        .metadata()
        .map_err(|_| "MSIX archive metadata unavailable")?
        .is_file()
    {
        return Err("MSIX archive must be a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(ARCHIVE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "MSIX archive read failed")?;
    report_bytes(&bytes, profile)
}

fn report_bytes(bytes: &[u8], profile: MsixResearchProfile) -> Result<MsixLifecycleReport, String> {
    // This gate precedes ZIP/JSON parsing. Review of additional profiles is a
    // source change; self-asserted export.json or a success-shaped ZIP is no authority.
    if bytes.len() as u64 != ARCHIVE_BYTES || digest(bytes) != ARCHIVE_SHA {
        return Err("MSIX archive is not the independently reviewed worker107 r5 artifact".into());
    }
    let files = read_zip(bytes)?;
    project_reviewed(&files, profile)
}

fn read_zip(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut zip =
        zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| "Invalid MSIX evidence ZIP")?;
    if zip.len() != 118 {
        return Err("MSIX evidence entry count differs".into());
    }
    let mut files = BTreeMap::new();
    let mut total = 0;
    for index in 0..zip.len() {
        let mut entry = zip
            .by_index(index)
            .map_err(|_| "Unreadable MSIX evidence entry")?;
        let name = entry
            .name()
            .map_err(|_| "Invalid MSIX evidence entry name")?
            .into_owned();
        if entry.is_dir()
            || entry.size() > MAX_ENTRY
            || name.contains(['\\', ':'])
            || name
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || entry
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            return Err("Unsafe MSIX evidence entry".into());
        }
        let mut data = Vec::new();
        entry
            .by_ref()
            .take(MAX_ENTRY + 1)
            .read_to_end(&mut data)
            .map_err(|_| "MSIX evidence read failed")?;
        total += data.len() as u64;
        if data.len() as u64 > MAX_ENTRY || total > MAX_TOTAL || files.insert(name, data).is_some()
        {
            return Err("MSIX evidence bound or unique-name check failed".into());
        }
    }
    Ok(files)
}

fn data<'a>(files: &'a BTreeMap<String, Vec<u8>>, name: &str) -> Result<&'a [u8], String> {
    files
        .get(name)
        .map(Vec::as_slice)
        .ok_or_else(|| format!("Required MSIX evidence absent: {name}"))
}
fn json(files: &BTreeMap<String, Vec<u8>>, name: &str) -> Result<Value, String> {
    let bytes = data(files, name)?;
    // Windows PowerShell 5.1 emits UTF-8 BOMs. Keep original bytes for hashes;
    // match the native reader's decoding without normalizing retained evidence.
    serde_json::from_slice(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes))
        .map_err(|_| format!("Malformed MSIX receipt: {name}"))
}
fn text(value: &Value, key: &str) -> Result<String, String> {
    value[key]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("MSIX receipt missing text: {key}"))
}
fn number(value: &Value, key: &str) -> Result<u64, String> {
    value[key]
        .as_u64()
        .ok_or_else(|| format!("MSIX receipt missing integer: {key}"))
}
fn reference(
    files: &BTreeMap<String, Vec<u8>>,
    name: &str,
) -> Result<MsixEvidenceReference, String> {
    let bytes = data(files, name)?;
    Ok(MsixEvidenceReference {
        archive_entry: name.into(),
        sha256: digest(bytes),
        bytes: bytes.len(),
    })
}

fn project_reviewed(
    files: &BTreeMap<String, Vec<u8>>,
    profile: MsixResearchProfile,
) -> Result<MsixLifecycleReport, String> {
    if files.keys().any(|name| name.ends_with("failure.json")) {
        return Err("Failed research cannot be promoted".into());
    }
    let bundle = json(files, "worker/bundle.json")?;
    let account = json(files, "worker/account.json")?;
    if digest(data(files, "worker/bundle.json")?) != BUNDLE_SHA
        || bundle["sourceCommit"] != SOURCE
        || bundle["driverSha256"] != NATIVE
        || bundle["workerUuid"] != UUID
        || account["vmId"] != UUID
        || account["runNonce"] != NONCE
    {
        return Err("Reviewed MSIX provenance differs".into());
    }
    // Project the accepted native/controller results rather than reconstructing
    // success from exit codes. Missing terminal/cleanup receipts never pass.
    for operation in ["Control", "Trial"] {
        let outer = json(files, &format!("worker/{operation}.result.json"))?;
        let controller = &outer["controller"];
        if outer["passed"] != true
            || outer["runNonce"] != NONCE
            || controller["nonce"] != NONCE
            || controller["vmId"] != UUID
            || controller["result"]["actionExitCode"] != 0
        {
            return Err("MSIX controller terminal acceptance missing".into());
        }
        for key in [
            "instanceAbsent",
            "taskAbsent",
            "actionExited",
            "nativeExitConfirmed",
        ] {
            if controller["cleanup"][key] != true {
                return Err("MSIX controller cleanup incomplete".into());
            }
        }
        let key = if operation == "Trial" {
            "nativeLifecycle"
        } else {
            "nativeControl"
        };
        let native = &controller["result"][key];
        if native["nonce"] != NONCE
            || native["wrapper"]["exitCode"] != 0
            || native["wrapper"]["terminalReceiptPresent"] != true
            || native["result"]["passed"] != true
            || native["result"]["jobEmpty"] != true
        {
            return Err("MSIX native terminal acceptance missing".into());
        }
    }
    let stage = |name: &str| json(files, &format!("{STAGES}{name}"));
    let result = stage("result.json")?;
    let cleanup = stage("cleanup.json")?;
    let job = json(files, &format!("{ROOT}job-cleanup.json"))?;
    if result["completed"] != true
        || result["researchOnly"] != true
        || result["documentWorkflow"] != "exactBytesVerified"
        || result["payloadUnchanged"] != true
        || result["registrationCleanup"] != "verified"
        || result["isolation"] != "notMeasured"
        || cleanup["registrationAbsent"] != true
        || cleanup["applicationProcessesAbsent"] != true
        || cleanup["installLocationPresent"] != false
        || job["activeJobProcesses"] != 0
    {
        return Err("MSIX lifecycle terminal/cleanup receipt incomplete".into());
    }
    for key in [
        "beforeInventoryError",
        "cleanupError",
        "externalInventoryError",
        "normalCleanupError",
        "operationError",
        "readbackError",
    ] {
        if !job.get(key).is_some_and(Value::is_null) {
            return Err("MSIX job cleanup error or missing readback".into());
        }
    }
    let parent = json(files, &format!("{ROOT}parent-after.json"))?;
    for array in [
        &parent["packages"],
        &parent["provisioned"],
        &parent["processes"]["matches"],
        &parent["processes"]["queryErrors"],
    ] {
        if !array.as_array().is_some_and(Vec::is_empty) {
            return Err("Privileged MSIX absence readback incomplete".into());
        }
    }
    let assembly = json(files, "worker/assembly.json")?;
    let input = stage("package-input.json")?;
    let installed = stage("installed.json")?;
    let activated = stage("activated.json")?;
    let token = &activated["packageObservation"];
    let worker = stage("worker.json")?;
    let configurations = stage("config-after.json")?;
    let configuration = configurations
        .as_array()
        .ok_or("MSIX configuration inventory missing")?
        .iter()
        .map(|file| {
            let entry = format!("{STAGES}{}", text(file, "retainedFile")?);
            let retained = reference(files, &entry)?;
            if file["sha256"] != retained.sha256 || file["sizeBytes"] != retained.bytes {
                return Err("MSIX configuration content differs".into());
            }
            Ok(MsixConfigurationObservation {
                observed_path: text(file, "path")?,
                retained_evidence: retained,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let document = reference(files, &format!("{STAGES}document.txt"))?;
    let output = stage("document-output.json")?;
    if data(files, &document.archive_entry)?
        != b"AIW MSIX package lifecycle\r\nAIW packaged validation\r\n"
        || output["sha256"] != document.sha256
        || output["sizeBytes"] != document.bytes
        || token["UserSid"] != account["userSid"]
        || token["TokenSessionId"] != worker["sessionId"]
    {
        return Err("MSIX document or session binding differs".into());
    }
    let evidence = [
        "worker/Trial.result.json".to_owned(),
        "worker/Control.result.json".into(),
        format!("{ROOT}parent-after.json"),
        format!("{ROOT}job-cleanup.json"),
        format!("{STAGES}result.json"),
        format!("{STAGES}activated.json"),
        format!("{STAGES}cleanup.json"),
        format!("{STAGES}payload-after.json"),
    ]
    .iter()
    .map(|name| reference(files, name))
    .collect::<Result<_, _>>()?;
    Ok(MsixLifecycleReport {
        schema_version: "aiw.dev/msix-research-lifecycle-report/v0alpha1".into(),
        profile,
        archive_sha256: ARCHIVE_SHA.into(),
        source_commit: SOURCE.into(),
        bundle_sha256: BUNDLE_SHA.into(),
        native_sha256: NATIVE.into(),
        worker_uuid: UUID.into(),
        run_nonce: NONCE.into(),
        observed_windows_build: text(&worker, "windowsBuild")?,
        research_only: true,
        lifecycle_completed: true,
        functions: ApplicationReportFunctions {
            install: Some(true),
            launch: Some(true),
            open_document: Some(true),
            edit_save_document: Some(true),
            close: Some(true),
            uninstall: Some(true),
            ..Default::default()
        },
        source_application: MsixApplicationIdentity {
            name: "Notepad++".into(),
            version: "8.9.8".into(),
            portable_source_sha256: text(&input, "sourceSha256")?,
            removed_configuration_file: text(&assembly["adaptation"], "removed")?,
            removed_configuration_file_sha256: text(&assembly["adaptation"], "sha256")?,
        },
        package: MsixPackageObservation {
            signed_sha256: text(&input, "signedSha256")?,
            publisher: text(&input, "publisher")?,
            full_name: text(&installed, "packageFullName")?,
            family_name: text(&installed, "packageFamilyName")?,
            install_location: text(&installed, "installLocation")?,
            delivery_model: aiw_schema::DeliveryModel::ContainedMsix,
            runtime_boundary: aiw_schema::RuntimeBoundary::MediumIlFullTrust,
            observed_process_id: number(&activated, "processId")?,
            observed_user_sid: text(token, "UserSid")?,
            observed_session_id: number(token, "TokenSessionId")?,
            observed_integrity_sid: text(token, "IntegritySid")?,
            observed_elevated: token["IsElevated"]
                .as_bool()
                .ok_or("Missing elevation observation")?,
            observed_app_container: token["IsAppContainer"]
                .as_bool()
                .ok_or("Missing AppContainer observation")?,
            identity_verified_before_resume: activated["identityVerifiedBeforeResume"] == true,
        },
        document,
        configuration,
        unchanged_payload_files: number(&stage("payload-after.json")?, "filesChecked")?,
        registration_cleanup_verified: true,
        install_location_absent: true,
        recorded_process_job_task_cleanup_verified: true,
        user_data_deletion: text(&cleanup, "userDataDeletionClaim")?,
        edit_method: "consoleDrivenOpenAppendSaveClose; foreground helper not invoked".into(),
        evidence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const FIXTURE: &[u8] = include_bytes!("../../../fixtures/msix-lifecycle/worker107-r5.zip");

    #[test]
    fn reviewed_archive_projects_real_observations_without_upgrading_research() {
        let report = report_bytes(FIXTURE, MsixResearchProfile::Worker107NotepadR5).unwrap();
        assert_eq!(report.archive_sha256, ARCHIVE_SHA);
        assert_eq!(
            report.package.full_name,
            "AIWResearch.NotepadPP_8.9.8.0_x64__q1fhfzcjv9wt6"
        );
        assert_eq!(report.package.observed_process_id, 8700);
        assert_eq!(report.package.observed_integrity_sid, "S-1-16-8192");
        assert!(!report.package.observed_app_container);
        assert!(!report.package.observed_elevated);
        assert!(report.package.identity_verified_before_resume);
        assert_eq!(report.observed_windows_build, "10.0.26300.0");
        assert_eq!(report.document.bytes, 53);
        assert_eq!(
            report.document.sha256,
            "91b82efd755bd5a46b47f6277bd050954b9fb3e78e56f9f086129d04da4dbd42"
        );
        assert_eq!(report.unchanged_payload_files, 220);
        assert_eq!(report.configuration.len(), 6);
        assert!(
            report
                .configuration
                .iter()
                .all(|f| f.observed_path.contains(r"\LocalCache\Roaming\Notepad++\"))
        );
        assert_eq!(report.functions.uninstall, Some(true));
        assert_eq!(report.functions.stl_to_3mf_export, None);
        assert_eq!(report.user_data_deletion, "notInferredFromUninstall");
        assert!(report.research_only);
        assert!(report.recorded_process_job_task_cleanup_verified);
        assert_ne!(
            report.source_application.portable_source_sha256,
            report.package.signed_sha256
        );
        assert_eq!(
            report.source_application.removed_configuration_file,
            "Application/doLocalConf.xml"
        );
    }

    #[test]
    fn changed_truncated_appended_and_success_shaped_archives_are_rejected() {
        let mut changed = FIXTURE.to_vec();
        changed[128] ^= 1;
        assert!(report_bytes(&changed, MsixResearchProfile::Worker107NotepadR5).is_err());
        assert!(
            report_bytes(
                &FIXTURE[..FIXTURE.len() - 1],
                MsixResearchProfile::Worker107NotepadR5
            )
            .is_err()
        );
        let mut appended = FIXTURE.to_vec();
        appended.push(0);
        assert!(report_bytes(&appended, MsixResearchProfile::Worker107NotepadR5).is_err());
        assert!(
            report_bytes(
                br#"{"passed":true,"exitCode":0}"#,
                MsixResearchProfile::Worker107NotepadR5
            )
            .is_err()
        );
    }

    #[test]
    fn projection_requires_terminal_native_and_privileged_cleanup_receipts() {
        let original = read_zip(FIXTURE).unwrap();
        for name in [
            "worker/Trial.result.json",
            "worker/Control.result.json",
            "0/standard-user-lifecycle/job-cleanup.json",
            "0/standard-user-lifecycle/parent-after.json",
            "0/standard-user-lifecycle/msix-lifecycle/result.json",
            "0/standard-user-lifecycle/msix-lifecycle/document.txt",
        ] {
            let mut files = original.clone();
            files.remove(name);
            assert!(
                project_reviewed(&files, MsixResearchProfile::Worker107NotepadR5).is_err(),
                "{name}"
            );
        }
        let mut files = original.clone();
        files.insert(
            "0/standard-user-lifecycle/msix-lifecycle/failure.json".into(),
            b"{}".to_vec(),
        );
        assert!(project_reviewed(&files, MsixResearchProfile::Worker107NotepadR5).is_err());
        for (name, pointer, replacement) in [
            (
                "worker/Trial.result.json",
                "/controller/result/nativeLifecycle/result/passed",
                serde_json::json!(false),
            ),
            (
                "worker/Control.result.json",
                "/controller/cleanup/nativeExitConfirmed",
                serde_json::json!(false),
            ),
            (
                "0/standard-user-lifecycle/job-cleanup.json",
                "/readbackError",
                serde_json::json!("unknown"),
            ),
            (
                "0/standard-user-lifecycle/parent-after.json",
                "/processes/queryErrors",
                serde_json::json!([{"pid":42}]),
            ),
            (
                "0/standard-user-lifecycle/msix-lifecycle/cleanup.json",
                "/registrationAbsent",
                serde_json::json!(false),
            ),
        ] {
            let mut files = original.clone();
            let mut value = json(&files, name).unwrap();
            *value.pointer_mut(pointer).unwrap() = replacement;
            files.insert(name.into(), serde_json::to_vec(&value).unwrap());
            assert!(
                project_reviewed(&files, MsixResearchProfile::Worker107NotepadR5).is_err(),
                "{pointer}"
            );
        }
    }
}
