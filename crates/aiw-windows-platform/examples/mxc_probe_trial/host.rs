use aiw_probe::WorkspaceBindingEvidence;
use aiw_provider_mxc::process_container::{self as contract, FixedOperation, FixedRequest};
use aiw_provider_wsb::{GoldenProbe, MappedFolder, MappingPurpose, WindowsSandboxPlan};
use aiw_windows_platform::{CanonicalSandboxId, HeldApplicationFile, HeldRunWorkspace};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    io::Write,
    path::Path,
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const ROOT: &str = r"C:\AIW-Mxc-Probe-Trial-20261106";
const PROVIDER: &str = "247e092b5c5bd37820f225a7dd3ddf10ae37a67e2751a19c24b802c84769c441";
const SESSION: &str = "e7b03fc5-5f62-452e-8521-7fcb0fa14c3e";
const SCHEMA: &str = "aiw.dev/research/mxc-probe-host-trial/v0alpha1";
const VM_UUID: &str = "e5cecc90-35c2-4831-bf9c-424be23f7d4e";
const OPERATOR_SID: &str = "S-1-5-21-3556347314-2314855617-1438300668-1001";
const EXPECTED_HOST: &str = "10.0.26300.9711/x86_64";
const EXPECTED_GUEST: &str = "10.0.26100.9711/x86_64";
const OUTPUT_BOUND: u64 = 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum TrialProfile {
    Capability,
    Creation,
}
impl TrialProfile {
    fn root(self) -> &'static str {
        match self {
            Self::Capability => ROOT,
            Self::Creation => r"C:\AIW-Mxc-Creation-Entry-Trial-20261106",
        }
    }
    fn session(self) -> &'static str {
        match self {
            Self::Capability => SESSION,
            Self::Creation => "a340ac6c-e056-47e7-9f24-a3b3fb401b98",
        }
    }
    fn schema(self) -> &'static str {
        match self {
            Self::Capability => SCHEMA,
            Self::Creation => "aiw.dev/research/mxc-creation-host-trial/v0alpha1",
        }
    }
    fn output(self) -> &'static str {
        match self {
            Self::Capability => r"C:\AIW\MxcProbeOutput",
            Self::Creation => r"C:\AIW\MxcCreationOutput",
        }
    }
}

#[path = "publication.rs"]
mod publication;

#[allow(dead_code)]
pub fn run_publication() -> Result<()> {
    publication::run()
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Proposal {
    schema_version: String,
    workspace: WorkspaceBindingEvidence,
    plan: WindowsSandboxPlan,
    helper_sha256: String,
    helper_size_bytes: u64,
    dll_sha256: String,
    dll_size_bytes: u64,
    runtime_source_revision: String,
    runtime_release: String,
    aiw_source_sha256: String,
    expected_host: String,
    expected_guest: String,
    worker_uuid: String,
    fixed_requests: Vec<PolicyRequest>,
    rendered_config_sha256: String,
    provider_sha256: String,
    session_id: String,
    operator_sid: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyRequest {
    operation: FixedOperation,
    request_sha256: String,
    request: serde_json::Value,
}

fn fixed_requests_for(profile: TrialProfile) -> Result<Vec<PolicyRequest>> {
    let operations = if profile == TrialProfile::Creation {
        vec![FixedOperation::Driver]
    } else {
        vec![
            FixedOperation::Driver,
            FixedOperation::Boundary,
            FixedOperation::Create,
            FixedOperation::Test,
            FixedOperation::Extract,
        ]
    };
    operations
        .into_iter()
        .map(|operation| {
            let request = FixedRequest::new(operation)?;
            Ok(PolicyRequest {
                operation,
                request_sha256: request.sha256().into(),
                request: serde_json::from_str(request.json())?,
            })
        })
        .collect()
}
fn fixed_requests() -> Result<Vec<PolicyRequest>> {
    fixed_requests_for(TrialProfile::Capability)
}

fn aiw_source_hash() -> String {
    // Exact ordered UTF-8 inputs, each prefixed by its u64 little-endian byte
    // length, matching the existing seven_zip_source_sha256 framing. First
    // input is that function's lowercase ASCII digest, not a caller assertion.
    let shared = aiw_probe::seven_zip_source_sha256();
    let sources = [
        shared.as_str(),
        include_str!("host.rs"),
        include_str!("../mxc_probe_sandbox_trial.rs"),
        include_str!("../mxc_process_probe.rs"),
        include_str!("../../src/lib.rs"),
        include_str!("../../src/mxc_process.rs"),
        include_str!("../../src/mxc_process/creation.rs"),
        include_str!("../../src/guest_msi/mxc_child.rs"),
        include_str!("../../src/research_publication.rs"),
        include_str!("publication.rs"),
        include_str!("../publication_control_guest.rs"),
        include_str!("../publication_control_sandbox_trial.rs"),
        include_str!("../../src/guest_document/paired_inputs/mxc_probe.rs"),
        include_str!("../../src/guest_document/paired_inputs.rs"),
        include_str!("../../src/guest_document.rs"),
        include_str!("../../src/guest_standard_user.rs"),
        include_str!("../../src/guest_msi.rs"),
        include_str!("../../src/source_inspection.rs"),
        include_str!("../../src/windows_platform.rs"),
        include_str!("../../src/workspace.rs"),
        include_str!("../../src/exact_dispose.rs"),
        include_str!("../../../aiw-token/src/lib.rs"),
        include_str!("../../../aiw-probe/src/lib.rs"),
        include_str!("../../src/coordination.rs"),
        include_str!("../../src/powershell.rs"),
        include_str!("../../../aiw-provider-mxc/src/process_container.rs"),
        include_str!("../../../aiw-provider-wsb/src/lib.rs"),
        include_str!("../../../aiw-provider-wsb/Cargo.toml"),
        include_str!("../../../aiw-provider-wsb/src/runtime_context.rs"),
        include_str!("../../../aiw-windows-command-line/src/lib.rs"),
        include_str!("../../Cargo.toml"),
        include_str!("../../../../Cargo.lock"),
        include_str!("../../../../third-party/mxc-process-pin.json"),
    ];
    let mut digest = Sha256::new();
    for source in sources {
        digest.update((source.len() as u64).to_le_bytes());
        digest.update(source.as_bytes());
    }
    hex::encode(digest.finalize())
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn recovery_allowed_for(
    record: Option<&serde_json::Value>,
    hash: &str,
    recovered: bool,
    profile: TrialProfile,
) -> bool {
    if recovered {
        return false;
    }
    record.is_none_or(|record| {
        record["schemaVersion"] == profile.schema()
            && record["researchOnly"] == true
            && record["capabilityOnly"] == (profile == TrialProfile::Capability)
            && record["planSha256"] == hash
            && record["sessionId"] == profile.session()
            && record["outerCleanupVerified"] == false
    })
}
#[cfg(test)]
fn recovery_allowed(record: Option<&serde_json::Value>, hash: &str, recovered: bool) -> bool {
    recovery_allowed_for(record, hash, recovered, TrialProfile::Capability)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreationTrial {
    schema_version: String,
    research_only: bool,
    helper_sha256: String,
    helper_size_bytes: u64,
    dll_sha256: String,
    windows: aiw_probe::WindowsVersionObservation,
    held_worker_token: aiw_token::TokenEvidence,
    standard_context: aiw_provider_wsb::StandardUserRuntimeContext,
    handshake: Option<serde_json::Value>,
    handshake_error: Option<String>,
    worker: Option<serde_json::Value>,
    worker_read_error: Option<String>,
    owned_job_empty: bool,
    cleanup_error: Option<String>,
    validation_errors: Vec<String>,
    application_execution_requested: bool,
    selected_tier_attestation: String,
    owner_observations: CreationOwnerObservations,
    retained_prefixes: std::collections::BTreeMap<String, CreationPrefix>,
    raw_contained_diagnostics: std::collections::BTreeMap<String, RawContainedDiagnostic>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawContainedDiagnostic {
    capture_complete: bool,
    disposition: RawDiagnosticDisposition,
    raw_hex: Option<String>,
    sha256: Option<String>,
    size_bytes: Option<u64>,
    identity: Option<aiw_probe::WindowsFileIdentity>,
    read_error: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum RawDiagnosticDisposition {
    Captured,
    Refused,
}

const RAW_DIAGNOSTIC_BOUND: usize = 16 * 1024;
const RAW_DIAGNOSTIC_NAMES: [&str; 8] = [
    "ENTRY.DAT",
    "ENTRY.DAT.pending",
    "SELF.DAT",
    "SELF.DAT.pending",
    "CONTROL.DAT",
    "CONTROL.DAT.pending",
    "FAILURE.DAT",
    "FAILURE.DAT.pending",
];

fn validate_raw_contained_diagnostics(
    records: &std::collections::BTreeMap<String, RawContainedDiagnostic>,
) -> Result<()> {
    if records.len() != RAW_DIAGNOSTIC_NAMES.len()
        || RAW_DIAGNOSTIC_NAMES
            .iter()
            .any(|key| !records.contains_key(*key))
    {
        return Err("raw contained diagnostic inventory differs".into());
    }
    let lower_hex = |value: &str, length: usize| {
        value.len() == length
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let mut total_hex_bytes = 0_usize;
    for (name, record) in records {
        if serde_json::to_vec(record)?.len() > 40 * 1024 {
            return Err("raw diagnostic serialized record budget".into());
        }
        match record.disposition {
            RawDiagnosticDisposition::Captured => {
                let (Some(raw), Some(hash), Some(size), Some(identity)) = (
                    record.raw_hex.as_ref(),
                    record.sha256.as_ref(),
                    record.size_bytes,
                    record.identity.as_ref(),
                ) else {
                    return Err("complete raw diagnostic lacks held capture facts".into());
                };
                if !record.capture_complete
                    || record.read_error.is_some()
                    || size > RAW_DIAGNOSTIC_BOUND as u64
                    || !lower_hex(raw, size as usize * 2)
                    || !lower_hex(hash, 64)
                    || !lower_hex(&identity.volume_serial_number, 16)
                    || !lower_hex(&identity.file_id, 32)
                    || !identity
                        .final_path
                        .strip_prefix(r"\\?\")
                        .unwrap_or(&identity.final_path)
                        .eq_ignore_ascii_case(&format!(r"C:\AIW\SevenZip\Work\Mxc\Output\{name}"))
                {
                    return Err("complete raw diagnostic shape/binding differs".into());
                }
                let bytes = hex::decode(raw)?;
                if digest(&bytes) != *hash {
                    return Err("complete raw diagnostic byte digest differs".into());
                }
                total_hex_bytes += raw.len();
            }
            RawDiagnosticDisposition::Refused => {
                if record.capture_complete
                    || record.raw_hex.is_some()
                    || record.sha256.is_some()
                    || record.size_bytes.is_some()
                    || record.identity.is_some()
                    || record
                        .read_error
                        .as_ref()
                        .is_none_or(|s| s.is_empty() || s.len() > 2048)
                {
                    return Err("refused raw diagnostic claims captured facts".into());
                }
            }
        }
    }
    if total_hex_bytes > 256 * 1024 {
        return Err("raw contained diagnostic total bound".into());
    }
    Ok(())
}

fn validate_creation_serialized_budgets(value: &serde_json::Value) -> Result<()> {
    let prefixes = value["retainedPrefixes"]
        .as_object()
        .ok_or("prefix map required")?;
    let mut prefix_bytes = 0;
    for record in prefixes.values() {
        let bytes = serde_json::to_vec(record)?.len();
        if bytes > 8 * 1024 {
            return Err("parsed prefix serialized record budget".into());
        }
        prefix_bytes += bytes;
    }
    if prefix_bytes > 128 * 1024 {
        return Err("parsed prefix aggregate serialized budget".into());
    }
    for field in ["worker", "handshake"] {
        if serde_json::to_vec(&value[field])?.len() > 64 * 1024 {
            return Err("ancillary serialized budget".into());
        }
    }
    if serde_json::to_vec(&value["ownerObservations"])?.len() > 128 * 1024 {
        return Err("owner serialized budget".into());
    }
    let mut fixed = value.clone();
    for field in [
        "retainedPrefixes",
        "rawContainedDiagnostics",
        "worker",
        "handshake",
        "ownerObservations",
    ] {
        fixed[field] = serde_json::Value::Null;
    }
    if serde_json::to_vec(&fixed)?.len() > 128 * 1024 {
        return Err("fixed creation envelope serialized budget".into());
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreationOwnerObservations {
    root_token_measurement: Option<serde_json::Value>,
    root_token_measurement_read_error: Option<String>,
    owner_measured_child: Option<serde_json::Value>,
    exact_outer_job_membership: Option<bool>,
    release_gate_published: bool,
    post_exit_binding_error: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreationPrefix {
    value: Option<serde_json::Value>,
    read_error: Option<String>,
}
const CREATION_PREFIXES: [&str; 19] = [
    "baseline",
    "probe",
    "spawn",
    "rootToken",
    "containedSelf",
    "containedEntry",
    "boundChild",
    "warnings",
    "ready",
    "controls",
    "containedFailure",
    "spawnCall",
    "completion",
    "freeBegin",
    "freeEnd",
    "pollEnd",
    "waitEnd",
    "timeout",
    "timeoutEnd",
];
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreationFailure {
    schema_version: String,
    research_only: bool,
    error: String,
    application_execution_requested: bool,
}
fn creation_marker_digest(
    bytes: &[u8],
    helper_sha256: &str,
    helper_size_bytes: u64,
) -> Result<String> {
    if bytes.len() > OUTPUT_BOUND as usize {
        return Err("creation output bound".into());
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    match value["schemaVersion"].as_str() {
        Some("aiw.dev/mxc-creation-trial/v0alpha1") => {
            validate_creation_serialized_budgets(&value)?;
            let v: CreationTrial = serde_json::from_slice(bytes)?;
            if v.schema_version != "aiw.dev/mxc-creation-trial/v0alpha1"
                || !v.research_only
                || v.application_execution_requested
                || v.helper_sha256 != helper_sha256
                || v.helper_size_bytes != helper_size_bytes
                || v.dll_sha256 != contract::RUNTIME_DLL_SHA256
                || windows_label(&v.windows) != EXPECTED_GUEST
                || v.selected_tier_attestation != "unmeasured"
                || v.held_worker_token.is_elevated
                || v.held_worker_token.is_app_container
                || v.owned_job_empty != v.cleanup_error.is_none()
                || v.handshake.is_some() == v.handshake_error.is_some()
                || v.worker.is_some() == v.worker_read_error.is_some()
                || v.validation_errors.len() > 4
                || v.validation_errors.iter().any(|s| s.len() > 8192)
                || [&v.handshake_error, &v.worker_read_error, &v.cleanup_error]
                    .into_iter()
                    .flatten()
                    .any(|s| s.len() > 8192)
            {
                return Err("creation observation envelope differs".into());
            }
            v.standard_context.validate_token(&v.held_worker_token)?;
            validate_raw_contained_diagnostics(&v.raw_contained_diagnostics)?;
            let owner = &v.owner_observations;
            if owner.owner_measured_child.is_some()
                != (owner.exact_outer_job_membership == Some(true))
                || (owner.release_gate_published && owner.owner_measured_child.is_none())
                || owner
                    .root_token_measurement
                    .as_ref()
                    .is_some_and(|m| !m.is_object())
                || owner
                    .root_token_measurement_read_error
                    .as_ref()
                    .is_some_and(|error| {
                        error.is_empty()
                            || error.len() > 2048
                            || owner.root_token_measurement.is_some()
                    })
                || owner
                    .post_exit_binding_error
                    .as_ref()
                    .is_some_and(|s| s.len() > 8192)
                || v.retained_prefixes.len() != CREATION_PREFIXES.len()
                || CREATION_PREFIXES
                    .iter()
                    .any(|key| !v.retained_prefixes.contains_key(*key))
                || v.retained_prefixes.values().any(|p| {
                    p.value.is_some() == p.read_error.is_some()
                        || p.read_error
                            .as_ref()
                            .is_some_and(|s| s.is_empty() || s.len() > 8192)
                })
            {
                return Err("creation owner/prefix observation shape differs".into());
            }
            // Nested observations are retained research data. This reader does
            // not turn successful custody into an enforcement/product verdict.
        }
        Some("aiw.dev/mxc-creation-setup-failure/v0alpha1") => {
            let v: CreationFailure = serde_json::from_slice(bytes)?;
            if v.schema_version != "aiw.dev/mxc-creation-setup-failure/v0alpha1"
                || !v.research_only
                || v.application_execution_requested
                || v.error.is_empty()
                || v.error.len() > 8192
            {
                return Err("creation setup failure differs".into());
            }
        }
        _ => return Err("unknown creation research envelope".into()),
    }
    Ok(digest(bytes))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GuestSuccess {
    schema_version: String,
    research_only: bool,
    helper_sha256: String,
    helper_size_bytes: u64,
    dll_sha256: String,
    dll_size_bytes: u64,
    windows: aiw_probe::WindowsVersionObservation,
    standard_context: aiw_provider_wsb::StandardUserRuntimeContext,
    held_observer_token: aiw_token::TokenEvidence,
    child_exit_code: Option<i32>,
    child_error: Option<String>,
    owned_job_empty: bool,
    cleanup_error: Option<String>,
    probe: Option<serde_json::Value>,
    probe_read_error: Option<String>,
    payload_bindings_verified: bool,
    validation_errors: Vec<String>,
    requested_application_execution: bool,
    enforcement: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GuestFailure {
    schema_version: String,
    research_only: bool,
    driver_error: String,
    requested_application_execution: bool,
    enforcement: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProbeCollection {
    schema_version: String,
    dll_sha256: String,
    dll_size_bytes: u64,
    runtime_source: String,
    runtime_release: String,
    windows: aiw_probe::WindowsVersionObservation,
    observer_token: aiw_token::TokenEvidence,
    requests: Vec<ProbeRequestObservation>,
    collection_complete: bool,
    collection_error: Option<String>,
    failed_operation: Option<FixedOperation>,
    requested_application_execution: bool,
    enforcement: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProbeRequestObservation {
    operation: FixedOperation,
    request_sha256: String,
    request: serde_json::Value,
    ffi_status: i32,
    probe: Option<contract::ProbeOutput>,
    disposition: Option<contract::ProbeDisposition>,
    error_detail: Option<Vec<Option<String>>>,
    enforcement: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProbeFailure {
    schema_version: String,
    driver_error: String,
    requested_application_execution: bool,
    enforcement: String,
}
fn validate_probe_collection(value: &serde_json::Value, marker: &GuestSuccess) -> Result<()> {
    match value["schemaVersion"].as_str() {
        Some("aiw.dev/mxc-request-probe-failure/v0alpha1") => {
            let failure: ProbeFailure = serde_json::from_value(value.clone())?;
            if failure.schema_version != "aiw.dev/mxc-request-probe-failure/v0alpha1"
                || failure.driver_error.is_empty()
                || failure.driver_error.len() > 8192
                || failure.requested_application_execution
                || failure.enforcement != "unmeasured"
            {
                return Err("invalid bounded request-probe failure".into());
            }
        }
        Some("aiw.dev/mxc-request-probe-observations/v0alpha1") => {
            let collection: ProbeCollection = serde_json::from_value(value.clone())?;
            if collection.schema_version != "aiw.dev/mxc-request-probe-observations/v0alpha1"
                || collection.dll_sha256 != contract::RUNTIME_DLL_SHA256
                || collection.dll_size_bytes != contract::RUNTIME_DLL_SIZE
                || collection.runtime_source != contract::SOURCE_REVISION
                || collection.runtime_release != contract::RELEASE
                || windows_label(&collection.windows) != EXPECTED_GUEST
                || collection.observer_token != marker.held_observer_token
                || collection.requested_application_execution
                || collection.enforcement != "unmeasured"
                || collection.requests.len() > 5
                || (collection.collection_complete
                    && (collection.requests.len() != 5
                        || collection.collection_error.is_some()
                        || collection.failed_operation.is_some()))
                || (!collection.collection_complete
                    && (collection.requests.len() == 5
                        || collection
                            .collection_error
                            .as_ref()
                            .is_none_or(|error| error.is_empty() || error.len() > 8192)
                        || collection.failed_operation
                            != fixed_requests()?
                                .get(collection.requests.len())
                                .map(|r| r.operation)))
            {
                return Err("request-probe collection binding differs".into());
            }
            marker
                .standard_context
                .validate_token(&collection.observer_token)?;
            for (observed, expected) in collection.requests.into_iter().zip(fixed_requests()?) {
                if observed.operation != expected.operation
                    || observed.request_sha256 != expected.request_sha256
                    || observed.request != expected.request
                    || observed.enforcement != "unmeasured"
                {
                    return Err("probe request policy/ordering differs".into());
                }
                if observed.ffi_status == 0 {
                    if observed.error_detail.is_some() {
                        return Err("contradictory ABI probe status".into());
                    }
                    let probe = observed.probe.ok_or("successful ABI call has no probe")?;
                    let request = FixedRequest::new(observed.operation)?;
                    let bound = contract::parse_probe(
                        &request,
                        &observed.request_sha256,
                        &serde_json::to_vec(&probe)?,
                    )?;
                    if observed.disposition != Some(bound.disposition) {
                        return Err("probe classification differs from closed policy".into());
                    }
                } else if observed.probe.is_some()
                    || observed.disposition.is_some()
                    || observed
                        .error_detail
                        .as_ref()
                        .is_none_or(|d| d.len() != 4 || d.iter().flatten().any(|s| s.len() > 8192))
                {
                    return Err("invalid bounded ABI failure detail".into());
                }
            }
        }
        _ => return Err("unknown request-probe result schema".into()),
    }
    Ok(())
}
fn completed_marker(
    workspace: &HeldRunWorkspace,
    proposal: &Proposal,
    profile: TrialProfile,
) -> Result<String> {
    let bound = workspace.reopen_output_file_readonly("RESULT.DAT")?;
    let file = HeldApplicationFile::open_bounded(bound.final_path(), OUTPUT_BOUND)?;
    let bytes = file.read_bounded(OUTPUT_BOUND)?;
    let hash = if profile == TrialProfile::Creation {
        creation_marker_digest(&bytes, &proposal.helper_sha256, proposal.helper_size_bytes)?
    } else {
        marker_digest(&bytes, &proposal.helper_sha256, proposal.helper_size_bytes)?
    };
    bound.revalidate()?;
    file.revalidate()?;
    Ok(hash)
}
fn creation_output_hex(
    workspace: &HeldRunWorkspace,
    proposal: &Proposal,
    expected_hash: &str,
) -> Result<String> {
    let bound = workspace.reopen_output_file_readonly("RESULT.DAT")?;
    let file = HeldApplicationFile::open_bounded(bound.final_path(), OUTPUT_BOUND)?;
    if file.observation().identity != *bound.identity() {
        return Err("creation output identity differs".into());
    }
    let bytes = file.read_bounded(OUTPUT_BOUND)?;
    require_same_output_bytes(&bytes, expected_hash)?;
    creation_marker_digest(&bytes, &proposal.helper_sha256, proposal.helper_size_bytes)?;
    bound.revalidate()?;
    file.revalidate()?;
    Ok(hex::encode(bytes))
}
fn require_same_output_bytes(bytes: &[u8], expected_hash: &str) -> Result<()> {
    if digest(bytes) != expected_hash {
        return Err("creation raw output changed since accepted retained hash".into());
    }
    Ok(())
}
fn marker_digest(bytes: &[u8], helper_sha256: &str, helper_size_bytes: u64) -> Result<String> {
    if bytes.len() > OUTPUT_BOUND as usize {
        return Err("guest marker exceeds bound".into());
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    match value["schemaVersion"].as_str() {
        Some("aiw.dev/mxc-probe-trial/v0alpha1") => {
            let marker: GuestSuccess = serde_json::from_slice(bytes)?;
            if marker.schema_version != "aiw.dev/mxc-probe-trial/v0alpha1"
                || !marker.research_only
                || marker.requested_application_execution
                || marker.enforcement != "unmeasured"
                || marker.helper_sha256 != helper_sha256
                || marker.helper_size_bytes != helper_size_bytes
                || marker.dll_sha256 != contract::RUNTIME_DLL_SHA256
                || marker.dll_size_bytes != contract::RUNTIME_DLL_SIZE
                || windows_label(&marker.windows) != EXPECTED_GUEST
                || marker.held_observer_token.is_elevated
                || marker.held_observer_token.is_app_container
                || marker.validation_errors.len() > 3
                || marker.validation_errors.iter().any(|s| s.len() > 8192)
                || marker.payload_bindings_verified != marker.validation_errors.is_empty()
                || marker.child_exit_code.is_some() == marker.child_error.is_some()
                || marker.owned_job_empty != marker.cleanup_error.is_none()
                || marker.probe.is_some() == marker.probe_read_error.is_some()
                || marker.child_error.as_ref().is_some_and(|s| s.len() > 8192)
                || marker
                    .cleanup_error
                    .as_ref()
                    .is_some_and(|s| s.len() > 8192)
                || marker
                    .probe_read_error
                    .as_ref()
                    .is_some_and(|s| s.len() > 8192)
            {
                return Err("untrusted MXC observation identity/contract differs".into());
            }
            marker
                .standard_context
                .validate_token(&marker.held_observer_token)?;
            if let Some(probe) = &marker.probe {
                validate_probe_collection(probe, &marker)?;
            }
            // Completion is not success: preserve unsuccessful child, probe,
            // classification and inner cleanup facts for independent review.
            let _partial_facts = (marker.child_exit_code, marker.owned_job_empty, marker.probe);
        }
        Some("aiw.dev/mxc-probe-trial-failure/v0alpha1") => {
            let marker: GuestFailure = serde_json::from_slice(bytes)?;
            if marker.schema_version != "aiw.dev/mxc-probe-trial-failure/v0alpha1"
                || !marker.research_only
                || marker.requested_application_execution
                || marker.enforcement != "unmeasured"
                || marker.driver_error.is_empty()
                || marker.driver_error.len() > 8192
            {
                return Err("invalid untrusted MXC setup failure".into());
            }
        }
        _ => return Err("unknown untrusted MXC result contract".into()),
    }
    Ok(digest(bytes))
}
fn windows_label(os: &aiw_probe::WindowsVersionObservation) -> String {
    format!(
        "{}.{}.{}.{}/{}",
        os.major, os.minor, os.build, os.revision, os.observer_architecture
    )
}
fn helper_hash() -> Result<&'static str> {
    let value = option_env!("AIW_MXC_PROBE_HELPER_SHA256")
        .ok_or("build must enroll the separately verified helper SHA-256")?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid build-time helper commitment".into());
    }
    Ok(value)
}
fn fixed_os_and_actor() -> Result<String> {
    let os = aiw_windows_platform::observe_windows_version()?;
    if (
        os.major,
        os.minor,
        os.build,
        os.revision,
        os.observer_architecture.as_str(),
    ) != (10, 0, 26300, 9711, "x86_64")
    {
        return Err("host differs from the reviewed VM107 OS; no dispatch".into());
    }
    let token = aiw_token::collect_current_process_token()?;
    if token.is_elevated || token.is_app_container || token.user_sid != OPERATOR_SID {
        return Err("existing non-elevated ordinary operator account is required".into());
    }
    fixed_vm_console_guard()?;
    Ok(token.user_sid)
}
fn fixed_vm_console_guard() -> Result<()> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    let runtime = aiw_windows_platform::HeldPowerShell::observe()?;
    runtime.revalidate()?;
    let script = concat!(
        "$ErrorActionPreference='Stop';",
        "if((Get-CimInstance Win32_ComputerSystemProduct -OperationTimeoutSec 15).UUID -ine ",
        "'e5cecc90-35c2-4831-bf9c-424be23f7d4e'){throw 'Wrong disposable worker'};",
        "if([Security.Principal.WindowsIdentity]::GetCurrent().Name -ine 'AIW\\labadmin' ",
        "-or [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 1){throw 'Wrong operator console'};",
        "[Console]::Out.Write('VM107-MXC-GUARD-OK')"
    );
    let mut child = Command::new(aiw_probe::powershell::POWERSHELL_EXECUTABLE)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("VM guard stdout absent")?;
    let stderr = child.stderr.take().ok_or("VM guard stderr absent")?;
    let (send_out, out) = std::sync::mpsc::channel();
    let (send_err, err) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let r = stdout.take(4097).read_to_end(&mut b).map(|_| b);
        let _ = send_out.send(r);
    });
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let r = stderr.take(4097).read_to_end(&mut b).map(|_| b);
        let _ = send_err.send(r);
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("fixed VM guard deadline".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let output = out.recv_timeout(Duration::from_secs(1))??;
    let errors = err.recv_timeout(Duration::from_secs(1))??;
    runtime.revalidate()?;
    if !status.success() || output != b"VM107-MXC-GUARD-OK" || !errors.is_empty() {
        return Err("fixed disposable VM/operator console guard failed".into());
    }
    Ok(())
}
fn publish(workspace: &HeldRunWorkspace, leaf: &str, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = workspace.create_root_file_new(leaf)?;
    file.as_file_mut().write_all(&bytes)?;
    file.as_file_mut().sync_all()?;
    Ok(())
}
fn read_protected<T: for<'a> Deserialize<'a>>(
    workspace: &HeldRunWorkspace,
    leaf: &str,
) -> Result<T> {
    let bound = workspace.reopen_root_file_readonly(leaf)?;
    let held = HeldApplicationFile::open_bounded(bound.final_path(), 1024 * 1024)?;
    let value = serde_json::from_slice(&held.read_bounded(1024 * 1024)?)?;
    bound.revalidate()?;
    held.revalidate()?;
    Ok(value)
}
fn normalized(path: &Path) -> String {
    path.to_string_lossy()
        .strip_prefix(r"\\?\")
        .unwrap_or(&path.to_string_lossy())
        .to_owned()
}
fn plan(workspace: &HeldRunWorkspace, profile: TrialProfile) -> WindowsSandboxPlan {
    WindowsSandboxPlan {
        schema_version: aiw_provider_wsb::WINDOWS_SANDBOX_PLAN_SCHEMA_VERSION.into(),
        workspace_root: normalized(workspace.root_path()),
        mappings: vec![
            MappedFolder {
                purpose: MappingPurpose::Tools,
                host_folder: normalized(&workspace.tools_path()),
                sandbox_folder: r"C:\AIW\Tools".into(),
            },
            MappedFolder {
                purpose: MappingPurpose::Output,
                host_folder: normalized(&workspace.output_path()),
                sandbox_folder: profile.output().into(),
            },
        ],
        probe: GoldenProbe {
            executable: r"C:\AIW\Tools\mxc_process_probe.exe".into(),
            request: None,
            output: format!(r"{}\RESULT.DAT", profile.output()),
        },
        memory_mb: Some(2048),
    }
}
fn stage(
    workspace: &HeldRunWorkspace,
    name: &str,
    expected: &str,
    profile: TrialProfile,
) -> Result<u64> {
    let source = HeldApplicationFile::open_bounded(
        Path::new(profile.root())
            .join("Inputs")
            .join(name)
            .as_path(),
        128 * 1024 * 1024,
    )?;
    if source.observation().sha256 != expected {
        return Err("input hash differs from build commitment".into());
    }
    if name == "mxc_ffi.dll" && source.observation().size_bytes != contract::RUNTIME_DLL_SIZE {
        return Err("pinned runtime size mismatch".into());
    }
    let mut writer = workspace.create_tools_file_new(name)?;
    source.copy_to(writer.as_file_mut())?;
    writer.as_file_mut().sync_all()?;
    let size = source.observation().size_bytes;
    source.revalidate()?;
    drop(writer);
    let file = workspace.reopen_tools_file_readonly(name)?;
    let held = HeldApplicationFile::open(file.final_path())?;
    if held.observation().sha256 != expected || held.observation().size_bytes != size {
        return Err("staged input mismatch".into());
    }
    Ok(size)
}
fn verify_tools(
    workspace: &HeldRunWorkspace,
    proposal: &Proposal,
) -> Result<
    Vec<(
        aiw_windows_platform::BoundWorkspaceFile,
        HeldApplicationFile,
    )>,
> {
    let mut held = vec![];
    let mut names = std::fs::read_dir(workspace.tools_path())?
        .map(|entry| entry.map(|e| e.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    names.sort();
    if names
        != [
            std::ffi::OsString::from("mxc_ffi.dll"),
            std::ffi::OsString::from("mxc_process_probe.exe"),
        ]
    {
        return Err("fixed Tools inventory differs".into());
    }
    for (name, hash, size) in [
        (
            "mxc_ffi.dll",
            contract::RUNTIME_DLL_SHA256,
            contract::RUNTIME_DLL_SIZE,
        ),
        (
            "mxc_process_probe.exe",
            helper_hash()?,
            proposal.helper_size_bytes,
        ),
    ] {
        let bound = workspace.reopen_tools_file_readonly(name)?;
        let file = HeldApplicationFile::open(bound.final_path())?;
        if file.observation().identity != *bound.identity()
            || file.observation().sha256 != hash
            || file.observation().size_bytes != size
        {
            return Err("protected input identity drift".into());
        }
        held.push((bound, file));
    }
    Ok(held)
}
pub fn run() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let profile = if args.first().is_some_and(|a| a.starts_with("--creation-")) {
        TrialProfile::Creation
    } else {
        TrialProfile::Capability
    };
    if profile == TrialProfile::Creation {
        args[0] = match args[0].as_str() {
            "--creation-prepare" => "--prepare",
            "--creation-approve" => "--approve",
            "--creation-start" => "--start",
            "--creation-read" => "--read",
            "--creation-recover" => "--recover",
            _ => return Err("closed creation action required".into()),
        }
        .into();
    }
    let root = profile.root();
    let schema = profile.schema();
    let session = profile.session();
    let actor = fixed_os_and_actor()?;
    helper_hash()?;
    if args == ["--prepare"] {
        let workspace = HeldRunWorkspace::create(Path::new(root), "Trial")?;
        let helper_size = stage(&workspace, "mxc_process_probe.exe", helper_hash()?, profile)?;
        stage(
            &workspace,
            "mxc_ffi.dll",
            contract::RUNTIME_DLL_SHA256,
            profile,
        )?;
        let fixed_plan = plan(&workspace, profile);
        let rendered = aiw_provider_wsb::render_config(&fixed_plan)?;
        let proposal = Proposal {
            schema_version: schema.into(),
            workspace: workspace.evidence().clone(),
            plan: fixed_plan,
            helper_sha256: helper_hash()?.into(),
            helper_size_bytes: helper_size,
            dll_sha256: contract::RUNTIME_DLL_SHA256.into(),
            dll_size_bytes: contract::RUNTIME_DLL_SIZE,
            runtime_source_revision: contract::SOURCE_REVISION.into(),
            runtime_release: contract::RELEASE.into(),
            aiw_source_sha256: aiw_source_hash(),
            expected_host: EXPECTED_HOST.into(),
            expected_guest: EXPECTED_GUEST.into(),
            worker_uuid: VM_UUID.into(),
            fixed_requests: fixed_requests_for(profile)?,
            rendered_config_sha256: rendered.sha256.clone(),
            provider_sha256: PROVIDER.into(),
            session_id: session.into(),
            operator_sid: actor,
        };
        publish(&workspace, "proposal.json", &proposal)?;
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"researchOnly":true,"capabilityOnly":profile==TrialProfile::Capability,"noGeneralEnforcementAcceptance":true,"planSha256":digest(&serde_json::to_vec(&proposal)?),"proposal":proposal,"rendered":rendered,"effects":if profile==TrialProfile::Creation {"One fresh offline owned Sandbox; pinned MXC DLL only in guest ordinary worker; one fixed cooperative first-party Driver ProcessContainer, with matching baseline file controls, same-account process binding and owner-held exact-job release gate. Guest-local test account/owned fixture ACLs only. No vendor application, fallback, parent runtime installation or VM/security-setting changes; exact owned cleanup; no replay."} else {"One fresh offline owned Sandbox; pinned helper and MXC DLL only in ordinary guest worker; five fixed capability probes; no workload/application dispatch; exact owned cleanup; no replay."}})
            )?
        );
        return Ok(());
    }
    let read_only = args == ["--read"];
    if !read_only
        && (args.len() != 2 || !matches!(args[0].as_str(), "--approve" | "--start" | "--recover"))
    {
        return Err(
            "expected --prepare, --approve HASH, --start HASH, --recover HASH, or --read".into(),
        );
    }
    // Bootstrap reads no executable authority; reopening the exact protected
    // workspace below re-reads this same proposal through bound held handles.
    let proposal_file = HeldApplicationFile::open_bounded(
        &Path::new(root).join(r"Trial\proposal.json"),
        1024 * 1024,
    )?;
    let proposal: Proposal = serde_json::from_slice(&proposal_file.read_bounded(1024 * 1024)?)?;
    let workspace = HeldRunWorkspace::reopen_bound(&proposal.workspace)?;
    if normalized(workspace.root_path()) != format!(r"{root}\Trial")
        || proposal != read_protected::<Proposal>(&workspace, "proposal.json")?
        || proposal.schema_version != schema
        || proposal.plan != plan(&workspace, profile)
        || proposal.helper_sha256 != helper_hash()?
        || proposal.provider_sha256 != PROVIDER
        || proposal.dll_sha256 != contract::RUNTIME_DLL_SHA256
        || proposal.dll_size_bytes != contract::RUNTIME_DLL_SIZE
        || proposal.helper_size_bytes == 0
        || proposal.helper_size_bytes > 128 * 1024 * 1024
        || proposal.runtime_source_revision != contract::SOURCE_REVISION
        || proposal.runtime_release != contract::RELEASE
        || proposal.aiw_source_sha256 != aiw_source_hash()
        || proposal.expected_host != EXPECTED_HOST
        || proposal.expected_guest != EXPECTED_GUEST
        || proposal.worker_uuid != VM_UUID
        || proposal.fixed_requests != fixed_requests_for(profile)?
        || proposal.rendered_config_sha256
            != aiw_provider_wsb::render_config(&proposal.plan)?.sha256
        || proposal.session_id != session
        || proposal.operator_sid != actor
    {
        return Err("proposal drift or foreign original workspace".into());
    }
    let hash = digest(&serde_json::to_vec(&proposal)?);
    if read_only {
        let mut records = serde_json::Map::new();
        for leaf in [
            "approval.json",
            "start-intent.json",
            "cleanup-observation.json",
            "host-result.json",
            "recovery-intent.json",
            "recovery.json",
        ] {
            if workspace.root_path().join(leaf).try_exists()? {
                records.insert(
                    leaf.into(),
                    read_protected::<serde_json::Value>(&workspace, leaf)?,
                );
            }
        }
        let marker = completed_marker(&workspace, &proposal, profile);
        let raw = if profile == TrialProfile::Creation {
            Some(match &marker {
                Ok(hash) => creation_output_hex(&workspace, &proposal, hash),
                Err(e) => Err(format!("creation marker refused: {e}").into()),
            })
        } else {
            None
        };
        let retained_match = raw.as_ref().is_none_or(|r| r.is_ok())
            && marker.as_ref().ok().is_some_and(|hash| {
                records
                    .get("host-result.json")
                    .is_some_and(|v| v["outputSha256"] == *hash)
            });
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"schemaVersion":schema,
            "researchOnly":true,"capabilityOnly":profile==TrialProfile::Capability,"noGeneralEnforcementAcceptance":true,
            "readOnly":true,"providerCalls":0,"planSha256":hash,"proposal":proposal,
            "hostRecords":records,"guestOutputSha256":marker.as_ref().ok(),"retainedOutputMatches":retained_match,
            "guestOutputHex":raw.as_ref().and_then(|r|r.as_ref().ok()),"guestOutputHexError":raw.as_ref().and_then(|r|r.as_ref().err()).map(ToString::to_string),
            "guestOutputReadError":marker.as_ref().err().map(ToString::to_string)}))?
        );
        return Ok(());
    }
    if args[1] != hash {
        return Err("exact proposal hash required".into());
    }
    if args[0] == "--approve" {
        let _tools = verify_tools(&workspace, &proposal)?;
        publish(&workspace, "approval.json", &hash)?;
        println!("Approved research proposal {hash}; Start remains separate.");
        return Ok(());
    }
    if read_protected::<String>(&workspace, "approval.json")? != hash {
        return Err("matching approval required".into());
    }
    let id = CanonicalSandboxId::parse(session)?;
    if args[0] == "--recover" {
        let prior = if workspace
            .root_path()
            .join("host-result.json")
            .try_exists()?
        {
            Some(read_protected::<serde_json::Value>(
                &workspace,
                "host-result.json",
            )?)
        } else {
            None
        };
        let cleanup = if workspace
            .root_path()
            .join("cleanup-observation.json")
            .try_exists()?
        {
            Some(read_protected::<serde_json::Value>(
                &workspace,
                "cleanup-observation.json",
            )?)
        } else {
            None
        };
        if read_protected::<String>(&workspace, "start-intent.json")? != hash
            || !recovery_allowed_for(
                prior.as_ref(),
                &hash,
                workspace.root_path().join("recovery.json").try_exists()?,
                profile,
            )
            || !recovery_allowed_for(cleanup.as_ref(), &hash, false, profile)
        {
            return Err("only unresolved original trial can be recovered once".into());
        }
        // A crash during recovery needs review of this exact transaction. Never
        // retry a mutation against a later session reusing the original UUID.
        publish(&workspace, "recovery-intent.json", &hash)?;
        let mut lease = aiw_windows_platform::acquire_windows_sandbox_recovery(PROVIDER, id)?;
        let result = lease.reconcile()?;
        let record = json!({"schemaVersion":schema,"researchOnly":true,"capabilityOnly":profile==TrialProfile::Capability,"noGeneralEnforcementAcceptance":true,"planSha256":hash,"sessionId":result.session_id,"outerCleanupVerified":true,"disposition":format!("{:?}",result.disposition),"providerDrifted":result.provider_drifted,"sessionIdsBefore":result.session_ids_before,"sessionIdsAfter":result.session_ids_after});
        publish(&workspace, "recovery.json", &record)?;
        println!("{}", serde_json::to_string_pretty(&record)?);
        return Ok(());
    }
    let tools = verify_tools(&workspace, &proposal)?;
    if std::fs::read_dir(workspace.output_path())?.next().is_some() {
        return Err("output must be empty; preserve existing evidence".into());
    }
    if Path::new(root).join(r"Trial\recovery.json").exists() {
        return Err("recovered trial cannot Start".into());
    }
    let mut lease = aiw_windows_platform::acquire_windows_sandbox(PROVIDER)?;
    if !lease.list()?.session_ids.is_empty() {
        return Err("worker provider is in use".into());
    }
    // Durable create-new transaction precedes the mutating call. Any interruption
    // requires exact recovery, never another installation attempt in this root.
    publish(&workspace, "start-intent.json", &hash)?;
    let execution = (|| -> Result<String> {
        workspace.revalidate()?;
        for (bound, file) in &tools {
            bound.revalidate()?;
            file.revalidate()?;
        }
        lease.start(&id, &proposal.plan)?;
        lease.connect_owned()?;
        let deadline = Instant::now() + Duration::from_secs(420);
        while Instant::now() < deadline {
            if let Ok(hash) = completed_marker(&workspace, &proposal, profile) {
                return Ok(hash);
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Err(
            "capability observation deadline; request support and enforcement remain unmeasured"
                .into(),
        )
    })();
    let cleanup = lease.stop_owned();
    let cleanup_verified = cleanup.is_ok();
    // Persist cleanup independently before touching any returned guest bytes.
    publish(
        &workspace,
        "cleanup-observation.json",
        &json!({"schemaVersion":schema,"researchOnly":true,"capabilityOnly":profile==TrialProfile::Capability,"noGeneralEnforcementAcceptance":true,"planSha256":hash,"sessionId":session,"outerCleanupVerified":cleanup_verified,"cleanupError":cleanup.as_ref().err().map(ToString::to_string)}),
    )?;
    let output = completed_marker(&workspace, &proposal, profile);
    let observations_stable = matches!((&execution,&output),(Ok(a),Ok(b)) if a==b);
    let record = json!({"schemaVersion":schema,"researchOnly":true,"capabilityOnly":profile==TrialProfile::Capability,"noGeneralEnforcementAcceptance":true,"planSha256":hash,"sessionId":session,"guestMarkerObserved":execution.is_ok(),"outputSha256BeforeCleanup":execution.as_ref().ok(),"observationsStable":observations_stable,"executionError":execution.as_ref().err().map(ToString::to_string),"outerCleanupVerified":cleanup_verified,"cleanupError":cleanup.as_ref().err().map(ToString::to_string),"outputSha256":output.as_ref().ok(),"outputError":output.as_ref().err().map(ToString::to_string),"applicationExecutionRequested":false,"applicationCompatibility":"unmeasured","isolationVerdict":"unmeasured"});
    publish(&workspace, "host-result.json", &record)?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    execution?;
    cleanup?;
    output?;
    if !observations_stable {
        return Err("research marker changed across cleanup".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused_raw_diagnostics() -> serde_json::Value {
        let mut records = serde_json::Map::new();
        for name in RAW_DIAGNOSTIC_NAMES {
            records.insert(
                name.into(),
                json!({"captureComplete":false,"disposition":"refused",
                "rawHex":null,"sha256":null,"sizeBytes":null,"identity":null,
                "readError":"complete capture refused; native reason not classified"}),
            );
        }
        records.into()
    }

    fn raw_diagnostics_valid(value: &serde_json::Value) -> bool {
        serde_json::from_value::<std::collections::BTreeMap<String, RawContainedDiagnostic>>(
            value.clone(),
        )
        .is_ok_and(|records| validate_raw_contained_diagnostics(&records).is_ok())
    }

    #[test]
    fn raw_diagnostics_preserve_complete_arbitrary_bytes_and_explicit_refusals() {
        let mut value = refused_raw_diagnostics();
        assert!(raw_diagnostics_valid(&value));
        for bytes in [
            vec![],
            vec![0, 255, 128],
            b"{malformed".to_vec(),
            vec![42; 16384],
        ] {
            value["ENTRY.DAT.pending"] = json!({"captureComplete":true,"disposition":"captured",
                "rawHex":hex::encode(&bytes),"sha256":digest(&bytes),"sizeBytes":bytes.len(),
                "identity":{"finalPath":r"\\?\C:\AIW\SevenZip\Work\Mxc\Output\ENTRY.DAT.pending",
                    "volumeSerialNumber":"1".repeat(16),"fileId":"2".repeat(32)},"readError":null});
            assert!(raw_diagnostics_valid(&value));
        }
        let captured = value.clone();
        let bytes = vec![0; RAW_DIAGNOSTIC_BOUND];
        let mut maximum = refused_raw_diagnostics();
        for name in RAW_DIAGNOSTIC_NAMES {
            maximum[name] = json!({"captureComplete":true,"disposition":"captured",
                "rawHex":hex::encode(&bytes),"sha256":digest(&bytes),"sizeBytes":bytes.len(),
                "identity":{"finalPath":format!(r"C:\AIW\SevenZip\Work\Mxc\Output\{name}"),
                    "volumeSerialNumber":"1".repeat(16),"fileId":"2".repeat(32)},"readError":null});
        }
        assert!(raw_diagnostics_valid(&maximum));
        assert!(serde_json::to_vec(&maximum).unwrap().len() < 322 * 1024);
        for (field, replacement) in [
            ("rawHex", json!("00")),
            ("sha256", json!("0".repeat(64))),
            ("sizeBytes", json!(16385)),
            ("captureComplete", json!(false)),
            ("readError", json!("read failed")),
            ("unexpected", json!(true)),
        ] {
            let mut changed = captured.clone();
            changed["ENTRY.DAT.pending"][field] = replacement;
            assert!(!raw_diagnostics_valid(&changed), "{field}");
        }
        let mut wrong_path = captured.clone();
        wrong_path["ENTRY.DAT.pending"]["identity"]["finalPath"] =
            json!(r"C:\other\ENTRY.DAT.pending");
        assert!(!raw_diagnostics_valid(&wrong_path));
        let mut missing = captured.clone();
        missing.as_object_mut().unwrap().remove("SELF.DAT");
        assert!(!raw_diagnostics_valid(&missing));
        let mut extra = captured.clone();
        extra["arbitrary-path"] = extra["SELF.DAT"].clone();
        assert!(!raw_diagnostics_valid(&extra));
        let mut invented = refused_raw_diagnostics();
        invented["SELF.DAT"]["sizeBytes"] = json!(0);
        assert!(!raw_diagnostics_valid(&invented));
    }

    #[test]
    fn combined_creation_budget_fits_and_preserves_owner_error_and_binding() {
        // Synthetic bounded nested research data tests custody parsing only;
        // these strings are not assertions about an actual SDK execution.
        let old = marker_fixture();
        let hash = "a".repeat(64);
        let mut marker = json!({"schemaVersion":"aiw.dev/mxc-creation-trial/v0alpha1","researchOnly":true,
            "helperSha256":hash,"helperSizeBytes":100,"dllSha256":contract::RUNTIME_DLL_SHA256,
            "windows":old["windows"],"standardContext":old["standardContext"],"heldWorkerToken":old["heldObserverToken"],
            "handshake":{"diagnostic":"h".repeat(63000)},"handshakeError":null,
            "worker":{"diagnostic":"w".repeat(63000)},"workerReadError":null,
            "ownedJobEmpty":true,"cleanupError":null,"validationErrors":[],"applicationExecutionRequested":false,
            "selectedTierAttestation":"unmeasured","ownerObservations":{
                "ownerMeasuredChild":{"processId":43,"creationTime":42,"diagnostic":"c".repeat(63000)},
                "exactOuterJobMembership":true,"releaseGatePublished":true,
                "postExitBindingError":"QueryFullProcessImageNameW: hresult=0x8007001f",
                "rootTokenMeasurement":null,"rootTokenMeasurementReadError":"duplicate token serialized budget exceeded"},
            "retainedPrefixes":{},"rawContainedDiagnostics":{}});
        for (index, key) in CREATION_PREFIXES.iter().enumerate() {
            marker["retainedPrefixes"][*key] = if index < 16 {
                json!({"value":{"processId":43,"diagnostic":"p".repeat(7950)},"readError":null})
            } else {
                json!({"value":null,"readError":"prefix aggregate budget exceeded"})
            };
        }
        let raw = vec![0; RAW_DIAGNOSTIC_BOUND];
        for key in RAW_DIAGNOSTIC_NAMES {
            marker["rawContainedDiagnostics"][key] = json!({"captureComplete":true,"disposition":"captured",
                "rawHex":hex::encode(&raw),"sha256":digest(&raw),"sizeBytes":raw.len(),
                "identity":{"finalPath":format!(r"C:\AIW\SevenZip\Work\Mxc\Output\{key}"),
                    "volumeSerialNumber":"1".repeat(16),"fileId":"2".repeat(32)},"readError":null});
        }
        let serialized = serde_json::to_vec(&marker).unwrap();
        assert!(serialized.len() < 834 * 1024);
        assert_eq!(
            creation_marker_digest(&serialized, &hash, 100).unwrap(),
            digest(&serialized)
        );
        assert_eq!(
            marker["ownerObservations"]["ownerMeasuredChild"]["processId"],
            43
        );
        assert_eq!(marker["ownerObservations"]["releaseGatePublished"], true);
        assert!(
            marker["ownerObservations"]["postExitBindingError"]
                .as_str()
                .unwrap()
                .contains("0x8007001f")
        );
        for (field, text) in [
            ("worker", "x".repeat(65536)),
            ("handshake", "x".repeat(65536)),
            ("ownerObservations", "x".repeat(131072)),
        ] {
            let mut oversized = marker.clone();
            oversized[field] = json!({"diagnostic":text});
            assert!(
                creation_marker_digest(&serde_json::to_vec(&oversized).unwrap(), &hash, 100)
                    .is_err()
            );
        }
        let mut contradiction = marker.clone();
        contradiction["ownerObservations"]["rootTokenMeasurement"] = json!({"token":"retained"});
        assert!(
            creation_marker_digest(&serde_json::to_vec(&contradiction).unwrap(), &hash, 100)
                .is_err()
        );
        contradiction = marker;
        contradiction["ownerObservations"]["rootTokenMeasurementReadError"] =
            json!("😀".repeat(513));
        assert!(
            creation_marker_digest(&serde_json::to_vec(&contradiction).unwrap(), &hash, 100)
                .is_err()
        );
    }
    #[test]
    fn changed_raw_creation_bytes_cannot_be_exported_under_an_accepted_hash() {
        let first = b"original accepted research marker";
        let hash = digest(first);
        require_same_output_bytes(first, &hash).unwrap();
        assert!(require_same_output_bytes(b"different research marker", &hash).is_err());
        assert!(require_same_output_bytes(first, "").is_err());
    }
    #[test]
    fn creation_profile_is_driver_only_and_cannot_recover_a_capability_transaction() {
        let requests = fixed_requests_for(TrialProfile::Creation).unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].operation, FixedOperation::Driver);
        assert_eq!(requests[0].request["fallback"]["allowDaclMutation"], false);
        assert_ne!(TrialProfile::Creation.root(), ROOT);
        assert_ne!(TrialProfile::Creation.session(), SESSION);
        let record = json!({"schemaVersion":SCHEMA,"researchOnly":true,"capabilityOnly":true,"planSha256":"a","sessionId":SESSION,"outerCleanupVerified":false});
        assert!(!recovery_allowed_for(
            Some(&record),
            "a",
            false,
            TrialProfile::Creation
        ));
    }
    #[test]
    fn creation_retains_failed_prefix_without_accepting_a_production_verdict() {
        let old = marker_fixture();
        let hash = "a".repeat(64);
        let mut marker = json!({"schemaVersion":"aiw.dev/mxc-creation-trial/v0alpha1","researchOnly":true,
            "helperSha256":hash,"helperSizeBytes":100,"dllSha256":contract::RUNTIME_DLL_SHA256,
            "windows":old["windows"],"standardContext":old["standardContext"],"heldWorkerToken":old["heldObserverToken"],
            "handshake":null,"handshakeError":"worker watchdog after measured release","worker":null,"workerReadError":"missing",
            "ownedJobEmpty":true,"cleanupError":null,"validationErrors":[],"applicationExecutionRequested":false,
            "selectedTierAttestation":"unmeasured","ownerObservations":{"ownerMeasuredChild":{"processId":43},"exactOuterJobMembership":true,"releaseGatePublished":true},"retainedPrefixes":{},"rawContainedDiagnostics":refused_raw_diagnostics()});
        for key in CREATION_PREFIXES {
            marker["retainedPrefixes"][key] =
                json!({"value":null,"readError":"missing after interrupted worker"});
        }
        marker["retainedPrefixes"]["probe"] = json!({"value":{"ffiStatus":0},"readError":null});
        let bytes = serde_json::to_vec(&marker).unwrap();
        assert_eq!(
            creation_marker_digest(&bytes, &hash, 100).unwrap(),
            digest(&bytes)
        );
        let canonical_owner = marker["ownerObservations"].clone();
        let mut oversized = marker.clone();
        oversized["retainedPrefixes"]["probe"] =
            json!({"value":"\0".repeat(8192),"readError":null});
        assert!(
            creation_marker_digest(&serde_json::to_vec(&oversized).unwrap(), &hash, 100).is_err()
        );
        // Explicit refusal is valid without changing the canonical envelope,
        // retained baseline/spawn fields or owner binding observations.
        oversized["retainedPrefixes"]["probe"] =
            json!({"value":null,"readError":"serialized prefix budget exceeded"});
        assert_eq!(oversized["ownerObservations"], canonical_owner);
        assert!(
            creation_marker_digest(&serde_json::to_vec(&oversized).unwrap(), &hash, 100).is_ok()
        );
        let mut refused = marker.clone();
        refused["ownerObservations"] = json!({"releaseGatePublished":false,
            "rootTokenMeasurement":{"token":{"isAppContainer":true},"validationErrors":["userSid"]}});
        refused["retainedPrefixes"]["rootToken"] =
            json!({"value":{"measured":{"validationErrors":["userSid"]}},"readError":null});
        assert!(creation_marker_digest(&serde_json::to_vec(&refused).unwrap(), &hash, 100).is_ok());
        refused["ownerObservations"]["rootTokenMeasurement"] = json!(true);
        assert!(
            creation_marker_digest(&serde_json::to_vec(&refused).unwrap(), &hash, 100).is_err()
        );
        for (field, value) in [
            ("helperSha256", json!("b".repeat(64))),
            ("selectedTierAttestation", json!("native-verified")),
            ("applicationExecutionRequested", json!(true)),
            ("unexpected", json!(true)),
            ("handshake", json!({"unexpectedSuccess":true})),
            ("cleanupError", json!("unresolved")),
        ] {
            let mut invalid = marker.clone();
            invalid[field] = value;
            assert!(
                creation_marker_digest(&serde_json::to_vec(&invalid).unwrap(), &hash, 100).is_err(),
                "{field}"
            );
        }
    }
    fn marker_fixture() -> serde_json::Value {
        let hash = "a".repeat(64);
        let token = json!({"schemaVersion":"aiw.dev/token-evidence/v0alpha1","processId":42,
            "tokenType":"primary","isAppContainer":false,"userSid":"S-1-5-21-1-2-3-1002",
            "integrity":{"sid":"S-1-16-8192","rid":8192,"level":"medium"},
            "elevationType":"default","isElevated":false,"capabilities":[],"restrictedSidCount":0});
        json!({"schemaVersion":"aiw.dev/mxc-probe-trial/v0alpha1","researchOnly":true,
            "helperSha256":hash,"helperSizeBytes":100,"dllSha256":contract::RUNTIME_DLL_SHA256,
            "dllSizeBytes":contract::RUNTIME_DLL_SIZE,
            "windows":{"major":10,"minor":0,"build":26100,"revision":9711,"observerArchitecture":"x86_64"},
            "standardContext":{"userSid":"S-1-5-21-1-2-3-1002","profilePath":"C:\\Users\\AiwStandardUser",
                "roamingAppData":"C:\\Users\\AiwStandardUser\\AppData\\Roaming",
                "localAppData":"C:\\Users\\AiwStandardUser\\AppData\\Local","administratorsEnabled":false},
            "heldObserverToken":token,"childExitCode":null,"childError":"child deadline",
            "ownedJobEmpty":false,"cleanupError":"cleanup unresolved","probe":null,"probeReadError":"missing child output",
            "payloadBindingsVerified":false,"validationErrors":["post-child drift"],
            "requestedApplicationExecution":false,"enforcement":"unmeasured"})
    }
    #[test]
    fn failed_child_prefix_is_retained_but_wrong_binding_or_unknown_fields_are_rejected() {
        let hash = "a".repeat(64);
        let marker = marker_fixture();
        let bytes = serde_json::to_vec(&marker).unwrap();
        assert_eq!(marker_digest(&bytes, &hash, 100).unwrap(), digest(&bytes));
        for (key, value) in [
            ("helperSha256", json!("b".repeat(64))),
            ("dllSizeBytes", json!(contract::RUNTIME_DLL_SIZE + 1)),
            ("payloadBindingsVerified", json!(true)),
            ("unexpected", json!(true)),
        ] {
            let mut invalid = marker.clone();
            invalid[key] = value;
            assert!(
                marker_digest(&serde_json::to_vec(&invalid).unwrap(), &hash, 100).is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn full_emitted_probe_shape_and_signed_crash_exit_survive_strict_retained_read() {
        let hash = "a".repeat(64);
        let mut marker = marker_fixture();
        let requests = fixed_requests().unwrap().into_iter().map(|request| json!({
            "operation":request.operation,"requestSha256":request.request_sha256,
            "request":request.request,"ffiStatus":-4,"errorDetail":["native failure",null,null,null],
            "enforcement":"unmeasured"
        })).collect::<Vec<_>>();
        marker["childExitCode"] = json!(-1073741819_i32);
        marker["childError"] = serde_json::Value::Null;
        marker["probeReadError"] = serde_json::Value::Null;
        marker["probe"] = json!({"schemaVersion":"aiw.dev/mxc-request-probe-observations/v0alpha1",
            "dllSha256":contract::RUNTIME_DLL_SHA256,"dllSizeBytes":contract::RUNTIME_DLL_SIZE,
            "runtimeSource":contract::SOURCE_REVISION,"runtimeRelease":contract::RELEASE,
            "windows":marker["windows"],"observerToken":marker["heldObserverToken"],
            "collectionComplete":true,"collectionError":null,"failedOperation":null,
            "requests":requests,"requestedApplicationExecution":false,"enforcement":"unmeasured"});
        let bytes = serde_json::to_vec(&marker).unwrap();
        assert_eq!(marker_digest(&bytes, &hash, 100).unwrap(), digest(&bytes));
        let mut probe = json!({"tier":"base-container","needsDaclAugmentation":false,"warnings":[],
            "probes":{"baseContainerApiPresent":true,"nativeCaptureAvailable":false,
            "guardedCaptureAvailable":false,"bfscfgPresent":false,"bfsCompiledIn":false,
            "baseContainerSupportsDenyPaths":true,"baseContainerSupportsEnumeratePaths":false,
            "baseContainerSupportsIngressHostLoopbackAllow":false,"baseContainerSupportsIdentitylessLoopbackProxy":false,
            "isolationSessionAvailable":false,"hyperlightAvailable":false,
            "uiCapabilities":{"canBlockClipboardRead":true,"canBlockClipboardWrite":true,
            "canBlockInputInjection":true,"canBlockInputMethodChanges":true,"canBlockExternalUiObjects":true,
            "canBlockGlobalUiNamespace":true,"canBlockDesktopSwitching":true,"canBlockLogoffOrShutdown":true,
            "canBlockSystemParameterChanges":true,"canBlockDisplaySettingsChanges":true}}});
        for request in marker["probe"]["requests"].as_array_mut().unwrap() {
            request.as_object_mut().unwrap().remove("errorDetail");
            request["ffiStatus"] = json!(0);
            request["probe"] = probe.clone();
            request["disposition"] = json!("supportedForRequest");
        }
        assert!(marker_digest(&serde_json::to_vec(&marker).unwrap(), &hash, 100).is_ok());
        marker["probe"]["requests"][0]["enforcement"] = json!("effective");
        assert!(marker_digest(&serde_json::to_vec(&marker).unwrap(), &hash, 100).is_err());
        probe["unknown"] = json!(true);
        marker["probe"]["requests"][0]["enforcement"] = json!("unmeasured");
        marker["probe"]["requests"][0]["probe"] = probe;
        assert!(marker_digest(&serde_json::to_vec(&marker).unwrap(), &hash, 100).is_err());
        marker["probe"]["requests"]
            .as_array_mut()
            .unwrap()
            .truncate(1);
        marker["probe"]["requests"][0]["probe"]
            .as_object_mut()
            .unwrap()
            .remove("unknown");
        marker["probe"]["collectionComplete"] = json!(false);
        marker["probe"]["collectionError"] = json!("invalid later ABI output");
        marker["probe"]["failedOperation"] = json!("boundary");
        assert!(marker_digest(&serde_json::to_vec(&marker).unwrap(), &hash, 100).is_ok());
        marker["probe"]["failedOperation"] = json!("create");
        assert!(marker_digest(&serde_json::to_vec(&marker).unwrap(), &hash, 100).is_err());
    }
    #[test]
    fn guest_failure_is_completion_without_capability_or_enforcement_acceptance() {
        let marker = json!({"schemaVersion":"aiw.dev/mxc-probe-trial-failure/v0alpha1",
            "researchOnly":true,"driverError":"setup incomplete",
            "requestedApplicationExecution":false,"enforcement":"unmeasured"});
        let hash = "a".repeat(64);
        assert!(marker_digest(&serde_json::to_vec(&marker).unwrap(), &hash, 100).is_ok());
        for (key, value) in [
            ("researchOnly", json!(false)),
            ("requestedApplicationExecution", json!(true)),
            ("enforcement", json!("effective")),
            ("driverError", json!("")),
            ("unknown", json!(true)),
        ] {
            let mut invalid = marker.clone();
            invalid[key] = value;
            assert!(
                marker_digest(&serde_json::to_vec(&invalid).unwrap(), &hash, 100).is_err(),
                "{key}"
            );
        }
        assert!(marker_digest(b"{\"schemaVersion\":", &hash, 100).is_err());
        assert!(marker_digest(&vec![b' '; OUTPUT_BOUND as usize + 1], &hash, 100).is_err());
    }
    #[test]
    fn fixed_requests_bind_every_operation_without_execution_or_fallback_authority() {
        let requests = fixed_requests().unwrap();
        assert_eq!(requests.len(), 5);
        let hashes = requests
            .iter()
            .map(|r| r.request_sha256.clone())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(hashes.len(), 5);
        for policy in requests {
            assert_eq!(policy.request["fallback"]["allowDaclMutation"], false);
            assert_eq!(policy.request["telemetry"]["enabled"], false);
            assert_eq!(policy.request["containment"], "processcontainer");
        }
    }
    #[test]
    fn unresolved_cleanup_remains_recoverable_but_completed_and_reused_transactions_do_not() {
        let hash = "a".repeat(64);
        let unresolved = json!({"schemaVersion":SCHEMA,"researchOnly":true,"capabilityOnly":true,
            "planSha256":hash,"sessionId":SESSION,"outerCleanupVerified":false});
        assert!(recovery_allowed(Some(&unresolved), &hash, false));
        assert!(recovery_allowed(None, &hash, false));
        assert!(!recovery_allowed(Some(&unresolved), &hash, true));
        for field in [
            "schemaVersion",
            "researchOnly",
            "capabilityOnly",
            "planSha256",
            "sessionId",
            "outerCleanupVerified",
        ] {
            let mut invalid = unresolved.clone();
            invalid.as_object_mut().unwrap().remove(field);
            assert!(!recovery_allowed(Some(&invalid), &hash, false), "{field}");
        }
        let mut completed = unresolved;
        completed["outerCleanupVerified"] = json!(true);
        assert!(!recovery_allowed(Some(&completed), &hash, false));
    }
}
