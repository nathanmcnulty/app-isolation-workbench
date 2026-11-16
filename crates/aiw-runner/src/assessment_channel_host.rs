//! Approved local Start is the public-key trust anchor. Nothing in the mapped
//! transport can create or replace this authority. Retained verification never
//! creates entropy, signs, repairs a latch or publishes an acknowledgement.
use super::*;
use aiw_provider_wsb::assessment_channel::*;
use aiw_provider_wsb::assessment_request::{
    APPLICATION_ASSESSMENT_REQUEST_MAX_BYTES, ASSESSMENT_CHANNEL_REQUEST_SCHEMA,
    ApplicationAssessmentGuestRequest, AssessmentChannelRequest, assessment_value_sha256,
};
use aiw_windows_platform::assessment_channel_crypto::{self, AssessmentSigningKey};
use aiw_windows_platform::{BoundWorkspaceDirectory, HeldRunWorkspace, WorkspaceAclPolicy};

const DESCRIPTOR_FILE: &str = "assessment-channel-execution.json";
const LATCH_FILE: &str = "assessment-channel-latch.json";
const MAX_DESCRIPTOR: u64 = APPLICATION_ASSESSMENT_REQUEST_MAX_BYTES + 16 * 1024;
const MAX_LATCH: u64 = 64 * 1024;
const MIN_FREE: u64 = 10 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ExecutionDescriptor {
    schema_version: String,
    start_intent_sha256: String,
    pub request: ApplicationAssessmentGuestRequest,
    pub binding: AssessmentChannelBinding,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicLatch {
    schema_version: String,
    descriptor_sha256: String,
    bootstrap: AssessmentChannelRecord,
    acknowledgement: AssessmentChannelRecord,
}

pub(super) struct StartChannel {
    pub descriptor: ExecutionDescriptor,
    pub descriptor_sha256: String,
    signer: Option<AssessmentSigningKey>,
}
pub(super) struct CngVerifier;
impl AssessmentChannelVerifier for CngVerifier {
    fn verify_digest(
        &self,
        key: &[u8; 72],
        digest: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), String> {
        assessment_channel_crypto::verify_digest(key, digest, signature)
    }
}

fn receipt_error(_: impl std::fmt::Display) -> RunnerError {
    RunnerError::Receipt("authenticated assessment channel record refused".into())
}
fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, RunnerError> {
    let value = serde_json::to_value(value).map_err(receipt_error)?;
    aiw_evidence::canonical_json_bytes(&value).map_err(receipt_error)
}
fn records_directory(
    workspace: &HeldRunWorkspace,
    layout: &RunLayout,
) -> Result<BoundWorkspaceDirectory, RunnerError> {
    workspace
        .reopen_root_directory("runs", WorkspaceAclPolicy::Inherited)
        .and_then(|runs| runs.reopen_directory(layout.run_id(), WorkspaceAclPolicy::Inherited))
        .map_err(|_| RunnerError::Drift)
}
fn write_new(
    directory: &BoundWorkspaceDirectory,
    leaf: &str,
    bytes: &[u8],
    cap: u64,
) -> Result<(), RunnerError> {
    if bytes.is_empty() || bytes.len() as u64 > cap {
        return Err(RunnerError::Drift);
    }
    directory.revalidate().map_err(|_| RunnerError::Drift)?;
    // Create-only direct writes: a torn file consumes this publication and is
    // never adopted, removed or completed by another execution attempt.
    let created = directory
        .create_file_new(leaf)
        .map_err(|_| RunnerError::Drift)?;
    let mut file = created.into_file();
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| RunnerError::Drift)?;
    directory.revalidate().map_err(|_| RunnerError::Drift)
}
fn read_exact(
    directory: &BoundWorkspaceDirectory,
    leaf: &str,
    cap: u64,
) -> Result<Vec<u8>, RunnerError> {
    let file = directory
        .reopen_file_readonly(leaf)
        .map_err(|_| RunnerError::Drift)?;
    let before = file.identity().clone();
    let length = file
        .as_file()
        .metadata()
        .map_err(|_| RunnerError::Drift)?
        .len();
    if length == 0 || length > cap {
        return Err(RunnerError::Drift);
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.as_file()
        .take(cap + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RunnerError::Drift)?;
    file.revalidate().map_err(|_| RunnerError::Drift)?;
    if bytes.len() as u64 != length || file.identity() != &before {
        return Err(RunnerError::Drift);
    }
    Ok(bytes)
}

pub(super) fn begin_start(
    request: &WsbGoldenProbeStart,
    plan: &RunPlan,
    layout: &RunLayout,
    workspace: &HeldRunWorkspace,
) -> Result<StartChannel, RunnerError> {
    plan.ensure_current().map_err(journal_error)?;
    let approval = layout.read_approval().map_err(journal_error)?;
    ensure_approval(plan, &approval, request)?;
    let assessment = request
        .application_assessment
        .as_ref()
        .ok_or(RunnerError::ApprovalBinding)?;
    assessment
        .validate(&request.workspace)
        .map_err(|_| RunnerError::ApprovalBinding)?;
    revalidate_project_revision(plan, Path::new(&request.project_path))?;
    revalidate_workspace(request, workspace)?;
    if workspace
        .available_volume_bytes()
        .map_err(|_| RunnerError::Drift)?
        < MIN_FREE + MAX_PRODUCER_BYTES
    {
        return Err(RunnerError::Receipt(
            "channel Start requires 10 GiB free plus its bounded transport reserve".into(),
        ));
    }
    let protocol = plan
        .actions
        .iter()
        .find_map(|a| match a {
            PlannedAction::ExecuteWindowsSandboxApplicationAssessment {
                provider_protocol,
                evidence_channel,
                ..
            } if evidence_channel.as_deref() == Some(CHANNEL_PROTOCOL) => provider_protocol.clone(),
            _ => None,
        })
        .ok_or(RunnerError::ApprovalBinding)?;
    let intent = layout
        .consume_application_channel_start(&plan.hash().map_err(journal_error)?)
        .map_err(journal_error)?;
    let signer = AssessmentSigningKey::generate().map_err(receipt_error)?;
    let public = hex::encode(signer.public_key().map_err(receipt_error)?);
    let nonce = hex::encode(assessment_channel_crypto::generate_nonce().map_err(receipt_error)?);
    let config = render_config(&request.wsb_plan).map_err(|_| RunnerError::Drift)?;
    let guest = ApplicationAssessmentGuestRequest::new_authenticated(
        plan.run_id.clone(),
        deterministic_sandbox_id(&plan.run_id),
        config.sha256,
        request.guest_agent.sha256.clone(),
        plan.project_revision_hash.clone(),
        assessment.compiled.clone(),
        AssessmentChannelRequest {
            schema_version: ASSESSMENT_CHANNEL_REQUEST_SCHEMA.into(),
            channel_protocol: CHANNEL_PROTOCOL.into(),
            plan_sha256: plan.hash().map_err(journal_error)?,
            provider_sha256: request.provider.sha256.clone(),
            provider_protocol: protocol,
            workspace_identity_sha256: request.workspace_identity_sha256.clone(),
            nonce_hex: nonce,
            host_ack_public_key_hex: public,
        },
    )
    .map_err(receipt_error)?;
    let descriptor = ExecutionDescriptor {
        schema_version: "aiw.dev/assessment-channel-execution/v0alpha1".into(),
        start_intent_sha256: assessment_value_sha256(&intent).map_err(receipt_error)?,
        binding: guest.channel_binding().map_err(receipt_error)?,
        request: guest,
    };
    let bytes = canonical_bytes(&descriptor)?;
    let digest = hex::encode(Sha256::digest(&bytes));
    write_new(
        &records_directory(workspace, layout)?,
        DESCRIPTOR_FILE,
        &bytes,
        MAX_DESCRIPTOR,
    )?;
    Ok(StartChannel {
        descriptor,
        descriptor_sha256: digest,
        signer: Some(signer),
    })
}

pub(super) fn read_descriptor(
    workspace: &HeldRunWorkspace,
    layout: &RunLayout,
    request: &WsbGoldenProbeStart,
    plan: &RunPlan,
) -> Result<(ExecutionDescriptor, String), RunnerError> {
    let intent = layout
        .read_application_channel_start_intent()
        .map_err(journal_error)?;
    let raw = read_exact(
        &records_directory(workspace, layout)?,
        DESCRIPTOR_FILE,
        MAX_DESCRIPTOR,
    )?;
    let descriptor: ExecutionDescriptor = serde_json::from_slice(&raw).map_err(receipt_error)?;
    let assessment = request
        .application_assessment
        .as_ref()
        .ok_or(RunnerError::ApprovalBinding)?;
    let protocol = plan
        .actions
        .iter()
        .find_map(|a| match a {
            PlannedAction::ExecuteWindowsSandboxApplicationAssessment {
                provider_protocol,
                evidence_channel,
                ..
            } if evidence_channel.as_deref() == Some(CHANNEL_PROTOCOL) => {
                provider_protocol.as_ref()
            }
            _ => None,
        })
        .ok_or(RunnerError::ApprovalBinding)?;
    let expected = &descriptor.request;
    let binding = expected.channel_binding().map_err(receipt_error)?;
    if canonical_bytes(&descriptor)? != raw
        || descriptor.schema_version != "aiw.dev/assessment-channel-execution/v0alpha1"
        || descriptor.start_intent_sha256
            != assessment_value_sha256(&intent).map_err(receipt_error)?
        || descriptor.binding != binding
        || binding.plan_sha256 != plan.hash().map_err(journal_error)?
        || binding.provider_sha256 != request.provider.sha256
        || &binding.provider_protocol != protocol
        || binding.workspace_identity_sha256 != request.workspace_identity_sha256
        || expected.run_id != plan.run_id
        || expected.sandbox_id != deterministic_sandbox_id(&plan.run_id)
        || expected.config_sha256
            != render_config(&request.wsb_plan)
                .map_err(|_| RunnerError::Drift)?
                .sha256
        || expected.agent_sha256 != request.guest_agent.sha256
        || expected.project_revision_sha256 != plan.project_revision_hash
        || expected.assessment != assessment.compiled
    {
        return Err(RunnerError::ApprovalBinding);
    }
    Ok((descriptor, hex::encode(Sha256::digest(&raw))))
}

pub(super) fn validate_recovery_authority(
    workspace: &HeldRunWorkspace,
    layout: &RunLayout,
    plan: &RunPlan,
    transaction: &SessionTransaction,
) -> Result<ExecutionDescriptor, RunnerError> {
    let intent = layout
        .read_application_channel_start_intent()
        .map_err(journal_error)?;
    let raw = read_exact(
        &records_directory(workspace, layout)?,
        DESCRIPTOR_FILE,
        MAX_DESCRIPTOR,
    )?;
    let descriptor: ExecutionDescriptor = serde_json::from_slice(&raw).map_err(receipt_error)?;
    let expected = descriptor
        .request
        .channel_binding()
        .map_err(receipt_error)?;
    let action = plan
        .actions
        .iter()
        .find_map(|a| match a {
            PlannedAction::ExecuteWindowsSandboxApplicationAssessment {
                provider_protocol,
                evidence_channel,
                sandbox_plan_sha256,
                provider_sha256,
                guest_agent_sha256,
                workspace_identity_sha256,
                source_manifest_sha256,
                assessment_sha256,
                ..
            } => Some((
                provider_protocol,
                evidence_channel,
                sandbox_plan_sha256,
                provider_sha256,
                guest_agent_sha256,
                workspace_identity_sha256,
                source_manifest_sha256,
                assessment_sha256,
            )),
            _ => None,
        })
        .ok_or(RunnerError::ApprovalBinding)?;
    let held_plan = workspace
        .reopen_root_file_readonly("wsb-plan.json")
        .map_err(|_| RunnerError::Drift)?;
    let mut plan_bytes = Vec::new();
    held_plan
        .as_file()
        .take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut plan_bytes)
        .map_err(|_| RunnerError::Drift)?;
    if plan_bytes.len() > 2 * 1024 * 1024 {
        return Err(RunnerError::Drift);
    }
    let sandbox_plan: WindowsSandboxPlan =
        serde_json::from_slice(&plan_bytes).map_err(receipt_error)?;
    verify_sandbox_plan_commitments(&sandbox_plan, action.2, &expected.config_sha256)?;
    held_plan.revalidate().map_err(|_| RunnerError::Drift)?;
    if canonical_bytes(&descriptor)? != raw
        || descriptor.schema_version != "aiw.dev/assessment-channel-execution/v0alpha1"
        || descriptor.binding != expected
        || descriptor.start_intent_sha256
            != assessment_value_sha256(&intent).map_err(receipt_error)?
        || transaction.schema_version != session::AUTHENTICATED_SESSION_TRANSACTION_SCHEMA
        || transaction.descriptor_sha256.as_deref()
            != Some(hex::encode(Sha256::digest(&raw)).as_str())
        || transaction.plan_hash != plan.hash().map_err(journal_error)?
        || expected.plan_sha256 != transaction.plan_hash
        || expected.run_id != transaction.run_id
        || expected.sandbox_id != transaction.session_id
        || expected.project_revision_sha256 != transaction.project_revision_hash
        || expected.config_sha256 != transaction.config_sha256
        || expected.provider_sha256 != transaction.provider_sha256
        || expected.workspace_identity_sha256 != transaction.workspace_identity_sha256
        || expected.request_sha256 != transaction.request_sha256
        || action.0.as_ref() != Some(&expected.provider_protocol)
        || action.1.as_deref() != Some(CHANNEL_PROTOCOL)
        || action.3 != &expected.provider_sha256
        || action.4 != &expected.agent_sha256
        || action.5 != &expected.workspace_identity_sha256
        || action.6 != &expected.application_content_manifest_sha256
        || action.7 != &expected.assessment_sha256
    {
        return Err(RunnerError::ApprovalBinding);
    }
    // An orphan/missing latch grants no evidence authority. Cleanup authority
    // comes from this separately approved exact descriptor/session; recovery
    // never adopts a latch, publishes an ACK, signs or resumes the application.
    Ok(descriptor)
}

fn verify_sandbox_plan_commitments(
    plan: &WindowsSandboxPlan,
    approved_plan_sha256: &str,
    expected_config_sha256: &str,
) -> Result<(), RunnerError> {
    if canonical_hash(plan)? != approved_plan_sha256
        || render_config(plan).map_err(|_| RunnerError::Drift)?.sha256 != expected_config_sha256
    {
        return Err(RunnerError::ApprovalBinding);
    }
    Ok(())
}

pub(super) struct CompletedChannelEvidence {
    pub verification: aiw_provider_wsb::WindowsSandboxCompletionVerification,
    pub observed: aiw_provider_wsb::assessment_observation::ApplicationAssessmentResult,
    pub evidence: aiw_provider_wsb::assessment_evidence::VerifiedAssessmentEvidence,
}
pub(super) fn hold_output(
    output: &Path,
) -> Result<Vec<aiw_windows_platform::HeldApplicationFile>, RunnerError> {
    [
        ("assessment-result.json", 16 * 1024 * 1024),
        ("evidence.jsonl", 1024 * 1024),
        ("completion.json", 1024 * 1024),
        (CHANNEL_PROGRESS_LEAF, MAX_PROGRESS_BYTES as u64),
        (CHANNEL_TERMINAL_LEAF, MAX_TERMINAL_BYTES as u64),
    ]
    .into_iter()
    .map(|(leaf, cap)| {
        aiw_windows_platform::HeldApplicationFile::open_bounded(&output.join(leaf), cap)
            .map_err(|_| RunnerError::Drift)
    })
    .collect()
}
fn replay_public_latch(
    workspace: &HeldRunWorkspace,
    layout: &RunLayout,
    descriptor: &ExecutionDescriptor,
    transaction: &SessionTransaction,
) -> Result<AssessmentChannelSession, RunnerError> {
    let expected = transaction
        .transitions
        .last()
        .and_then(|t| t.channel_latch_sha256.as_deref())
        .ok_or_else(|| RunnerError::Receipt("no committed local collector-key latch".into()))?;
    let raw = read_exact(
        &records_directory(workspace, layout)?,
        LATCH_FILE,
        MAX_LATCH,
    )?;
    let latch: PublicLatch = serde_json::from_slice(&raw).map_err(receipt_error)?;
    if canonical_bytes(&latch)? != raw
        || hex::encode(Sha256::digest(&raw)) != expected
        || latch.schema_version != "aiw.dev/assessment-channel-latch/v0alpha1"
        || Some(latch.descriptor_sha256.as_str()) != transaction.descriptor_sha256.as_deref()
        || descriptor.binding
            != descriptor
                .request
                .channel_binding()
                .map_err(receipt_error)?
    {
        return Err(RunnerError::ApprovalBinding);
    }
    let mut session =
        AssessmentChannelSession::new(descriptor.binding.clone()).map_err(receipt_error)?;
    session
        .latch_bootstrap(
            &latch.bootstrap.canonical_wire().map_err(receipt_error)?,
            &CngVerifier,
        )
        .map_err(receipt_error)?;
    // Pure verification replay of an already committed public ACK. This does
    // not generate a key, sign, create an intent file or deliver another ACK.
    let _material = session.begin_ack().map_err(receipt_error)?;
    session
        .accept_ack(
            &latch
                .acknowledgement
                .canonical_wire()
                .map_err(receipt_error)?,
            &CngVerifier,
        )
        .map_err(receipt_error)?;
    Ok(session)
}

pub(super) fn verify_completed(
    workspace: &HeldRunWorkspace,
    layout: &RunLayout,
    plan: &RunPlan,
    transaction: &SessionTransaction,
) -> Result<CompletedChannelEvidence, RunnerError> {
    let descriptor = validate_recovery_authority(workspace, layout, plan, transaction)?;
    let mut session = replay_public_latch(workspace, layout, &descriptor, transaction)?;
    let progress = optional_output(workspace, CHANNEL_PROGRESS_LEAF, MAX_PROGRESS_BYTES as u64)?
        .ok_or(RunnerError::Drift)?;
    let mut records = Vec::new();
    let mut raw = Vec::new();
    let mut consumed = 0;
    ingest_prefix(
        &mut session,
        &mut records,
        &mut raw,
        &mut consumed,
        progress,
    )?;
    if consumed != raw.len() {
        return Err(RunnerError::Receipt(
            "signed terminal journal is incomplete".into(),
        ));
    }
    let terminal = optional_output(workspace, CHANNEL_TERMINAL_LEAF, MAX_TERMINAL_BYTES as u64)?
        .ok_or(RunnerError::Drift)?;
    let terminal = session
        .accept_terminal(&terminal, &CngVerifier)
        .map_err(receipt_error)?;
    verify_artifacts(workspace, &terminal)?;
    let request = &descriptor.request;
    let mut expectation = completion_expectation(
        &request.run_id,
        &request.sandbox_id,
        &request.config_sha256,
        &request.agent_sha256,
        &request.request_sha256,
    );
    expectation.artifacts[0].path = "assessment-result.json".into();
    expectation.artifacts[0].role = aiw_evidence::ArtifactRole::ScenarioResults;
    expectation.artifacts[0].maximum_bytes = 16 * 1024 * 1024;
    expectation.artifacts[1].maximum_bytes = 1024 * 1024;
    expectation
        .artifacts
        .push(aiw_provider_wsb::CompletionArtifactExpectation {
            path: CHANNEL_PROGRESS_LEAF.into(),
            role: aiw_evidence::ArtifactRole::DiagnosticLog,
            sensitivity: aiw_evidence::DataSensitivity::Confidential,
            media_type: "application/x-ndjson".into(),
            maximum_bytes: MAX_PROGRESS_BYTES as u64,
        });
    let verification =
        verify_completion_receipt(workspace.output_path(), &expectation).map_err(receipt_error)?;
    let result = optional_output(workspace, "assessment-result.json", 16 * 1024 * 1024)?
        .ok_or(RunnerError::Drift)?;
    let observed = serde_json::from_slice(&result).map_err(receipt_error)?;
    let evidence =
        optional_output(workspace, "evidence.jsonl", 1024 * 1024)?.ok_or(RunnerError::Drift)?;
    let receipt =
        optional_output(workspace, "completion.json", 1024 * 1024)?.ok_or(RunnerError::Drift)?;
    let evidence = aiw_provider_wsb::assessment_evidence::verify_authenticated_assessment_evidence(
        &terminal,
        &evidence,
        &verification.evidence_root_hash,
        &result,
        &receipt,
        &raw,
        &records,
        request,
        &observed,
    )
    .map_err(receipt_error)?;
    workspace.revalidate().map_err(|_| RunnerError::Drift)?;
    Ok(CompletedChannelEvidence {
        verification,
        observed,
        evidence,
    })
}

pub(super) fn verify_prefix(
    workspace: &HeldRunWorkspace,
    layout: &RunLayout,
    plan: &RunPlan,
    transaction: &SessionTransaction,
) -> Result<Option<aiw_provider_wsb::assessment_evidence::AssessmentProgressPrefix>, RunnerError> {
    let descriptor = validate_recovery_authority(workspace, layout, plan, transaction)?;
    if transaction
        .transitions
        .last()
        .is_none_or(|t| t.channel_latch_sha256.is_none())
    {
        return Ok(None);
    }
    let mut session = replay_public_latch(workspace, layout, &descriptor, transaction)?;
    match fs::symlink_metadata(workspace.output_path().join(CHANNEL_PROGRESS_LEAF)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(RunnerError::Drift),
        Ok(_) => {}
    }
    let prefix = workspace
        .read_assessment_channel_progress_prefix()
        .map_err(|_| RunnerError::Drift)?;
    let mut records = Vec::new();
    let mut raw = Vec::new();
    let mut consumed = 0;
    ingest_prefix(&mut session, &mut records, &mut raw, &mut consumed, prefix)?;
    if records.is_empty() {
        return Ok(None);
    }
    aiw_provider_wsb::assessment_evidence::parse_authenticated_assessment_progress(
        &raw,
        &records,
        &descriptor.request,
    )
    .map(Some)
    .map_err(receipt_error)
}

fn optional_output(
    workspace: &HeldRunWorkspace,
    leaf: &str,
    cap: u64,
) -> Result<Option<Vec<u8>>, RunnerError> {
    match fs::symlink_metadata(workspace.output_path().join(leaf)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(RunnerError::Drift),
        Ok(m) if m.is_file() && !m.file_type().is_symlink() => {
            let directory = workspace
                .reopen_root_directory("output", WorkspaceAclPolicy::Protected)
                .map_err(|_| RunnerError::Drift)?;
            read_exact(&directory, leaf, cap).map(Some)
        }
        _ => Err(RunnerError::Drift),
    }
}
fn output_budget(workspace: &HeldRunWorkspace) -> Result<(), RunnerError> {
    if workspace
        .available_volume_bytes()
        .map_err(|_| RunnerError::Drift)?
        < MIN_FREE
    {
        return Err(RunnerError::Receipt(
            "channel free-space watchdog floor crossed".into(),
        ));
    }
    let allowed = [
        (CHANNEL_BOOTSTRAP_LEAF, MAX_BOOTSTRAP_BYTES as u64),
        (CHANNEL_BOOTSTRAP_PENDING_LEAF, MAX_BOOTSTRAP_BYTES as u64),
        (CHANNEL_ACK_LEAF, MAX_ACK_BYTES as u64),
        (CHANNEL_TERMINAL_LEAF, MAX_TERMINAL_BYTES as u64),
        (CHANNEL_TERMINAL_PENDING_LEAF, MAX_TERMINAL_BYTES as u64),
        ("assessment-result.json", 16 * 1024 * 1024),
        ("evidence.jsonl", 1024 * 1024),
        ("completion.json", 1024 * 1024),
        (CHANNEL_PROGRESS_LEAF, MAX_PROGRESS_BYTES as u64),
    ];
    let mut total = 0_u64;
    let mut count = 0;
    for entry in fs::read_dir(workspace.output_path()).map_err(|_| RunnerError::Drift)? {
        count += 1;
        if count > allowed.len() {
            return Err(RunnerError::Receipt(
                "channel output entry budget exceeded".into(),
            ));
        }
        let entry = entry.map_err(|_| RunnerError::Drift)?;
        let leaf = entry.file_name();
        let cap = allowed
            .iter()
            .find(|(name, _)| Some(*name) == leaf.to_str())
            .map(|(_, cap)| *cap)
            .ok_or_else(|| RunnerError::Receipt("unexpected channel output entry".into()))?;
        // This finite, flat inventory is diagnostic only. Never follow a
        // directory/reparse point, recurse, or grant metadata evidence authority.
        let metadata = fs::symlink_metadata(entry.path()).map_err(|_| RunnerError::Drift)?;
        use std::os::windows::fs::MetadataExt;
        if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0 || metadata.len() > cap {
            return Err(RunnerError::Receipt(
                "channel output type or file budget exceeded".into(),
            ));
        }
        total = total
            .checked_add(metadata.len())
            .ok_or(RunnerError::Drift)?;
        if total > MAX_PRODUCER_BYTES {
            return Err(RunnerError::Receipt(
                "channel aggregate output budget exceeded".into(),
            ));
        }
    }
    workspace.revalidate().map_err(|_| RunnerError::Drift)
}

impl AuthenticatedAssessmentChannel for StartChannel {
    fn wait(
        &mut self,
        request: &WsbGoldenProbeStart,
        layout: &RunLayout,
        context: &ExecutionContext,
        store: &TransactionStore<'_>,
    ) -> Result<(), RunnerError> {
        let workspace =
            HeldRunWorkspace::reopen_bound(&request.workspace).map_err(|_| RunnerError::Drift)?;
        let (descriptor, digest) = read_descriptor(&workspace, layout, request, &context.plan)?;
        if descriptor != self.descriptor
            || digest != self.descriptor_sha256
            || context.binding.descriptor_sha256.as_deref() != Some(digest.as_str())
        {
            return Err(RunnerError::ApprovalBinding);
        }
        let mut session =
            AssessmentChannelSession::new(descriptor.binding.clone()).map_err(receipt_error)?;
        let deadline = Instant::now() + Duration::from_secs(u64::from(request.timeout_seconds));
        let mut last_prefix = Vec::new();
        let mut consumed = 0_usize;
        let mut records = Vec::new();
        loop {
            if cancellation_requested(layout)? {
                return Err(RunnerError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(RunnerError::Receipt(
                    "authenticated assessment deadline expired".into(),
                ));
            }
            output_budget(&workspace)?;
            if !session.ack_verified() {
                if let Some(bytes) = optional_output(
                    &workspace,
                    CHANNEL_BOOTSTRAP_LEAF,
                    MAX_BOOTSTRAP_BYTES as u64,
                )? {
                    let bootstrap = session
                        .latch_bootstrap(&bytes, &CngVerifier)
                        .map_err(receipt_error)?;
                    let intent = session.begin_ack().map_err(receipt_error)?;
                    let signer = self.signer.take().ok_or(RunnerError::ApprovalBinding)?;
                    let signature = match signer
                        .sign_digest(&intent.signing_digest().map_err(receipt_error)?)
                    {
                        Ok(signature) => signature,
                        Err(error) => {
                            let cleanup = signer.destroy();
                            return Err(receipt_error(format!("{error}; {cleanup:?}")));
                        }
                    };
                    let acknowledgement = intent.with_signature(&signature);
                    let ack_bytes = acknowledgement.canonical_wire().map_err(receipt_error)?;
                    session
                        .accept_ack(&ack_bytes, &CngVerifier)
                        .map_err(receipt_error)?;
                    let latch = PublicLatch {
                        schema_version: "aiw.dev/assessment-channel-latch/v0alpha1".into(),
                        descriptor_sha256: digest.clone(),
                        bootstrap: bootstrap.record().clone(),
                        acknowledgement,
                    };
                    let bytes = canonical_bytes(&latch)?;
                    let hash = hex::encode(Sha256::digest(&bytes));
                    write_new(
                        &records_directory(&workspace, layout)?,
                        LATCH_FILE,
                        &bytes,
                        MAX_LATCH,
                    )?;
                    store.commit_channel_latch(&hash)?;
                    // Observed release precedes gate delivery. Every failure
                    // after durable latch intent remains cleanup-only/unknown.
                    signer.destroy().map_err(receipt_error)?;
                    workspace
                        .publish_assessment_channel_ack(&ack_bytes)
                        .map_err(|_| RunnerError::Drift)?;
                }
            } else {
                match fs::symlink_metadata(workspace.output_path().join(CHANNEL_PROGRESS_LEAF)) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(RunnerError::Drift),
                    Ok(_) => {
                        let prefix = workspace
                            .read_assessment_channel_progress_prefix()
                            .map_err(|_| RunnerError::Drift)?;
                        ingest_prefix(
                            &mut session,
                            &mut records,
                            &mut last_prefix,
                            &mut consumed,
                            prefix,
                        )?;
                    }
                }
                if let Some(terminal) =
                    optional_output(&workspace, CHANNEL_TERMINAL_LEAF, MAX_TERMINAL_BYTES as u64)?
                {
                    // The terminal can appear after this iteration's prefix
                    // sample. Consume the final closed journal first.
                    let complete = optional_output(
                        &workspace,
                        CHANNEL_PROGRESS_LEAF,
                        MAX_PROGRESS_BYTES as u64,
                    )?
                    .ok_or(RunnerError::Drift)?;
                    ingest_prefix(
                        &mut session,
                        &mut records,
                        &mut last_prefix,
                        &mut consumed,
                        complete,
                    )?;
                    if consumed != last_prefix.len() {
                        return Err(RunnerError::Receipt(
                            "terminal progress has an incomplete tail".into(),
                        ));
                    }
                    let verified = session
                        .accept_terminal(&terminal, &CngVerifier)
                        .map_err(receipt_error)?;
                    verify_artifacts(&workspace, &verified)?;
                    return Ok(());
                }
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

fn ingest_prefix(
    session: &mut AssessmentChannelSession,
    records: &mut Vec<VerifiedChannelRecord>,
    last: &mut Vec<u8>,
    consumed: &mut usize,
    prefix: Vec<u8>,
) -> Result<(), RunnerError> {
    if !prefix.starts_with(last.as_slice()) {
        return Err(RunnerError::Receipt(
            "signed progress prefix changed".into(),
        ));
    }
    while let Some(relative) = prefix[*consumed..].iter().position(|b| *b == b'\n') {
        let end = *consumed + relative + 1;
        records.push(
            session
                .accept_progress_line(&prefix[*consumed..end], &CngVerifier)
                .map_err(receipt_error)?,
        );
        *consumed = end;
    }
    *last = prefix;
    Ok(())
}

fn verify_artifacts(
    workspace: &HeldRunWorkspace,
    terminal: &VerifiedChannelRecord,
) -> Result<(), RunnerError> {
    let AssessmentChannelPayload::Terminal { artifacts, .. } = &terminal.record().payload else {
        return Err(RunnerError::Drift);
    };
    for artifact in artifacts {
        let raw = optional_output(workspace, &artifact.path, artifact.size_bytes)?
            .ok_or(RunnerError::Drift)?;
        verify_channel_artifact(terminal, artifact.role, &raw).map_err(receipt_error)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_optional_output_reads_protected_workspace_without_relaxing_guards() {
        let parent = std::env::temp_dir().canonicalize().unwrap();
        let leaf = format!("aiw-channel-output-test-{}", std::process::id());
        let workspace = HeldRunWorkspace::create(&parent, &leaf).unwrap();
        let root = workspace.root_path().to_owned();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert!(
                optional_output(&workspace, CHANNEL_BOOTSTRAP_LEAF, 16)
                    .unwrap()
                    .is_none()
            );
            // The production workspace protects output. Requiring inherited
            // ACLs used to refuse the first present bootstrap before ACK.
            assert!(
                workspace
                    .reopen_root_directory("output", WorkspaceAclPolicy::Inherited)
                    .is_err()
            );
            let mut file = workspace
                .create_output_file_new(CHANNEL_BOOTSTRAP_LEAF)
                .unwrap()
                .into_file();
            file.write_all(b"inert bootstrap").unwrap();
            file.sync_all().unwrap();
            drop(file);
            assert_eq!(
                optional_output(&workspace, CHANNEL_BOOTSTRAP_LEAF, 16).unwrap(),
                Some(b"inert bootstrap".to_vec())
            );
            assert!(optional_output(&workspace, CHANNEL_BOOTSTRAP_LEAF, 14).is_err());
            // Ensure the traversal target exists so this exercises the held
            // reader's leaf validation rather than the optional absent case.
            let mut plan = workspace
                .create_root_file_new("plan.json")
                .unwrap()
                .into_file();
            plan.write_all(b"inert plan").unwrap();
            drop(plan);
            assert!(optional_output(&workspace, "../plan.json", 1024).is_err());
            let directory = workspace.create_output_directory_new("collision").unwrap();
            drop(directory);
            assert!(optional_output(&workspace, "collision", 16).is_err());
            workspace.revalidate().unwrap();
        }));
        drop(workspace);
        std::fs::remove_dir_all(root).unwrap();
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }

    #[test]
    fn native_cng_host_ingestion_waits_for_lf_and_refuses_prefix_rewrite() {
        use aiw_provider_wsb::assessment_observation::AssessmentProgressEvent;
        use aiw_token::{
            ElevationType, IntegrityEvidence, IntegrityLevel, TokenEvidence, TokenType,
        };
        let host = AssessmentSigningKey::generate().unwrap();
        let guest = AssessmentSigningKey::generate().unwrap();
        let guest_public = hex::encode(guest.public_key().unwrap());
        let binding = AssessmentChannelBinding {
            schema_version: CHANNEL_SCHEMA.into(),
            channel_protocol: CHANNEL_PROTOCOL.into(),
            run_id: "host-channel-test".into(),
            plan_sha256: "1".repeat(64),
            project_revision_sha256: "2".repeat(64),
            assessment_sha256: "3".repeat(64),
            semantic_sha256: "4".repeat(64),
            application_content_manifest_sha256: "5".repeat(64),
            agent_sha256: "6".repeat(64),
            provider_sha256: "7".repeat(64),
            provider_protocol: aiw_probe::WindowsSandboxCliAdapter::V0_8_114_0.protocol(),
            config_sha256: "8".repeat(64),
            sandbox_id: "12345678-1234-4234-9234-123456789abc".into(),
            workspace_identity_sha256: "9".repeat(64),
            request_sha256: "a".repeat(64),
            nonce_hex: "b".repeat(64),
            host_ack_public_key_hex: hex::encode(host.public_key().unwrap()),
        };
        // Synthetic identity describes protocol input only. CNG signatures below
        // are real; this test grants no native collector or application credit.
        let collector = TokenEvidence {
            schema_version: aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION.into(),
            process_id: 42,
            token_type: TokenType::Primary,
            impersonation_level: None,
            is_app_container: false,
            app_container_sid: None,
            user_sid: "S-1-5-21-1-2-3-504".into(),
            integrity: IntegrityEvidence {
                sid: "S-1-16-12288".into(),
                rid: 12288,
                level: IntegrityLevel::High,
            },
            elevation_type: ElevationType::Full,
            is_elevated: true,
            capabilities: vec![],
            restricted_sid_count: 0,
        };
        let mut session = AssessmentChannelSession::new(binding.clone()).unwrap();
        let bootstrap_intent = signing_intent(
            &binding,
            &guest_public,
            0,
            &"0".repeat(64),
            AssessmentChannelPayload::Bootstrap {
                schema_version: CHANNEL_SCHEMA.into(),
                binding: Box::new(binding.clone()),
                guest_public_key_hex: guest_public.clone(),
                collector_token: Box::new(collector.clone()),
                collector_storage: ChannelCollectorStorage::ProtectedGuestLocal,
            },
        )
        .unwrap();
        let signature = guest
            .sign_digest(&bootstrap_intent.signing_digest().unwrap())
            .unwrap();
        let bootstrap = bootstrap_intent.with_signature(&signature);
        session
            .latch_bootstrap(&bootstrap.canonical_wire().unwrap(), &CngVerifier)
            .unwrap();
        let ack_intent = session.begin_ack().unwrap();
        let signature = host
            .sign_digest(&ack_intent.signing_digest().unwrap())
            .unwrap();
        let ack = ack_intent.with_signature(&signature);
        let verified_ack = session
            .accept_ack(&ack.canonical_wire().unwrap(), &CngVerifier)
            .unwrap();
        let previous = verified_ack.commitment().to_owned();
        host.destroy().unwrap();
        let event = AssessmentProgressEvent::Header {
            schema_version: CHANNEL_PROGRESS_SCHEMA.into(),
            run_id: binding.run_id.clone(),
            sandbox_id: binding.sandbox_id.clone(),
            request_sha256: binding.request_sha256.clone(),
            assessment_sha256: binding.assessment_sha256.clone(),
            agent_sha256: binding.agent_sha256.clone(),
            config_sha256: binding.config_sha256.clone(),
            project_revision_sha256: binding.project_revision_sha256.clone(),
            collector_token: collector,
        };
        let intent = signing_intent(
            &binding,
            &guest_public,
            1,
            &previous,
            AssessmentChannelPayload::Progress {
                schema_version: CHANNEL_PROGRESS_SCHEMA.into(),
                event: Box::new(event),
            },
        )
        .unwrap();
        let signature = guest
            .sign_digest(&intent.signing_digest().unwrap())
            .unwrap();
        let record = intent.with_signature(&signature);
        guest.destroy().unwrap();
        let mut wire = record.canonical_wire().unwrap();
        let mut records = Vec::new();
        let mut last = Vec::new();
        let mut consumed = 0;
        ingest_prefix(
            &mut session,
            &mut records,
            &mut last,
            &mut consumed,
            wire.clone(),
        )
        .unwrap();
        assert!(records.is_empty());
        assert_eq!(consumed, 0);
        wire.push(b'\n');
        ingest_prefix(
            &mut session,
            &mut records,
            &mut last,
            &mut consumed,
            wire.clone(),
        )
        .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(consumed, wire.len());
        ingest_prefix(
            &mut session,
            &mut records,
            &mut last,
            &mut consumed,
            wire.clone(),
        )
        .unwrap();
        assert_eq!(records.len(), 1);
        wire[0] ^= 1;
        assert!(ingest_prefix(&mut session, &mut records, &mut last, &mut consumed, wire).is_err());
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn recovery_preserves_distinct_plan_and_rendered_xml_commitments() {
        use aiw_provider_wsb::{GoldenProbe, MappedFolder, WINDOWS_SANDBOX_PLAN_SCHEMA_VERSION};
        let plan = WindowsSandboxPlan {
            schema_version: WINDOWS_SANDBOX_PLAN_SCHEMA_VERSION.into(),
            workspace_root: r"C:\AIW\Test".into(),
            mappings: vec![
                MappedFolder {
                    purpose: MappingPurpose::Tools,
                    host_folder: r"C:\AIW\Test\tools".into(),
                    sandbox_folder: r"C:\AIW\Tools".into(),
                },
                MappedFolder {
                    purpose: MappingPurpose::Output,
                    host_folder: r"C:\AIW\Test\output".into(),
                    sandbox_folder: r"C:\AIW\Output".into(),
                },
            ],
            probe: GoldenProbe {
                executable: r"C:\AIW\Tools\agent.exe".into(),
                request: Some(r"C:\AIW\Tools\request.json".into()),
                output: r"C:\AIW\Output\token.json".into(),
            },
            memory_mb: Some(2048),
        };
        let approved = canonical_hash(&plan).unwrap();
        let rendered = render_config(&plan).unwrap().sha256;
        assert_ne!(approved, rendered);
        verify_sandbox_plan_commitments(&plan, &approved, &rendered).unwrap();
        assert!(verify_sandbox_plan_commitments(&plan, &rendered, &rendered).is_err());
        assert!(verify_sandbox_plan_commitments(&plan, &approved, &approved).is_err());
        let mut changed = plan;
        changed.memory_mb = Some(4096);
        assert!(verify_sandbox_plan_commitments(&changed, &approved, &rendered).is_err());
    }
}
