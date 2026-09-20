use std::collections::BTreeSet;

use aiw_evidence::{EvidenceError, EvidenceRecord, verify_records};
use aiw_schema::{AnalystAuthority, ModelPack, is_sha256, validate_model_pack};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const ANALYST_REPORT_SCHEMA_VERSION: &str = "aiw.dev/analyst-report/v0alpha1";
pub const ANALYST_REPORT_KIND: &str = "AIWAnalystReport";
pub const ANALYST_VALIDATION_SCHEMA_VERSION: &str = "aiw.dev/analyst-report-validation/v0alpha1";
const MAX_FINDINGS: usize = 64;
const MAX_RECOMMENDATIONS: usize = 32;
const MAX_CITATIONS: usize = 16;
const MAX_STATEMENT_BYTES: usize = 4096;
const RUNTIME_ROOT_ALGORITHM: &str = "sha256-merkle-v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AnalystTextFormat {
    PlainText,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AnalystTransport {
    InProcess,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AnalystNetworkAccess {
    None,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AnalystToolAccess {
    None,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AnalystInputClass {
    NormalizedEvidenceOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalystProvenance {
    pub provider: String,
    pub provider_version: String,
    pub model_pack_id: String,
    pub model_pack_version: String,
    pub model_alias: String,
    pub model_variant_id: String,
    pub model_payload_root_hash: String,
    pub execution_provider: String,
    pub runtime_artifact_root_algorithm: String,
    pub runtime_artifact_root_hash: String,
    pub prompt_template_sha256: String,
    pub generation_config_sha256: String,
    pub transport: AnalystTransport,
    pub external_network_access: AnalystNetworkAccess,
    pub tool_access: AnalystToolAccess,
    pub input_class: AnalystInputClass,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceCitation {
    pub sequence: u64,
    pub record_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CitedStatement {
    pub format: AnalystTextFormat,
    pub text: String,
    pub citations: Vec<EvidenceCitation>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AnalystSeverity {
    Informational,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AnalystConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AnalystCategory {
    Compatibility,
    IsolationBoundary,
    EvidenceQuality,
    Packaging,
    Performance,
    Cleanup,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalystFinding {
    pub id: String,
    pub severity: AnalystSeverity,
    pub confidence: AnalystConfidence,
    pub category: AnalystCategory,
    pub statement: CitedStatement,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AnalystPriority {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EvidenceKind {
    Backend,
    Token,
    ProcessTree,
    FileSystem,
    Registry,
    Network,
    UserInterface,
    Com,
    Crash,
    Installer,
    Cleanup,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RelaxationControl {
    FileSystemAccess,
    RegistryAccess,
    NetworkAccess,
    UserInterfaceAccess,
    ClipboardAccess,
    ProcessAccess,
    ComAccess,
    NamedPipeAccess,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EscalationTarget {
    MicrosoftProductGroup,
    SoftwareVendor,
    InternalSecurity,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum AnalystAction {
    CollectMoreEvidence {
        #[serde(rename = "evidenceKind")]
        evidence_kind: EvidenceKind,
    },
    TestPolicyRelaxation {
        control: RelaxationControl,
        #[serde(rename = "requiresNewDisposableRun")]
        requires_new_disposable_run: bool,
        #[serde(rename = "requiresHumanApproval")]
        requires_human_approval: bool,
    },
    Escalate {
        target: EscalationTarget,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalystRecommendation {
    pub id: String,
    pub priority: AnalystPriority,
    pub rationale: CitedStatement,
    pub action: AnalystAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalystReport {
    pub schema_version: String,
    pub kind: String,
    pub report_id: String,
    pub run_id: String,
    pub candidate_id: String,
    pub authority: AnalystAuthority,
    pub evidence_root_hash: String,
    pub provenance: AnalystProvenance,
    pub executive_summary: CitedStatement,
    #[serde(default)]
    pub findings: Vec<AnalystFinding>,
    #[serde(default)]
    pub recommendations: Vec<AnalystRecommendation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalystReportValidation {
    pub schema_version: String,
    pub report_id: String,
    pub run_id: String,
    pub candidate_id: String,
    pub authority: AnalystAuthority,
    pub evidence_root_hash: String,
    pub model_pack_id: String,
    pub model_variant_id: String,
    pub finding_count: u64,
    pub recommendation_count: u64,
    pub citation_count: u64,
    pub contract_valid: bool,
    pub evidence_chain_verified: bool,
    pub citations_resolved: bool,
    pub content_authoritative: bool,
}

#[derive(Debug, Error)]
pub enum AnalystReportError {
    #[error(transparent)]
    Evidence(#[from] EvidenceError),
    #[error("model pack failed structural validation with {issue_count} issue(s)")]
    InvalidModelPack { issue_count: usize },
    #[error("unsupported analyst report schema version '{0}'")]
    UnsupportedSchema(String),
    #[error("unexpected analyst report kind '{0}'")]
    UnexpectedKind(String),
    #[error("analyst report field '{0}' contains an invalid ID")]
    InvalidId(&'static str),
    #[error("analyst report field '{0}' must be non-empty, bounded plain text")]
    InvalidText(&'static str),
    #[error("analyst report field '{0}' must contain a lowercase SHA-256 value")]
    InvalidSha256(&'static str),
    #[error("analyst report evidence root does not match the verified evidence chain")]
    EvidenceRootMismatch,
    #[error("analyst provenance field '{0}' does not match the validated model pack")]
    ModelPackMismatch(&'static str),
    #[error("execution provider is not approved by the model pack: {0}")]
    ExecutionProviderNotApproved(String),
    #[error("model pack does not declare required analyst task '{0}'")]
    ModelPackMissingTask(String),
    #[error("runtime artifact root algorithm must be sha256-merkle-v1")]
    InvalidRuntimeRootAlgorithm,
    #[error("analyst report has {actual} findings; maximum is {maximum}")]
    TooManyFindings { actual: usize, maximum: usize },
    #[error("analyst report has {actual} recommendations; maximum is {maximum}")]
    TooManyRecommendations { actual: usize, maximum: usize },
    #[error("analyst report contains duplicate {kind} ID '{id}'")]
    DuplicateId { kind: &'static str, id: String },
    #[error("cited statement '{path}' must contain 1-{MAX_CITATIONS} citations")]
    InvalidCitationCount { path: String },
    #[error("cited statement '{path}' contains duplicate citation {sequence}:{record_hash}")]
    DuplicateCitation {
        path: String,
        sequence: u64,
        record_hash: String,
    },
    #[error("cited statement '{path}' references missing evidence sequence {sequence}")]
    MissingEvidence { path: String, sequence: u64 },
    #[error("cited statement '{path}' hash does not match evidence sequence {sequence}")]
    CitationHashMismatch { path: String, sequence: u64 },
    #[error(
        "recommendation '{id}' may test a relaxation only with human approval in a new disposable run"
    )]
    UnsafeRelaxationProposal { id: String },
}

pub fn validate_analyst_report(
    report: &AnalystReport,
    evidence_records: &[EvidenceRecord],
    model_pack: &ModelPack,
) -> Result<AnalystReportValidation, AnalystReportError> {
    let evidence_manifest = verify_records(evidence_records)?;
    let model_issues = validate_model_pack(model_pack);
    if !model_issues.is_empty() {
        return Err(AnalystReportError::InvalidModelPack {
            issue_count: model_issues.len(),
        });
    }
    validate_report_identity(report)?;
    if report.evidence_root_hash != evidence_manifest.root_hash {
        return Err(AnalystReportError::EvidenceRootMismatch);
    }
    validate_provenance(&report.provenance, model_pack)?;
    require_model_task(model_pack, "summarizeEvidence")?;
    if !report.findings.is_empty() {
        require_model_task(model_pack, "classifyHypothesis")?;
    }
    if !report.recommendations.is_empty() {
        require_model_task(model_pack, "structuredProposal")?;
    }
    if report.findings.len() > MAX_FINDINGS {
        return Err(AnalystReportError::TooManyFindings {
            actual: report.findings.len(),
            maximum: MAX_FINDINGS,
        });
    }
    if report.recommendations.len() > MAX_RECOMMENDATIONS {
        return Err(AnalystReportError::TooManyRecommendations {
            actual: report.recommendations.len(),
            maximum: MAX_RECOMMENDATIONS,
        });
    }

    let mut citation_count = validate_statement(
        "$.executiveSummary",
        &report.executive_summary,
        evidence_records,
    )?;
    let mut finding_ids = BTreeSet::new();
    for (index, finding) in report.findings.iter().enumerate() {
        if !is_valid_id(&finding.id) {
            return Err(AnalystReportError::InvalidId("findings[].id"));
        }
        if !finding_ids.insert(finding.id.as_str()) {
            return Err(AnalystReportError::DuplicateId {
                kind: "finding",
                id: finding.id.clone(),
            });
        }
        citation_count += validate_statement(
            &format!("$.findings[{index}].statement"),
            &finding.statement,
            evidence_records,
        )?;
    }

    let mut recommendation_ids = BTreeSet::new();
    for (index, recommendation) in report.recommendations.iter().enumerate() {
        if !is_valid_id(&recommendation.id) {
            return Err(AnalystReportError::InvalidId("recommendations[].id"));
        }
        if !recommendation_ids.insert(recommendation.id.as_str()) {
            return Err(AnalystReportError::DuplicateId {
                kind: "recommendation",
                id: recommendation.id.clone(),
            });
        }
        citation_count += validate_statement(
            &format!("$.recommendations[{index}].rationale"),
            &recommendation.rationale,
            evidence_records,
        )?;
        if matches!(
            recommendation.action,
            AnalystAction::TestPolicyRelaxation {
                requires_new_disposable_run,
                requires_human_approval,
                ..
            } if !requires_new_disposable_run || !requires_human_approval
        ) {
            return Err(AnalystReportError::UnsafeRelaxationProposal {
                id: recommendation.id.clone(),
            });
        }
    }

    Ok(AnalystReportValidation {
        schema_version: ANALYST_VALIDATION_SCHEMA_VERSION.to_owned(),
        report_id: report.report_id.clone(),
        run_id: report.run_id.clone(),
        candidate_id: report.candidate_id.clone(),
        authority: report.authority.clone(),
        evidence_root_hash: report.evidence_root_hash.clone(),
        model_pack_id: report.provenance.model_pack_id.clone(),
        model_variant_id: report.provenance.model_variant_id.clone(),
        finding_count: report.findings.len() as u64,
        recommendation_count: report.recommendations.len() as u64,
        citation_count,
        contract_valid: true,
        evidence_chain_verified: true,
        citations_resolved: true,
        content_authoritative: false,
    })
}

fn validate_report_identity(report: &AnalystReport) -> Result<(), AnalystReportError> {
    if report.schema_version != ANALYST_REPORT_SCHEMA_VERSION {
        return Err(AnalystReportError::UnsupportedSchema(
            report.schema_version.clone(),
        ));
    }
    if report.kind != ANALYST_REPORT_KIND {
        return Err(AnalystReportError::UnexpectedKind(report.kind.clone()));
    }
    for (field, value) in [
        ("reportId", report.report_id.as_str()),
        ("runId", report.run_id.as_str()),
        ("candidateId", report.candidate_id.as_str()),
    ] {
        if !is_valid_id(value) {
            return Err(AnalystReportError::InvalidId(field));
        }
    }
    if !is_lower_sha256(&report.evidence_root_hash) {
        return Err(AnalystReportError::InvalidSha256("evidenceRootHash"));
    }
    Ok(())
}

fn validate_provenance(
    provenance: &AnalystProvenance,
    model_pack: &ModelPack,
) -> Result<(), AnalystReportError> {
    for (field, actual, expected) in [
        (
            "provider",
            provenance.provider.as_str(),
            model_pack.runtime.provider.as_str(),
        ),
        (
            "providerVersion",
            provenance.provider_version.as_str(),
            model_pack.runtime.provider_version.as_str(),
        ),
        (
            "modelPackId",
            provenance.model_pack_id.as_str(),
            model_pack.metadata.id.as_str(),
        ),
        (
            "modelPackVersion",
            provenance.model_pack_version.as_str(),
            model_pack.metadata.version.as_str(),
        ),
        (
            "modelVariantId",
            provenance.model_variant_id.as_str(),
            model_pack.model.resolved_variant_id.as_str(),
        ),
        (
            "modelPayloadRootHash",
            provenance.model_payload_root_hash.as_str(),
            model_pack.payload.root_hash.as_str(),
        ),
    ] {
        if actual != expected {
            return Err(AnalystReportError::ModelPackMismatch(field));
        }
    }
    for (field, value) in [
        ("provider", provenance.provider.as_str()),
        ("providerVersion", provenance.provider_version.as_str()),
        ("modelPackId", provenance.model_pack_id.as_str()),
        ("modelPackVersion", provenance.model_pack_version.as_str()),
        ("modelAlias", provenance.model_alias.as_str()),
        ("modelVariantId", provenance.model_variant_id.as_str()),
        ("executionProvider", provenance.execution_provider.as_str()),
    ] {
        if !is_bounded_text(value, 256) {
            return Err(AnalystReportError::InvalidText(field));
        }
    }
    if !model_pack
        .runtime
        .approved_execution_providers
        .iter()
        .any(|provider| provider == &provenance.execution_provider)
    {
        return Err(AnalystReportError::ExecutionProviderNotApproved(
            provenance.execution_provider.clone(),
        ));
    }
    if provenance.runtime_artifact_root_algorithm != RUNTIME_ROOT_ALGORITHM {
        return Err(AnalystReportError::InvalidRuntimeRootAlgorithm);
    }
    for (field, value) in [
        (
            "modelPayloadRootHash",
            provenance.model_payload_root_hash.as_str(),
        ),
        (
            "runtimeArtifactRootHash",
            provenance.runtime_artifact_root_hash.as_str(),
        ),
        (
            "promptTemplateSha256",
            provenance.prompt_template_sha256.as_str(),
        ),
        (
            "generationConfigSha256",
            provenance.generation_config_sha256.as_str(),
        ),
    ] {
        if !is_lower_sha256(value) {
            return Err(AnalystReportError::InvalidSha256(field));
        }
    }
    Ok(())
}

fn validate_statement(
    path: &str,
    statement: &CitedStatement,
    evidence_records: &[EvidenceRecord],
) -> Result<u64, AnalystReportError> {
    if !is_bounded_text(&statement.text, MAX_STATEMENT_BYTES) {
        return Err(AnalystReportError::InvalidText("cited statement"));
    }
    if statement.citations.is_empty() || statement.citations.len() > MAX_CITATIONS {
        return Err(AnalystReportError::InvalidCitationCount {
            path: path.to_owned(),
        });
    }
    let mut citations = BTreeSet::new();
    for citation in &statement.citations {
        if !citations.insert(citation) {
            return Err(AnalystReportError::DuplicateCitation {
                path: path.to_owned(),
                sequence: citation.sequence,
                record_hash: citation.record_hash.clone(),
            });
        }
        let index = usize::try_from(citation.sequence).map_err(|_| {
            AnalystReportError::MissingEvidence {
                path: path.to_owned(),
                sequence: citation.sequence,
            }
        })?;
        let record =
            evidence_records
                .get(index)
                .ok_or_else(|| AnalystReportError::MissingEvidence {
                    path: path.to_owned(),
                    sequence: citation.sequence,
                })?;
        if citation.record_hash != record.hash {
            return Err(AnalystReportError::CitationHashMismatch {
                path: path.to_owned(),
                sequence: citation.sequence,
            });
        }
    }
    Ok(statement.citations.len() as u64)
}

fn require_model_task(model_pack: &ModelPack, task: &str) -> Result<(), AnalystReportError> {
    if model_pack
        .model
        .tasks
        .iter()
        .any(|candidate| candidate == task)
    {
        Ok(())
    } else {
        Err(AnalystReportError::ModelPackMissingTask(task.to_owned()))
    }
}

fn is_valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_lower_sha256(value: &str) -> bool {
    is_sha256(value) && !value.bytes().any(|byte| byte.is_ascii_uppercase())
}

fn is_bounded_text(value: &str, maximum_bytes: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= maximum_bytes
        && !value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\r' | '\n' | '\t'))
}

#[cfg(test)]
mod tests {
    use aiw_evidence::{EvidenceEvent, EvidenceLog};
    use aiw_schema::{
        ArtifactClass, MODEL_PACK_KIND, MODEL_PACK_SCHEMA_VERSION, ModelFile, ModelIdentity,
        ModelLicense, ModelPackMetadata, ModelPayload, ModelRuntime, ModelSignature,
        RedistributionDecision,
    };

    use super::*;

    fn evidence_log() -> EvidenceLog {
        let mut log = EvidenceLog::new();
        log.append(EvidenceEvent {
            observed_utc: "2026-08-19T00:00:00Z".to_owned(),
            kind: "environment".to_owned(),
            source: "fixture".to_owned(),
            payload: serde_json::json!({"build": 26100}),
        })
        .unwrap();
        log.append(EvidenceEvent {
            observed_utc: "2026-08-19T00:00:01Z".to_owned(),
            kind: "token".to_owned(),
            source: "fixture".to_owned(),
            payload: serde_json::json!({"appContainer": true, "integrity": "medium"}),
        })
        .unwrap();
        log
    }

    fn model_pack() -> ModelPack {
        ModelPack {
            schema_version: MODEL_PACK_SCHEMA_VERSION.to_owned(),
            kind: MODEL_PACK_KIND.to_owned(),
            metadata: ModelPackMetadata {
                id: "aiw-analyst-small".to_owned(),
                version: "1.0.0".to_owned(),
                artifact_class: ArtifactClass::Model,
            },
            model: ModelIdentity {
                family: "example".to_owned(),
                source_revision: "immutable".to_owned(),
                resolved_variant_id: "example-int4-cpu".to_owned(),
                format: "onnx-genai".to_owned(),
                quantization: "int4".to_owned(),
                tokenizer: "example-tokenizer".to_owned(),
                tasks: vec![
                    "summarizeEvidence".to_owned(),
                    "classifyHypothesis".to_owned(),
                    "structuredProposal".to_owned(),
                ],
            },
            runtime: ModelRuntime {
                provider: "foundryLocal".to_owned(),
                provider_version: "1.0.0".to_owned(),
                minimum_aiw_core_api: "0.1.0".to_owned(),
                architectures: vec!["x64".to_owned()],
                approved_execution_providers: vec!["cpu".to_owned()],
            },
            license: ModelLicense {
                identifier: "example".to_owned(),
                license_file: "licenses/LICENSE.txt".to_owned(),
                license_sha256: "b".repeat(64),
                redistribution_decision: RedistributionDecision::Approved,
                required_notices: vec![],
            },
            payload: ModelPayload {
                root_algorithm: "sha256-merkle-v1".to_owned(),
                root_hash: "c".repeat(64),
                no_executable_content: true,
                files: vec![ModelFile {
                    path: "model/model.onnx".to_owned(),
                    size_bytes: 1,
                    sha256: "d".repeat(64),
                }],
            },
            signature: ModelSignature {
                canonicalization: "jcs-rfc8785".to_owned(),
                detached_signature: "signatures/model.p7s".to_owned(),
                required_trust_class: "model".to_owned(),
                timestamp_required: true,
            },
        }
    }

    fn statement(text: &str, record: &EvidenceRecord) -> CitedStatement {
        CitedStatement {
            format: AnalystTextFormat::PlainText,
            text: text.to_owned(),
            citations: vec![EvidenceCitation {
                sequence: record.sequence,
                record_hash: record.hash.clone(),
            }],
        }
    }

    fn report(log: &EvidenceLog) -> AnalystReport {
        let records = log.records();
        AnalystReport {
            schema_version: ANALYST_REPORT_SCHEMA_VERSION.to_owned(),
            kind: ANALYST_REPORT_KIND.to_owned(),
            report_id: "fixture-report".to_owned(),
            run_id: "fixture-run".to_owned(),
            candidate_id: "process-container".to_owned(),
            authority: AnalystAuthority::AdvisoryOnly,
            evidence_root_hash: log.manifest().unwrap().root_hash,
            provenance: AnalystProvenance {
                provider: "foundryLocal".to_owned(),
                provider_version: "1.0.0".to_owned(),
                model_pack_id: "aiw-analyst-small".to_owned(),
                model_pack_version: "1.0.0".to_owned(),
                model_alias: "example".to_owned(),
                model_variant_id: "example-int4-cpu".to_owned(),
                model_payload_root_hash: "c".repeat(64),
                execution_provider: "cpu".to_owned(),
                runtime_artifact_root_algorithm: "sha256-merkle-v1".to_owned(),
                runtime_artifact_root_hash: "e".repeat(64),
                prompt_template_sha256: "f".repeat(64),
                generation_config_sha256: "a".repeat(64),
                transport: AnalystTransport::InProcess,
                external_network_access: AnalystNetworkAccess::None,
                tool_access: AnalystToolAccess::None,
                input_class: AnalystInputClass::NormalizedEvidenceOnly,
            },
            executive_summary: statement("Token evidence was collected.", &records[1]),
            findings: vec![AnalystFinding {
                id: "token-observed".to_owned(),
                severity: AnalystSeverity::Informational,
                confidence: AnalystConfidence::High,
                category: AnalystCategory::IsolationBoundary,
                statement: statement("The recorded token is an AppContainer token.", &records[1]),
            }],
            recommendations: vec![AnalystRecommendation {
                id: "collect-process-tree".to_owned(),
                priority: AnalystPriority::Medium,
                rationale: statement(
                    "The token record does not describe child processes.",
                    &records[1],
                ),
                action: AnalystAction::CollectMoreEvidence {
                    evidence_kind: EvidenceKind::ProcessTree,
                },
            }],
        }
    }

    #[test]
    fn valid_report_resolves_every_citation_and_stays_advisory() {
        let log = evidence_log();
        let validation = validate_analyst_report(&report(&log), log.records(), &model_pack())
            .expect("fixture report should validate");
        assert!(validation.contract_valid);
        assert!(validation.evidence_chain_verified);
        assert!(validation.citations_resolved);
        assert!(!validation.content_authoritative);
        assert_eq!(validation.citation_count, 3);
    }

    #[test]
    fn invented_citation_is_rejected() {
        let log = evidence_log();
        let mut report = report(&log);
        report.findings[0].statement.citations[0].record_hash = "0".repeat(64);
        assert!(matches!(
            validate_analyst_report(&report, log.records(), &model_pack()),
            Err(AnalystReportError::CitationHashMismatch { .. })
        ));
    }

    #[test]
    fn evidence_root_must_match_verified_chain() {
        let log = evidence_log();
        let mut report = report(&log);
        report.evidence_root_hash = "0".repeat(64);
        assert!(matches!(
            validate_analyst_report(&report, log.records(), &model_pack()),
            Err(AnalystReportError::EvidenceRootMismatch)
        ));
    }

    #[test]
    fn model_variant_must_match_pack() {
        let log = evidence_log();
        let mut report = report(&log);
        report.provenance.model_variant_id = "other-variant".to_owned();
        assert!(matches!(
            validate_analyst_report(&report, log.records(), &model_pack()),
            Err(AnalystReportError::ModelPackMismatch("modelVariantId"))
        ));
    }

    #[test]
    fn unapproved_execution_provider_is_rejected() {
        let log = evidence_log();
        let mut report = report(&log);
        report.provenance.execution_provider = "cuda".to_owned();
        assert!(matches!(
            validate_analyst_report(&report, log.records(), &model_pack()),
            Err(AnalystReportError::ExecutionProviderNotApproved(_))
        ));
    }

    #[test]
    fn model_pack_must_declare_structured_proposal_task() {
        let log = evidence_log();
        let report = report(&log);
        let mut pack = model_pack();
        pack.model.tasks.retain(|task| task != "structuredProposal");
        assert!(matches!(
            validate_analyst_report(&report, log.records(), &pack),
            Err(AnalystReportError::ModelPackMissingTask(task))
                if task == "structuredProposal"
        ));
    }

    #[test]
    fn relaxation_cannot_bypass_new_run_or_human_approval() {
        let log = evidence_log();
        let mut report = report(&log);
        report.recommendations[0].action = AnalystAction::TestPolicyRelaxation {
            control: RelaxationControl::FileSystemAccess,
            requires_new_disposable_run: false,
            requires_human_approval: true,
        };
        assert!(matches!(
            validate_analyst_report(&report, log.records(), &model_pack()),
            Err(AnalystReportError::UnsafeRelaxationProposal { .. })
        ));
    }

    #[test]
    fn tampered_evidence_chain_fails_before_report_validation() {
        let log = evidence_log();
        let report = report(&log);
        let mut records = log.records().to_vec();
        records[0].payload = serde_json::json!({"build": 99999});
        assert!(matches!(
            validate_analyst_report(&report, &records, &model_pack()),
            Err(AnalystReportError::Evidence(
                EvidenceError::HashMismatch { .. }
            ))
        ));
    }
}
