//! One fresh collector attempt. Mapped files are authenticated delivery, never authority.
use super::{
    COLLECTOR, Result, files::Directories, guard_no_impersonation, protection::ProtectionHold,
};
use crate::{
    assessment_channel_crypto::{AssessmentSigningKey, verify_digest},
    guest_document as relative,
};
use aiw_provider_wsb::{
    assessment_channel::*, assessment_observation::*,
    assessment_request::ApplicationAssessmentGuestRequest,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::Path,
    time::{Duration, Instant},
};
use windows::{
    Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK, GetFileType, MOVE_FILE_FLAGS,
            MoveFileExW,
        },
        System::Threading::GetCurrentThreadId,
    },
    core::PCWSTR,
};
const TRANSPORT: &str = r"C:\AIW\Output";
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub(super) struct CngVerifier;
impl AssessmentChannelVerifier for CngVerifier {
    fn verify_digest(&self, k: &[u8; 72], d: &[u8; 32], s: &[u8; 64]) -> Result<()> {
        verify_digest(k, d, s)
    }
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn info(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let i = relative::file_information(file)?;
    if !relative::ordinary_file(&i)
        || i.nNumberOfLinks != 1
        || i.dwVolumeSerialNumber == 0
        || (i.nFileIndexHigh == 0 && i.nFileIndexLow == 0)
        || unsafe { GetFileType(HANDLE(file.as_raw_handle())) } != FILE_TYPE_DISK
    {
        return Err("channel file identity/type/link refused".into());
    }
    Ok(i)
}
fn same(a: &BY_HANDLE_FILE_INFORMATION, b: &BY_HANDLE_FILE_INFORMATION) -> bool {
    a.dwVolumeSerialNumber == b.dwVolumeSerialNumber
        && a.nFileIndexHigh == b.nFileIndexHigh
        && a.nFileIndexLow == b.nFileIndexLow
        && a.dwFileAttributes == b.dwFileAttributes
        && a.nNumberOfLinks == b.nNumberOfLinks
}
fn read_file(file: &mut File, cap: usize) -> Result<Vec<u8>> {
    let before = info(file)?;
    let n = relative::file_length(&before);
    if n > cap as u64 {
        return Err("channel complete read exceeds cap".into());
    }
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut bytes = vec![0; n as usize];
    file.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    let mut one = [0];
    if file.read(&mut one).map_err(|e| e.to_string())? != 0 {
        return Err("channel complete file grew".into());
    }
    let after = info(file)?;
    if !same(&before, &after) || relative::file_length(&after) != n {
        return Err("channel complete read changed".into());
    }
    Ok(bytes)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .map_err(|e| e.to_string())?;
    info(&f)?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|e| e.to_string())?;
    let observed = read_file(&mut f, bytes.len())?;
    if observed != bytes {
        return Err("channel new file readback differs".into());
    }
    Ok(())
}
fn atomic_transport(pending: &str, final_leaf: &str, bytes: &[u8], cap: usize) -> Result<()> {
    guard_no_impersonation()?;
    if bytes.is_empty() || bytes.len() > cap {
        return Err("channel publication bound".into());
    }
    let from = Path::new(TRANSPORT).join(pending);
    let to = Path::new(TRANSPORT).join(final_leaf);
    write_new(&from, bytes)?;
    use std::os::windows::ffi::OsStrExt;
    let a: Vec<_> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let b: Vec<_> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    unsafe { MoveFileExW(PCWSTR(a.as_ptr()), PCWSTR(b.as_ptr()), MOVE_FILE_FLAGS(0)) }
        .map_err(|e| e.to_string())
}
pub(super) struct Progress {
    _directories: Directories,
    _transport_directories: Directories,
    file: Option<File>,
    transport: Option<File>,
    identity: BY_HANDLE_FILE_INFORMATION,
    bytes: usize,
    digest: Sha256,
    refused: bool,
    signer: Option<AssessmentSigningKey>,
    thread_id: u32,
    binding: AssessmentChannelBinding,
    key: String,
    session: AssessmentChannelSession,
    sequence: u64,
    previous: String,
    records: Vec<VerifiedChannelRecord>,
    file_denial: Option<bool>,
    file_probe_consumed: bool,
    protection: Option<ProtectionHold>,
}
impl Progress {
    pub(super) fn create(
        request: &ApplicationAssessmentGuestRequest,
        token: aiw_token::TokenEvidence,
        deadline: Instant,
    ) -> Result<Self> {
        guard_no_impersonation()?;
        let binding = request.channel_binding()?;
        let local = Directories::collector_probe()?;
        let transport = Directories::hold(Path::new(TRANSPORT))?;
        if std::fs::read_dir(TRANSPORT)
            .map_err(|e| e.to_string())?
            .next()
            .transpose()
            .map_err(|e| e.to_string())?
            .is_some()
        {
            return Err("fresh channel output is not empty".into());
        }
        let signer = AssessmentSigningKey::generate()?;
        let key = hex::encode(signer.public_key()?);
        let mut session = AssessmentChannelSession::new(binding.clone())?;
        let bootstrap = signing_intent(
            &binding,
            &key,
            0,
            ZERO,
            AssessmentChannelPayload::Bootstrap {
                schema_version: binding.schema_version.clone(),
                binding: Box::new(binding.clone()),
                guest_public_key_hex: key.clone(),
                collector_token: Box::new(token.clone()),
                collector_storage: ChannelCollectorStorage::ProtectedGuestLocal,
                collector_sessions: Some(super::system0_sessions()?),
            },
        )?;
        let bootstrap_digest = bootstrap.signing_digest()?;
        let signed = bootstrap.with_signature(&signer.sign_digest(&bootstrap_digest)?);
        let bootstrap_wire = signed.canonical_wire()?;
        session.latch_bootstrap(&bootstrap_wire, &CngVerifier)?;
        // Consume expected ACK intent without signing. Only the host owns its private key.
        let _expected_ack = session.begin_ack()?;
        atomic_transport(
            CHANNEL_BOOTSTRAP_PENDING_LEAF,
            CHANNEL_BOOTSTRAP_LEAF,
            &bootstrap_wire,
            MAX_BOOTSTRAP_BYTES,
        )?;
        let ack_deadline = deadline.min(Instant::now() + Duration::from_secs(30));
        let ack_path = Path::new(TRANSPORT).join(CHANNEL_ACK_LEAF);
        let ack = loop {
            if Instant::now() >= ack_deadline {
                return Err(
                    "collector key acknowledgement deadline; no application created".into(),
                );
            }
            match OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
                .open(&ack_path)
            {
                Ok(mut f) => break read_file(&mut f, MAX_ACK_BYTES)?,
                Err(e) if e.raw_os_error() == Some(2) => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                Err(e) => return Err(format!("closed collector ACK read: {e}")),
            }
        };
        let verified = session.accept_ack(&ack, &CngVerifier)?;
        let previous = verified.commitment().to_owned();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(super::local_progress())
            .map_err(|e| e.to_string())?;
        let identity = info(&file)?;
        // Public mirror supports bounded live prefix reads, but no delete sharing.
        let public = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(Path::new(TRANSPORT).join(CHANNEL_PROGRESS_LEAF))
            .map_err(|e| e.to_string())?;
        info(&public)?;
        let mut value = Self {
            _directories: local,
            _transport_directories: transport,
            file: Some(file),
            transport: Some(public),
            identity,
            bytes: 0,
            digest: Sha256::new(),
            refused: false,
            signer: Some(signer),
            thread_id: unsafe { GetCurrentThreadId() },
            binding,
            key,
            session,
            sequence: 0,
            previous,
            records: vec![],
            file_denial: None,
            file_probe_consumed: false,
            protection: None,
        };
        value.record(&AssessmentProgressEvent::Header {
            schema_version: CHANNEL_PROGRESS_SCHEMA.into(),
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            request_sha256: request.request_sha256.clone(),
            assessment_sha256: request.assessment_sha256.clone(),
            agent_sha256: request.agent_sha256.clone(),
            config_sha256: request.config_sha256.clone(),
            project_revision_sha256: request.project_revision_sha256.clone(),
            collector_token: token,
        })?;
        Ok(value)
    }
    pub(super) fn record(&mut self, event: &AssessmentProgressEvent) -> Result<()> {
        guard_no_impersonation()?;
        if self.refused || unsafe { GetCurrentThreadId() } != self.thread_id {
            return Err("signed progress refused or signing thread differs".into());
        }
        // The latch is consumed before invoking the signer, not after publication.
        self.refused = true;
        // Enforce the same structural reserves used by preflight, without ever
        // changing the actual observation/capture bytes being signed.
        let mut metadata = event.clone();
        let reserve = match &mut metadata {
            AssessmentProgressEvent::Step { observation } => {
                if let Some(process) = &mut observation.process {
                    process.stdout.bytes_hex.clear();
                    process.stderr.bytes_hex.clear();
                }
                Some(65536)
            }
            AssessmentProgressEvent::LaunchStarted { .. } => Some(16384),
            AssessmentProgressEvent::Assertion { .. } => Some(4096),
            AssessmentProgressEvent::Terminal { .. } => Some(65536),
            _ => None,
        };
        if let Some(cap) = reserve {
            let shape = AssessmentChannelPayload::Progress {
                schema_version: CHANNEL_PROGRESS_SCHEMA.into(),
                event: Box::new(metadata),
            };
            let n = aiw_evidence::canonical_json_bytes(
                &serde_json::to_value(shape)
                    .map_err(|_| "progress metadata serialization refused")?,
            )
            .map_err(|_| "progress metadata canonicalization refused")?
            .len();
            if n > cap {
                return Err(
                    "complete progress metadata exceeds reserved bound; no truncation".into(),
                );
            }
        }
        let intent = signing_intent(
            &self.binding,
            &self.key,
            self.sequence + 1,
            &self.previous,
            AssessmentChannelPayload::Progress {
                schema_version: CHANNEL_PROGRESS_SCHEMA.into(),
                event: Box::new(event.clone()),
            },
        )?;
        let digest = intent.signing_digest()?;
        let signature = self
            .signer
            .as_ref()
            .ok_or("collector signer absent")?
            .sign_digest(&digest)?;
        let mut wire = intent.with_signature(&signature).canonical_wire()?;
        wire.push(b'\n');
        let verified = self.session.accept_progress_line(&wire, &CngVerifier)?;
        let file = self.file.as_mut().ok_or("local progress writer absent")?;
        let before = info(file)?;
        if !same(&before, &self.identity) || relative::file_length(&before) != self.bytes as u64 {
            return Err("local signed progress identity/size changed".into());
        }
        file.write_all(&wire)
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())?;
        self.bytes += wire.len();
        self.digest.update(&wire);
        self.sequence += 1;
        self.previous = verified.commitment().to_owned();
        self.records.push(verified);
        let mirror = self
            .transport
            .as_mut()
            .ok_or("public progress mirror absent")?;
        mirror
            .write_all(&wire)
            .and_then(|_| mirror.sync_all())
            .map_err(|e| e.to_string())?;
        self.refused = false;
        Ok(())
    }
    pub(super) fn revalidate(&self) -> Result<()> {
        guard_no_impersonation()?;
        let f = self.file.as_ref().ok_or("local progress absent")?;
        let now = info(f)?;
        if !same(&now, &self.identity) || relative::file_length(&now) != self.bytes as u64 {
            return Err("local signed progress changed".into());
        }
        use std::os::windows::fs::FileExt;
        let mut h = Sha256::new();
        let mut position = 0;
        let mut buffer = [0u8; 65536];
        while position < self.bytes {
            let take = (self.bytes - position).min(buffer.len());
            let n = f
                .seek_read(&mut buffer[..take], position as u64)
                .map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("local progress truncated".into());
            }
            h.update(&buffer[..n]);
            position += n;
        }
        if h.finalize() != self.digest.clone().finalize() {
            return Err("local progress hash changed".into());
        }
        Ok(())
    }
    pub(super) fn seal_before_apps(&mut self) -> Result<()> {
        self.revalidate()?;
        drop(self.file.take());
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ.0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(super::local_progress())
            .map_err(|e| e.to_string())?;
        if !same(&info(&f)?, &self.identity) {
            return Err("local progress reopen identity differs".into());
        }
        f.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
        self.file = Some(f);
        let narrow = Directories::hold(Path::new(COLLECTOR))?;
        if !self._directories.same_leaf(&narrow)? {
            return Err("local collector changed during probes".into());
        }
        self._directories = narrow;
        self.revalidate()
    }
    pub(super) fn set_file_denial(
        &mut self,
        facts: &[AssessmentCollectorAccessDenial],
        sid: &str,
    ) -> Result<()> {
        if self.file_probe_consumed {
            return Err("local mutation probes already consumed".into());
        }
        self.file_probe_consumed = true;
        self.file_denial = super::progress::derive_denial(facts, sid);
        Ok(())
    }
    pub(super) fn set_protection(&mut self, hold: ProtectionHold) -> Result<()> {
        if self.protection.is_some() {
            return Err("collector key protection already consumed".into());
        }
        self.protection = Some(hold);
        self.require_dispatch()
    }
    pub(super) fn require_dispatch(&self) -> Result<()> {
        guard_no_impersonation()?;
        if self.refused
            || !self.session.ack_verified()
            || self.file_denial != Some(true)
            || unsafe { GetCurrentThreadId() } != self.thread_id
        {
            return Err(
                "ACK is not dispatch authority; required collector gates unavailable".into(),
            );
        }
        self.protection
            .as_ref()
            .ok_or("collector object protection unmeasured")?
            .require_denied()
    }
    /// Conservative successful-wire reservation after actual setup/protection
    /// bytes have been measured, before any app creation. Refusal is explicit.
    pub(super) fn preflight_remaining(
        &self,
        plan: &aiw_provider_wsb::assessment::CompiledAssessment,
    ) -> Result<()> {
        use aiw_provider_wsb::assessment::{AssessmentMode, CompiledAssessmentStep};
        let launches = plan
            .steps
            .iter()
            .filter(|s| matches!(s, CompiledAssessmentStep::Launch { .. }))
            .count() as u64;
        let records = progress_record_bound(plan, 1)?;
        let captures = launches
            .checked_mul(plan.settings.stdout_max_bytes + plan.settings.stderr_max_bytes)
            .and_then(|n| n.checked_mul(2))
            .ok_or("signed capture reservation overflow")?;
        // ASCII paths/SIDs/hashes; bounded success metadata reserves64KiB/step,
        //16KiB/pre-Resume root,4KiB/assertion,64KiB cleanup. Failures may refuse
        // journal publication but can never become truncated successful evidence.
        let structural = (plan.steps.len() as u64)
            .checked_mul(65536)
            .and_then(|n| n.checked_add(launches * 16384))
            .and_then(|n| n.checked_add(plan.settings.assertions.len() as u64 * 4096))
            .and_then(|n| {
                n.checked_add(
                    65536
                        + u64::from(plan.mode == AssessmentMode::ClassicAppContainer) * 4096
                        + self.bytes as u64,
                )
            })
            .ok_or("signed structural reservation overflow")?;
        let payload = captures
            .checked_add(structural)
            .ok_or("signed payload reservation overflow")?;
        let framing = maximum_progress_framing_bytes()?;
        let largest = 2 * (plan.settings.stdout_max_bytes + plan.settings.stderr_max_bytes) + 65536;
        check_progress_wire_budget(
            payload,
            framing
                .checked_mul(records)
                .ok_or("signed framing overflow")?,
            largest,
            framing,
            records,
        )
    }
    pub(super) fn publish_result(
        mut self,
        request: &ApplicationAssessmentGuestRequest,
        native: AssessmentNativeOutcome,
    ) -> Result<()> {
        use aiw_evidence::{ArtifactRole, EvidenceEvent, EvidenceLog};
        use aiw_provider_wsb::{
            CompletionArtifact, CompletionStatus,
            WINDOWS_SANDBOX_COMPLETION_RECEIPT_SCHEMA_VERSION, WindowsSandboxCompletionReceipt,
            assessment_evidence::{
                APPLICATION_ASSESSMENT_EVIDENCE_EVENT, assessment_result_reference,
                verify_authenticated_assessment_evidence, verify_authenticated_assessment_progress,
            },
        };
        guard_no_impersonation()?;
        self.revalidate()?;
        let result = ApplicationAssessmentResult {
            schema_version: APPLICATION_ASSESSMENT_RESULT_V2_SCHEMA.into(),
            run_id: request.run_id.clone(),
            request_sha256: request.request_sha256.clone(),
            assessment_sha256: request.assessment_sha256.clone(),
            native,
        };
        let result_bytes = serde_json::to_vec(&result).map_err(|e| e.to_string())?;
        if result_bytes.len() > 16 * 1024 * 1024 {
            return Err("complete signed result exceeds cap".into());
        }
        let mut evidence = EvidenceLog::new();
        evidence
            .append(EvidenceEvent {
                observed_utc: "guest-agent-time-not-trusted".into(),
                kind: APPLICATION_ASSESSMENT_EVIDENCE_EVENT.into(),
                source: "aiw-guest-agent".into(),
                payload: serde_json::to_value(assessment_result_reference(request, &result)?)
                    .map_err(|e| e.to_string())?,
            })
            .map_err(|e| e.to_string())?;
        let mut log = Vec::new();
        for record in evidence.records() {
            serde_json::to_writer(&mut log, record).map_err(|e| e.to_string())?;
            log.push(b'\n');
        }
        if log.len() > 1024 * 1024 {
            return Err("signed evidence log exceeds cap".into());
        }
        let root = evidence.manifest().map_err(|e| e.to_string())?.root_hash;
        let raw_progress = read_file(
            self.file.as_mut().ok_or("local progress missing")?,
            MAX_PROGRESS_BYTES,
        )?;
        // Diagnostic originals survive even if semantic/journal comparison
        // refuses completion. Public copies have NO authority without terminal.
        for (name, bytes) in [
            ("assessment-result.json", result_bytes.as_slice()),
            ("evidence.jsonl", log.as_slice()),
        ] {
            write_new(&Path::new(COLLECTOR).join(name), bytes)?;
            write_new(&Path::new(TRANSPORT).join(name), bytes)?;
        }
        verify_authenticated_assessment_progress(&raw_progress, &self.records, request, &result)?;
        let status = if result.native.driver_completed {
            CompletionStatus::Succeeded
        } else {
            CompletionStatus::Failed
        };
        let fact = |path: &str, role: ArtifactRole, bytes: &[u8], media: &str| CompletionArtifact {
            path: path.into(),
            role,
            media_type: media.into(),
            size_bytes: bytes.len() as u64,
            sha256: sha(bytes),
        };
        let receipt = WindowsSandboxCompletionReceipt {
            schema_version: WINDOWS_SANDBOX_COMPLETION_RECEIPT_SCHEMA_VERSION.into(),
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            config_sha256: request.config_sha256.clone(),
            request_sha256: request.request_sha256.clone(),
            agent_sha256: request.agent_sha256.clone(),
            status,
            exit_code: if status == CompletionStatus::Succeeded {
                0
            } else {
                1
            },
            evidence_root_hash: root.clone(),
            artifacts: vec![
                fact(
                    "assessment-result.json",
                    ArtifactRole::ScenarioResults,
                    &result_bytes,
                    "application/json",
                ),
                fact(
                    "evidence.jsonl",
                    ArtifactRole::EvidenceLog,
                    &log,
                    "application/x-ndjson",
                ),
                fact(
                    CHANNEL_PROGRESS_LEAF,
                    ArtifactRole::DiagnosticLog,
                    &raw_progress,
                    "application/x-ndjson",
                ),
            ],
        };
        let receipt_bytes = serde_json::to_vec(&receipt).map_err(|e| e.to_string())?;
        if receipt_bytes.len() > 1024 * 1024 {
            return Err("signed receipt exceeds cap".into());
        }
        write_new(
            &Path::new(COLLECTOR).join("completion.json"),
            &receipt_bytes,
        )?;
        let artifacts = vec![
            ChannelArtifact {
                role: ChannelArtifactRole::Result,
                path: "assessment-result.json".into(),
                size_bytes: result_bytes.len() as u64,
                sha256: sha(&result_bytes),
            },
            ChannelArtifact {
                role: ChannelArtifactRole::Evidence,
                path: "evidence.jsonl".into(),
                size_bytes: log.len() as u64,
                sha256: sha(&log),
            },
            ChannelArtifact {
                role: ChannelArtifactRole::Completion,
                path: "completion.json".into(),
                size_bytes: receipt_bytes.len() as u64,
                sha256: sha(&receipt_bytes),
            },
            ChannelArtifact {
                role: ChannelArtifactRole::Progress,
                path: CHANNEL_PROGRESS_LEAF.into(),
                size_bytes: raw_progress.len() as u64,
                sha256: sha(&raw_progress),
            },
        ];
        // CreateNew intent consumes terminal signing BEFORE invoking CNG.
        write_new(
            &Path::new(COLLECTOR).join("terminal.intent"),
            b"one-terminal-attempt",
        )?;
        self.refused = true;
        let intent = signing_intent(
            &self.binding,
            &self.key,
            self.sequence + 1,
            &self.previous,
            AssessmentChannelPayload::Terminal {
                schema_version: CHANNEL_SCHEMA.into(),
                request_sha256: request.request_sha256.clone(),
                assessment_sha256: request.assessment_sha256.clone(),
                artifacts,
                evidence_root_hash: root.clone(),
                last_progress_sequence: self.sequence,
                last_progress_commitment: self.previous.clone(),
            },
        )?;
        let digest = intent.signing_digest()?;
        let signed = intent.with_signature(
            &self
                .signer
                .as_ref()
                .ok_or("terminal signer absent")?
                .sign_digest(&digest)?,
        );
        let terminal = signed.canonical_wire()?;
        let verified_terminal = self.session.accept_terminal(&terminal, &CngVerifier)?;
        verify_authenticated_assessment_evidence(
            &verified_terminal,
            &log,
            &root,
            &result_bytes,
            &receipt_bytes,
            &raw_progress,
            &self.records,
            request,
            &result,
        )?;
        // Key release is observed BEFORE publishing the authoritative terminal.
        self.signer.take().ok_or("terminal key absent")?.destroy()?;
        drop(self.transport.take());
        drop(self.file.take());
        write_new(
            &Path::new(TRANSPORT).join("completion.json"),
            &receipt_bytes,
        )?;
        let mut mirror = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ.0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(Path::new(TRANSPORT).join(CHANNEL_PROGRESS_LEAF))
            .map_err(|e| e.to_string())?;
        if read_file(&mut mirror, MAX_PROGRESS_BYTES)? != raw_progress {
            return Err("public signed progress mirror differs; no terminal publication".into());
        }
        atomic_transport(
            CHANNEL_TERMINAL_PENDING_LEAF,
            CHANNEL_TERMINAL_LEAF,
            &terminal,
            MAX_TERMINAL_BYTES,
        )
    }
}
