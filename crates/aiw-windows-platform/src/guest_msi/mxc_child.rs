//! Retained observation of the one fixed cooperative MXC child. No execution,
//! termination, privilege adjustment or PID-only acceptance API.
use super::{GuestProcess, ScenarioJob};
use crate::{HeldApplicationFile, control_appcontainer::research_sevenzip::fixed_role_image};
use aiw_probe::WindowsFileIdentity;
use aiw_provider_mxc::process_container::CONTROL_IMAGE;
use aiw_token::{TokenEvidence, TokenType, collect_process_token};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use windows::Win32::Foundation::{FILETIME, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows::Win32::System::JobObjects::IsProcessInJob;
use windows::Win32::System::Threading::{
    GetProcessId, GetProcessTimes, OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW, WaitForSingleObject,
};
use windows::core::{BOOL, PWSTR};

const IMAGE_BOUND: u64 = 128 * 1024 * 1024;
const SCHEMA: &str = "aiw.dev/research-mxc-child-observation/v0alpha1";
type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResearchMxcChildObservation {
    pub schema_version: String,
    pub process_id: u32,
    /// Exact Windows creation FILETIME, serialized as a lossless u64.
    pub creation_time: u64,
    pub queried_image_path: String,
    pub image_identity: WindowsFileIdentity,
    pub image_sha256: String,
    pub image_size_bytes: u64,
    pub image_attributes: u32,
    pub image_link_count: u32,
    pub image_only_unnamed_data_stream: bool,
    pub token: TokenEvidence,
}

pub(crate) struct ResearchMxcChild<'owner> {
    process: OwnedHandle,
    image: HeldApplicationFile,
    _ancestry: Vec<File>,
    observation: ResearchMxcChildObservation,
    expected_hash: String,
    expected_sid: String,
    // A bound holder cannot outlive the owner or its exact kernel job handle.
    owner_job: Option<&'owner ScenarioJob>,
}

fn native(stage: &str, error: windows::core::Error) -> String {
    format!("{stage}: {error}; hresult=0x{:08x}", error.code().0 as u32)
}

fn validate_expectations(pid: u32, hash: &str, sid: &str) -> Result<()> {
    if pid == 0
        || hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !sid.starts_with("S-1-5-21-")
        || sid.len() > 184
        || sid.split('-').count() != 8
        || sid
            .split('-')
            .skip(1)
            .any(|part| part.parse::<u32>().is_err())
    {
        return Err("fixed MXC child PID/hash/ordinary SID expectation rejected".into());
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResearchMxcRootToken {
    pub schema_version: String,
    pub expected_process_id: u32,
    pub expected_user_sid: String,
    pub token: TokenEvidence,
    pub validation_errors: Vec<String>,
}

impl ResearchMxcRootToken {
    pub(crate) fn measure(pid: u32, sid: &str, token: TokenEvidence) -> Self {
        // PSEC provenance comes from the exact SDK request/dispatch, not the
        // TokenIsAppContainer flag. Retain that flag and all other token fields.
        let mut validation_errors = self_token_errors(pid, &token);
        if token.user_sid != sid {
            validation_errors.push("userSid".into());
        }
        Self {
            schema_version: "aiw.dev/research-mxc-root-token/v0alpha1".into(),
            expected_process_id: pid,
            expected_user_sid: sid.into(),
            token,
            validation_errors,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.validation_errors.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "fixed MXC root token differs: {}",
                self.validation_errors.join(", ")
            ))
        }
    }
}

/// Structural self checks do not authorize an actor. Outside observers supply
/// the expected SID; the contained role must match their full protected gate.
pub(crate) fn self_token_errors(pid: u32, token: &TokenEvidence) -> Vec<String> {
    [
        (
            token.schema_version != aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION,
            "schemaVersion",
        ),
        (token.process_id != pid, "processId"),
        (token.token_type != TokenType::Primary, "tokenType"),
        (token.is_elevated, "isElevated"),
    ]
    .into_iter()
    .filter(|(failed, _)| *failed)
    .map(|(_, field)| field.into())
    .collect()
}

fn retain_then_validate_token(
    measured: &ResearchMxcRootToken,
    retain: impl FnOnce(&ResearchMxcRootToken) -> Result<()>,
) -> Result<()> {
    retain(measured)?;
    measured.validate()
}

fn validate_token(pid: u32, sid: &str, token: &TokenEvidence) -> Result<()> {
    ResearchMxcRootToken::measure(pid, sid, token.clone()).validate()
}

fn ancestry() -> Result<Vec<File>> {
    [r"C:\", r"C:\AIW", r"C:\AIW\SevenZip"]
        .into_iter()
        .map(|path| {
            let file = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
                .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
                .open(path)
                .map_err(|e| format!("hold fixed MXC child ancestry: {e}"))?;
            let metadata = file.metadata().map_err(|e| e.to_string())?;
            if !metadata.is_dir()
                || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
            {
                return Err("fixed MXC child ancestry is not an ordinary directory".into());
            }
            Ok(file)
        })
        .collect()
}

fn process_identity(process: HANDLE) -> Result<(u32, u64, String)> {
    // SAFETY: caller retains the live process handle through all queries.
    let pid = unsafe { GetProcessId(process) };
    if pid == 0 {
        return Err(native("GetProcessId", windows::core::Error::from_thread()));
    }
    let (mut c, mut e, mut k, mut u) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: all FILETIME outputs are valid writable storage.
    unsafe { GetProcessTimes(process, &mut c, &mut e, &mut k, &mut u) }
        .map_err(|e| native("GetProcessTimes", e))?;
    let mut buffer = [0_u16; 32768];
    let mut size = buffer.len() as u32;
    // SAFETY: bounded buffer and retained process with QUERY_LIMITED rights.
    unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )
    }
    .map_err(|e| native("QueryFullProcessImageNameW", e))?;
    if size == 0 || size as usize >= buffer.len() {
        return Err("fixed child image query truncated".into());
    }
    let image = String::from_utf16(&buffer[..size as usize]).map_err(|e| e.to_string())?;
    if !fixed_role_image(Path::new(&image), CONTROL_IMAGE) {
        return Err("queried child image is outside the exact fixed role".into());
    }
    Ok((
        pid,
        (u64::from(c.dwHighDateTime) << 32) | u64::from(c.dwLowDateTime),
        image,
    ))
}

impl<'owner> ResearchMxcChild<'owner> {
    /// Setup must retain its verified CONTROL_IMAGE copy across SDK creation.
    /// A queried image path plus the presently held file does not retrospectively
    /// attest loaded bytes if a caller allowed replacement before this open.
    pub(crate) fn open(
        pid: u32,
        helper_sha256: &str,
        standard_sid: &str,
        retain_token: impl FnOnce(&ResearchMxcRootToken) -> Result<()>,
    ) -> Result<Self> {
        validate_expectations(pid, helper_sha256, standard_sid)?;
        let ancestors = ancestry()?;
        // SYNCHRONIZE is the standard access bit 0x00100000. Never request
        // TERMINATE, SET_INFORMATION, VM_READ, DUP_HANDLE or privilege changes.
        let access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_ACCESS_RIGHTS(0x0010_0000);
        // SAFETY: exact PID from the SDK is not trusted until all held queries
        // below succeed. The returned handle is owned and never reopened by PID.
        let raw = unsafe { OpenProcess(access, false, pid) }
            .map_err(|e| native("OpenProcess(MXC child)", e))?;
        // SAFETY: successful OpenProcess transfers ownership of this handle.
        let process = unsafe { OwnedHandle::from_raw_handle(raw.0) };
        let (actual_pid, creation_time, queried_image_path) = process_identity(raw)?;
        if actual_pid != pid || creation_time == 0 {
            return Err("fixed MXC child PID/time differs".into());
        }
        let image = HeldApplicationFile::open_bounded(Path::new(CONTROL_IMAGE), IMAGE_BOUND)
            .map_err(|e| e.to_string())?;
        let facts = image.observation();
        if facts.sha256 != helper_sha256
            || facts.size_bytes == 0
            || facts.link_count != 1
            || !facts.only_unnamed_data_stream
            || !fixed_role_image(Path::new(&facts.canonical_path), CONTROL_IMAGE)
        {
            return Err("held fixed MXC child image differs".into());
        }
        let token = collect_process_token(process.as_handle())
            .map_err(|e| format!("collect held MXC child token: {e}"))?;
        let measured = ResearchMxcRootToken::measure(pid, standard_sid, token);
        retain_then_validate_token(&measured, retain_token)?;
        let observation = ResearchMxcChildObservation {
            schema_version: SCHEMA.into(),
            process_id: pid,
            creation_time,
            queried_image_path,
            image_identity: facts.identity.clone(),
            image_sha256: facts.sha256.clone(),
            image_size_bytes: facts.size_bytes,
            image_attributes: facts.attributes,
            image_link_count: facts.link_count,
            image_only_unnamed_data_stream: facts.only_unnamed_data_stream,
            token: measured.token,
        };
        let holder = Self {
            process,
            image,
            _ancestry: ancestors,
            observation,
            expected_hash: helper_sha256.into(),
            expected_sid: standard_sid.into(),
            owner_job: None,
        };
        holder.revalidate()?;
        Ok(holder)
    }

    pub(crate) fn observation(&self) -> &ResearchMxcChildObservation {
        &self.observation
    }

    /// Separate release-time precondition. Revalidation itself also permits a
    /// retained exited process, so completion cannot reopen/rebind a reused PID.
    pub(crate) fn require_running(&self) -> Result<()> {
        self.revalidate()?;
        // SAFETY: retained handle was opened with SYNCHRONIZE.
        match unsafe { WaitForSingleObject(HANDLE(self.process.as_raw_handle()), 0) } {
            WAIT_TIMEOUT => Ok(()),
            WAIT_OBJECT_0 => Err("fixed MXC child exited before gate release".into()),
            _ => Err(native(
                "WaitForSingleObject(MXC child)",
                windows::core::Error::from_thread(),
            )),
        }
    }

    pub(crate) fn revalidate(&self) -> Result<()> {
        self.image.revalidate().map_err(|e| e.to_string())?;
        let process = HANDLE(self.process.as_raw_handle());
        let (pid, time, path) = process_identity(process)?;
        let token = collect_process_token(self.process.as_handle())
            .map_err(|e| format!("revalidate held MXC child token: {e}"))?;
        validate_token(pid, &self.expected_sid, &token)?;
        if pid != self.observation.process_id
            || time != self.observation.creation_time
            || path != self.observation.queried_image_path
            || token != self.observation.token
            || self.image.observation().sha256 != self.expected_hash
        {
            return Err("retained MXC child observation changed".into());
        }
        if let Some(job) = self.owner_job {
            let mut member = BOOL(0);
            // SAFETY: borrowed exact owner job cannot close during this holder's
            // lifetime. Never query the NULL/ambient job as an ownership proof.
            unsafe { IsProcessInJob(process, Some(job.raw()), &mut member) }
                .map_err(|e| native("IsProcessInJob(exact owner)", e))?;
            if !member.as_bool() {
                return Err("fixed MXC child is outside exact owner job".into());
            }
        }
        Ok(())
    }
}

impl GuestProcess {
    pub(crate) fn observe_mxc_child(
        &self,
        pid: u32,
        helper_sha256: &str,
        standard_sid: &str,
        retain_token: impl FnOnce(&ResearchMxcRootToken) -> Result<()>,
    ) -> Result<ResearchMxcChild<'_>> {
        if pid == self.process_id {
            return Err("SDK child cannot be its owning worker".into());
        }
        let mut child = ResearchMxcChild::open(pid, helper_sha256, standard_sid, retain_token)?;
        child.owner_job = Some(&self.job);
        child.revalidate()?;
        child.require_running()?;
        Ok(child)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_bindings_are_rejected_before_native_access() {
        let hash = "a".repeat(64);
        let sid = "S-1-5-21-1-2-3-1001";
        assert!(validate_expectations(42, &hash, sid).is_ok());
        for (pid, hash, sid) in [
            (0, hash.as_str(), sid),
            (42, "bad", sid),
            (42, hash.as_str(), "S-1-5-18"),
            (42, hash.as_str(), "S-1-5-21-1-2-3-x"),
        ] {
            assert!(validate_expectations(pid, hash, sid).is_err());
        }
    }
    #[test]
    fn root_token_binding_retains_flags_and_rejects_each_identity_constraint() {
        let token: TokenEvidence = serde_json::from_value(serde_json::json!({
            "schemaVersion":aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION,"processId":42,"tokenType":"primary",
            "isAppContainer":false,"userSid":"S-1-5-21-1-2-3-1001","integrity":{"sid":"S-1-16-8192","rid":8192,"level":"medium"},
            "elevationType":"default","isElevated":false,"capabilities":[],"restrictedSidCount":0
        })).unwrap();
        assert!(validate_token(42, &token.user_sid, &token).is_ok());
        assert!(validate_token(43, &token.user_sid, &token).is_err());
        assert!(validate_token(42, "S-1-5-21-1-2-3-1002", &token).is_err());
        let mut elevated = token.clone();
        elevated.is_elevated = true;
        assert!(validate_token(42, &token.user_sid, &elevated).is_err());
        let mut contained = token.clone();
        contained.is_app_container = true;
        assert!(validate_token(42, &token.user_sid, &contained).is_ok());
        for (field, value) in [
            ("schemaVersion", serde_json::json!("wrong")),
            ("processId", serde_json::json!(43)),
            ("userSid", serde_json::json!("S-1-5-18")),
            ("tokenType", serde_json::json!("impersonation")),
            ("isElevated", serde_json::json!(true)),
        ] {
            let mut bad = serde_json::to_value(&token).unwrap();
            bad[field] = value;
            let measured = ResearchMxcRootToken::measure(
                42,
                &token.user_sid,
                serde_json::from_value(bad).unwrap(),
            );
            assert_eq!(measured.validation_errors, [field]);
            let mut retained = None;
            let result = retain_then_validate_token(&measured, |actual| {
                retained = Some(serde_json::to_value(actual).unwrap());
                Ok(())
            });
            assert!(result.is_err());
            assert_eq!(
                retained.unwrap()["validationErrors"],
                serde_json::json!([field])
            );
        }
        let measured = ResearchMxcRootToken::measure(42, &token.user_sid, contained.clone());
        let mut retained = None;
        assert!(
            retain_then_validate_token(&measured, |actual| {
                retained = Some(actual.token.clone());
                Ok(())
            })
            .is_ok()
        );
        assert_eq!(retained.unwrap(), contained);
        assert!(retain_then_validate_token(&measured, |_| Err("retention failed".into())).is_err());
    }
}
