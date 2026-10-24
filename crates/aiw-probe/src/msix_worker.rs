//! Closed production profile shared by the host and disposable VM agent.
//! These records are bindings, not permission to execute or evidence of isolation.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MSIX_WORKER_REQUEST_SCHEMA: &str = "aiw.dev/msix-worker-request/v0alpha1";
pub const MSIX_PACKAGE_SHA256: &str =
    "2ae3a7c685e811eb34479980bff41d1442b023578074e19f4dca8fc676070437";
pub const MSIX_ASSEMBLY_SHA256: &str =
    "d7eca3af76598534d29e411b4d4775d61e6ffe11174aa5a171b44bfe2a080c38";
pub const MSIX_SIGNING_SHA256: &str =
    "670e6f9e44211848c305c61261aa2ed6e2c94fac229214ec843cd4c9afab9e80";
pub const MSIX_WORKER_UUID: &str = "e5cecc90-35c2-4831-bf9c-424be23f7d4e";
pub const MSIX_WORKER_CHECKPOINT: &str = "aiw-msix-worker107-tls-clean-r1";
/// Planned runtime-equipped baseline. Provisioning and its config pin need
/// explicit approval; the historical checkpoint must never be relabeled.
pub const MSIX_CORE_WORKER_CHECKPOINT: &str = "aiw-msix-worker107-pwsh76-clean-r1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum VmMsixRecipe {
    Notepad898MediumFullTrust,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VmMsixWorkerProfile {
    pub schema_version: String,
    pub vm_id: u32,
    pub worker_uuid: String,
    pub worker_mac: String,
    pub checkpoint: String,
    pub checkpoint_config_sha256: String,
    pub provider_sha256: String,
    pub hypervisor_address: String,
    pub hypervisor_host_key_sha256: String,
    pub https_address: String,
    pub https_certificate_sha1: String,
}
impl VmMsixWorkerProfile {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != "aiw.dev/vm-msix-worker-profile/v0alpha1"
            || self.vm_id != 107
            || self.worker_uuid != MSIX_WORKER_UUID
            || self.worker_mac != "CC:34:21:B8:5A:31"
            || !matches!(
                self.checkpoint.as_str(),
                MSIX_WORKER_CHECKPOINT | MSIX_CORE_WORKER_CHECKPOINT
            )
            || !lower_hash(&self.checkpoint_config_sha256)
            || !lower_hash(&self.provider_sha256)
            || self.hypervisor_address != "192.168.1.6"
            || self.hypervisor_host_key_sha256
                != "SHA256:J/kc0UwUBil5TFBQbQhwBoRKnDoRlZ8ggXAhmYEpq1E"
            || self.https_address != "192.168.1.174"
            || self.https_certificate_sha1 != "BC14DCC4E37F83161EBB55AF8624E36A79E19256"
            || !self
                .https_certificate_sha1
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_lowercase())
        {
            return Err("Only the enrolled disposable VM107 worker profile is supported".into());
        }
        Ok(())
    }
    pub fn hash(&self) -> Result<String, String> {
        self.validate()?;
        hash_record(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MsixWorkerRequest {
    pub schema_version: String,
    pub run_id: String,
    pub nonce: String,
    pub recipe: VmMsixRecipe,
    pub plan_sha256: String,
    pub worker_profile_sha256: String,
    pub agent_sha256: String,
    pub package_sha256: String,
    pub assembly_sha256: String,
    pub signing_sha256: String,
    pub worker_uuid: String,
    /// Absent only in historical records, which remain readable without execution.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "powerShellRuntime"
    )]
    pub power_shell_runtime: Option<crate::powershell::PowerShellExecutionBinding>,
    pub not_before_file_time: i64,
    pub not_after_file_time: i64,
}
impl MsixWorkerRequest {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(runtime) = &self.power_shell_runtime {
            runtime.validate()?;
        }
        if self.schema_version != MSIX_WORKER_REQUEST_SCHEMA
            || !safe_run_id(&self.run_id)
            || !lower_hash(&self.nonce)
            || !lower_hash(&self.plan_sha256)
            || !lower_hash(&self.worker_profile_sha256)
            || !lower_hash(&self.agent_sha256)
            || self.package_sha256 != MSIX_PACKAGE_SHA256
            || self.assembly_sha256 != MSIX_ASSEMBLY_SHA256
            || self.signing_sha256 != MSIX_SIGNING_SHA256
            || self.worker_uuid != MSIX_WORKER_UUID
            || self.not_before_file_time <= 0
            || self
                .not_after_file_time
                .checked_sub(self.not_before_file_time)
                != Some(18_000_000_000)
        {
            return Err(
                "MSIX request is not the fixed nonce/plan/worker/input/deadline contract".into(),
            );
        }
        Ok(())
    }
    pub fn validate_at(&self, now: i64) -> Result<(), String> {
        self.validate()?;
        if now < self.not_before_file_time || now >= self.not_after_file_time {
            return Err("MSIX request is outside its approved 30-minute interval".into());
        }
        Ok(())
    }
    pub fn execution_runtime(
        &self,
    ) -> Result<&crate::powershell::PowerShellExecutionBinding, String> {
        self.validate()?;
        let runtime = self.power_shell_runtime.as_ref().ok_or(
            "Historical MSIX request has no approved Core runtime; do not execute or rewrite it",
        )?;
        runtime.validate()?;
        Ok(runtime)
    }
    pub fn hash(&self) -> Result<String, String> {
        self.validate()?;
        hash_record(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum VmMsixPhase {
    Prepared,
    Approved,
    LeaseAcquired,
    StartIntent,
    GuestStaged,
    Enrolling,
    Rebooting,
    ControlRunning,
    TrialRunning,
    AwaitingEdit,
    EvidenceCollecting,
    Restoring,
    RecoveryRequired,
    Finalized,
}

pub fn safe_run_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
pub fn lower_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hash_record<T: Serialize>(record: &T) -> Result<String, String> {
    let value = serde_json::to_value(record).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> MsixWorkerRequest {
        MsixWorkerRequest {
            schema_version: MSIX_WORKER_REQUEST_SCHEMA.into(),
            run_id: "msix-fixed-run".into(),
            nonce: "a".repeat(64),
            recipe: VmMsixRecipe::Notepad898MediumFullTrust,
            plan_sha256: "b".repeat(64),
            worker_profile_sha256: "c".repeat(64),
            agent_sha256: "d".repeat(64),
            package_sha256: MSIX_PACKAGE_SHA256.into(),
            assembly_sha256: MSIX_ASSEMBLY_SHA256.into(),
            signing_sha256: MSIX_SIGNING_SHA256.into(),
            worker_uuid: MSIX_WORKER_UUID.into(),
            power_shell_runtime: None,
            not_before_file_time: 134371378919507943,
            not_after_file_time: 134371396919507943,
        }
    }
    #[test]
    fn closed_request_rejects_commands_other_workers_inputs_and_stale_runs() {
        let r = request();
        r.validate_at(r.not_before_file_time).unwrap();
        assert!(r.validate_at(r.not_after_file_time).is_err());
        assert!(r.validate_at(r.not_before_file_time - 1).is_err());
        for (field, bad) in [
            ("runId", "../escape"),
            ("nonce", "unknown"),
            ("workerUuid", "wrong-vm"),
            ("packageSha256", &"0".repeat(64)),
        ] {
            let mut v = serde_json::to_value(&r).unwrap();
            v[field] = bad.into();
            assert!(
                serde_json::from_value::<MsixWorkerRequest>(v)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
        let mut v = serde_json::to_value(&r).unwrap();
        v["command"] = "anything".into();
        assert!(serde_json::from_value::<MsixWorkerRequest>(v).is_err());
        let mut changed = r.clone();
        changed.nonce = "e".repeat(64);
        assert_ne!(r.hash().unwrap(), changed.hash().unwrap());
    }
    #[test]
    fn historical_request_roundtrips_without_runtime_or_hash_rewrite_but_cannot_execute() {
        let original = request();
        let value = serde_json::to_value(&original).unwrap();
        assert!(value.get("powerShellRuntime").is_none());
        let retained: MsixWorkerRequest = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(retained.hash().unwrap(), original.hash().unwrap());
        assert_eq!(serde_json::to_value(&retained).unwrap(), value);
        assert!(retained.execution_runtime().is_err());
    }
}
