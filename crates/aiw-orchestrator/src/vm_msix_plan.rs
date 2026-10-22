//! Production VM MSIX preparation and plan provenance. No provider execution.
use crate::*;
use aiw_probe::{
    ApplicationFileImportReceipt, ApplicationInspectionKind, MSIX_PACKAGE_SHA256,
    VmMsixWorkerProfile,
};

pub const VM_MSIX_RUN_PLAN_SCHEMA: &str = "aiw.dev/run-plan/v0alpha6";
pub const VM_MSIX_PREPARATION_SCHEMA: &str = "aiw.dev/vm-msix-preparation/v0alpha1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VmMsixPreparedFile {
    pub leaf: String,
    pub sha256: String,
    pub size_bytes: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VmMsixPreparation {
    pub schema_version: String,
    pub run_id: String,
    pub worker: VmMsixWorkerProfile,
    pub workspace: WorkspaceBindingEvidence,
    pub package_import: ApplicationFileImportReceipt,
    pub files: Vec<VmMsixPreparedFile>,
}
impl VmMsixPreparation {
    pub fn validate(&self) -> Result<(), String> {
        self.worker.validate()?;
        self.workspace.validate()?;
        if self.schema_version != VM_MSIX_PREPARATION_SCHEMA
            || !aiw_probe::valid_msix_run_id(&self.run_id)
            || self.package_import.source_kind != ApplicationInspectionKind::Msix
            || self.package_import.sha256 != MSIX_PACKAGE_SHA256
            || self.files.len() != 4
        {
            return Err("Invalid VM MSIX preparation contract".into());
        }
        let mut names = self
            .files
            .iter()
            .map(|f| f.leaf.as_str())
            .collect::<Vec<_>>();
        names.sort_unstable();
        if names
            != [
                "agent.exe",
                "assembly.json",
                "signing.json",
                "transport.ps1",
            ]
        {
            return Err("VM MSIX tools allowlist differs".into());
        }
        for file in &self.files {
            if !is_hash(&file.sha256) || file.size_bytes == 0 || file.size_bytes > 32 * 1024 * 1024
            {
                return Err("VM MSIX tool identity invalid".into());
            }
        }
        Ok(())
    }
    pub fn hash(&self) -> Result<String, String> {
        self.validate()?;
        hash_value(self).map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VmMsixExecutionBinding {
    pub preparation_sha256: String,
    pub worker_profile_sha256: String,
    pub package_sha256: String,
    pub workspace: Box<WorkspaceBindingEvidence>,
}
impl VmMsixExecutionBinding {
    pub fn validate(&self) -> Result<(), String> {
        self.workspace.validate()?;
        if !is_hash(&self.preparation_sha256)
            || !is_hash(&self.worker_profile_sha256)
            || self.package_sha256 != MSIX_PACKAGE_SHA256
        {
            return Err("VM MSIX plan binding differs".into());
        }
        Ok(())
    }
    pub fn matches(&self, prepared: &VmMsixPreparation) -> Result<(), String> {
        self.validate()?;
        prepared.validate()?;
        if self.preparation_sha256 != prepared.hash()?
            || self.worker_profile_sha256 != prepared.worker.hash()?
            || self.package_sha256 != prepared.package_import.sha256
            || *self.workspace != prepared.workspace
        {
            return Err("VM MSIX preparation does not match the approved binding".into());
        }
        Ok(())
    }
}

#[cfg(windows)]
pub struct HeldVmMsixPreparation {
    pub preparation: VmMsixPreparation,
    pub workspace: HeldRunWorkspace,
    _receipt: aiw_windows_platform::BoundWorkspaceFile,
    _tools: Vec<aiw_windows_platform::BoundWorkspaceFile>,
    _package: aiw_windows_platform::HeldVerifiedApplicationFileImport,
}
#[cfg(windows)]
pub fn open_vm_msix_preparation(plan: &RunPlan) -> Result<HeldVmMsixPreparation, AiwError> {
    let binding = plan
        .actions
        .iter()
        .find_map(|action| match action {
            PlannedAction::ExecuteVmMsix { binding } => Some(binding.as_ref()),
            _ => None,
        })
        .ok_or_else(|| {
            run_error(
                "AIW_MSIX_PROFILE_REQUIRED",
                "VM MSIX action required",
                "prepare",
                &plan.run_id,
            )
        })?;
    let reject = |detail: String| {
        run_error(
            "AIW_MSIX_PROVENANCE_REJECTED",
            &detail,
            "msixPreparation",
            &plan.run_id,
        )
    };
    binding.validate().map_err(reject)?;
    let workspace =
        HeldRunWorkspace::reopen_bound(&binding.workspace).map_err(|e| reject(e.to_string()))?;
    let receipt = workspace
        .reopen_tools_file_readonly("msix-preparation.json")
        .map_err(|e| reject(e.to_string()))?;
    let mut bytes = Vec::new();
    receipt
        .as_file()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| reject(e.to_string()))?;
    if bytes.len() > 1024 * 1024 {
        return Err(reject("MSIX preparation exceeds bound".into()));
    }
    let preparation: VmMsixPreparation =
        serde_json::from_slice(&bytes).map_err(|e| reject(e.to_string()))?;
    binding.matches(&preparation).map_err(reject)?;
    if preparation.run_id != plan.run_id {
        return Err(reject("MSIX run identity differs".into()));
    }
    let package =
        aiw_windows_platform::open_verified_application_file_import(&preparation.package_import)
            .map_err(|e| reject(e.to_string()))?;
    let mut tools = Vec::new();
    for expected in &preparation.files {
        let file = workspace
            .reopen_tools_file_readonly(&expected.leaf)
            .map_err(|e| reject(e.to_string()))?;
        let mut bytes = Vec::new();
        file.as_file()
            .take(expected.size_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| reject(e.to_string()))?;
        if bytes.len() as u64 != expected.size_bytes
            || hex::encode(Sha256::digest(&bytes)) != expected.sha256
        {
            return Err(reject("MSIX prepared tool drift".into()));
        }
        file.revalidate().map_err(|e| reject(e.to_string()))?;
        tools.push(file);
    }
    workspace.revalidate().map_err(|e| reject(e.to_string()))?;
    Ok(HeldVmMsixPreparation {
        preparation,
        workspace,
        _receipt: receipt,
        _tools: tools,
        _package: package,
    })
}
