//! Closed machine runtime policy. Historical evidence readers never execute it.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const POWERSHELL_EXECUTABLE: &str = r"C:\Program Files\PowerShell\7\pwsh.exe";
pub const POWERSHELL_PSHOME: &str = r"C:\Program Files\PowerShell\7";
pub const POWERSHELL_REMOTING_ENDPOINT: &str = "PowerShell.7.6";
pub const POWERSHELL_RUNTIME_GUARD: &str = include_str!("powershell_runtime.ps1");
pub const POWERSHELL_RUNTIME_OBSERVATION: &str =
    "$AiwPowerShellRuntime | ConvertTo-Json -Compress -Depth 8";
pub const POWERSHELL_CAPABILITIES: &[&str] = &[
    "Add-Type",
    "Get-CimInstance",
    "Get-AppxPackage",
    "Get-AppxPackageManifest",
    "Add-AppxPackage",
    "Remove-AppxPackage",
    "Get-AppxProvisionedPackage",
    "Get-LocalUser",
    "New-LocalUser",
    "Disable-LocalUser",
    "Add-LocalGroupMember",
    "Get-LocalGroupMember",
    "Get-AuthenticodeSignature",
    "Get-ScheduledTask",
    "New-PSSession",
];

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PowerShellRuntimeIdentity {
    pub edition: String,
    pub version: String,
    pub prerelease: String,
    pub architecture: String,
    pub executable: String,
    pub ps_home: String,
    pub executable_sha256: String,
    pub capabilities: Vec<String>,
    pub compatibility_session_count: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PowerShellExecutionBinding {
    pub host: PowerShellRuntimeIdentity,
    pub worker: PowerShellRuntimeIdentity,
    pub endpoint: String,
}
impl PowerShellExecutionBinding {
    pub fn verify_worker_receipts(&self, receipts: &[&serde_json::Value]) -> Result<(), String> {
        self.validate()?;
        let expected = serde_json::to_value(&self.worker).map_err(|e| e.to_string())?;
        if receipts
            .iter()
            .any(|receipt| receipt["powerShellRuntime"] != expected)
        {
            return Err("SYSTEM, Control and lifecycle runtime receipts must match the approved worker runtime".into());
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<(), String> {
        self.host.validate()?;
        self.worker.validate()?;
        if self.endpoint != POWERSHELL_REMOTING_ENDPOINT {
            return Err("Approved explicit PowerShell 7.6 endpoint required".into());
        }
        Ok(())
    }
}
impl PowerShellRuntimeIdentity {
    pub fn validate(&self) -> Result<(), String> {
        let numbers = self
            .version
            .split('.')
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "Stable numeric PowerShell version required")?;
        if !(3..=4).contains(&numbers.len())
            || numbers[0] < 7
            || (numbers[0] == 7 && numbers[1] < 6)
            || self.edition != "Core"
            || !self.prerelease.is_empty()
            || self.architecture != "X64"
            || !self.executable.eq_ignore_ascii_case(POWERSHELL_EXECUTABLE)
            || !self.ps_home.eq_ignore_ascii_case(POWERSHELL_PSHOME)
            || self.executable_sha256.len() != 64
            || !self
                .executable_sha256
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            || self.compatibility_session_count != 0
            || self.capabilities.len() != POWERSHELL_CAPABILITIES.len()
            || POWERSHELL_CAPABILITIES
                .iter()
                .any(|name| !self.capabilities.iter().any(|observed| observed == name))
        {
            return Err(
                "Machine x64 stable PowerShell Core >=7.6 with native capabilities required".into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn approved_runtime_cannot_mix_legacy_or_different_lifecycle_receipts() {
        let binding = PowerShellExecutionBinding {
            host: valid(),
            worker: valid(),
            endpoint: POWERSHELL_REMOTING_ENDPOINT.into(),
        };
        let record = serde_json::json!({"powerShellRuntime":binding.worker});
        assert!(
            binding
                .verify_worker_receipts(&[&record, &record, &record])
                .is_ok()
        );
        assert!(
            binding
                .verify_worker_receipts(&[&record, &record, &serde_json::json!({})])
                .is_err()
        );
        let mut other = record.clone();
        other["powerShellRuntime"]["executableSha256"] = serde_json::json!("b".repeat(64));
        assert!(
            binding
                .verify_worker_receipts(&[&record, &record, &other])
                .is_err()
        );
        other = record.clone();
        other["powerShellRuntime"]["version"] = "7.6.7".into();
        assert!(
            binding
                .verify_worker_receipts(&[&record, &record, &other])
                .is_err()
        );
    }
    fn valid() -> PowerShellRuntimeIdentity {
        PowerShellRuntimeIdentity {
            edition: "Core".into(),
            version: "7.6.5".into(),
            prerelease: String::new(),
            architecture: "X64".into(),
            executable: POWERSHELL_EXECUTABLE.into(),
            ps_home: POWERSHELL_PSHOME.into(),
            executable_sha256: "a".repeat(64),
            capabilities: POWERSHELL_CAPABILITIES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            compatibility_session_count: 0,
        }
    }
    #[test]
    fn supported_runtime_and_exact_machine_identity_required() {
        assert!(valid().validate().is_ok());
        for version in ["5.1.26100.1", "7.5.4", "7.6.0-preview.1", "7.6", "garbage"] {
            let mut r = valid();
            r.version = version.into();
            assert!(r.validate().is_err());
        }
        let mut r = valid();
        r.prerelease = "preview.1".into();
        assert!(r.validate().is_err());
        let mut r = valid();
        r.executable = r"C:\Users\user\pwsh.exe".into();
        assert!(r.validate().is_err());
        let mut r = valid();
        r.ps_home = r"C:\Other".into();
        assert!(r.validate().is_err());
        let mut r = valid();
        r.architecture = "X86".into();
        assert!(r.validate().is_err());
        let mut r = valid();
        r.compatibility_session_count = 1;
        assert!(r.validate().is_err());
        let mut r = valid();
        r.capabilities.pop();
        assert!(r.validate().is_err());
    }
}
