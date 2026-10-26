//! Closed machine runtime policy. Historical evidence readers never execute it.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const POWERSHELL_EXECUTABLE: &str = r"C:\Program Files\PowerShell\7\pwsh.exe";
pub const POWERSHELL_PSHOME: &str = r"C:\Program Files\PowerShell\7";
pub const POWERSHELL_ENGINE: &str =
    r"C:\Program Files\PowerShell\7\System.Management.Automation.dll";
pub const WSMAN_HOST: &str = r"C:\Windows\System32\wsmprovhost.exe";
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
pub struct PowerShellEngineIdentity {
    pub assembly_path: String,
    pub assembly_sha256: String,
    pub assembly_version: String,
    pub module_version_id: String,
}
impl PowerShellEngineIdentity {
    pub fn validate(&self, runtime_version: &str) -> Result<(), String> {
        let assembly = numeric_version(&self.assembly_version)?;
        let runtime = numeric_version(runtime_version)?;
        let mvid = self.module_version_id.as_bytes();
        if !self.assembly_path.eq_ignore_ascii_case(POWERSHELL_ENGINE)
            || !lower_hash(&self.assembly_sha256)
            || assembly.len() != 4
            || assembly[..2] != runtime[..2]
            || mvid.len() != 36
            || mvid.iter().enumerate().any(|(i, c)| {
                if [8, 13, 18, 23].contains(&i) {
                    *c != b'-'
                } else {
                    !c.is_ascii_hexdigit()
                }
            })
            || self.module_version_id == "00000000-0000-0000-0000-000000000000"
        {
            return Err("Fixed native PowerShell engine assembly identity required".into());
        }
        Ok(())
    }
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<PowerShellEngineIdentity>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WsmanEndpointIdentity {
    pub configuration_name: String,
    pub host_kind: String,
    pub host_executable: String,
    pub host_executable_sha256: String,
    pub edition: String,
    pub version: String,
    pub prerelease: String,
    pub architecture: String,
    pub ps_home: String,
    pub engine: PowerShellEngineIdentity,
    pub capabilities: Vec<String>,
    pub compatibility_session_count: u32,
    pub plugin_path: String,
    pub plugin_sha256: String,
    pub configuration_sha256: String,
    pub startup_config_sha256: String,
    pub resource_uri: String,
    pub configuration_ps_home: String,
    pub configuration_coreclr_dir: String,
}
impl WsmanEndpointIdentity {
    pub fn validate(&self) -> Result<(), String> {
        validate_core(
            &self.edition,
            &self.version,
            &self.prerelease,
            &self.architecture,
            &self.ps_home,
            &self.capabilities,
            self.compatibility_session_count,
        )?;
        self.engine.validate(&self.version)?;
        let direct_plugin = format!(r"{}\pwrshplugin.dll", POWERSHELL_PSHOME);
        let registered_plugin = format!(
            r"C:\Windows\System32\PowerShell\{}\pwrshplugin.dll",
            self.version
        );
        if self.configuration_name != POWERSHELL_REMOTING_ENDPOINT
            || self.host_kind != "WSMan"
            || !self.host_executable.eq_ignore_ascii_case(WSMAN_HOST)
            || !self
                .configuration_ps_home
                .eq_ignore_ascii_case(POWERSHELL_PSHOME)
            || !self
                .configuration_coreclr_dir
                .eq_ignore_ascii_case(POWERSHELL_PSHOME)
            || self.resource_uri != "http://schemas.microsoft.com/powershell/PowerShell.7.6"
            || !(self.plugin_path.eq_ignore_ascii_case(&direct_plugin)
                || self.plugin_path.eq_ignore_ascii_case(&registered_plugin))
            || [
                &self.host_executable_sha256,
                &self.plugin_sha256,
                &self.configuration_sha256,
                &self.startup_config_sha256,
            ]
            .iter()
            .any(|value| !lower_hash(value))
        {
            return Err("Bound Core WSMan host, plugin and endpoint configuration required".into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PowerShellExecutionBinding {
    pub host: PowerShellRuntimeIdentity,
    pub worker: PowerShellRuntimeIdentity,
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wsman: Option<WsmanEndpointIdentity>,
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
        if let Some(wsman) = &self.wsman {
            wsman.validate()?;
            if wsman.configuration_name != self.endpoint
                || wsman.version != self.worker.version
                || !wsman.ps_home.eq_ignore_ascii_case(&self.worker.ps_home)
                || self.worker.engine.as_ref() != Some(&wsman.engine)
            {
                return Err(
                    "WSMan endpoint and direct worker runtime must share the approved engine"
                        .into(),
                );
            }
        }
        Ok(())
    }
    pub fn validate_execution(&self) -> Result<(), String> {
        self.validate()?;
        self.host.validate_execution()?;
        self.worker.validate_execution()?;
        self.wsman
            .as_ref()
            .ok_or("Historical runtime binding has no WSMan identity; do not execute")?
            .validate()
    }
}
impl PowerShellRuntimeIdentity {
    pub fn validate(&self) -> Result<(), String> {
        validate_core(
            &self.edition,
            &self.version,
            &self.prerelease,
            &self.architecture,
            &self.ps_home,
            &self.capabilities,
            self.compatibility_session_count,
        )?;
        if !self.executable.eq_ignore_ascii_case(POWERSHELL_EXECUTABLE)
            || !lower_hash(&self.executable_sha256)
        {
            return Err("Fixed direct PowerShell executable identity required".into());
        }
        if let Some(engine) = &self.engine {
            engine.validate(&self.version)?;
        }
        Ok(())
    }
    pub fn validate_execution(&self) -> Result<(), String> {
        self.validate()?;
        self.engine
            .as_ref()
            .ok_or("Historical runtime has no engine identity; do not execute")?
            .validate(&self.version)
    }
}
fn lower_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}
fn numeric_version(value: &str) -> Result<Vec<u32>, String> {
    if value
        .split('.')
        .any(|part| part.is_empty() || !part.bytes().all(|c| c.is_ascii_digit()))
    {
        return Err("Stable numeric PowerShell version required".into());
    }
    let numbers = value
        .split('.')
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "Stable numeric PowerShell version required".to_string())?;
    if !(3..=4).contains(&numbers.len()) {
        return Err("Complete numeric PowerShell version required".into());
    }
    Ok(numbers)
}
fn validate_core(
    edition: &str,
    version: &str,
    prerelease: &str,
    architecture: &str,
    ps_home: &str,
    capabilities: &[String],
    compatibility_session_count: u32,
) -> Result<(), String> {
    let numbers = numeric_version(version)?;
    if !(3..=4).contains(&numbers.len())
        || numbers[0] < 7
        || (numbers[0] == 7 && numbers[1] < 6)
        || edition != "Core"
        || !prerelease.is_empty()
        || architecture != "X64"
        || !ps_home.eq_ignore_ascii_case(POWERSHELL_PSHOME)
        || compatibility_session_count != 0
        || capabilities.len() != POWERSHELL_CAPABILITIES.len()
        || POWERSHELL_CAPABILITIES
            .iter()
            .any(|name| !capabilities.iter().any(|observed| observed == name))
    {
        return Err(
            "Machine x64 stable PowerShell Core >=7.6 with native capabilities required".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn direct_runtime_guard_fits_the_native_windows_command_line() {
        // Conservative bound for Rust's Windows argument quoting: each
        // backslash/quote can add one escape, plus fixed executable/args/RNG.
        let quoted_guard = POWERSHELL_RUNTIME_GUARD.encode_utf16().count()
            + POWERSHELL_RUNTIME_GUARD.matches('\\').count()
            + POWERSHELL_RUNTIME_GUARD.matches('"').count()
            + 512;
        assert!(
            quoted_guard < 32_767,
            "Direct runtime proof requires a bounded stdin route"
        );
    }
    fn engine() -> PowerShellEngineIdentity {
        PowerShellEngineIdentity {
            assembly_path: POWERSHELL_ENGINE.into(),
            assembly_sha256: "b".repeat(64),
            assembly_version: "7.6.0.500".into(),
            module_version_id: "e5cecc90-35c2-4831-bf9c-424be23f7d4e".into(),
        }
    }
    fn executable_binding() -> PowerShellExecutionBinding {
        let mut worker = valid();
        worker.version = "7.6.7".into();
        worker.engine = Some(engine());
        PowerShellExecutionBinding {
            host: worker.clone(),
            worker: worker.clone(),
            endpoint: POWERSHELL_REMOTING_ENDPOINT.into(),
            wsman: Some(WsmanEndpointIdentity {
                configuration_name: POWERSHELL_REMOTING_ENDPOINT.into(),
                host_kind: "WSMan".into(),
                host_executable: WSMAN_HOST.into(),
                host_executable_sha256: "c".repeat(64),
                edition: worker.edition,
                version: worker.version,
                prerelease: worker.prerelease,
                architecture: worker.architecture,
                ps_home: worker.ps_home,
                engine: engine(),
                capabilities: worker.capabilities,
                compatibility_session_count: 0,
                plugin_path: format!(r"{}\pwrshplugin.dll", POWERSHELL_PSHOME),
                plugin_sha256: "d".repeat(64),
                configuration_sha256: "e".repeat(64),
                startup_config_sha256: "f".repeat(64),
                resource_uri: "http://schemas.microsoft.com/powershell/PowerShell.7.6".into(),
                configuration_ps_home: POWERSHELL_PSHOME.into(),
                configuration_coreclr_dir: POWERSHELL_PSHOME.into(),
            }),
        }
    }
    #[test]
    fn mixed_controller_and_worker_patches_keep_endpoint_coherence() {
        let mut binding = executable_binding();
        binding.host.version = "7.6.9".into();
        binding.host.executable_sha256 = "9".repeat(64);
        binding.host.engine.as_mut().unwrap().assembly_sha256 = "8".repeat(64);
        binding.validate_execution().unwrap();
        let mut stale = binding.clone();
        stale.wsman.as_mut().unwrap().version = "7.6.9".into();
        assert!(stale.validate_execution().is_err());
        for version in ["7.5.9", "7.6.9-preview.1"] {
            let mut invalid = binding.clone();
            invalid.host.version = version.into();
            assert!(invalid.validate_execution().is_err());
        }
    }
    #[test]
    fn wsman_host_is_distinct_from_direct_worker_but_engine_is_shared() {
        let mut binding = executable_binding();
        binding.validate_execution().unwrap();
        assert_ne!(
            binding.worker.executable,
            binding.wsman.as_ref().unwrap().host_executable
        );
        binding.wsman.as_mut().unwrap().plugin_path =
            r"C:\Windows\System32\PowerShell\7.6.7\pwrshplugin.dll".into();
        binding.validate_execution().unwrap();
        let record = serde_json::json!({"powerShellRuntime":binding.worker});
        binding
            .verify_worker_receipts(&[&record, &record, &record])
            .unwrap();
        let endpoint_record = serde_json::json!({"powerShellRuntime":binding.wsman});
        assert!(
            binding
                .verify_worker_receipts(&[&record, &endpoint_record])
                .is_err()
        );
    }
    #[test]
    fn wsman_engine_host_and_configuration_fail_closed() {
        let original = serde_json::to_value(executable_binding()).unwrap();
        for (field, wrong) in [
            ("hostKind", "Direct"),
            ("hostExecutable", POWERSHELL_EXECUTABLE),
            ("configurationName", "Microsoft.PowerShell"),
            ("edition", "Desktop"),
            ("prerelease", "preview.1"),
            ("version", "5.1.26100.1"),
            ("architecture", "X86"),
            ("psHome", r"C:\Other"),
            ("pluginPath", r"C:\Other\pwrshplugin.dll"),
            (
                "resourceUri",
                "http://schemas.microsoft.com/powershell/Microsoft.PowerShell",
            ),
            ("configurationPsHome", r"C:\Other"),
            ("configurationCoreclrDir", r"C:\Other"),
            ("hostExecutableSha256", "invalid"),
            ("pluginSha256", "invalid"),
            ("configurationSha256", "invalid"),
            ("startupConfigSha256", "invalid"),
        ] {
            let mut bad = original.clone();
            bad["wsman"][field] = wrong.into();
            let binding: PowerShellExecutionBinding = serde_json::from_value(bad).unwrap();
            assert!(binding.validate_execution().is_err(), "{field}");
        }
        let mut bad = original.clone();
        bad["wsman"]["compatibilitySessionCount"] = 1.into();
        assert!(
            serde_json::from_value::<PowerShellExecutionBinding>(bad)
                .unwrap()
                .validate_execution()
                .is_err()
        );
        for (field, wrong) in [
            ("assemblyPath", r"C:\Other\System.Management.Automation.dll"),
            ("assemblySha256", "ABCDEF"),
            ("assemblyVersion", "7.5.0.500"),
            ("assemblyVersion", "7.6.0"),
            ("moduleVersionId", "not-a-uuid"),
        ] {
            let mut bad = original.clone();
            bad["wsman"]["engine"][field] = wrong.into();
            assert!(
                serde_json::from_value::<PowerShellExecutionBinding>(bad)
                    .unwrap()
                    .validate_execution()
                    .is_err(),
                "{field}"
            );
        }
        for (role, field, wrong) in [
            ("worker", "version", "7.6.8"),
            ("worker", "psHome", r"C:\Other"),
            ("worker", "assemblySha256", &"1".repeat(64)),
            ("wsman", "assemblySha256", &"2".repeat(64)),
        ] {
            let mut bad = original.clone();
            if field == "assemblySha256" {
                bad[role]["engine"][field] = wrong.into();
            } else {
                bad[role][field] = wrong.into();
            }
            assert!(
                serde_json::from_value::<PowerShellExecutionBinding>(bad)
                    .unwrap()
                    .validate_execution()
                    .is_err()
            );
        }
    }
    #[test]
    fn historical_runtime_binding_roundtrips_without_new_fields_and_cannot_execute() {
        let binding = PowerShellExecutionBinding {
            host: valid(),
            worker: valid(),
            endpoint: POWERSHELL_REMOTING_ENDPOINT.into(),
            wsman: None,
        };
        let original = serde_json::to_vec(&binding).unwrap();
        assert!(!String::from_utf8_lossy(&original).contains("engine"));
        assert!(!String::from_utf8_lossy(&original).contains("wsman"));
        let retained: PowerShellExecutionBinding = serde_json::from_slice(&original).unwrap();
        retained.validate().unwrap();
        assert_eq!(serde_json::to_vec(&retained).unwrap(), original);
        assert!(retained.validate_execution().is_err());
        let mut incomplete = executable_binding();
        incomplete.host.engine = None;
        assert!(incomplete.validate_execution().is_err());
        incomplete = executable_binding();
        incomplete.worker.engine = None;
        assert!(incomplete.validate_execution().is_err());
    }
    #[test]
    fn approved_runtime_cannot_mix_legacy_or_different_lifecycle_receipts() {
        let binding = PowerShellExecutionBinding {
            host: valid(),
            worker: valid(),
            endpoint: POWERSHELL_REMOTING_ENDPOINT.into(),
            wsman: None,
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
            engine: None,
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
