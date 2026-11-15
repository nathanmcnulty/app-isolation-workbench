//! Default-off first-party environment observations, never application dispatch.
use std::{ffi::OsString, path::Path};

use aiw_probe::{WindowsFileIdentity, WindowsVersionObservation};
use aiw_token::{IntegrityLevel, TokenEvidence, TokenType};
use serde::{Deserialize, Serialize};
use windows::Win32::System::{
    SystemInformation::GetSystemDirectoryW,
    WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize},
};

use crate::{
    HeldApplicationFile,
    research_publication::{MappedPublication, publish_mapped_json},
};

pub const SCHEMA: &str = "aiw.dev/research/environment-observation/v0alpha1";
pub const OUTPUT: &str = r"C:\AIW\EnvironmentOutput";
pub const RESULT: &str = r"C:\AIW\EnvironmentOutput\RESULT.DAT";
pub const IMAGE: &str = r"C:\AIW\Tools\environment_probe.exe";
pub const DEPENDENCY: &str = r"C:\Windows\System32\vcruntime140.dll";
pub const OUTPUT_BOUND: u64 = 65536;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observed<T> {
    pub value: Option<T>,
    pub error: Option<String>,
}
impl<T> Observed<T> {
    fn capture(result: Result<T, String>) -> Self {
        match result {
            Ok(value) => Self {
                value: Some(value),
                error: None,
            },
            Err(error) => Self {
                value: None,
                error: Some(error.chars().take(1024).collect()),
            },
        }
    }
    fn valid_shape(&self) -> bool {
        matches!((&self.value, &self.error), (Some(_), None))
            || matches!((&self.value, &self.error), (None, Some(error)) if !error.is_empty() && error.len() <= 4096)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileFact {
    pub identity: WindowsFileIdentity,
    pub size_bytes: u64,
    pub sha256: String,
    pub link_count: u32,
    pub only_unnamed_data_stream: bool,
}
impl FileFact {
    pub fn from_held(file: &HeldApplicationFile) -> Self {
        let observation = file.observation();
        Self {
            identity: observation.identity.clone(),
            size_bytes: observation.size_bytes,
            sha256: observation.sha256.clone(),
            link_count: observation.link_count,
            only_unnamed_data_stream: observation.only_unnamed_data_stream,
        }
    }
    fn valid_dependency_fact(&self) -> bool {
        let nonzero_hex = |value: &str, size| {
            value.len() == size
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && value.bytes().any(|byte| byte != b'0')
        };
        self.identity
            .final_path
            .strip_prefix(r"\\?\")
            .unwrap_or(&self.identity.final_path)
            .eq_ignore_ascii_case(DEPENDENCY)
            && nonzero_hex(&self.identity.volume_serial_number, 16)
            && nonzero_hex(&self.identity.file_id, 32)
            && self.size_bytes <= 32 * 1024 * 1024
            && valid_hash(&self.sha256)
            && self.link_count == 1
            && self.only_unnamed_data_stream
    }
}

fn utility_account_sid(value: &str) -> bool {
    let parts = value.split('-').collect::<Vec<_>>();
    parts.len() == 8
        && parts[..4] == ["S", "1", "5", "21"]
        && parts[7] == "504"
        && parts[4..7].iter().all(|part| {
            part.parse::<u32>()
                .is_ok_and(|value| value.to_string() == *part)
        })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvironmentReport {
    pub schema_version: String,
    pub process_id: u32,
    pub observer_token: TokenEvidence,
    pub utility_account_sid: String,
    pub windows: Observed<WindowsVersionObservation>,
    pub system_directory: Observed<String>,
    pub dependency_path: String,
    /// Strict HAF errors mean measurement refused/unknown, never DLL absence.
    pub dependency_data: Observed<FileFact>,
    pub compiled_static_crt: bool,
    pub requested_application_execution: bool,
    pub requested_runtime_loads: bool,
    pub loader_compatibility: String,
    pub isolation_enforcement: String,
}

pub fn valid_guest_token(token: &TokenEvidence) -> bool {
    token.schema_version == aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION
        && token.process_id != 0
        && token.token_type == TokenType::Primary
        && token.impersonation_level.is_none()
        && !token.is_app_container
        && token.app_container_sid.is_none()
        && token.is_elevated
        && token.elevation_type != aiw_token::ElevationType::Limited
        && token.integrity.rid == 12288
        && token.integrity.sid == "S-1-16-12288"
        && token.integrity.level == IntegrityLevel::High
        && token.capabilities.is_empty()
        && token.restricted_sid_count == 0
}

impl EnvironmentReport {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != SCHEMA
            || !valid_guest_token(&self.observer_token)
            || self.process_id != self.observer_token.process_id
            || self.utility_account_sid != self.observer_token.user_sid
            || !utility_account_sid(&self.utility_account_sid)
            || !self.windows.valid_shape()
            || !self.system_directory.valid_shape()
            || !self.dependency_data.valid_shape()
            || self.dependency_path != DEPENDENCY
            || !self.compiled_static_crt
            || self.requested_application_execution
            || self.requested_runtime_loads
            || self.loader_compatibility != "unmeasured"
            || self.isolation_enforcement != "unmeasured"
        {
            return Err("environment report role, field state or scope differs".into());
        }
        if let Some(windows) = &self.windows.value {
            windows.validate()?;
            if windows.observer_architecture != "x86_64" {
                return Err("guest architecture differs".into());
            }
        }
        if self
            .system_directory
            .value
            .as_ref()
            .is_some_and(|path| path.len() > 512)
        {
            return Err("system-directory observation exceeds bound".into());
        }
        if let Some(file) = &self.dependency_data.value
            && (self
                .system_directory
                .value
                .as_ref()
                .is_none_or(|path| !path.eq_ignore_ascii_case(r"C:\Windows\System32"))
                || !file.valid_dependency_fact())
        {
            return Err("dependency data observation differs from fixed held file".into());
        }
        Ok(())
    }
}

pub fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn observe_windows() -> Result<WindowsVersionObservation, String> {
    struct Apartment;
    impl Drop for Apartment {
        fn drop(&mut self) {
            unsafe { RoUninitialize() };
        }
    }
    unsafe { RoInitialize(RO_INIT_MULTITHREADED) }
        .map_err(|error| format!("WinRT initialization refused: {error}"))?;
    let _apartment = Apartment;
    crate::observe_windows_version()
}

fn system_directory() -> Result<String, String> {
    let mut buffer = [0u16; 512];
    // Fixed writable UTF-16 buffer; no environment-variable path selection.
    let count = unsafe { GetSystemDirectoryW(Some(&mut buffer)) } as usize;
    if count == 0 || count >= buffer.len() {
        return Err("system directory unavailable or exceeds fixed bound".into());
    }
    String::from_utf16(&buffer[..count]).map_err(|error| error.to_string())
}

fn dependency_data(directory: &Observed<String>) -> Result<FileFact, String> {
    if directory
        .value
        .as_ref()
        .is_none_or(|path| !path.eq_ignore_ascii_case(r"C:\Windows\System32"))
    {
        return Err("fixed System32 scope not observed; no alternate path".into());
    }
    let file = HeldApplicationFile::open_bounded(Path::new(DEPENDENCY), 32 * 1024 * 1024)
        .map_err(|error| format!("strict data measurement refused (not absence): {error}"))?;
    let fact = FileFact::from_held(&file);
    file.revalidate()
        .map_err(|error| format!("data revalidation refused: {error}"))?;
    if !fact.valid_dependency_fact() {
        return Err(
            "strict dependency identity/stream observation refused; no absence inference".into(),
        );
    }
    Ok(fact)
}

fn exact_arguments(arguments: &[OsString]) -> bool {
    arguments == ["--output", RESULT]
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    if !cfg!(target_feature = "crt-static")
        || std::env::consts::ARCH != "x86_64"
        || !exact_arguments(&std::env::args_os().skip(1).collect::<Vec<_>>())
        || !crate::control_appcontainer::research_sevenzip::fixed_role_image(
            &std::env::current_exe()?,
            IMAGE,
        )
    {
        return Err("fixed static-CRT x64 environment observer role required".into());
    }
    let token = aiw_token::collect_current_process_token()?;
    let utility_account_sid = crate::control_appcontainer::fixed_account_sid("WDAGUtilityAccount")?;
    if !valid_guest_token(&token) || token.user_sid != utility_account_sid {
        return Err("fixed elevated Sandbox utility-account token required".into());
    }
    let windows = Observed::capture(observe_windows());
    let directory = Observed::capture(system_directory());
    let dependency = Observed::capture(dependency_data(&directory));
    let report = EnvironmentReport {
        schema_version: SCHEMA.into(),
        process_id: std::process::id(),
        observer_token: token,
        utility_account_sid,
        windows,
        system_directory: directory,
        dependency_path: DEPENDENCY.into(),
        dependency_data: dependency,
        compiled_static_crt: true,
        requested_application_execution: false,
        requested_runtime_loads: false,
        loader_compatibility: "unmeasured".into(),
        isolation_enforcement: "unmeasured".into(),
    };
    report.validate()?;
    let value = serde_json::to_value(report)?;
    if serde_json::to_vec(&value)?.len() as u64 > OUTPUT_BOUND {
        return Err("environment marker exceeds bound".into());
    }
    publish_mapped_json(MappedPublication::Environment, &value)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn report() -> EnvironmentReport {
        serde_json::from_value(serde_json::json!({
            "schemaVersion":SCHEMA,"processId":42,"observerToken":{
                "schemaVersion":aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION,"processId":42,"tokenType":"primary",
                "isAppContainer":false,"userSid":"S-1-5-21-1-2-3-504","integrity":{"sid":"S-1-16-12288","rid":12288,"level":"high"},
                "elevationType":"full","isElevated":true,"capabilities":[],"restrictedSidCount":0},
            "utilityAccountSid":"S-1-5-21-1-2-3-504",
            "windows":{"value":{"major":10,"minor":0,"build":26100,"revision":9974,"observerArchitecture":"x86_64"},"error":null},
            "systemDirectory":{"value":"C:\\Windows\\System32","error":null},
            "dependencyPath":DEPENDENCY,"dependencyData":{"value":null,"error":"strict data measurement refused; unknown"},
            "compiledStaticCrt":true,"requestedApplicationExecution":false,"requestedRuntimeLoads":false,
            "loaderCompatibility":"unmeasured","isolationEnforcement":"unmeasured"
        })).unwrap()
    }
    #[test]
    fn partial_environment_is_not_rewritten_as_unavailable_or_loader_success() {
        let mut value = report();
        value.validate().unwrap();
        value.windows = Observed::capture(Err("version API refused".into()));
        value.validate().unwrap();
        let bytes = serde_json::to_string(&value).unwrap();
        assert!(bytes.contains("version API refused"));
        assert!(bytes.contains("unmeasured"));
        value.loader_compatibility = "available".into();
        assert!(value.validate().is_err());
    }
    #[test]
    fn contradictory_identity_role_or_field_states_are_rejected() {
        for variant in 0..8 {
            let mut value = report();
            match variant {
                0 => value.observer_token.is_app_container = true,
                1 => value.process_id += 1,
                2 => value.utility_account_sid.push('0'),
                3 => value.windows.error = Some("contradiction".into()),
                4 => value.dependency_data.error = None,
                5 => value.requested_runtime_loads = true,
                6 => value.compiled_static_crt = false,
                _ => value
                    .observer_token
                    .capabilities
                    .push(aiw_token::SidAndAttributes {
                        sid: "S-1-1-0".into(),
                        attributes: 4,
                    }),
            }
            assert!(value.validate().is_err(), "variant {variant}");
        }
        let mut json = serde_json::to_value(report()).unwrap();
        json["applicationSucceeded"] = true.into();
        assert!(serde_json::from_value::<EnvironmentReport>(json).is_err());
    }
    #[test]
    fn high_local_accounts_and_malformed_sids_cannot_claim_the_utility_role() {
        for sid in [
            "S-1-5-21-1-2-3-1000",
            "S-1-5-21-1-2-504",
            "S-1-5-21-01-2-3-504",
            "S-1-5-21-4294967296-2-3-504",
            "S-1-5-21-1-2-3-504-1",
        ] {
            let mut value = report();
            value.utility_account_sid = sid.into();
            value.observer_token.user_sid = sid.into();
            assert!(value.validate().is_err(), "sid {sid}");
        }
        assert!(utility_account_sid("S-1-5-21-4294967295-2-3-504"));
    }
    #[test]
    fn contradictory_successful_file_facts_are_not_accepted_as_data_measurements() {
        let fact = FileFact {
            identity: WindowsFileIdentity {
                final_path: DEPENDENCY.into(),
                volume_serial_number: "0123456789abcdef".into(),
                file_id: "01".repeat(16),
            },
            size_bytes: 123,
            sha256: "ab".repeat(32),
            link_count: 1,
            only_unnamed_data_stream: true,
        };
        let mut value = report();
        value.dependency_data = Observed::capture(Ok(fact.clone()));
        value.validate().unwrap();
        for variant in 0..7 {
            let mut changed = fact.clone();
            match variant {
                0 => changed.only_unnamed_data_stream = false,
                1 => changed.identity.file_id = "00".repeat(16),
                2 => changed.identity.volume_serial_number = "0".repeat(16),
                3 => changed.identity.file_id = "1".into(),
                4 => changed.link_count = 2,
                5 => changed.identity.final_path = r"C:\Elsewhere\vcruntime140.dll".into(),
                _ => changed.sha256 = "AB".repeat(32),
            }
            value.dependency_data = Observed::capture(Ok(changed));
            assert!(value.validate().is_err(), "variant {variant}");
        }
        value.dependency_data = Observed::capture(Err(
            "strict observation refused; unknown, not missing".into(),
        ));
        value.validate().unwrap();
    }
    #[test]
    fn exact_role_arguments_do_not_admit_other_operations_or_paths() {
        let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
        assert!(exact_arguments(&args(&["--output", RESULT])));
        for values in [
            vec!["--output", RESULT, "--install"],
            vec!["--output", r"C:\AIW\EnvironmentOutput\result.dat"],
            vec!["--request", RESULT],
        ] {
            assert!(!exact_arguments(&args(&values)));
        }
    }
}
