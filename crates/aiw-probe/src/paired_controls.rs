//! Closed identities for the project-owned paired control, not an executable interface.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PAIRED_CONTROL_REVISION: &str = "aiw.dev/paired-file-registry-child/v0alpha2";
const LEGACY_CONTROL_REVISION: &str = "aiw.dev/paired-file-registry-child/v0alpha1";
pub const PAIRED_CONTROL_PLAN_SCHEMA: &str = "aiw.dev/run-plan/v0alpha7";
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ControlEvidenceOrigin {
    NativeWorker,
    SyntheticRehearsal,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairedControlProfile {
    pub revision: String,
    pub source_sha256: String,
    pub fixture_sha256: String,
    pub fixture_size_bytes: u64,
    pub launcher_sha256: String,
    pub launcher_size_bytes: u64,
    pub origin: ControlEvidenceOrigin,
    pub expected_windows: crate::WindowsVersionObservation,
    /// Exact host commitment is independent of the exact guest observation.
    /// Omission preserves the historical single-version profile bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_host_windows: Option<crate::WindowsVersionObservation>,
    pub policy: PairedControlPolicy,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum PairedControlPolicy {
    ClassicAppContainerNoCapabilitiesFixedChildOutputGrant,
}
impl PairedControlProfile {
    /// New preparation/dispatch must enroll the current fixed source bytes.
    pub fn validate(&self) -> Result<(), String> {
        self.validate_historical()?;
        if self.revision != PAIRED_CONTROL_REVISION
            || self.source_sha256 != paired_control_source_sha256()
        {
            return Err(
                "Paired source revision changed; prepare and approve a fresh plan before Start"
                    .into(),
            );
        }
        Ok(())
    }
    /// Structural historical identity only. This preserves exact-session cleanup
    /// and retained reporting; it never authorizes a fresh dispatch.
    pub fn validate_historical(&self) -> Result<(), String> {
        self.expected_windows.validate()?;
        match (self.revision.as_str(), &self.expected_host_windows) {
            (LEGACY_CONTROL_REVISION, None) => {}
            (PAIRED_CONTROL_REVISION, Some(host)) => {
                host.validate()?;
                if host.observer_architecture != "x86_64" {
                    return Err("Paired controls require an exact x64 host version".into());
                }
            }
            _ => return Err("Paired profile revision and host-version shape differ".into()),
        }
        if self.expected_windows.observer_architecture != "x86_64"
            || !control_hash(&self.source_sha256)
            || !control_hash(&self.fixture_sha256)
            || !control_hash(&self.launcher_sha256)
            || self.fixture_sha256 != self.launcher_sha256
            || self.fixture_size_bytes != self.launcher_size_bytes
            || self.fixture_size_bytes == 0
            || self.fixture_size_bytes > 128 * 1024 * 1024
            || self.launcher_size_bytes == 0
            || self.launcher_size_bytes > 128 * 1024 * 1024
        {
            return Err("Paired controls require the current fixed source revision and bounded exact executable commitments".into());
        }
        Ok(())
    }
    /// Historical v1 committed the same tuple for host and guest.
    pub fn approved_host_windows(&self) -> &crate::WindowsVersionObservation {
        self.expected_host_windows
            .as_ref()
            .unwrap_or(&self.expected_windows)
    }
    pub fn hash(&self) -> Result<String, String> {
        self.validate_historical()?;
        control_digest(self)
    }
}
/// Closed x64 version input, never a command or a claim about the running guest.
pub fn parse_guest_windows(value: &str) -> Result<crate::WindowsVersionObservation, String> {
    if value.len() > 23 {
        return Err("Expected exactly four decimal Windows-version components".into());
    }
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() != 4
        || parts.iter().any(|p| {
            p.is_empty()
                || (p.len() > 1 && p.starts_with('0'))
                || !p.bytes().all(|b| b.is_ascii_digit())
        })
    {
        return Err("Expected exactly four canonical decimal Windows-version components".into());
    }
    let numbers: Vec<u16> = parts
        .iter()
        .map(|part| {
            part.parse::<u16>()
                .map_err(|_| "Windows-version component exceeds 65535".to_owned())
        })
        .collect::<Result<_, _>>()?;
    let version = crate::WindowsVersionObservation {
        major: numbers[0],
        minor: numbers[1],
        build: numbers[2],
        revision: numbers[3],
        observer_architecture: "x86_64".into(),
    };
    version.validate()?;
    Ok(version)
}
/// The launcher never accepts caller arguments; these sources define its entire
/// permitted case/resource/policy surface. Build enrollment must bind its binaries.
pub fn paired_control_source_sha256() -> String {
    let sources = [
        include_str!("paired_controls.rs"),
        include_str!("../../aiw-provider-wsb/src/paired_controls.rs"),
        include_str!("../../aiw-control-fixture/src/main.rs"),
        include_str!("../../aiw-control-fixture/src/lib.rs"),
        include_str!("../../aiw-control-appcontainer/src/main.rs"),
        include_str!("../../aiw-windows-platform/src/control_appcontainer.rs"),
        include_str!("../../aiw-windows-platform/src/control_registry.rs"),
        include_str!("../../aiw-windows-platform/src/guest_paired_controls.rs"),
        include_str!("../../aiw-windows-platform/src/guest_document/paired_controls.rs"),
        include_str!("../../aiw-windows-platform/src/guest_standard_user.rs"),
        include_str!("../../aiw-windows-platform/src/guest_msi.rs"),
        include_str!("../../aiw-windows-platform/src/guest_document.rs"),
        include_str!("../../aiw-guest-agent/src/main.rs"),
    ];
    let mut digest = Sha256::new();
    for source in sources {
        digest.update((source.len() as u64).to_le_bytes());
        digest.update(source.as_bytes());
    }
    hex::encode(digest.finalize())
}
pub fn control_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn control_digest(value: &impl Serialize) -> Result<String, String> {
    let bytes = serde_json::to_value(value).map_err(|e| e.to_string())?;
    Ok(hex::encode(Sha256::digest(
        aiw_evidence::canonical_json_bytes(&bytes).map_err(|e| e.to_string())?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paired_profile() -> PairedControlProfile {
        PairedControlProfile {
            revision: PAIRED_CONTROL_REVISION.into(),
            source_sha256: paired_control_source_sha256(),
            fixture_sha256: "a".repeat(64),
            fixture_size_bytes: 7,
            launcher_sha256: "a".repeat(64),
            launcher_size_bytes: 7,
            origin: ControlEvidenceOrigin::SyntheticRehearsal,
            expected_windows: parse_guest_windows("10.0.26100.2").unwrap(),
            expected_host_windows: Some(parse_guest_windows("10.0.26300.1").unwrap()),
            policy: PairedControlPolicy::ClassicAppContainerNoCapabilitiesFixedChildOutputGrant,
        }
    }

    #[test]
    fn paired_profile_binds_host_and_guest_independently_and_requires_closed_revision_shapes() {
        let profile = paired_profile();
        profile.validate().unwrap();
        assert_ne!(&profile.expected_windows, profile.approved_host_windows());
        let hash = profile.hash().unwrap();
        let mut guest = profile.clone();
        guest.expected_windows.revision += 1;
        let mut host = profile.clone();
        host.expected_host_windows.as_mut().unwrap().revision += 1;
        assert_ne!(hash, guest.hash().unwrap());
        assert_ne!(hash, host.hash().unwrap());
        for case in 0..5 {
            let mut invalid = profile.clone();
            match case {
                0 => invalid.expected_host_windows = None,
                1 => invalid.revision = LEGACY_CONTROL_REVISION.into(),
                2 => invalid.revision = "unknown".into(),
                3 => {
                    invalid
                        .expected_host_windows
                        .as_mut()
                        .unwrap()
                        .observer_architecture = "aarch64".into()
                }
                _ => invalid.expected_windows.observer_architecture = "aarch64".into(),
            }
            assert!(invalid.validate_historical().is_err());
        }
    }

    #[test]
    fn paired_legacy_native_profile_hash_remains_exact_and_cannot_authorize_new_dispatch() {
        // Static, non-private profile metadata from retained a033 preparation;
        // this is neither a case observation nor a successful native result.
        let raw = serde_json::json!({
            "revision":"aiw.dev/paired-file-registry-child/v0alpha1",
            "sourceSha256":"69e6940c068e1864c714bd1eb06531a62dc84539f67c4d78404d26cc4521cf76",
            "fixtureSha256":"0e805e9198df58cf81d5bfe3286409d5d4eacb76bbb07841101c0897862fc1a9",
            "fixtureSizeBytes":5982208,
            "launcherSha256":"0e805e9198df58cf81d5bfe3286409d5d4eacb76bbb07841101c0897862fc1a9",
            "launcherSizeBytes":5982208, "origin":"nativeWorker",
            "expectedWindows":{"major":10,"minor":0,"build":26300,"revision":9711,"observerArchitecture":"x86_64"},
            "policy":"classicAppContainerNoCapabilitiesFixedChildOutputGrant"
        });
        let profile: PairedControlProfile = serde_json::from_value(raw.clone()).unwrap();
        profile.validate_historical().unwrap();
        assert!(profile.validate().is_err());
        assert_eq!(serde_json::to_value(&profile).unwrap(), raw);
        assert_eq!(
            profile.hash().unwrap(),
            "e338f9be45f7cddfd18eab1b8f4f7b8e42ddf2e263cd4d7514d84a3a80adfbfb"
        );
        assert_eq!(profile.approved_host_windows(), &profile.expected_windows);
    }

    #[test]
    fn paired_guest_version_input_is_bounded_canonical_and_not_executable_input() {
        assert_eq!(parse_guest_windows("10.0.26300.1").unwrap().revision, 1);
        for raw in [
            "",
            "10.0.1",
            "10.0.1.2.3",
            "010.0.1.2",
            "10.0.0.1",
            "0.0.1.2",
            "10.0.65536.0",
            "10.0.1.-1",
            "10.0.1.2\n",
            "10.0.1.2;Start",
            "１０.0.1.2",
            "65535.65535.65535.65535.",
        ] {
            assert!(parse_guest_windows(raw).is_err(), "accepted {raw:?}");
        }
    }
}
