use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    ImportedMsiGuestRequest, ImportedMsiScenarioResult,
    application_token::verified_application_records,
};

pub const IMPORTED_MSI_PRODUCT_REGISTRATION_SCHEMA_VERSION: &str =
    "aiw.dev/imported-msi-product-registration/v0alpha1";
pub const IMPORTED_MSI_PRODUCT_REGISTRATION_EVENT: &str = "importedMsiProductRegistration";

/// The machine-context product state observed by the fixed guest collector.
/// `Unavailable` is an explicit unmeasured state, not an installed-state claim.
#[derive(Debug, Clone, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum MsiMachineProductState {
    NotRegistered,
    Advertised,
    Installed,
    Unavailable { error_code: u32 },
}

impl<'de> Deserialize<'de> for MsiMachineProductState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            status: String,
            #[serde(default, deserialize_with = "present_error_code")]
            error_code: Option<u32>,
        }

        let wire = Wire::deserialize(deserializer)?;
        match (wire.status.as_str(), wire.error_code) {
            ("notRegistered", None) => Ok(Self::NotRegistered),
            ("advertised", None) => Ok(Self::Advertised),
            ("installed", None) => Ok(Self::Installed),
            ("unavailable", Some(error_code)) => Ok(Self::Unavailable { error_code }),
            _ => Err(serde::de::Error::custom(
                "invalid MSI machine product state shape",
            )),
        }
    }
}

/// Missing `errorCode` means no variant field. A present field must be a number;
/// accepting JSON null would make a malformed state indistinguishable from a
/// field that was absent.
fn present_error_code<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    u32::deserialize(deserializer).map(Some)
}

/// Receipt-bound product-registration observation for the exact approved MSI.
#[derive(Debug, Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedMsiProductRegistrationEvidence {
    pub schema_version: String,
    pub run_id: String,
    pub sandbox_id: String,
    pub request_sha256: String,
    pub scenario_sha256: String,
    pub installer_sha256: String,
    pub product_code: String,
    pub before_install: MsiMachineProductState,
    pub after_install: MsiMachineProductState,
}

impl ImportedMsiProductRegistrationEvidence {
    pub fn validate_for(
        &self,
        request: &ImportedMsiGuestRequest,
        result: &ImportedMsiScenarioResult,
    ) -> Result<(), String> {
        result
            .validate_for_request(request)
            .map_err(|error| error.to_string())?;
        if !request.scenario.requires_product_registration()
            || self.schema_version != IMPORTED_MSI_PRODUCT_REGISTRATION_SCHEMA_VERSION
            || self.run_id != request.run_id
            || self.sandbox_id != request.sandbox_id
            || self.request_sha256 != request.request_sha256
            || self.scenario_sha256 != request.scenario_sha256
            || self.installer_sha256 != request.installer_sha256
        {
            return Err("imported MSI product registration is not bound to the v6 request".into());
        }
        validate_msi_product_code(&self.product_code)
    }
}

/// Validates the Windows Installer canonical ProductCode spelling: an uppercase
/// braced GUID such as `{01234567-89AB-CDEF-0123-456789ABCDEF}`.
pub fn validate_msi_product_code(value: &str) -> Result<(), String> {
    let valid = value.len() == 38
        && value.as_bytes()[0] == b'{'
        && value.as_bytes()[37] == b'}'
        && value.bytes().enumerate().all(|(index, byte)| match index {
            0 | 37 => true,
            9 | 14 | 19 | 24 => byte == b'-',
            _ => byte.is_ascii_digit() || matches!(byte, b'A'..=b'F'),
        });
    if valid {
        Ok(())
    } else {
        Err("MSI ProductCode must be a canonical uppercase braced GUID".into())
    }
}

/// Reverify product registration against the completion root before using it.
/// V6 successful runs require exactly one event; older profiles reject it.
pub fn verify_msi_product_registration_evidence(
    bytes: &[u8],
    expected_root: &str,
    request: &ImportedMsiGuestRequest,
    result: &ImportedMsiScenarioResult,
) -> Result<Option<ImportedMsiProductRegistrationEvidence>, String> {
    result
        .validate_for_request(request)
        .map_err(|error| error.to_string())?;
    let records = verified_application_records(bytes, expected_root)?;
    let mut found = None;
    for record in records
        .iter()
        .filter(|record| record.kind == IMPORTED_MSI_PRODUCT_REGISTRATION_EVENT)
    {
        if found.is_some() || record.source != "aiw-guest-agent" {
            return Err("duplicate or foreign imported MSI product registration".into());
        }
        let value: ImportedMsiProductRegistrationEvidence =
            serde_json::from_value(record.payload.clone())
                .map_err(|error| format!("invalid imported MSI product registration: {error}"))?;
        value.validate_for(request, result)?;
        found = Some(value);
    }
    if found.is_none() && request.scenario.requires_product_registration() {
        return Err("v6 profile requires product registration evidence".into());
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CompiledMsiScenario, FixedDocumentExercise};
    use aiw_evidence::{EvidenceEvent, EvidenceLog};
    use sha2::Digest;

    fn request(version: &str) -> ImportedMsiGuestRequest {
        let profile = version.replace(
            "windows-sandbox-compiled-msi-scenario",
            "windows-sandbox/notepad-plus-plus-msi",
        );
        ImportedMsiGuestRequest::new(
            "run-one",
            "12345678-1234-abcd-9876-1234567890ab",
            "a".repeat(64),
            "b".repeat(64),
            CompiledMsiScenario {
                schema_version: version.into(),
                profile,
                scenario_id: "first-run".into(),
                application_sha256: "c".repeat(64),
                installer_path: r"C:\AIW\Tools\application.msi".into(),
                install_arguments: vec![
                    "/i".into(),
                    r"C:\AIW\Tools\application.msi".into(),
                    "/qn".into(),
                    "/norestart".into(),
                ],
                install_timeout_seconds: 120,
                launch_path: r"C:\Program Files\Notepad++\notepad++.exe".into(),
                launch_arguments: vec![],
                process_image: "notepad++.exe".into(),
                process_wait_timeout_seconds: 30,
                graceful_close_timeout_seconds: 15,
                expected_exit_code: 0,
                document_exercise: match version.rsplit_once('/').map(|(_, value)| value) {
                    Some("v0alpha1") | Some("v0alpha2") => None,
                    Some("v0alpha3") => Some(FixedDocumentExercise {
                        document_path: crate::DOCUMENT_EXERCISE_PATH.into(),
                        initial_sha256: hex::encode(sha2::Sha256::digest(
                            crate::DOCUMENT_INITIAL_TEXT.as_bytes(),
                        )),
                        expected_sha256: hex::encode(sha2::Sha256::digest(
                            crate::DOCUMENT_EXPECTED_TEXT.as_bytes(),
                        )),
                    }),
                    _ => Some(FixedDocumentExercise {
                        document_path: crate::STANDARD_USER_DOCUMENT_EXERCISE_PATH.into(),
                        initial_sha256: hex::encode(sha2::Sha256::digest(
                            crate::DOCUMENT_INITIAL_TEXT.as_bytes(),
                        )),
                        expected_sha256: hex::encode(sha2::Sha256::digest(
                            crate::DOCUMENT_EXPECTED_TEXT.as_bytes(),
                        )),
                    }),
                },
            },
            "c".repeat(64),
            1024,
            "d".repeat(64),
        )
        .unwrap()
    }

    fn result(request: &ImportedMsiGuestRequest) -> ImportedMsiScenarioResult {
        ImportedMsiScenarioResult::succeeded(request, 0, 42, 0).unwrap()
    }

    fn evidence(events: Vec<EvidenceEvent>) -> (Vec<u8>, String) {
        let mut log = EvidenceLog::new();
        for event in events {
            log.append(event).unwrap();
        }
        let root = log.manifest().unwrap().root_hash;
        let bytes = log
            .records()
            .iter()
            .flat_map(|record| {
                let mut line = serde_json::to_vec(record).unwrap();
                line.push(b'\n');
                line
            })
            .collect();
        (bytes, root)
    }

    fn value(request: &ImportedMsiGuestRequest) -> ImportedMsiProductRegistrationEvidence {
        ImportedMsiProductRegistrationEvidence {
            schema_version: IMPORTED_MSI_PRODUCT_REGISTRATION_SCHEMA_VERSION.into(),
            run_id: request.run_id.clone(),
            sandbox_id: request.sandbox_id.clone(),
            request_sha256: request.request_sha256.clone(),
            scenario_sha256: request.scenario_sha256.clone(),
            installer_sha256: request.installer_sha256.clone(),
            product_code: "{01234567-89AB-CDEF-0123-456789ABCDEF}".into(),
            before_install: MsiMachineProductState::Unavailable { error_code: 2 },
            after_install: MsiMachineProductState::Installed,
        }
    }

    fn event(value: &ImportedMsiProductRegistrationEvidence) -> EvidenceEvent {
        EvidenceEvent {
            observed_utc: "untrusted-time".into(),
            kind: IMPORTED_MSI_PRODUCT_REGISTRATION_EVENT.into(),
            source: "aiw-guest-agent".into(),
            payload: serde_json::to_value(value).unwrap(),
        }
    }

    #[test]
    fn accepts_bound_v6_observations_without_prescribing_a_transition() {
        let request = request("aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha6");
        let result = result(&request);
        let mut value = value(&request);
        value.before_install = MsiMachineProductState::Advertised;
        value.after_install = MsiMachineProductState::Unavailable { error_code: 5 };
        value.validate_for(&request, &result).unwrap();
        let (bytes, root) = evidence(vec![event(&value)]);
        assert_eq!(
            verify_msi_product_registration_evidence(&bytes, &root, &request, &result).unwrap(),
            Some(value.clone())
        );
        let mut wrong_installer = value;
        wrong_installer.installer_sha256 = "d".repeat(64);
        assert!(wrong_installer.validate_for(&request, &result).is_err());
    }

    #[test]
    fn product_code_and_state_shape_are_strict() {
        for value in [
            "01234567-89AB-CDEF-0123-456789ABCDEF",
            "{01234567-89ab-CDEF-0123-456789ABCDEF}",
            "{01234567-89AB-CDEF-0123-456789ABCDEG}",
        ] {
            assert!(validate_msi_product_code(value).is_err());
        }
        validate_msi_product_code("{01234567-89AB-CDEF-0123-456789ABCDEF}").unwrap();
        let state: serde_json::Value =
            serde_json::to_value(MsiMachineProductState::Unavailable { error_code: 7 }).unwrap();
        assert_eq!(
            state,
            serde_json::json!({"status": "unavailable", "errorCode": 7})
        );
        assert!(
            serde_json::from_value::<MsiMachineProductState>(
                serde_json::json!({"status": "installed", "errorCode": 7})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<MsiMachineProductState>(
                serde_json::json!({"status": "installed", "errorCode": null})
            )
            .is_err()
        );
    }

    #[test]
    fn verifier_requires_v6_and_rejects_tamper_duplicate_foreign_and_legacy_event() {
        let current_request = request("aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha6");
        let current_result = result(&current_request);
        let value = value(&current_request);
        let (bytes, root) = evidence(vec![event(&value)]);
        assert!(
            verify_msi_product_registration_evidence(
                &bytes,
                &"f".repeat(64),
                &current_request,
                &current_result
            )
            .is_err()
        );
        let (duplicate, duplicate_root) = evidence(vec![event(&value), event(&value)]);
        assert!(
            verify_msi_product_registration_evidence(
                &duplicate,
                &duplicate_root,
                &current_request,
                &current_result
            )
            .is_err()
        );
        let mut foreign = event(&value);
        foreign.source = "other".into();
        let (foreign, foreign_root) = evidence(vec![foreign]);
        assert!(
            verify_msi_product_registration_evidence(
                &foreign,
                &foreign_root,
                &current_request,
                &current_result
            )
            .is_err()
        );
        let (absent, absent_root) = evidence(vec![EvidenceEvent {
            observed_utc: "untrusted-time".into(),
            kind: "other".into(),
            source: "aiw-guest-agent".into(),
            payload: serde_json::json!({}),
        }]);
        assert!(
            verify_msi_product_registration_evidence(
                &absent,
                &absent_root,
                &current_request,
                &current_result
            )
            .is_err()
        );
        for version in 1..=5 {
            let legacy = request(&format!(
                "aiw.dev/windows-sandbox-compiled-msi-scenario/v0alpha{version}"
            ));
            let legacy_result = result(&legacy);
            assert_eq!(
                verify_msi_product_registration_evidence(
                    &absent,
                    &absent_root,
                    &legacy,
                    &legacy_result
                )
                .unwrap(),
                None
            );
            assert!(
                verify_msi_product_registration_evidence(&bytes, &root, &legacy, &legacy_result)
                    .is_err()
            );
        }
    }
}
