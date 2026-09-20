#![forbid(unsafe_code)]

mod bundle;

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use bundle::{
    ASSESSMENT_BUNDLE_MANIFEST_SCHEMA_VERSION, ASSESSMENT_BUNDLE_SPEC_SCHEMA_VERSION,
    ASSESSMENT_BUNDLE_VERIFICATION_SCHEMA_VERSION, ArtifactClass, ArtifactRole,
    AssessmentBundleError, AssessmentBundleManifest, AssessmentBundleSpec, BundleArtifact,
    BundleArtifactSpec, BundlePurpose, BundleVerification, ContentDeclaration, DataSensitivity,
    build_assessment_bundle, verify_assessment_bundle,
};

pub const EVIDENCE_RECORD_SCHEMA_VERSION: &str = "aiw.dev/evidence-record/v0alpha1";
pub const EVIDENCE_MANIFEST_SCHEMA_VERSION: &str = "aiw.dev/evidence-manifest/v0alpha1";
const EMPTY_LOG_DOMAIN: &[u8] = b"aiw-empty-evidence-v1";

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceEvent {
    pub observed_utc: String,
    pub kind: String,
    pub source: String,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceRecord {
    pub schema_version: String,
    pub sequence: u64,
    pub observed_utc: String,
    pub kind: String,
    pub source: String,
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<String>,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceManifest {
    pub schema_version: String,
    pub canonicalization: String,
    pub hash_algorithm: String,
    pub record_count: u64,
    pub root_hash: String,
    pub kinds: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Default)]
pub struct EvidenceLog {
    records: Vec<EvidenceRecord>,
}

impl EvidenceLog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_verified(records: Vec<EvidenceRecord>) -> Result<Self, EvidenceError> {
        verify_records(&records)?;
        Ok(Self { records })
    }

    pub fn append(&mut self, event: EvidenceEvent) -> Result<&EvidenceRecord, EvidenceError> {
        validate_event(&event)?;
        let sequence = self.records.len() as u64;
        let previous_hash = self.records.last().map(|record| record.hash.clone());
        let hash = calculate_record_hash(
            sequence,
            &event.observed_utc,
            &event.kind,
            &event.source,
            &event.payload,
            previous_hash.as_deref(),
        )?;
        self.records.push(EvidenceRecord {
            schema_version: EVIDENCE_RECORD_SCHEMA_VERSION.to_owned(),
            sequence,
            observed_utc: event.observed_utc,
            kind: event.kind,
            source: event.source,
            payload: event.payload,
            previous_hash,
            hash,
        });
        Ok(self.records.last().expect("record was just appended"))
    }

    #[must_use]
    pub fn records(&self) -> &[EvidenceRecord] {
        &self.records
    }

    pub fn manifest(&self) -> Result<EvidenceManifest, EvidenceError> {
        verify_records(&self.records)
    }
}

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("event field '{0}' must not be empty")]
    EmptyEventField(&'static str),
    #[error("record {index} uses unsupported schema version '{actual}'")]
    UnsupportedSchemaVersion { index: usize, actual: String },
    #[error("record {index} has sequence {actual}; expected {expected}")]
    SequenceMismatch {
        index: usize,
        expected: u64,
        actual: u64,
    },
    #[error("record {index} previous hash does not match its predecessor")]
    PreviousHashMismatch { index: usize },
    #[error("record {index} hash is invalid; expected {expected}, found {actual}")]
    HashMismatch {
        index: usize,
        expected: String,
        actual: String,
    },
    #[error(transparent)]
    CanonicalJson(#[from] CanonicalJsonError),
}

#[derive(Debug, Error)]
pub enum CanonicalJsonError {
    #[error("floating-point JSON numbers are forbidden in signed evidence")]
    FloatingPointNumber,
    #[error("failed to encode a JSON string: {0}")]
    StringEncoding(#[from] serde_json::Error),
}

pub fn verify_records(records: &[EvidenceRecord]) -> Result<EvidenceManifest, EvidenceError> {
    let mut previous_hash: Option<&str> = None;
    let mut kinds = BTreeMap::new();

    for (index, record) in records.iter().enumerate() {
        if record.schema_version != EVIDENCE_RECORD_SCHEMA_VERSION {
            return Err(EvidenceError::UnsupportedSchemaVersion {
                index,
                actual: record.schema_version.clone(),
            });
        }
        validate_event_metadata(&record.observed_utc, &record.kind, &record.source)?;
        let expected_sequence = index as u64;
        if record.sequence != expected_sequence {
            return Err(EvidenceError::SequenceMismatch {
                index,
                expected: expected_sequence,
                actual: record.sequence,
            });
        }
        if record.previous_hash.as_deref() != previous_hash {
            return Err(EvidenceError::PreviousHashMismatch { index });
        }
        let expected_hash = calculate_record_hash(
            record.sequence,
            &record.observed_utc,
            &record.kind,
            &record.source,
            &record.payload,
            record.previous_hash.as_deref(),
        )?;
        if record.hash != expected_hash {
            return Err(EvidenceError::HashMismatch {
                index,
                expected: expected_hash,
                actual: record.hash.clone(),
            });
        }
        *kinds.entry(record.kind.clone()).or_insert(0) += 1;
        previous_hash = Some(record.hash.as_str());
    }

    let root_hash = records.last().map_or_else(
        || hash_bytes(EMPTY_LOG_DOMAIN),
        |record| record.hash.clone(),
    );
    Ok(EvidenceManifest {
        schema_version: EVIDENCE_MANIFEST_SCHEMA_VERSION.to_owned(),
        canonicalization: "aiw-canonical-json-integer-v1".to_owned(),
        hash_algorithm: "sha256".to_owned(),
        record_count: records.len() as u64,
        root_hash,
        kinds,
    })
}

pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, CanonicalJsonError> {
    let mut output = Vec::new();
    write_canonical(value, &mut output)?;
    Ok(output)
}

fn calculate_record_hash(
    sequence: u64,
    observed_utc: &str,
    kind: &str,
    source: &str,
    payload: &Value,
    previous_hash: Option<&str>,
) -> Result<String, CanonicalJsonError> {
    let material = serde_json::json!({
        "schemaVersion": EVIDENCE_RECORD_SCHEMA_VERSION,
        "sequence": sequence,
        "observedUtc": observed_utc,
        "kind": kind,
        "source": source,
        "payload": payload,
        "previousHash": previous_hash,
    });
    Ok(hash_bytes(&canonical_json_bytes(&material)?))
}

fn validate_event(event: &EvidenceEvent) -> Result<(), EvidenceError> {
    validate_event_metadata(&event.observed_utc, &event.kind, &event.source)?;
    canonical_json_bytes(&event.payload)?;
    Ok(())
}

fn validate_event_metadata(
    observed_utc: &str,
    kind: &str,
    source: &str,
) -> Result<(), EvidenceError> {
    for (name, value) in [
        ("observedUtc", observed_utc),
        ("kind", kind),
        ("source", source),
    ] {
        if value.trim().is_empty() {
            return Err(EvidenceError::EmptyEventField(name));
        }
    }
    Ok(())
}

fn write_canonical(value: &Value, output: &mut Vec<u8>) -> Result<(), CanonicalJsonError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => {
            if !number.is_i64() && !number.is_u64() {
                return Err(CanonicalJsonError::FloatingPointNumber);
            }
            output.extend_from_slice(number.to_string().as_bytes());
        }
        Value::String(string) => serde_json::to_writer(output, string)?,
        Value::Array(values) => {
            output.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_canonical(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(map) => {
            output.push(b'{');
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort_unstable();
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)?;
                output.push(b':');
                write_canonical(&map[*key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn hash_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: &str, payload: Value) -> EvidenceEvent {
        EvidenceEvent {
            observed_utc: "2026-08-19T00:00:00Z".to_owned(),
            kind: kind.to_owned(),
            source: "test".to_owned(),
            payload,
        }
    }

    #[test]
    fn object_key_order_does_not_change_canonical_bytes() {
        let left = serde_json::json!({"b": 2, "a": 1});
        let right = serde_json::json!({"a": 1, "b": 2});
        assert_eq!(
            canonical_json_bytes(&left).unwrap(),
            canonical_json_bytes(&right).unwrap()
        );
    }

    #[test]
    fn floating_point_payloads_are_rejected() {
        let mut log = EvidenceLog::new();
        let error = log.append(event("metric", serde_json::json!({"value": 1.5})));
        assert!(matches!(
            error,
            Err(EvidenceError::CanonicalJson(
                CanonicalJsonError::FloatingPointNumber
            ))
        ));
    }

    #[test]
    fn append_and_verify_a_chain() {
        let mut log = EvidenceLog::new();
        log.append(event("environment", serde_json::json!({"build": 26100})))
            .unwrap();
        log.append(event("token", serde_json::json!({"appContainer": true})))
            .unwrap();

        let manifest = log.manifest().unwrap();
        assert_eq!(manifest.record_count, 2);
        assert_eq!(manifest.kinds["token"], 1);
        assert_eq!(manifest.root_hash, log.records()[1].hash);
    }

    #[test]
    fn self_consistent_hashes_do_not_authorize_empty_event_metadata() {
        for field in ["observedUtc", "kind", "source"] {
            for invalid in ["", " \t\r\n"] {
                let mut log = EvidenceLog::new();
                log.append(event("token", serde_json::json!({"appContainer": true})))
                    .unwrap();
                let mut records = log.records().to_vec();
                let record = &mut records[0];
                match field {
                    "observedUtc" => record.observed_utc = invalid.to_owned(),
                    "kind" => record.kind = invalid.to_owned(),
                    "source" => record.source = invalid.to_owned(),
                    _ => unreachable!(),
                }
                record.hash = calculate_record_hash(
                    record.sequence,
                    &record.observed_utc,
                    &record.kind,
                    &record.source,
                    &record.payload,
                    record.previous_hash.as_deref(),
                )
                .unwrap();
                assert!(matches!(
                    verify_records(&records),
                    Err(EvidenceError::EmptyEventField(actual)) if actual == field
                ));
                assert!(matches!(
                    EvidenceLog::from_verified(records),
                    Err(EvidenceError::EmptyEventField(actual)) if actual == field
                ));
            }
        }
    }

    #[test]
    fn tampering_is_detected() {
        let mut log = EvidenceLog::new();
        log.append(event("environment", serde_json::json!({"build": 26100})))
            .unwrap();
        let mut records = log.records().to_vec();
        records[0].payload = serde_json::json!({"build": 99999});
        assert!(matches!(
            verify_records(&records),
            Err(EvidenceError::HashMismatch { .. })
        ));
    }
}
