//! Private, bounded output bytes for investigating archive differences.
//! These bytes are evidence, never commands or an inferred explanation.
use crate::sevenzip::{SevenZipFileDigest, SevenZipInventory, sevenzip_fixture_inventory};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_SEVENZIP_ARCHIVE_BYTES: usize = 16 * 1024;

/// Native Windows FILETIME values (100 ns ticks since 1601), without conversion
/// or claims about which metadata the archiver chose to encode.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipFileMetadata {
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub attributes: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SevenZipArtifacts {
    pub archive_hex: String,
    pub extracted_hex: BTreeMap<String, String>,
    pub extracted_capture_complete: bool,
    pub input_before_metadata: BTreeMap<String, SevenZipFileMetadata>,
    pub input_after_metadata: BTreeMap<String, SevenZipFileMetadata>,
}

impl SevenZipArtifacts {
    pub fn validate(
        &self,
        archive: &SevenZipFileDigest,
        extracted: &SevenZipInventory,
    ) -> Result<(), String> {
        let bytes = decode_bounded(&self.archive_hex, MAX_SEVENZIP_ARCHIVE_BYTES)?;
        if SevenZipFileDigest::for_bytes(&bytes) != *archive {
            return Err("retained archive bytes differ from observed identity".into());
        }
        let expected = sevenzip_fixture_inventory();
        if self.extracted_hex.len() > expected.len()
            || self.input_before_metadata.keys().ne(expected.keys())
            || self.input_after_metadata.keys().ne(expected.keys())
        {
            return Err("retained output or metadata inventory differs from fixed fixture".into());
        }
        for (name, raw) in &self.extracted_hex {
            if !expected.contains_key(name) {
                return Err("retained payload outside fixed extracted fixture".into());
            }
            let digest = extracted
                .get(name)
                .ok_or("retained bytes without measured output")?;
            let bytes = decode_bounded(raw, 4096)?;
            if SevenZipFileDigest::for_bytes(&bytes) != *digest {
                return Err("retained extracted bytes differ from observed identity".into());
            }
        }
        let complete =
            extracted.keys().eq(expected.keys()) && self.extracted_hex.keys().eq(expected.keys());
        if self.extracted_capture_complete != complete {
            return Err("retained output completeness differs from actual capture".into());
        }
        Ok(())
    }
}

fn decode_bounded(value: &str, max: usize) -> Result<Vec<u8>, String> {
    if value.len() > max * 2
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("retained bytes are not bounded canonical lowercase hex".into());
    }
    hex::decode(value).map_err(|_| "retained bytes cannot be decoded".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sevenzip::sevenzip_fixture_bytes;

    fn artifacts() -> (SevenZipArtifacts, SevenZipFileDigest) {
        let archive = b"7z\xbc\xaf\x27\x1csynthetic bytes, not native evidence";
        let metadata = sevenzip_fixture_inventory()
            .keys()
            .map(|name| {
                (
                    name.clone(),
                    SevenZipFileMetadata {
                        creation_time: 1,
                        last_access_time: 2,
                        last_write_time: 3,
                        attributes: 32,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        (
            SevenZipArtifacts {
                archive_hex: hex::encode(archive),
                extracted_hex: sevenzip_fixture_bytes()
                    .into_iter()
                    .map(|(name, bytes)| (name, hex::encode(bytes)))
                    .collect(),
                extracted_capture_complete: true,
                input_before_metadata: metadata.clone(),
                input_after_metadata: metadata,
            },
            SevenZipFileDigest::for_bytes(archive),
        )
    }

    #[test]
    fn retained_bytes_bind_archive_content_and_complete_metadata_without_explaining_difference() {
        let (value, archive) = artifacts();
        let inventory = sevenzip_fixture_inventory();
        value.validate(&archive, &inventory).unwrap();
        for case in 0..7 {
            let mut changed = value.clone();
            match case {
                0 => changed.archive_hex.push_str("00"),
                1 => changed.archive_hex = "00".repeat(MAX_SEVENZIP_ARCHIVE_BYTES + 1),
                2 => changed.archive_hex = changed.archive_hex.to_uppercase(),
                3 => {
                    changed.extracted_hex.remove("hello.txt");
                }
                4 => {
                    changed
                        .extracted_hex
                        .insert("hello.txt".into(), "00".into());
                }
                5 => {
                    changed.input_before_metadata.remove("empty.txt");
                }
                _ => {
                    changed.input_after_metadata.insert(
                        "unexpected".into(),
                        changed.input_after_metadata["empty.txt"].clone(),
                    );
                }
            }
            assert!(
                changed.validate(&archive, &inventory).is_err(),
                "case {case}"
            );
        }
        assert!(decode_bounded("0", 1).is_err());
        assert!(decode_bounded("gg", 1).is_err());
    }

    #[test]
    fn capture_bounds_partial_outputs_and_filetimes_are_exact_without_format_or_function_claims() {
        let (mut value, _) = artifacts();
        let mut inventory = sevenzip_fixture_inventory();
        let archive = vec![0x5a; MAX_SEVENZIP_ARCHIVE_BYTES];
        value.archive_hex = hex::encode(&archive);
        value
            .input_before_metadata
            .get_mut("empty.txt")
            .unwrap()
            .creation_time = u64::MAX;
        inventory.remove("hello.txt");
        value.extracted_hex.remove("hello.txt");
        value.extracted_capture_complete = false;
        value
            .validate(&SevenZipFileDigest::for_bytes(&archive), &inventory)
            .unwrap();
        let raw = serde_json::to_vec(&value).unwrap();
        let decoded: SevenZipArtifacts = serde_json::from_slice(&raw).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(
            decoded.input_before_metadata["empty.txt"].creation_time,
            u64::MAX
        );
        value.extracted_capture_complete = true;
        assert!(
            value
                .validate(&SevenZipFileDigest::for_bytes(&archive), &inventory)
                .is_err()
        );
        value.archive_hex.push_str("00");
        assert!(
            value
                .validate(&SevenZipFileDigest::for_bytes(&archive), &inventory)
                .is_err()
        );
    }
}
