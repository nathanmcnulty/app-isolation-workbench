//! Read-only installer observations shared by assessment and package analysis.
use std::path::Path;

use aiw_probe::{ApplicationInspection, ApplicationInspectionKind, inspect_application_source};
use aiw_windows_platform::HeldApplicationFile;
use anyhow::{Result, bail};

/// The caller keeps custody through later import. This snapshot grants no
/// execution authority and makes no compatibility or publisher-identity claim.
pub(crate) fn inspect_held_installer(
    held: &HeldApplicationFile,
    kind: ApplicationInspectionKind,
) -> Result<ApplicationInspection> {
    if !matches!(
        kind,
        ApplicationInspectionKind::Msi | ApplicationInspectionKind::Exe
    ) {
        bail!("held installer inspection requires an MSI or EXE");
    }
    held.revalidate()?;
    let observed = held.observation();
    // Derive the path from the held authority rather than a second caller path.
    let mut inspection = inspect_application_source(Path::new(&observed.canonical_path), kind)?;
    if inspection.sha256.as_deref() != Some(&observed.sha256)
        || inspection.size_bytes != Some(observed.size_bytes)
    {
        bail!("installer drifted during inspection");
    }
    inspection.signature_status = held.embedded_signature_status()?;
    inspection
        .canonical_path
        .clone_from(&observed.canonical_path);
    inspection.file_authority = Some(aiw_probe::ApplicationFileAuthority {
        schema_version: if observed.download_metadata.is_empty() {
            aiw_probe::APPLICATION_FILE_AUTHORITY_SCHEMA
        } else {
            aiw_probe::APPLICATION_DOWNLOAD_AUTHORITY_SCHEMA
        }
        .into(),
        identity: observed.identity.clone(),
        size_bytes: observed.size_bytes,
        sha256: observed.sha256.clone(),
        link_count: observed.link_count,
        only_unnamed_data_stream: observed.only_unnamed_data_stream,
        download_metadata: observed.download_metadata.clone(),
    });
    inspection.limitations = vec![
        "Held file identity, streams and embedded signature were observed. Signature status is not publisher identity, execution approval or application compatibility.".into(),
        "Allow-listed download metadata is bound by name, size and hash; its contents are untrusted and do not establish source provenance.".into(),
        "Inspection grants no import or execution authority. Protected intake and execution independently revalidate the selected bytes.".into(),
    ];
    held.revalidate()?;
    Ok(inspection)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inert_file_inspection_preserves_custody_and_grants_no_trust() {
        for (extension, kind) in [
            ("msi", ApplicationInspectionKind::Msi),
            ("exe", ApplicationInspectionKind::Exe),
        ] {
            let root = std::env::temp_dir().join(format!(
                "aiw-held-inspection-{}-{}",
                std::process::id(),
                crate::nonce()
            ));
            std::fs::create_dir(&root).unwrap();
            let source = root.join(format!("inert.{extension}"));
            std::fs::write(&source, b"inert unsigned installer fixture").unwrap();
            let held = HeldApplicationFile::open_with_download_metadata(&source).unwrap();
            let inspection = inspect_held_installer(&held, kind).unwrap();
            assert_eq!(
                inspection.signature_status,
                aiw_probe::ReadinessState::Unknown
            );
            let authority = inspection.file_authority.unwrap();
            assert_eq!(
                authority.schema_version,
                aiw_probe::APPLICATION_FILE_AUTHORITY_SCHEMA
            );
            assert_eq!(authority.identity, held.observation().identity);
            assert_eq!(inspection.canonical_path, held.observation().canonical_path);
            assert_eq!(authority.link_count, 1);
            assert!(authority.only_unnamed_data_stream);
            assert_eq!(authority.sha256, inspection.sha256.unwrap());
            assert_eq!(authority.size_bytes, inspection.size_bytes.unwrap());
            assert!(authority.download_metadata.is_empty());
            assert!(
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&source)
                    .is_err()
            );
            assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
            drop(held);
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn download_stream_authority_is_retained_without_trusting_metadata() {
        let root = std::env::temp_dir().join(format!(
            "aiw-held-metadata-{}-{}",
            std::process::id(),
            crate::nonce()
        ));
        std::fs::create_dir(&root).unwrap();
        let source = root.join("inert.msi");
        std::fs::write(&source, b"inert unsigned installer fixture").unwrap();
        let metadata = b"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://untrusted.example/\r\n";
        std::fs::write(
            format!("{}:Zone.Identifier:$DATA", source.display()),
            metadata,
        )
        .unwrap();
        let held = HeldApplicationFile::open_with_download_metadata(&source).unwrap();
        let inspection = inspect_held_installer(&held, ApplicationInspectionKind::Msi).unwrap();
        let serialized = serde_json::to_string(&inspection).unwrap();
        assert!(!serialized.contains("untrusted.example"));
        assert!(!serialized.contains("HostUrl"));
        let authority = inspection.file_authority.unwrap();
        assert_eq!(
            authority.schema_version,
            aiw_probe::APPLICATION_DOWNLOAD_AUTHORITY_SCHEMA
        );
        assert!(!authority.only_unnamed_data_stream);
        assert_eq!(
            authority.download_metadata,
            held.observation().download_metadata
        );
        assert_eq!(
            authority.download_metadata[0].sha256,
            crate::lowercase_sha256(metadata)
        );
        assert_eq!(
            inspection.signature_status,
            aiw_probe::ReadinessState::Unknown
        );
        assert!(inspect_held_installer(&held, ApplicationInspectionKind::Exe).is_err());
        assert!(
            inspect_held_installer(&held, ApplicationInspectionKind::PortableDirectory).is_err()
        );
        held.revalidate().unwrap();
        drop(held);
        std::fs::remove_dir_all(root).unwrap();
    }
}
