//! Tree-only administrator-owned local evidence. Never an alternate intake path.
use super::{HeldApplicationFile, Result, Value, fs, hold_directory_chain, set_acl};
use std::path::Path;

pub(super) const ROOT: &str = r"C:\AIW\SevenZip\OwnerStages";
const OWNER_DACL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
const RECORD_BOUND: usize = 128 * 1024;

/// The complete owner filename authority. Parse before constructing any path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stage {
    Start,
    Context,
    Launcher,
    WorkflowExit,
    LauncherCleanup,
    Final,
    DriverError,
}

impl Stage {
    pub(super) fn parse(name: &str) -> Result<Self> {
        match name {
            "00-start" => Ok(Self::Start),
            "01-context" => Ok(Self::Context),
            "02-launcher" => Ok(Self::Launcher),
            "05-workflow-exit" => Ok(Self::WorkflowExit),
            "05-launcher-cleanup" => Ok(Self::LauncherCleanup),
            "06-final" => Ok(Self::Final),
            "99-driver-error" => Ok(Self::DriverError),
            _ => Err("unknown fixed tree owner journal stage".into()),
        }
    }
    fn stem(self) -> &'static str {
        match self {
            Self::Start => "00-start",
            Self::Context => "01-context",
            Self::Launcher => "02-launcher",
            Self::WorkflowExit => "05-workflow-exit",
            Self::LauncherCleanup => "05-launcher-cleanup",
            Self::Final => "06-final",
            Self::DriverError => "99-driver-error",
        }
    }
}

/// Keep this in setup's scope until terminal snapshot/publication returns.
pub(super) struct Journal {
    _ancestry: Vec<fs::File>,
}

pub(super) fn create() -> Result<Journal> {
    // Parent ROOT is freshly created and already held. No existing directory
    // can be adopted, repaired or recursively cleaned up here.
    fs::create_dir(ROOT)?;
    let ancestry = hold_directory_chain(Path::new(ROOT))?;
    set_acl(Path::new(ROOT), OWNER_DACL, false)?;
    Ok(Journal {
        _ancestry: ancestry,
    })
}

fn publish_at(root: &Path, stage: Stage, value: &Value) -> Result<()> {
    if serde_json::to_vec_pretty(value)?.len() > RECORD_BOUND {
        return Err("local owner journal record exceeds serialized bound".into());
    }
    // Existing first-party publication flushes CreateNew .pending bytes, closes
    // them, then performs a same-volume no-replace move. Failure preserves both
    // previous records and any pending bytes; no mapped copy is attempted.
    super::record(root, stage.stem(), value)
}

pub(super) fn publish(stage: Stage, value: &Value) -> Result<()> {
    publish_at(Path::new(ROOT), stage, value)
}

pub(super) fn verify_start(expected: &Value) -> Result<()> {
    let path = Path::new(ROOT).join(format!("{}.json", Stage::Start.stem()));
    let held = HeldApplicationFile::open_bounded(&path, RECORD_BOUND as u64)?;
    let bytes = held.read_bounded(RECORD_BOUND as u64)?;
    if bytes != serde_json::to_vec_pretty(expected)? {
        return Err("local owner start record bytes differ".into());
    }
    held.revalidate()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stage_authority_rejects_aliases_paths_and_other_records() {
        let names = [
            "00-start",
            "01-context",
            "02-launcher",
            "05-workflow-exit",
            "05-launcher-cleanup",
            "06-final",
            "99-driver-error",
        ];
        for name in names {
            assert_eq!(Stage::parse(name).unwrap().stem(), name);
        }
        for name in [
            "",
            "00-START",
            "00-start.json",
            "../00-start",
            r"..\00-start",
            "00-start:stream",
            "03-install-start",
            "tree-baseline",
            "00-start\0",
        ] {
            assert!(Stage::parse(name).is_err(), "{name}");
        }
    }

    #[test]
    fn duplicate_failed_and_missing_records_preserve_prior_durable_prefix() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("aiw-owner-journal-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let start = json!({"schemaVersion":"test","actualPrefix":true});
        publish_at(&root, Stage::Start, &start).unwrap();
        let original = fs::read(root.join("00-start.json")).unwrap();
        assert!(publish_at(&root, Stage::Start, &json!({"replacement":true})).is_err());
        assert_eq!(fs::read(root.join("00-start.json")).unwrap(), original);
        assert!(root.join("00-start.pending").is_file());
        assert_eq!(
            fs::read(root.join("01-context.json")).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        fs::write(root.join("01-context.pending"), b"interrupted bytes").unwrap();
        assert!(publish_at(&root, Stage::Context, &json!({"late":true})).is_err());
        assert_eq!(
            fs::read(root.join("01-context.pending")).unwrap(),
            b"interrupted bytes"
        );
        assert!(!root.join("01-context.json").exists());
        assert!(publish_at(&root, Stage::Final, &json!("x".repeat(RECORD_BOUND))).is_err());
        assert!(!root.join("06-final.pending").exists());
        assert_eq!(fs::read(root.join("00-start.json")).unwrap(), original);
        // Explicit known test files only; production has no cleanup operation.
        for name in ["00-start.json", "00-start.pending", "01-context.pending"] {
            fs::remove_file(root.join(name)).unwrap();
        }
        fs::remove_dir(root).unwrap();
    }
}
