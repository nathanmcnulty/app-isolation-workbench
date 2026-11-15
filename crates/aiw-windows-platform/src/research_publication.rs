//! Closed, default-off mapped-output publication control. No alias repair.
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
#[cfg(feature = "research-mxc-process")]
use std::{fs, io::Read};
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_READ, FILE_SHARE_WRITE, MOVE_FILE_FLAGS, MoveFileExW,
};
use windows::core::PCWSTR;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[cfg(feature = "research-mxc-process")]
pub const CONTROL_OUTPUT: &str = r"C:\AIW\PublicationOutput";
#[cfg(feature = "research-mxc-process")]
pub const CONTROL_RESULT: &str = r"C:\AIW\PublicationOutput\RESULT.DAT";
#[cfg(feature = "research-mxc-process")]
pub const CONTROL_SCHEMA: &str = "aiw.dev/publication-control/v0alpha1";
#[cfg(feature = "research-mxc-process")]
pub const OCCUPIED_BYTES: &[u8] = aiw_provider_wsb::FIXED_PUBLICATION_OCCUPIED_BYTES;
#[cfg(feature = "research-mxc-process")]
pub const PENDING_BYTES: &[u8] = b"AIW publication control: rejected replacement retained\n";
#[cfg(feature = "research-mxc-process")]
pub const PARTIAL_BYTES: &[u8] = b"AIW publication control: interrupted before publication\n";
#[cfg(feature = "research-mxc-process")]
pub const LEGACY_BYTES: &[u8] = b"AIW publication control: legacy long name\n";
#[cfg(feature = "research-mxc-process")]
const CAPABILITY_OUTPUT: &str = r"C:\AIW\MxcProbeOutput";
#[cfg(feature = "research-mxc-process")]
pub(crate) const CAPABILITY_RESULT: &str = r"C:\AIW\MxcProbeOutput\RESULT.DAT";
#[cfg(feature = "research-mxc-process")]
pub(crate) const CREATION_RESULT: &str = r"C:\AIW\MxcCreationOutput\RESULT.DAT";

#[derive(Clone, Copy)]
pub(crate) enum MappedPublication {
    #[cfg(feature = "research-mxc-process")]
    Capability,
    #[cfg(feature = "research-mxc-process")]
    Control,
    #[cfg(feature = "research-mxc-process")]
    Creation,
    #[cfg(feature = "research-environment")]
    Environment,
}
impl MappedPublication {
    fn output(self) -> &'static str {
        match self {
            #[cfg(feature = "research-mxc-process")]
            Self::Capability => CAPABILITY_OUTPUT,
            #[cfg(feature = "research-mxc-process")]
            Self::Control => CONTROL_OUTPUT,
            #[cfg(feature = "research-mxc-process")]
            Self::Creation => r"C:\AIW\MxcCreationOutput",
            #[cfg(feature = "research-environment")]
            Self::Environment => r"C:\AIW\EnvironmentOutput",
        }
    }
}

fn hold_directory(path: &str) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err("mapped publication ancestry is not an ordinary directory".into());
    }
    Ok(file)
}

fn hold_ancestry(role: MappedPublication) -> Result<Vec<File>> {
    [r"C:\", r"C:\AIW", role.output()]
        .into_iter()
        .map(hold_directory)
        .collect()
}

fn write_pending(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    // Close before rename. Failed publication preserves this exact pending file.
    drop(file);
    Ok(())
}

fn move_no_replace(pending: &Path, destination: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let pending: Vec<u16> = pending.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // No replacement, copying, delayed move, alias clearing or volume changes.
    unsafe {
        MoveFileExW(
            PCWSTR(pending.as_ptr()),
            PCWSTR(destination.as_ptr()),
            MOVE_FILE_FLAGS(0),
        )
    }?;
    Ok(())
}

pub(crate) fn publish_mapped_json(
    role: MappedPublication,
    value: &serde_json::Value,
) -> Result<()> {
    let _ancestry = hold_ancestry(role)?;
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > 1024 * 1024 {
        return Err("mapped research result exceeds one MiB".into());
    }
    let root = Path::new(role.output());
    write_pending(&root.join("RESULT.TMP"), &bytes)?;
    move_no_replace(&root.join("RESULT.TMP"), &root.join("RESULT.DAT"))
}

#[cfg(feature = "research-mxc-process")]
fn exact_arguments(arguments: &[std::ffi::OsString]) -> bool {
    arguments == ["--output", CONTROL_RESULT]
}

#[cfg(feature = "research-mxc-process")]
fn held_bytes(path: &Path, bound: usize) -> Result<(File, Vec<u8>)> {
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || metadata.len() > bound as u64
    {
        return Err("publication control file type or size rejected".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(bound as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > bound || bytes.len() as u64 != metadata.len() {
        return Err("publication control read changed size".into());
    }
    Ok((file, bytes))
}

#[cfg(feature = "research-mxc-process")]
fn namespace_absent(path: &Path) -> std::io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error),
    }
}

#[cfg(feature = "research-mxc-process")]
pub fn run_control() -> Result<()> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let token = aiw_token::collect_current_process_token()?;
    if !exact_arguments(&arguments)
        || !crate::control_appcontainer::research_sevenzip::fixed_role_image(
            &std::env::current_exe()?,
            r"C:\AIW\Tools\publication_control_guest.exe",
        )
        || !token.is_elevated
        || token.is_app_container
        || token.user_sid != crate::control_appcontainer::fixed_account_sid("WDAGUtilityAccount")?
    {
        return Err("fixed elevated disposable publication control role required".into());
    }
    let windows = crate::observe_windows_version()?;
    windows.validate()?;
    if (
        windows.major,
        windows.minor,
        windows.build,
        windows.revision,
        windows.observer_architecture.as_str(),
    ) != (10, 0, 26100, 9711, "x86_64")
    {
        return Err("publication control guest Windows differs".into());
    }
    let _ancestry = hold_ancestry(MappedPublication::Control)?;
    let root = Path::new(CONTROL_OUTPUT);
    let mut names = fs::read_dir(root)?
        .take(3)
        .map(|entry| entry.map(|e| e.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    if names.len() != 1 || names.pop().as_deref() != Some(std::ffi::OsStr::new("OCCUPY.DAT")) {
        return Err("publication control requires only the preseeded occupied file".into());
    }
    let (occupied, original) = held_bytes(&root.join("OCCUPY.DAT"), OCCUPIED_BYTES.len())?;
    if original != OCCUPIED_BYTES {
        return Err("occupied control bytes differ".into());
    }
    // Release the destination before testing rename. A sharing denial must not
    // masquerade as proof of the no-replace flag's existing-name behavior.
    drop(occupied);
    write_pending(&root.join("OCCUPY.TMP"), PENDING_BYTES)?;
    let occupied_move = move_no_replace(&root.join("OCCUPY.TMP"), &root.join("OCCUPY.DAT"));
    let occupied_move_rejected = occupied_move.is_err();
    let occupied_move_win32_code = occupied_move
        .as_ref()
        .err()
        .and_then(|error| error.downcast_ref::<windows::core::Error>())
        .map(|error| error.code().0 as u32)
        .filter(|code| code & 0xffff0000 == 0x80070000)
        .map(|code| code & 0xffff);
    let (_occupied_after, after) = held_bytes(&root.join("OCCUPY.DAT"), OCCUPIED_BYTES.len())?;
    let (_pending, pending) = held_bytes(&root.join("OCCUPY.TMP"), PENDING_BYTES.len())?;
    write_pending(&root.join("PARTIAL.TMP"), PARTIAL_BYTES)?;
    let partial_final_absent = namespace_absent(&root.join("PARTIAL.DAT"))?;
    write_pending(&root.join("legacy.json.pending"), LEGACY_BYTES)?;
    move_no_replace(&root.join("legacy.json.pending"), &root.join("legacy.json"))?;
    let (_legacy, legacy) = held_bytes(&root.join("legacy.json"), LEGACY_BYTES.len())?;
    let report = serde_json::json!({"schemaVersion":CONTROL_SCHEMA,"windows":windows,
        "observerToken":token,"legacyPublished":legacy == LEGACY_BYTES,
        "occupiedMoveRejected":occupied_move_rejected,"occupiedMoveWin32Code":occupied_move_win32_code,"occupiedUnchanged":after == OCCUPIED_BYTES,
        "pendingRetained":pending == PENDING_BYTES,"partialFinalAbsent":partial_final_absent,
        "requestedApplicationExecution":false,"enforcement":"unmeasured"});
    publish_mapped_json(MappedPublication::Control, &report)
}

#[cfg(all(test, feature = "research-mxc-process"))]
mod tests {
    use super::*;
    #[test]
    fn exact_control_arguments_reject_aliases_and_additions() {
        let args = |v: &[&str]| v.iter().map(std::ffi::OsString::from).collect::<Vec<_>>();
        assert!(exact_arguments(&args(&["--output", CONTROL_RESULT])));
        for values in [
            vec!["--output"],
            vec!["--output", r"C:\AIW\PublicationOutput\result.dat"],
            vec!["--output", CONTROL_RESULT, "--retry"],
            vec!["--setup"],
        ] {
            assert!(!exact_arguments(&args(&values)));
        }
    }
    #[test]
    fn interrupted_and_occupied_publications_preserve_originals() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("aiw-publication-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let pending = root.join("RESULT.TMP");
        let destination = root.join("RESULT.DAT");
        write_pending(&pending, PARTIAL_BYTES).unwrap();
        assert!(!destination.exists());
        assert!(write_pending(&pending, PENDING_BYTES).is_err());
        write_pending(&destination, OCCUPIED_BYTES).unwrap();
        assert!(move_no_replace(&pending, &destination).is_err());
        assert_eq!(fs::read(&pending).unwrap(), PARTIAL_BYTES);
        assert_eq!(fs::read(&destination).unwrap(), OCCUPIED_BYTES);
        fs::remove_file(pending).unwrap();
        fs::remove_file(destination).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
