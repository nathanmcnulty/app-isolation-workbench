//! Closed read-only mapped input transport, distinct from local execution custody.
//! Only default-stream bytes are transported. No source ACL/ADS or 128-bit file-ID
//! claim is made. All local executable copies still require HeldApplicationFile.
use super::*;
use std::io::{Seek, SeekFrom, Write};
use windows::Win32::Storage::FileSystem::{FILE_TYPE_DISK, GetFileType};

pub(crate) mod sevenzip;

const MAX_BYTES: u64 = 128 * 1024 * 1024;
// Read-only directory access, permitting other directory writers but never
// delete/rename sharing. Role files continue to use SHARE_READ exclusively.
const DIRECTORY_SHARING: u32 = FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0;

#[derive(Clone, Copy)]
enum Role {
    Agent,
    Fixture,
    Launcher,
}
impl Role {
    fn leaf(self) -> &'static str {
        match self {
            Self::Agent => "aiw-guest-agent.exe",
            Self::Fixture => "aiw-control-fixture.exe",
            Self::Launcher => "aiw-control-appcontainer.exe",
        }
    }
}

pub(crate) struct FixedPairedInputs {
    ancestors: Vec<File>,
    ancestry: Vec<BY_HANDLE_FILE_INFORMATION>,
    roles: [HeldRole; 3],
    size: u64,
    sha256: String,
}
struct HeldRole {
    role: Role,
    file: File,
    info: BY_HANDLE_FILE_INFORMATION,
}
impl FixedPairedInputs {
    pub(crate) fn open(size: u64, sha256: &str) -> Result<Self, String> {
        let ancestors = hold_fixed_ancestry()
            .map_err(|e| format!("hold fixed paired mapped Tools ancestry: {e}"))?;
        Self::from_ancestors(ancestors, size, sha256)
    }

    fn from_ancestors(ancestors: Vec<File>, size: u64, sha256: &str) -> Result<Self, String> {
        if size == 0 || size > MAX_BYTES || !aiw_probe::paired_controls::control_hash(sha256) {
            return Err("invalid fixed paired mapped byte commitment".into());
        }
        if ancestors.len() != 3 {
            return Err("fixed paired mapped ancestry depth differs".into());
        }
        let ancestry = ancestors
            .iter()
            .map(|file| {
                let info = file_information(file)?;
                require_directory(file, &info)?;
                Ok(info)
            })
            .collect::<Result<Vec<_>, String>>()?;
        let tools = ancestors.last().ok_or("mapped Tools ancestry absent")?;
        let roles = [
            HeldRole::open(tools, Role::Agent, size, sha256)?,
            HeldRole::open(tools, Role::Fixture, size, sha256)?,
            HeldRole::open(tools, Role::Launcher, size, sha256)?,
        ];
        let mut value = Self {
            ancestors,
            ancestry,
            roles,
            size,
            sha256: sha256.into(),
        };
        value.revalidate()?;
        Ok(value)
    }

    pub(crate) fn revalidate(&mut self) -> Result<(), String> {
        self.revalidate_ancestry()?;
        let tools = self
            .ancestors
            .last()
            .ok_or("mapped Tools ancestry absent")?;
        for role in &mut self.roles {
            role.revalidate(tools, self.size, &self.sha256)?;
        }
        self.revalidate_ancestry()
    }

    fn revalidate_ancestry(&self) -> Result<(), String> {
        // Reopen every named component from retained C:, not just Tools' leaf.
        // Each identity is compared independently across the mapping boundary.
        for (index, (file, expected)) in self.ancestors.iter().zip(&self.ancestry).enumerate() {
            let info = file_information(file)?;
            require_directory(file, &info)?;
            if !same_directory_identity(&info, expected) {
                return Err(format!(
                    "fixed paired mapped held ancestry changed at {index}: expected attrs={:08x}/volume={:08x}/index={:08x}{:08x}/links={}/bytes={}; observed attrs={:08x}/volume={:08x}/index={:08x}{:08x}/links={}/bytes={}",
                    expected.dwFileAttributes,
                    expected.dwVolumeSerialNumber,
                    expected.nFileIndexHigh,
                    expected.nFileIndexLow,
                    expected.nNumberOfLinks,
                    file_length(expected),
                    info.dwFileAttributes,
                    info.dwVolumeSerialNumber,
                    info.nFileIndexHigh,
                    info.nFileIndexLow,
                    info.nNumberOfLinks,
                    file_length(&info)
                ));
            }
        }
        let components = ["AIW", "Tools"];
        if self.ancestors.len() != components.len() + 1 {
            return Err("fixed paired mapped ancestry depth differs".into());
        }
        let mut reopened = Vec::new();
        for (index, leaf) in components.iter().enumerate() {
            let parent = reopened.last().unwrap_or(&self.ancestors[0]);
            let file = open_relative_directory(parent, leaf, 0, DIRECTORY_SHARING)
                .map_err(|e| format!("reopen fixed paired mapped directory ({leaf}): {e}"))?
                .ok_or("fixed paired mapped ancestor disappeared")?;
            let info = file_information(&file)?;
            require_directory(&file, &info)?;
            if !same_directory_identity(&info, &self.ancestry[index + 1]) {
                return Err("fixed paired mapped named ancestry changed".into());
            }
            reopened.push(file);
        }
        Ok(())
    }

    pub(crate) fn copy_fixture(&mut self, output: &mut File) -> Result<(), String> {
        self.copy_role(1, output)
    }
    pub(crate) fn copy_launcher(&mut self, output: &mut File) -> Result<(), String> {
        self.copy_role(2, output)
    }
    fn copy_role(&mut self, index: usize, output: &mut File) -> Result<(), String> {
        self.revalidate()?;
        let role = &mut self.roles[index];
        role.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| e.to_string())?;
        copy_exact(&mut role.file, output, self.size, &self.sha256)?;
        output.sync_all().map_err(|e| e.to_string())?;
        self.revalidate()
    }
}

fn hold_fixed_ancestry() -> Result<Vec<File>, String> {
    let root = open_absolute_c_root(DIRECTORY_SHARING)
        .map_err(|e| format!("open fixed paired mapped directory (C root): {e}"))?;
    let mut ancestors = vec![root];
    for leaf in ["AIW", "Tools"] {
        let file = open_relative_directory(
            ancestors
                .last()
                .ok_or("fixed paired mapped parent absent")?,
            leaf,
            0,
            DIRECTORY_SHARING,
        )
        .map_err(|e| format!("open fixed paired mapped directory ({leaf}): {e}"))?
        .ok_or_else(|| format!("fixed paired mapped directory absent: {leaf}"))?;
        ancestors.push(file);
    }
    Ok(ancestors)
}
impl HeldRole {
    fn open(parent: &File, role: Role, size: u64, sha256: &str) -> Result<Self, String> {
        let file = open_relative_file(parent, role.leaf(), FILE_READ_DATA.0)
            .map_err(|e| format!("open fixed paired mapped role ({}): {e}", role.leaf()))?
            .ok_or("fixed paired mapped role absent")?;
        let info = file_information(&file)?;
        require_role(&file, &info, size)?;
        let mut value = Self { role, file, info };
        value.revalidate(parent, size, sha256)?;
        Ok(value)
    }
    fn revalidate(&mut self, parent: &File, size: u64, sha256: &str) -> Result<(), String> {
        let before = file_information(&self.file)?;
        require_role(&self.file, &before, size)?;
        if !same_file_information(&before, &self.info) {
            return Err("fixed paired mapped role identity changed".into());
        }
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| e.to_string())?;
        copy_exact(&mut self.file, &mut std::io::sink(), size, sha256)?;
        let after = file_information(&self.file)?;
        require_role(&self.file, &after, size)?;
        if !same_file_information(&before, &after) {
            return Err("fixed paired mapped role changed while reading".into());
        }
        let named = open_relative_file(parent, self.role.leaf(), FILE_READ_DATA.0)?
            .ok_or("fixed paired mapped role disappeared")?;
        let current = file_information(&named)?;
        require_role(&named, &current, size)?;
        if !same_file_information(&current, &self.info) {
            return Err("fixed paired mapped named role changed".into());
        }
        Ok(())
    }
}

fn supported_identity(info: &BY_HANDLE_FILE_INFORMATION) -> bool {
    info.dwVolumeSerialNumber != 0 && (info.nFileIndexHigh != 0 || info.nFileIndexLow != 0)
}
fn same_directory_identity(
    left: &BY_HANDLE_FILE_INFORMATION,
    right: &BY_HANDLE_FILE_INFORMATION,
) -> bool {
    // Directory child creation can change size/link metadata without replacing
    // the directory. Disk/type/reparse/nonzero checks are applied separately on
    // every observation; compare only the retained volume/index identity here.
    left.dwVolumeSerialNumber == right.dwVolumeSerialNumber
        && left.nFileIndexHigh == right.nFileIndexHigh
        && left.nFileIndexLow == right.nFileIndexLow
}
fn require_disk(file: &File) -> Result<(), String> {
    // SAFETY: the owned handle remains live. Unsupported handle types fail closed.
    if unsafe { GetFileType(raw_handle(file)) } != FILE_TYPE_DISK {
        return Err("fixed paired mapped object is not a disk handle".into());
    }
    Ok(())
}
fn require_directory(file: &File, info: &BY_HANDLE_FILE_INFORMATION) -> Result<(), String> {
    require_disk(file)?;
    if !ordinary_directory(info) || !supported_identity(info) {
        return Err("fixed paired mapped directory metadata unsupported or unsafe".into());
    }
    Ok(())
}
fn require_role(file: &File, info: &BY_HANDLE_FILE_INFORMATION, size: u64) -> Result<(), String> {
    require_disk(file)?;
    if !ordinary_file(info)
        || !supported_identity(info)
        || info.nNumberOfLinks != 1
        || file_length(info) != size
    {
        return Err("fixed paired mapped role metadata unsupported or unsafe".into());
    }
    Ok(())
}

// Byte/memory bounds only: synchronous mapped IO is not cancellable by this helper.
fn copy_exact(
    input: &mut impl std::io::Read,
    output: &mut impl Write,
    size: u64,
    sha256: &str,
) -> Result<(), String> {
    if size == 0 || size > MAX_BYTES {
        return Err("fixed paired mapped byte bound rejected".into());
    }
    let mut remaining = size;
    let mut buffer = [0u8; 64 * 1024];
    let mut digest = Sha256::new();
    while remaining != 0 {
        let cap = remaining.min(buffer.len() as u64) as usize;
        let count = input.read(&mut buffer[..cap]).map_err(|e| e.to_string())?;
        if count == 0 {
            return Err("fixed paired mapped role truncated".into());
        }
        output
            .write_all(&buffer[..count])
            .map_err(|e| e.to_string())?;
        digest.update(&buffer[..count]);
        remaining -= count as u64;
    }
    if input.read(&mut buffer[..1]).map_err(|e| e.to_string())? != 0 {
        return Err("fixed paired mapped role has trailing bytes".into());
    }
    if hex::encode(digest.finalize()) != sha256 {
        return Err("fixed paired mapped role bytes differ from approved agent".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Error, ErrorKind};
    use std::path::PathBuf;

    const BYTES: &[u8] = b"bounded inert paired transport fixture";
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "aiw-paired-input-test-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::create_dir(path.join("AIW")).unwrap();
            std::fs::create_dir(path.join("AIW\\Tools")).unwrap();
            for role in [Role::Agent, Role::Fixture, Role::Launcher] {
                std::fs::write(path.join("AIW\\Tools").join(role.leaf()), BYTES).unwrap();
            }
            Self(path)
        }
        fn leaf(&self, role: Role) -> PathBuf {
            self.0.join("AIW\\Tools").join(role.leaf())
        }
        fn ancestors(&self) -> Vec<File> {
            let root = OpenOptions::new()
                .read(true)
                .share_mode(DIRECTORY_SHARING)
                .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
                .open(&self.0)
                .unwrap();
            let aiw = open_relative_directory(&root, "AIW", 0, DIRECTORY_SHARING)
                .unwrap()
                .unwrap();
            let tools = open_relative_directory(&aiw, "Tools", 0, DIRECTORY_SHARING)
                .unwrap()
                .unwrap();
            vec![root, aiw, tools]
        }
        fn open(&self) -> Result<FixedPairedInputs, String> {
            FixedPairedInputs::from_ancestors(
                self.ancestors(),
                BYTES.len() as u64,
                &hex::encode(Sha256::digest(BYTES)),
            )
        }
    }

    #[test]
    fn directory_writers_are_compatible_but_directory_deleters_and_role_writers_refuse() {
        use windows::Win32::Storage::FileSystem::DELETE;
        for relative in ["", "AIW", "AIW\\Tools"] {
            let f = Fixture::new();
            let path = f.0.join(relative);
            let writer = OpenOptions::new()
                .access_mode(FILE_ADD_FILE.0 | FILE_ADD_SUBDIRECTORY.0 | FILE_READ_ATTRIBUTES.0)
                .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
                .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
                .open(&path)
                .unwrap();
            let mut inputs = f.open().unwrap();
            let output_path = f.0.join("copy-with-directory-writer.exe");
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .share_mode(FILE_SHARE_READ.0)
                .open(&output_path)
                .unwrap();
            inputs.copy_fixture(&mut output).unwrap();
            assert!(std::fs::rename(&path, path.with_extension("replaced")).is_err());
            assert!(
                OpenOptions::new()
                    .access_mode(DELETE.0)
                    .share_mode(DIRECTORY_SHARING)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
                    .open(&path)
                    .is_err()
            );
            assert!(
                OpenOptions::new()
                    .write(true)
                    .open(f.leaf(Role::Fixture))
                    .is_err()
            );
            assert!(
                OpenOptions::new()
                    .access_mode(DELETE.0)
                    .share_mode(DIRECTORY_SHARING)
                    .open(f.leaf(Role::Launcher))
                    .is_err()
            );
            inputs.revalidate().unwrap();
            drop(output);
            drop(inputs);
            drop(writer);
            let deleter = OpenOptions::new()
                .access_mode(DELETE.0 | FILE_READ_ATTRIBUTES.0)
                .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
                .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
                .open(&path)
                .unwrap();
            // Unsupported mapping semantics requiring DELETE sharing never fall back.
            // Fixture acquisition uses the same directory sharing as production.
            let root = OpenOptions::new()
                .read(true)
                .share_mode(DIRECTORY_SHARING)
                .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
                .open(&f.0);
            if relative.is_empty() {
                assert!(root.is_err());
            } else {
                let root = root.unwrap();
                let aiw = open_relative_directory(&root, "AIW", 0, DIRECTORY_SHARING);
                if relative == "AIW" {
                    assert!(aiw.is_err());
                } else {
                    assert!(
                        open_relative_directory(
                            &aiw.unwrap().unwrap(),
                            "Tools",
                            0,
                            DIRECTORY_SHARING
                        )
                        .is_err()
                    );
                }
            }
            drop(deleter);
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            // Delete only this exclusively created, named test root under Temp.
            let resolved = self.0.canonicalize().unwrap();
            assert!(resolved.starts_with(std::env::temp_dir().canonicalize().unwrap()));
            assert!(
                resolved
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("aiw-paired-input-test-")
            );
            std::fs::remove_dir_all(resolved).unwrap();
        }
    }

    #[test]
    fn copies_only_held_fixed_roles_and_retains_namespace_custody() {
        let f = Fixture::new();
        let mut inputs = f.open().unwrap();
        let output_path = f.0.join("local-copy.exe");
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ.0)
            .open(&output_path)
            .unwrap();
        inputs.copy_fixture(&mut output).unwrap();
        assert!(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output_path)
                .is_err()
        );
        // A retained writer cannot be silently treated as strict local custody.
        assert!(crate::HeldApplicationFile::open_bounded(&output_path, MAX_BYTES).is_err());
        drop(output);
        assert_eq!(std::fs::read(&output_path).unwrap(), BYTES);
        let local = crate::HeldApplicationFile::open_bounded(&output_path, MAX_BYTES).unwrap();
        assert_eq!(
            local.observation().sha256,
            hex::encode(Sha256::digest(BYTES))
        );
        local.revalidate().unwrap();
        drop(local);
        std::fs::write(
            format!("{}:unexpected", output_path.display()),
            b"inert ADS",
        )
        .unwrap();
        assert!(crate::HeldApplicationFile::open_bounded(&output_path, MAX_BYTES).is_err());
        let launcher_path = f.0.join("local-launcher.exe");
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ.0)
            .open(&launcher_path)
            .unwrap();
        inputs.copy_launcher(&mut output).unwrap();
        drop(output);
        assert_eq!(std::fs::read(&launcher_path).unwrap(), BYTES);
        for path in [
            f.0.clone(),
            f.0.join("AIW"),
            f.0.join("AIW\\Tools"),
            f.leaf(Role::Agent),
            f.leaf(Role::Fixture),
            f.leaf(Role::Launcher),
        ] {
            assert!(std::fs::rename(&path, path.with_extension("renamed")).is_err());
        }
        assert!(
            OpenOptions::new()
                .write(true)
                .open(f.leaf(Role::Fixture))
                .is_err()
        );
        assert!(std::fs::remove_file(f.leaf(Role::Launcher)).is_err());
        inputs.revalidate().unwrap();
    }

    #[test]
    fn rejects_missing_wrong_truncated_extra_or_linked_role_and_preexisting_writer() {
        for role in [Role::Agent, Role::Fixture, Role::Launcher] {
            for variant in 0..6 {
                let f = Fixture::new();
                let path = f.leaf(role);
                let mut writer = None;
                match variant {
                    0 => std::fs::remove_file(&path).unwrap(),
                    1 => std::fs::write(&path, vec![b'x'; BYTES.len()]).unwrap(),
                    2 => std::fs::write(&path, &BYTES[..BYTES.len() - 1]).unwrap(),
                    3 => std::fs::write(&path, [BYTES, b"x"].concat()).unwrap(),
                    4 => std::fs::hard_link(&path, f.0.join("extra-link")).unwrap(),
                    _ => {
                        writer = Some(
                            OpenOptions::new()
                                .write(true)
                                .share_mode(
                                    FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0,
                                )
                                .open(&path)
                                .unwrap(),
                        )
                    }
                }
                assert!(f.open().is_err(), "role {} variant {variant}", role.leaf());
                drop(writer);
            }
        }
    }

    #[test]
    fn rejects_unsafe_or_partial_metadata_and_detects_every_identity_component() {
        let f = Fixture::new();
        let file = File::open(f.leaf(Role::Agent)).unwrap();
        let original = file_information(&file).unwrap();
        require_role(&file, &original, BYTES.len() as u64).unwrap();
        for mutation in 0..8 {
            let mut changed = original;
            match mutation {
                0 => changed.dwFileAttributes |= FILE_ATTRIBUTE_REPARSE_POINT.0,
                1 => changed.dwFileAttributes |= FILE_ATTRIBUTE_DIRECTORY.0,
                2 => changed.dwFileAttributes |= FILE_ATTRIBUTE_DEVICE.0,
                3 => changed.dwVolumeSerialNumber = 0,
                4 => {
                    changed.nFileIndexHigh = 0;
                    changed.nFileIndexLow = 0;
                }
                5 => changed.nNumberOfLinks = 0,
                6 => changed.nNumberOfLinks = 2,
                _ => changed.nFileSizeLow += 1,
            }
            assert!(require_role(&file, &changed, BYTES.len() as u64).is_err());
            assert!(!same_file_information(&original, &changed));
        }
        let ancestors = f.ancestors();
        for directory in ancestors {
            let original = file_information(&directory).unwrap();
            require_directory(&directory, &original).unwrap();
            let mut grown = original;
            grown.nFileSizeLow = grown.nFileSizeLow.wrapping_add(4096);
            grown.nNumberOfLinks = grown.nNumberOfLinks.wrapping_add(1);
            assert!(same_directory_identity(&original, &grown));
            require_directory(&directory, &grown).unwrap();
            for mutation in 0..5 {
                let mut changed = original;
                match mutation {
                    0 => changed.dwFileAttributes |= FILE_ATTRIBUTE_REPARSE_POINT.0,
                    1 => changed.dwFileAttributes &= !FILE_ATTRIBUTE_DIRECTORY.0,
                    2 => changed.dwFileAttributes |= FILE_ATTRIBUTE_DEVICE.0,
                    3 => changed.dwVolumeSerialNumber = 0,
                    _ => {
                        changed.nFileIndexHigh = 0;
                        changed.nFileIndexLow = 0;
                    }
                }
                assert!(require_directory(&directory, &changed).is_err());
                assert!(!same_file_information(&original, &changed));
            }
        }
    }

    #[test]
    fn rejects_changed_held_ancestry_leaf_and_named_bindings() {
        let f = Fixture::new();
        for index in 0..3 {
            let mut inputs = f.open().unwrap();
            inputs.ancestry[index].nFileIndexLow ^= 1;
            assert!(inputs.revalidate().is_err());
        }
        for index in 0..3 {
            let mut inputs = f.open().unwrap();
            inputs.roles[index].info.nFileIndexLow ^= 1;
            assert!(inputs.revalidate().is_err());
        }
        let mut inputs = f.open().unwrap();
        inputs.roles[1].role = Role::Launcher;
        assert!(inputs.revalidate().is_err());
    }

    #[test]
    fn exact_copy_rejects_same_identity_byte_drift_short_extra_and_partial_io() {
        let hash = hex::encode(Sha256::digest(BYTES));
        for bytes in [
            vec![b'x'; BYTES.len()],
            BYTES[..BYTES.len() - 1].to_vec(),
            [BYTES, b"x"].concat(),
        ] {
            assert!(
                copy_exact(
                    &mut Cursor::new(bytes),
                    &mut Vec::new(),
                    BYTES.len() as u64,
                    &hash
                )
                .is_err()
            );
        }
        struct BrokenRead;
        impl std::io::Read for BrokenRead {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(Error::new(
                    ErrorKind::Unsupported,
                    "synthetic unsupported mapped IO",
                ))
            }
        }
        struct BrokenWrite;
        impl Write for BrokenWrite {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(Error::new(
                    ErrorKind::WriteZero,
                    "synthetic partial destination",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(copy_exact(&mut BrokenRead, &mut Vec::new(), BYTES.len() as u64, &hash).is_err());
        assert!(
            copy_exact(
                &mut Cursor::new(BYTES),
                &mut BrokenWrite,
                BYTES.len() as u64,
                &hash
            )
            .is_err()
        );
        for size in [0, MAX_BYTES + 1] {
            assert!(copy_exact(&mut Cursor::new(BYTES), &mut Vec::new(), size, &hash).is_err());
        }
        let mut output = Vec::new();
        copy_exact(
            &mut Cursor::new(BYTES),
            &mut output,
            BYTES.len() as u64,
            &hash,
        )
        .unwrap();
        assert_eq!(output, BYTES);
    }
}
