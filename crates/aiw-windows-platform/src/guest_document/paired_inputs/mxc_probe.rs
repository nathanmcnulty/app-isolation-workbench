//! Closed mapped default-stream transport for the MXC capability helper.
//!
//! This does not load a DLL or execute either role. The helper digest is only a
//! transport observation: the approved caller must compare it with its enrolled
//! package commitment. After CreateNew copying to the fixed guest-local root,
//! both executable files must acquire strict HeldApplicationFile custody before
//! loading/execution. Mapped basic identity is never local execution custody.
use super::*;
use std::io::Read;

use aiw_provider_mxc::process_container::{RUNTIME_DLL_SHA256, RUNTIME_DLL_SIZE};

const HELPER: &str = "mxc_process_probe.exe";
const RUNTIME: &str = "mxc_ffi.dll";

pub(crate) struct FixedMxcProbeInputs {
    ancestors: Vec<File>,
    ancestry: Vec<BY_HANDLE_FILE_INFORMATION>,
    roles: [MxcProbeRole; 2],
}

struct MxcProbeRole {
    leaf: &'static str,
    file: File,
    info: BY_HANDLE_FILE_INFORMATION,
    size: u64,
    hash: String,
}

impl FixedMxcProbeInputs {
    pub(crate) fn open() -> Result<Self, String> {
        Self::from_ancestors(hold_fixed_ancestry()?)
    }

    fn from_ancestors(ancestors: Vec<File>) -> Result<Self, String> {
        if ancestors.len() != 3 {
            return Err("MXC probe mapped ancestry depth differs".into());
        }
        let ancestry = ancestors
            .iter()
            .map(|file| {
                let info = file_information(file)?;
                require_directory(file, &info)?;
                Ok(info)
            })
            .collect::<Result<Vec<_>, String>>()?;
        let tools = ancestors.last().ok_or("mapped Tools absent")?;
        let helper = MxcProbeRole::open(tools, HELPER, None)?;
        let runtime =
            MxcProbeRole::open(tools, RUNTIME, Some((RUNTIME_DLL_SIZE, RUNTIME_DLL_SHA256)))?;
        let mut value = Self {
            ancestors,
            ancestry,
            roles: [helper, runtime],
        };
        value.revalidate()?;
        Ok(value)
    }

    pub(crate) fn helper_hash(&self) -> &str {
        &self.roles[0].hash
    }

    pub(crate) fn helper_size(&self) -> u64 {
        self.roles[0].size
    }

    pub(crate) fn copy_helper(&mut self, output: &mut File) -> Result<(), String> {
        self.copy_role(0, output)
    }

    pub(crate) fn copy_runtime(&mut self, output: &mut File) -> Result<(), String> {
        self.copy_role(1, output)
    }

    fn copy_role(&mut self, index: usize, output: &mut File) -> Result<(), String> {
        self.revalidate()?;
        // The fixed setup caller owns CreateNew destination creation and held
        // local ancestry. Refuse stale/prefixed streams even at this byte layer.
        if output.metadata().map_err(|e| e.to_string())?.len() != 0
            || output.stream_position().map_err(|e| e.to_string())? != 0
        {
            return Err("MXC probe copy requires an empty destination stream".into());
        }
        let role = &mut self.roles[index];
        role.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| e.to_string())?;
        copy_exact(&mut role.file, output, role.size, &role.hash)?;
        output.sync_all().map_err(|e| e.to_string())?;
        if output.metadata().map_err(|e| e.to_string())?.len() != role.size
            || output.stream_position().map_err(|e| e.to_string())? != role.size
        {
            return Err("MXC probe copied destination length differs".into());
        }
        self.revalidate()
    }

    pub(crate) fn revalidate(&mut self) -> Result<(), String> {
        self.revalidate_ancestry()?;
        let tools = self.ancestors.last().ok_or("mapped Tools absent")?;
        for role in &mut self.roles {
            role.revalidate(tools)?;
        }
        self.revalidate_ancestry()
    }

    fn revalidate_ancestry(&self) -> Result<(), String> {
        for (file, expected) in self.ancestors.iter().zip(&self.ancestry) {
            let info = file_information(file)?;
            require_directory(file, &info)?;
            if !same_directory_identity(&info, expected) {
                return Err("held MXC probe mapped ancestry changed".into());
            }
        }
        let mut reopened = Vec::new();
        for (index, leaf) in ["AIW", "Tools"].into_iter().enumerate() {
            let parent = reopened.last().unwrap_or(&self.ancestors[0]);
            let file = open_relative_directory(parent, leaf, 0, DIRECTORY_SHARING)?
                .ok_or("MXC probe mapped ancestor disappeared")?;
            let info = file_information(&file)?;
            require_directory(&file, &info)?;
            if !same_directory_identity(&info, &self.ancestry[index + 1]) {
                return Err("named MXC probe mapped ancestry changed".into());
            }
            reopened.push(file);
        }
        Ok(())
    }
}

impl MxcProbeRole {
    fn open(
        parent: &File,
        leaf: &'static str,
        expected: Option<(u64, &str)>,
    ) -> Result<Self, String> {
        let mut file = open_relative_file(parent, leaf, FILE_READ_DATA.0)?
            .ok_or("fixed MXC probe mapped role absent")?;
        let info = file_information(&file)?;
        let size = file_length(&info);
        if size == 0 || size > MAX_BYTES {
            return Err("MXC probe role size outside transport bound".into());
        }
        require_role(&file, &info, size)?;
        let hash = if let Some((expected_size, hash)) = expected {
            if size != expected_size {
                return Err("pinned MXC runtime size differs".into());
            }
            hash.to_owned()
        } else {
            let mut digest = Sha256::new();
            let mut remaining = size;
            let mut buffer = [0_u8; 64 * 1024];
            while remaining > 0 {
                let cap = remaining.min(buffer.len() as u64) as usize;
                let count = file.read(&mut buffer[..cap]).map_err(|e| e.to_string())?;
                if count == 0 {
                    return Err("mapped MXC probe helper truncated".into());
                }
                digest.update(&buffer[..count]);
                remaining -= count as u64;
            }
            if file.read(&mut buffer[..1]).map_err(|e| e.to_string())? != 0 {
                return Err("mapped MXC probe helper grew".into());
            }
            hex::encode(digest.finalize())
        };
        let mut role = Self {
            leaf,
            file,
            info,
            size,
            hash,
        };
        role.revalidate(parent)?;
        Ok(role)
    }

    fn revalidate(&mut self, parent: &File) -> Result<(), String> {
        let before = file_information(&self.file)?;
        require_role(&self.file, &before, self.size)?;
        if !same_file_information(&before, &self.info) {
            return Err("held MXC probe mapped role changed".into());
        }
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| e.to_string())?;
        copy_exact(&mut self.file, &mut std::io::sink(), self.size, &self.hash)?;
        let after = file_information(&self.file)?;
        require_role(&self.file, &after, self.size)?;
        if !same_file_information(&before, &after) {
            return Err("MXC probe mapped role changed during read".into());
        }
        let named = open_relative_file(parent, self.leaf, FILE_READ_DATA.0)?
            .ok_or("MXC probe mapped role disappeared")?;
        let current = file_information(&named)?;
        require_role(&named, &current, self.size)?;
        if !same_file_information(&current, &self.info) {
            return Err("named MXC probe mapped role changed".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "aiw-mxc-mapped-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&root).unwrap();
            std::fs::create_dir(root.join("AIW")).unwrap();
            std::fs::create_dir(root.join(r"AIW\Tools")).unwrap();
            std::fs::write(root.join(r"AIW\Tools").join(HELPER), b"inert helper").unwrap();
            Self(root)
        }

        fn ancestors(&self) -> Vec<File> {
            [
                self.0.clone(),
                self.0.join("AIW"),
                self.0.join(r"AIW\Tools"),
            ]
            .iter()
            .map(|path| {
                OpenOptions::new()
                    .read(true)
                    .share_mode(DIRECTORY_SHARING)
                    .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
                    .open(path)
                    .unwrap()
            })
            .collect()
        }

        fn runtime(&self) -> PathBuf {
            self.0.join(r"AIW\Tools").join(RUNTIME)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            // Fixed inert leaves only, no recursive removal or discovered paths.
            for leaf in [
                r"AIW\Tools\mxc_process_probe.exe",
                r"AIW\Tools\mxc_process_probe.renamed",
                r"AIW\Tools\mxc_ffi.dll",
                "copy.bin",
                "fresh.bin",
            ] {
                match std::fs::remove_file(self.0.join(leaf)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => panic!("remove inert fixture leaf: {error}"),
                }
            }
            std::fs::remove_dir(self.0.join(r"AIW\Tools")).unwrap();
            std::fs::remove_dir(self.0.join("AIW")).unwrap();
            std::fs::remove_dir(&self.0).unwrap();
        }
    }

    #[test]
    fn fixed_transport_rejects_wrong_runtime_size_and_same_size_wrong_digest() {
        let fixture = Fixture::new();
        std::fs::write(fixture.runtime(), b"not a runtime").unwrap();
        assert!(FixedMxcProbeInputs::from_ancestors(fixture.ancestors()).is_err());
        let file = OpenOptions::new()
            .write(true)
            .open(fixture.runtime())
            .unwrap();
        file.set_len(RUNTIME_DLL_SIZE).unwrap();
        drop(file);
        assert!(FixedMxcProbeInputs::from_ancestors(fixture.ancestors()).is_err());
        assert!(FixedMxcProbeInputs::from_ancestors(Vec::new()).is_err());
    }

    #[test]
    fn role_custody_blocks_writers_rename_and_detects_commitment_drift() {
        let fixture = Fixture::new();
        let ancestors = fixture.ancestors();
        let parent = ancestors.last().unwrap();
        let mut helper = MxcProbeRole::open(parent, HELPER, None).unwrap();
        assert_eq!(helper.size, 12);
        assert_eq!(helper.hash, hex::encode(Sha256::digest(b"inert helper")));
        let path = fixture.0.join(r"AIW\Tools").join(HELPER);
        assert!(std::fs::write(&path, b"replacement").is_err());
        assert!(std::fs::rename(&path, path.with_extension("renamed")).is_err());
        helper.revalidate(parent).unwrap();
        helper.hash = "0".repeat(64);
        assert!(helper.revalidate(parent).is_err());
    }

    #[test]
    fn copy_revalidates_before_writing_and_rejects_prefixed_destination() {
        let fixture = Fixture::new();
        let ancestors = fixture.ancestors();
        let ancestry = ancestors
            .iter()
            .map(|f| file_information(f).unwrap())
            .collect();
        let parent = ancestors.last().unwrap();
        // Test-only inert role substitutes exercise the copy algorithm without
        // making a native DLL part of the test fixture or changing production pins.
        std::fs::write(fixture.runtime(), b"inert runtime").unwrap();
        let helper = MxcProbeRole::open(parent, HELPER, None).unwrap();
        let runtime = MxcProbeRole::open(parent, RUNTIME, None).unwrap();
        let mut inputs = FixedMxcProbeInputs {
            ancestors,
            ancestry,
            roles: [helper, runtime],
        };
        assert_eq!(inputs.helper_size(), 12);
        assert_eq!(
            inputs.helper_hash(),
            hex::encode(Sha256::digest(b"inert helper"))
        );
        let path = fixture.0.join("copy.bin");
        let mut output = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        inputs.copy_helper(&mut output).unwrap();
        assert!(inputs.copy_runtime(&mut output).is_err());
        let path = fixture.0.join("fresh.bin");
        let mut fresh = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        inputs.roles[0].info.nFileIndexLow ^= 1;
        assert!(inputs.copy_helper(&mut fresh).is_err());
        assert_eq!(fresh.metadata().unwrap().len(), 0);
    }
}
