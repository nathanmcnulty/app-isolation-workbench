//! Fixed two-role research transport. The inherited paired transport primitives
//! perform basic-identity/byte checks for mapped default streams; all executable
//! execution custody is reacquired with strict HeldApplicationFile after copying.
use super::*;
use std::io::Read;

const INSTALLER: &str = "7z2605-x64.exe";
const HELPER: &str = "sevenzip_assessment.exe";
const INSTALLER_HASH: &str = "fd99e86f57d8f429ef5ed045bf98315af962e2309b0f1ba87a147a44c71647d0";
const INSTALLER_SIZE: u64 = 1_663_506;

pub(crate) struct FixedSevenZipInputs {
    ancestors: Vec<File>,
    ancestry: Vec<BY_HANDLE_FILE_INFORMATION>,
    roles: [SevenZipRole; 2],
}
struct SevenZipRole {
    leaf: &'static str,
    file: File,
    info: BY_HANDLE_FILE_INFORMATION,
    size: u64,
    hash: String,
}
impl FixedSevenZipInputs {
    pub(crate) fn open() -> Result<Self, String> {
        Self::from_ancestors(hold_fixed_ancestry()?)
    }
    fn from_ancestors(ancestors: Vec<File>) -> Result<Self, String> {
        if ancestors.len() != 3 {
            return Err("sevenzip mapped ancestry depth differs".into());
        }
        let ancestry = ancestors
            .iter()
            .map(|file| {
                let info = file_information(file)?;
                require_directory(file, &info)?;
                Ok(info)
            })
            .collect::<Result<Vec<_>, String>>()?;
        let tools = ancestors.last().ok_or("mappedTools absent")?;
        let installer =
            SevenZipRole::open(tools, INSTALLER, Some((INSTALLER_SIZE, INSTALLER_HASH)))?;
        let helper = SevenZipRole::open(tools, HELPER, None)?;
        let mut value = Self {
            ancestors,
            ancestry,
            roles: [installer, helper],
        };
        value.revalidate()?;
        Ok(value)
    }
    pub(crate) fn helper_hash(&self) -> &str {
        &self.roles[1].hash
    }
    pub(crate) fn helper_size(&self) -> u64 {
        self.roles[1].size
    }
    pub(crate) fn copy_installer(&mut self, output: &mut File) -> Result<(), String> {
        self.copy_role(0, output)
    }
    pub(crate) fn copy_helper(&mut self, output: &mut File) -> Result<(), String> {
        self.copy_role(1, output)
    }
    fn copy_role(&mut self, index: usize, output: &mut File) -> Result<(), String> {
        self.revalidate()?;
        let role = &mut self.roles[index];
        role.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| e.to_string())?;
        copy_exact(&mut role.file, output, role.size, &role.hash)?;
        output.sync_all().map_err(|e| e.to_string())?;
        self.revalidate()
    }
    pub(crate) fn revalidate(&mut self) -> Result<(), String> {
        for (file, expected) in self.ancestors.iter().zip(&self.ancestry) {
            let info = file_information(file)?;
            require_directory(file, &info)?;
            if !same_directory_identity(&info, expected) {
                return Err("held mapped ancestry changed".into());
            }
        }
        let mut reopened = vec![];
        for (index, leaf) in ["AIW", "Tools"].into_iter().enumerate() {
            let parent = reopened.last().unwrap_or(&self.ancestors[0]);
            let file = open_relative_directory(parent, leaf, 0, DIRECTORY_SHARING)?
                .ok_or("mapped ancestor disappeared")?;
            let info = file_information(&file)?;
            require_directory(&file, &info)?;
            if !same_directory_identity(&info, &self.ancestry[index + 1]) {
                return Err("named mapped ancestry changed".into());
            }
            reopened.push(file);
        }
        let parent = self.ancestors.last().ok_or("mappedTools absent")?;
        for role in &mut self.roles {
            role.revalidate(parent)?;
        }
        Ok(())
    }
}
impl SevenZipRole {
    fn open(
        parent: &File,
        leaf: &'static str,
        expected: Option<(u64, &str)>,
    ) -> Result<Self, String> {
        let mut file = open_relative_file(parent, leaf, FILE_READ_DATA.0)?
            .ok_or("fixed sevenzip mapped role absent")?;
        let info = file_information(&file)?;
        let size = file_length(&info);
        if size == 0 || size > MAX_BYTES {
            return Err("sevenzip role size outside transport bound".into());
        }
        require_role(&file, &info, size)?;
        // The helper's hash is a transport observation. The host separately
        // enrolls it before Sandbox start; this is not source/provenance proof.
        let hash = if let Some((expected_size, hash)) = expected {
            if size != expected_size {
                return Err("official installer size differs".into());
            }
            hash.to_owned()
        } else {
            let mut digest = Sha256::new();
            let mut remaining = size;
            let mut buffer = [0u8; 64 * 1024];
            while remaining > 0 {
                let cap = remaining.min(buffer.len() as u64) as usize;
                let count = file.read(&mut buffer[..cap]).map_err(|e| e.to_string())?;
                if count == 0 {
                    return Err("mapped helper truncated".into());
                }
                digest.update(&buffer[..count]);
                remaining -= count as u64;
            }
            if file.read(&mut buffer[..1]).map_err(|e| e.to_string())? != 0 {
                return Err("mapped helper grew".into());
            }
            hex::encode(digest.finalize())
        };
        let mut value = Self {
            leaf,
            file,
            info,
            size,
            hash,
        };
        value.revalidate(parent)?;
        Ok(value)
    }
    fn revalidate(&mut self, parent: &File) -> Result<(), String> {
        let before = file_information(&self.file)?;
        require_role(&self.file, &before, self.size)?;
        if !same_file_information(&before, &self.info) {
            return Err("mapped sevenzip role changed".into());
        }
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| e.to_string())?;
        copy_exact(&mut self.file, &mut std::io::sink(), self.size, &self.hash)?;
        let after = file_information(&self.file)?;
        require_role(&self.file, &after, self.size)?;
        if !same_file_information(&before, &after) {
            return Err("mapped role changed during read".into());
        }
        let named = open_relative_file(parent, self.leaf, FILE_READ_DATA.0)?
            .ok_or("mapped role disappeared")?;
        let current = file_information(&named)?;
        require_role(&named, &current, self.size)?;
        if !same_file_information(&current, &self.info) {
            return Err("named mapped sevenzip role changed".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sevenzip_mapped_transport_rejects_unpinned_installer_before_copy() {
        let root = std::env::temp_dir().join(format!("aiw-sevenzip-mapped-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join(INSTALLER), b"wrong installer").unwrap();
        std::fs::write(root.join(HELPER), b"inert helper").unwrap();
        let parent = OpenOptions::new()
            .read(true)
            .share_mode(DIRECTORY_SHARING)
            .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
            .open(&root)
            .unwrap();
        assert!(
            SevenZipRole::open(&parent, INSTALLER, Some((INSTALLER_SIZE, INSTALLER_HASH))).is_err()
        );
        let mut helper = SevenZipRole::open(&parent, HELPER, None).unwrap();
        assert!(std::fs::write(root.join(HELPER), b"replacement").is_err());
        assert!(std::fs::rename(root.join(HELPER), root.join("renamed")).is_err());
        helper.revalidate(&parent).unwrap();
        helper.info.nFileIndexLow ^= 1;
        assert!(helper.revalidate(&parent).is_err());
        drop(helper);
        drop(parent);
        std::fs::remove_file(root.join(INSTALLER)).unwrap();
        std::fs::remove_file(root.join(HELPER)).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
