//! Narrow mapped-byte transport, fresh local staging and strict local custody.
use super::{APP, COLLECTOR, ROOT, Result, WORK};
use crate::{HeldApplicationFile, guest_document as relative};
use aiw_probe::PortableContentEntryKind;
use aiw_provider_wsb::assessment::{CompiledAssessment, safe_assessment_relative_path};
use aiw_provider_wsb::assessment_observation::AssessmentFileObservation;
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    path::{Path, PathBuf},
};
use windows::{
    Win32::{
        Foundation::{HANDLE, HLOCAL, LocalFree},
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SetFileSecurityW,
        },
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE,
            FILE_TYPE_DISK, GetFileType,
        },
    },
    core::PCWSTR,
};

pub(super) fn at(root: &str, path: &str) -> Result<PathBuf> {
    if !safe_assessment_relative_path(path) {
        return Err("unsafe assessment relative path".into());
    }
    Ok(path
        .split('/')
        .fold(PathBuf::from(root), |p, leaf| p.join(leaf)))
}
pub(super) fn cwd(path: &str) -> Result<PathBuf> {
    if path == "." {
        Ok(PathBuf::from(WORK))
    } else {
        at(WORK, path)
    }
}
pub(super) fn set_acl(path: &Path, sddl: &str, label: bool) -> Result<()> {
    if !path.starts_with(Path::new(ROOT))
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(
            "security mutation outside fresh guest-local assessment resources refused".into(),
        );
    }
    apply_acl(path, sddl, label)
}
fn apply_acl(path: &Path, sddl: &str, label: bool) -> Result<()> {
    let text: Vec<_> = OsStr::new(sddl).encode_wide().chain(Some(0)).collect();
    let name: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(text.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(|e| e.to_string())?;
    let result = unsafe {
        SetFileSecurityW(
            PCWSTR(name.as_ptr()),
            if label {
                LABEL_SECURITY_INFORMATION
            } else {
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
            },
            descriptor,
        )
    }
    .ok();
    unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    result.map_err(|e| e.to_string())
}
/// SetFileSecurityW does NOT propagate to preexisting children. Apply only the
/// finite already-staged plan roster, not a recursive walk of mutable state.
pub(super) fn grant_declared_resources(
    plan: &CompiledAssessment,
    sid: &str,
    package: Option<&str>,
) -> Result<()> {
    let root_package = package
        .map(|p| format!("(A;;GRGX;;;{p})"))
        .unwrap_or_default();
    let read_package = package
        .map(|p| format!("(A;OICI;GRGX;;;{p})"))
        .unwrap_or_default();
    let write_package = package
        .map(|p| format!("(A;OICI;FA;;;{p})"))
        .unwrap_or_default();
    let read = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;{sid}){read_package}");
    let write = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid}){write_package}");
    set_acl(
        Path::new(ROOT),
        &format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;GRGX;;;{sid}){root_package}"),
        false,
    )?;
    set_acl(Path::new(APP), &read, false)?;
    for entry in &plan.portable_entries {
        set_acl(&at(APP, &entry.relative_path)?, &read, false)?;
    }
    let level = if package.is_some() { "LW" } else { "ME" };
    set_acl(Path::new(WORK), &write, false)?;
    set_acl(Path::new(WORK), &format!("S:(ML;OICI;NW;;;{level})"), true)?;
    for directory in work_directories(plan) {
        let path = at(WORK, &directory)?;
        set_acl(&path, &write, false)?;
        set_acl(&path, &format!("S:(ML;OICI;NW;;;{level})"), true)?;
    }
    for input in &plan.settings.inputs {
        let path = at(WORK, &input.path)?;
        set_acl(&path, &write, false)?;
        set_acl(&path, &format!("S:(ML;;NW;;;{level})"), true)?;
    }
    Ok(())
}
fn work_directories(plan: &CompiledAssessment) -> std::collections::BTreeSet<String> {
    let mut directories = std::collections::BTreeSet::new();
    for input in &plan.settings.inputs {
        let mut path = input.path.as_str();
        while let Some((parent, _)) = path.rsplit_once('/') {
            directories.insert(parent.to_string());
            path = parent;
        }
    }
    if plan.settings.working_directory != "." {
        let mut prefix = String::new();
        for leaf in plan.settings.working_directory.split('/') {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(leaf);
            directories.insert(prefix.clone());
        }
    }
    directories
}
/// Ordinary-context non-mutating preflight of the actual existing entry/data
/// files, and create access to the actual cwd. No application code executes.
pub(super) fn verify_declared_access(plan: &CompiledAssessment) -> Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::{
        FILE_ADD_FILE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    for entry in &plan.portable_entries {
        if entry.kind == PortableContentEntryKind::File {
            let path = at(APP, &entry.relative_path)?;
            let _file =
                File::open(path).map_err(|e| format!("ordinary App read preflight: {e}"))?;
        }
    }
    for input in &plan.settings.inputs {
        let _file = File::open(at(WORK, &input.path)?)
            .map_err(|e| format!("ordinary fixture read preflight: {e}"))?;
    }
    let _directory = OpenOptions::new()
        .access_mode(FILE_ADD_FILE.0)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(cwd(&plan.settings.working_directory)?)
        .map_err(|e| format!("ordinary cwd create-access preflight: {e}"))?;
    Ok(())
}
pub(super) struct Directories(Vec<File>);
impl Directories {
    pub(super) fn collector_probe() -> Result<Self> {
        use windows::Win32::Storage::FileSystem::FILE_SHARE_DELETE;
        let mut held = Self::hold(Path::new(ROOT))?;
        let output = relative::open_relative_directory(
            held.last()?,
            "Collector",
            0,
            FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0,
        )?
        .ok_or("collector Output absent")?;
        held.0.push(output);
        held.revalidate()?;
        Ok(held)
    }
    pub(super) fn same_leaf(&self, other: &Self) -> Result<bool> {
        let a = relative::file_information(self.last()?)?;
        let b = relative::file_information(other.last()?)?;
        Ok(a.dwVolumeSerialNumber == b.dwVolumeSerialNumber
            && a.nFileIndexHigh == b.nFileIndexHigh
            && a.nFileIndexLow == b.nFileIndexLow)
    }
    fn revalidate(&self) -> Result<()> {
        for file in &self.0 {
            let info = relative::file_information(file)?;
            if !relative::ordinary_directory(&info)
                || info.dwVolumeSerialNumber == 0
                || (info.nFileIndexHigh == 0 && info.nFileIndexLow == 0)
                || unsafe { GetFileType(HANDLE(file.as_raw_handle())) } != FILE_TYPE_DISK
            {
                return Err("held directory changed to unsupported/reparse object".into());
            }
        }
        Ok(())
    }
    pub(super) fn hold(path: &Path) -> Result<Self> {
        let text = path.to_str().ok_or("directory path encoding")?;
        if !text.starts_with("C:\\") || text.contains('/') {
            return Err("directory must use fixed C-drive namespace".into());
        }
        let mut held = vec![relative::open_absolute_c_root(
            FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0,
        )?];
        for leaf in text[3..].split('\\').filter(|s| !s.is_empty()) {
            let next = relative::open_relative_directory(
                held.last().ok_or("directory parent missing")?,
                leaf,
                0,
                FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0,
            )?
            .ok_or("directory absent")?;
            let info = relative::file_information(&next)?;
            if !relative::ordinary_directory(&info)
                || info.dwVolumeSerialNumber == 0
                || (info.nFileIndexHigh == 0 && info.nFileIndexLow == 0)
            {
                return Err("directory identity unsupported".into());
            }
            held.push(next);
        }
        Ok(Self(held))
    }
    fn last(&self) -> Result<&File> {
        self.0.last().ok_or("directory chain empty".into())
    }
}
struct MappedFile {
    parents: Directories,
    leaf: String,
    file: File,
    identity: BY_HANDLE_FILE_INFORMATION,
    size: u64,
    hash: String,
}
pub(super) struct AgentHold {
    _mapped: MappedFile,
}
impl AgentHold {
    pub(super) fn revalidate(&mut self) -> Result<()> {
        self._mapped.verify()
    }
}
/// Fresh root is created exactly once before progress/bootstrap/user setup.
/// The collector leaf is not narrowly held until its wide-share probes finish.
pub(super) fn initialize_collector() -> Result<Directories> {
    let _parents = Directories::hold(Path::new(r"C:\AIW"))?;
    fs::create_dir(ROOT).map_err(|e| format!("fresh local assessment root: {e}"))?;
    set_acl(
        Path::new(ROOT),
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
        false,
    )?;
    let root = Directories::hold(Path::new(ROOT))?;
    fs::create_dir(COLLECTOR).map_err(|e| format!("fresh local collector: {e}"))?;
    set_acl(
        Path::new(COLLECTOR),
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
        false,
    )?;
    set_acl(Path::new(COLLECTOR), "S:(ML;OICI;NW;;;HI)", true)?;
    Ok(root)
}
pub(super) fn hold_agent(hash: &str) -> Result<AgentHold> {
    let parents = Directories::hold(Path::new(r"C:\AIW\Tools"))?;
    let named =
        relative::open_relative_file(parents.last()?, "aiw-guest-agent.exe", FILE_READ_DATA.0)?
            .ok_or("assessment agent source absent")?;
    let info = relative::file_information(&named)?;
    let size = relative::file_length(&info);
    if size == 0
        || size > 128 * 1024 * 1024
        || !relative::ordinary_file(&info)
        || info.nNumberOfLinks != 1
    {
        return Err("assessment agent type/link/size refused".into());
    }
    let mapped = MappedFile::open(r"C:\AIW\Tools", "aiw-guest-agent.exe", size, hash)?;
    if !relative::same_file_information(&info, &mapped.identity) {
        return Err("assessment agent enrollment identity changed".into());
    }
    Ok(AgentHold { _mapped: mapped })
}
impl MappedFile {
    fn open(root: &str, path: &str, size: u64, hash: &str) -> Result<Self> {
        let path = at(root, path)?;
        let parent = path.parent().ok_or("input parent absent")?;
        let parents = Directories::hold(parent)?;
        let leaf = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or("input leaf encoding")?
            .to_string();
        let file = relative::open_relative_file(parents.last()?, &leaf, FILE_READ_DATA.0)?
            .ok_or("approved input absent")?;
        let identity = relative::file_information(&file)?;
        let mut value = Self {
            parents,
            leaf,
            file,
            identity,
            size,
            hash: hash.into(),
        };
        value.verify()?;
        Ok(value)
    }
    fn metadata(&self, info: &BY_HANDLE_FILE_INFORMATION) -> Result<()> {
        if unsafe { GetFileType(HANDLE(self.file.as_raw_handle())) } != FILE_TYPE_DISK
            || !relative::ordinary_file(info)
            || info.nNumberOfLinks != 1
            || info.dwVolumeSerialNumber == 0
            || (info.nFileIndexHigh == 0 && info.nFileIndexLow == 0)
            || relative::file_length(info) != self.size
            || self.size > 512 * 1024 * 1024
        {
            return Err("mapped input type/link/size/identity refused".into());
        }
        Ok(())
    }
    fn copy(&mut self, output: &mut impl Write) -> Result<()> {
        self.parents.revalidate()?;
        self.metadata(&relative::file_information(&self.file)?)?;
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| e.to_string())?;
        let mut remaining = self.size;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 65536];
        while remaining != 0 {
            let amount = remaining.min(buffer.len() as u64) as usize;
            let n = self
                .file
                .read(&mut buffer[..amount])
                .map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("approved input truncated".into());
            }
            digest.update(&buffer[..n]);
            output.write_all(&buffer[..n]).map_err(|e| e.to_string())?;
            remaining -= n as u64;
        }
        if self
            .file
            .read(&mut buffer[..1])
            .map_err(|e| e.to_string())?
            != 0
            || hex::encode(digest.finalize()) != self.hash
        {
            return Err("approved input bytes differ".into());
        }
        let current = relative::file_information(&self.file)?;
        self.metadata(&current)?;
        if !relative::same_file_information(&self.identity, &current) {
            return Err("held input identity changed".into());
        }
        self.parents.revalidate()?;
        Ok(())
    }
    fn verify(&mut self) -> Result<()> {
        self.copy(&mut std::io::sink())?;
        let named =
            relative::open_relative_file(self.parents.last()?, &self.leaf, FILE_READ_DATA.0)?
                .ok_or("named input disappeared")?;
        if !relative::same_file_information(&relative::file_information(&named)?, &self.identity) {
            return Err("named input changed".into());
        }
        Ok(())
    }
}
pub(super) struct Staged {
    _directories: Vec<Directories>,
    inputs: Vec<MappedFile>,
}
impl Staged {
    pub(super) fn prepare(plan: &CompiledAssessment) -> Result<Self> {
        let ancestors = Directories::hold(Path::new(r"C:\AIW"))?;
        // The privileged entry owns initialize_collector's fresh-root lease;
        // no alternate entry may adopt an existing root to execute applications.
        let root = Directories::hold(Path::new(ROOT))?;
        for path in [APP, WORK] {
            fs::create_dir(path).map_err(|e| e.to_string())?;
        }
        let mut directories = vec![
            ancestors,
            root,
            Directories::hold(Path::new(APP))?,
            Directories::hold(Path::new(WORK))?,
        ];
        let mut inputs = vec![];
        for entry in &plan.portable_entries {
            let destination = at(APP, &entry.relative_path)?;
            match entry.kind {
                PortableContentEntryKind::Directory => {
                    fs::create_dir(&destination).map_err(|e| e.to_string())?;
                    directories.push(Directories::hold(&destination)?);
                }
                PortableContentEntryKind::File => {
                    let mut input = MappedFile::open(
                        r"C:\AIW\Input\App",
                        &entry.relative_path,
                        entry.size_bytes,
                        entry.sha256.as_deref().ok_or("file hash missing")?,
                    )?;
                    let mut output = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&destination)
                        .map_err(|e| e.to_string())?;
                    input.copy(&mut output)?;
                    output.sync_all().map_err(|e| e.to_string())?;
                    drop(output);
                    let held = HeldApplicationFile::open_bounded(&destination, entry.size_bytes)
                        .map_err(|e| e.to_string())?;
                    if held.observation().sha256 != input.hash {
                        return Err("staged content differs".into());
                    }
                    held.revalidate().map_err(|e| e.to_string())?;
                    inputs.push(input);
                }
            }
        }
        for fixture in &plan.settings.inputs {
            let destination = at(WORK, &fixture.path)?;
            // Work-only parent creation; all ancestors remain held and are
            // created before the untrusted account exists.
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                directories.push(Directories::hold(parent)?);
            }
            let mut input = MappedFile::open(
                r"C:\AIW\Input\Fixtures",
                &fixture.path,
                fixture.size_bytes,
                &fixture.sha256,
            )?;
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&destination)
                .map_err(|e| e.to_string())?;
            input.copy(&mut output)?;
            output.sync_all().map_err(|e| e.to_string())?;
            inputs.push(input);
        }
        let working_directory = cwd(&plan.settings.working_directory)?;
        fs::create_dir_all(&working_directory).map_err(|e| e.to_string())?;
        directories.push(Directories::hold(&working_directory)?);
        Ok(Self {
            _directories: directories,
            inputs,
        })
    }
    pub(super) fn revalidate(&mut self) -> Result<()> {
        for input in &mut self.inputs {
            input.verify()?;
        }
        for directory in &self._directories {
            directory.revalidate()?;
        }
        Ok(())
    }
}
pub(super) fn observe_work(path: &str, maximum: u64) -> Result<Option<AssessmentFileObservation>> {
    let absolute = at(WORK, path)?;
    let mut held = Directories::hold(Path::new(WORK))?;
    let mut parts = path.split('/').peekable();
    while let Some(leaf) = parts.next() {
        if parts.peek().is_some() {
            match relative::open_relative_directory(
                held.last()?,
                leaf,
                0,
                FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0,
            )? {
                Some(directory) => held.0.push(directory),
                None => return Ok(None),
            }
        } else {
            let Some(named) = relative::open_relative_file(held.last()?, leaf, FILE_READ_DATA.0)?
            else {
                return Ok(None);
            };
            let info = relative::file_information(&named)?;
            if !relative::ordinary_file(&info)
                || info.nNumberOfLinks != 1
                || relative::file_length(&info) > maximum
            {
                return Err("work observation type/link/size refused".into());
            }
            let file =
                HeldApplicationFile::open_bounded(&absolute, maximum).map_err(|e| e.to_string())?;
            let fact = file.observation();
            let observation = AssessmentFileObservation {
                relative_path: path.into(),
                identity: fact.identity.clone(),
                size_bytes: fact.size_bytes,
                sha256: fact.sha256.clone(),
            };
            file.revalidate().map_err(|e| e.to_string())?;
            if !relative::same_file_information(&info, &relative::file_information(&named)?) {
                return Err("work file changed during observation".into());
            }
            return Ok(Some(observation));
        }
    }
    Err("work observation leaf missing".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn dacl_text(path: &Path) -> String {
        use windows::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
            SE_FILE_OBJECT,
        };
        use windows::core::PWSTR;
        let name: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let status = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(name.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                &mut descriptor,
            )
        };
        assert_eq!(status.0, 0);
        let mut output = PWSTR::null();
        let converted = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut output,
                None,
            )
        };
        unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
        converted.unwrap();
        let result = unsafe { output.to_string() }.unwrap();
        unsafe { LocalFree(Some(HLOCAL(output.0.cast()))) };
        result
    }
    #[test]
    fn preexisting_child_needs_explicit_acl_instead_of_parent_only_setfilesecurity() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("aiw-owned-acl-{}-{nonce}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let child = directory.join("DATA.DAT");
        fs::write(&child, b"inert ACL regression").unwrap();
        struct Owned {
            directory: PathBuf,
            child: PathBuf,
        }
        impl Drop for Owned {
            fn drop(&mut self) {
                let _ = fs::remove_file(&self.child);
                let _ = fs::remove_dir(&self.directory);
            }
        }
        let _owned = Owned {
            directory: directory.clone(),
            child: child.clone(),
        };
        let owner = aiw_token::collect_current_process_token().unwrap().user_sid;
        let synthetic = "S-1-5-21-111-222-333-4444";
        let acl = format!("D:P(A;OICI;FA;;;{owner})(A;OICI;GRGX;;;{synthetic})");
        assert!(!dacl_text(&child).contains(synthetic));
        apply_acl(&directory, &acl, false).unwrap();
        assert!(
            !dacl_text(&child).contains(synthetic),
            "SetFileSecurityW unexpectedly propagated old child; review native semantics"
        );
        apply_acl(&child, &acl, false).unwrap();
        assert!(dacl_text(&child).contains(synthetic));
    }
    #[test]
    fn paths_remain_in_declared_namespace() {
        for path in [
            "../x", "C:/x", "x:ads", "/x", "a//b", "a\\b", "CON", "a/../x",
        ] {
            assert!(at(APP, path).is_err());
        }
        assert_eq!(
            at(APP, "bin/tool.exe").unwrap(),
            Path::new(APP).join("bin").join("tool.exe")
        );
        assert_eq!(cwd(".").unwrap(), Path::new(WORK));
    }
}
