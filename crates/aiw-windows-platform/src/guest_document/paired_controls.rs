//! Fixed native paired resources, created only by the guarded elevated guest.
//! Parent-relative creation and retained non-reparse ancestry reuse the document
//! boundary. This module exposes no public path, SDDL, hive or value arguments.
use super::*;
use aiw_provider_wsb::paired_controls::PairedControlResources;
use aiw_provider_wsb::paired_controls::{PAIRED_CONTROL_FILE_BYTES, PAIRED_CONTROL_REGISTRY_BYTES};
use std::io::{Seek, SeekFrom};
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT, SE_OBJECT_TYPE, SE_REGISTRY_KEY,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    SetFileSecurityW,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, KEY_WOW64_64KEY, REG_BINARY,
    REG_CREATE_KEY_DISPOSITION, REG_CREATED_NEW_KEY, REG_OPTION_NON_VOLATILE, RegCloseKey,
    RegCreateKeyExW, RegQueryValueExW, RegSetValueExW,
};
use windows::core::{BOOL, PCWSTR};

const ROOT: &str = r"C:\AIW\Control";
const CANARY_DIR: &str = r"C:\AIW\Control\SharedCanary";
const CANARY: &str = r"C:\AIW\Control\SharedCanary\canary.txt";
const CHILD_DIR: &str = r"C:\AIW\Control\AppContainerChild";
const KEY: &str = r"SOFTWARE\AIWControlCanary";

pub(crate) struct FixedPairedResources {
    _ancestors: Vec<File>,
    directories: Vec<File>,
    file: File,
    file_identity: BY_HANDLE_FILE_INFORMATION,
    key: RegistryKey,
    file_acl: String,
    registry_acl: String,
}
impl FixedPairedResources {
    pub(crate) fn prepare(user_sid: &str) -> Result<Self, String> {
        // User SID comes only from StandardUserSession, never request JSON.
        if !user_sid.starts_with("S-1-5-21-")
            || !user_sid
                .bytes()
                .all(|b| b.is_ascii_digit() || b"S-".contains(&b))
        {
            return Err("fixed paired standard-user SID rejected".into());
        }
        let ancestors =
            held_directory_chain_with_sharing(Path::new(FIXED_ROOT), FILE_SHARE_READ.0)?;
        let root_created = create_relative_directory(
            ancestors.last().ok_or("guest AIW parent absent")?,
            "Control",
            FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0,
        )
        .map_err(|e| relative_error("create fresh paired root", e))?;
        let full = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user_sid})");
        set_fixed_acl(ROOT, &full, false)?;
        let root = open_relative_directory(
            ancestors.last().ok_or("guest AIW parent absent")?,
            "Control",
            0,
            FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0,
        )?
        .ok_or("paired root absent")?;
        drop(root_created);
        let mut directories = vec![root];
        for (leaf, path) in [
            ("SharedCanary", CANARY_DIR),
            ("AppContainerChild", CHILD_DIR),
        ] {
            let created = create_relative_directory(
                &directories[0],
                leaf,
                FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0,
            )
            .map_err(|e| relative_error("create fresh paired directory", e))?;
            set_fixed_acl(path, &full, false)?;
            if leaf == "AppContainerChild" {
                set_fixed_acl(path, "S:(ML;OICI;NW;;;LW)", true)?;
            }
            let held = open_relative_directory(
                &directories[0],
                leaf,
                0,
                FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0,
            )?
            .ok_or("paired directory absent")?;
            drop(created);
            directories.push(held);
        }
        let mut created = create_new_file(&directories[1], "canary.txt")?;
        created
            .write_all(PAIRED_CONTROL_FILE_BYTES)
            .map_err(|e| e.to_string())?;
        created.sync_all().map_err(|e| e.to_string())?;
        set_fixed_acl(
            CANARY,
            &format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;{user_sid})"),
            false,
        )?;
        drop(created);
        let file = open_relative_file(&directories[1], "canary.txt", FILE_READ_DATA.0)?
            .ok_or("fixed paired canary absent")?;
        let file_identity = file_information(&file)?;
        let file_acl = dacl_hash(raw_handle(&file), SE_FILE_OBJECT)?;
        let key = RegistryKey::create(user_sid)?;
        let registry_acl = dacl_hash(key.handle(), SE_REGISTRY_KEY)?;
        if key.bytes()? != PAIRED_CONTROL_REGISTRY_BYTES
            || held_bytes(&file)? != PAIRED_CONTROL_FILE_BYTES
        {
            return Err("new paired resource bytes differ from fixed controls".into());
        }
        Ok(Self {
            _ancestors: ancestors,
            directories,
            file,
            file_identity,
            key,
            file_acl,
            registry_acl,
        })
    }

    pub(crate) fn observation(&self) -> Result<(PairedControlResources, bool, bool), String> {
        let file_unchanged =
            same_file_information(&file_information(&self.file)?, &self.file_identity)
                && ordinary_file(&file_information(&self.file)?)
                && held_bytes(&self.file)? == PAIRED_CONTROL_FILE_BYTES;
        // Verify the fixed namespace still resolves to the retained file.
        let reopened = open_relative_file(&self.directories[1], "canary.txt", FILE_READ_DATA.0)?
            .ok_or("paired canary disappeared")?;
        let file_unchanged = file_unchanged
            && same_file_information(&file_information(&reopened)?, &self.file_identity);
        let file_after = dacl_hash(raw_handle(&self.file), SE_FILE_OBJECT)?;
        let registry_after = dacl_hash(self.key.handle(), SE_REGISTRY_KEY)?;
        let registry_unchanged = self.key.bytes()? == PAIRED_CONTROL_REGISTRY_BYTES;
        Ok((
            PairedControlResources {
                file_path: CANARY.into(),
                file_sha256: hex::encode(Sha256::digest(PAIRED_CONTROL_FILE_BYTES)),
                file_size_bytes: PAIRED_CONTROL_FILE_BYTES.len() as u64,
                file_dacl_before_sha256: self.file_acl.clone(),
                file_dacl_after_sha256: file_after,
                registry_hive: "HKLM".into(),
                registry_view: "registry64".into(),
                registry_key: KEY.into(),
                registry_value: "Canary".into(),
                registry_type: "binary".into(),
                registry_sha256: hex::encode(Sha256::digest(PAIRED_CONTROL_REGISTRY_BYTES)),
                registry_size_bytes: PAIRED_CONTROL_REGISTRY_BYTES.len() as u64,
                registry_dacl_before_sha256: self.registry_acl.clone(),
                registry_dacl_after_sha256: registry_after,
            },
            file_unchanged,
            registry_unchanged,
        ))
    }
    pub(crate) fn stage_roles(&self) -> Result<(), String> {
        for leaf in ["aiw-control-fixture.exe", "aiw-control-appcontainer.exe"] {
            let source = Path::new(r"C:\AIW\Tools").join(leaf);
            let mut input = File::open(source).map_err(|e| e.to_string())?;
            let mut output = create_new_file(&self.directories[0], leaf)?;
            std::io::copy(&mut input, &mut output).map_err(|e| e.to_string())?;
            output.sync_all().map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}
fn held_bytes(mut file: &File) -> Result<Vec<u8>, String> {
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(1025)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    Ok(bytes)
}
struct Descriptor(PSECURITY_DESCRIPTOR);
impl Descriptor {
    fn new(sddl: &str) -> Result<Self, String> {
        let value = wide(sddl);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(value.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|e| e.to_string())?;
        Ok(Self(descriptor))
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}
fn set_fixed_acl(path: &str, sddl: &str, label: bool) -> Result<(), String> {
    let descriptor = Descriptor::new(sddl)?;
    let path = wide(path);
    let information = if label {
        LABEL_SECURITY_INFORMATION
    } else {
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
    };
    unsafe { SetFileSecurityW(PCWSTR(path.as_ptr()), information, descriptor.0) }
        .ok()
        .map_err(|e| e.to_string())
}
fn dacl_hash(handle: HANDLE, kind: SE_OBJECT_TYPE) -> Result<String, String> {
    let mut acl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            kind,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut acl),
            None,
            Some(&mut descriptor),
        )
    };
    if status.0 != 0 {
        return Err(format!("read fixed control DACL: {}", status.0));
    }
    let _descriptor = Descriptor(descriptor);
    if acl.is_null() {
        return Err("fixed control has a null DACL".into());
    }
    // GetSecurityInfo owns a valid self-relative descriptor until LocalFree.
    let size = unsafe { (*acl).AclSize as usize };
    if !(8..=65535).contains(&size) {
        return Err("fixed control DACL size invalid".into());
    }
    let bytes = unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), size) };
    Ok(hex::encode(Sha256::digest(bytes)))
}
struct RegistryKey(HKEY);
impl RegistryKey {
    fn create(user_sid: &str) -> Result<Self, String> {
        let descriptor =
            Descriptor::new(&format!("D:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;{user_sid})"))?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0.0,
            bInheritHandle: BOOL(0),
        };
        let mut key = HKEY::default();
        let mut disposition = REG_CREATE_KEY_DISPOSITION::default();
        let name = wide(KEY);
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(name.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS | KEY_WOW64_64KEY,
                Some(&attributes),
                &mut key,
                Some(&mut disposition),
            )
        };
        if status.0 != 0 {
            return Err(format!("create fixed registry control: {}", status.0));
        }
        let key = Self(key);
        if disposition != REG_CREATED_NEW_KEY {
            return Err("fixed registry control already exists; never adopt or repair".into());
        }
        let value = wide("Canary");
        let status = unsafe {
            RegSetValueExW(
                key.0,
                PCWSTR(value.as_ptr()),
                None,
                REG_BINARY,
                Some(PAIRED_CONTROL_REGISTRY_BYTES),
            )
        };
        if status.0 != 0 {
            return Err(format!("write fixed registry control: {}", status.0));
        }
        Ok(key)
    }
    fn handle(&self) -> HANDLE {
        HANDLE(self.0.0)
    }
    fn bytes(&self) -> Result<Vec<u8>, String> {
        let value = wide("Canary");
        let mut bytes = vec![0; 1024];
        let mut length = bytes.len() as u32;
        let mut kind = REG_BINARY;
        let status = unsafe {
            RegQueryValueExW(
                self.0,
                PCWSTR(value.as_ptr()),
                None,
                Some(&mut kind),
                Some(bytes.as_mut_ptr()),
                Some(&mut length),
            )
        };
        if status.0 != 0 || kind != REG_BINARY || length as usize > bytes.len() {
            return Err(format!("read fixed registry control: {}", status.0));
        }
        bytes.truncate(length as usize);
        Ok(bytes)
    }
}
impl Drop for RegistryKey {
    fn drop(&mut self) {
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
