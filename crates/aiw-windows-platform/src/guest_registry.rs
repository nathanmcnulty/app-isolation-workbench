//! Read-only snapshots of the fixed application's registry settings.
//! Handles and metadata checks detect some drift; enumeration is not atomic.

use std::collections::BTreeSet;
use std::ptr::null_mut;
use std::time::{Duration, Instant};

use aiw_provider_wsb::{
    ApplicationRegistryRoot, ApplicationRegistrySnapshot, RegistryCaptureIssue,
    RegistryCaptureIssueReason as Issue, RegistryKeyEntry, RegistryScope, RegistryValueEntry,
    RegistryView, StandardUserRuntimeContext,
};
use sha2::{Digest, Sha256};

const HKLM: isize = 0x8000_0002u32 as i32 as isize;
const HKU: isize = 0x8000_0003u32 as i32 as isize;
const KEY_QUERY_ENUMERATE: u32 = 0x0009;
const OPEN_LINK: u32 = 8;
const REG_LINK: u32 = 6;
const NOT_FOUND: i32 = 2;
const MORE_DATA: i32 = 234;
const MAX_KEYS: usize = 256;
const MAX_VALUES: usize = 1024;
const MAX_VALUE: usize = 64 * 1024;
const MAX_TOTAL: u64 = 4 * 1024 * 1024;
const MAX_NAME: usize = 256;
const MAX_PATH: usize = 1024;
const MAX_DEPTH: usize = 16;
const TIMEOUT: Duration = Duration::from_secs(10);

#[link(name = "Advapi32")]
unsafe extern "system" {
    fn RegOpenKeyExW(
        root: isize,
        name: *const u16,
        options: u32,
        access: u32,
        out: *mut isize,
    ) -> i32;
    fn RegCloseKey(key: isize) -> i32;
    fn RegQueryInfoKeyW(
        key: isize,
        class: *mut u16,
        class_len: *mut u32,
        reserved: *mut u32,
        subkeys: *mut u32,
        max_subkey: *mut u32,
        max_class: *mut u32,
        values: *mut u32,
        max_value_name: *mut u32,
        max_value_len: *mut u32,
        security: *mut u32,
        last_write: *mut FileTime,
    ) -> i32;
    fn RegEnumKeyExW(
        key: isize,
        index: u32,
        name: *mut u16,
        len: *mut u32,
        reserved: *mut u32,
        class: *mut u16,
        class_len: *mut u32,
        last_write: *mut FileTime,
    ) -> i32;
    fn RegEnumValueW(
        key: isize,
        index: u32,
        name: *mut u16,
        len: *mut u32,
        reserved: *mut u32,
        value_type: *mut u32,
        data: *mut u8,
        data_len: *mut u32,
    ) -> i32;
    fn RegQueryValueExW(
        key: isize,
        name: *const u16,
        reserved: *mut u32,
        value_type: *mut u32,
        data: *mut u8,
        data_len: *mut u32,
    ) -> i32;
}

#[repr(C)]
#[derive(Default, Clone, Copy, PartialEq, Eq)]
struct FileTime {
    low: u32,
    high: u32,
}

#[derive(Default, PartialEq, Eq)]
struct Metadata {
    subkeys: u32,
    max_subkey: u32,
    values: u32,
    max_value_name: u32,
    max_value_len: u32,
    last_write: FileTime,
}

struct Key(isize);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

fn metadata(key: &Key) -> Result<Metadata, Issue> {
    let mut m = Metadata::default();
    let status = unsafe {
        RegQueryInfoKeyW(
            key.0,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut m.subkeys,
            &mut m.max_subkey,
            null_mut(),
            &mut m.values,
            &mut m.max_value_name,
            &mut m.max_value_len,
            null_mut(),
            &mut m.last_write,
        )
    };
    if status == 0 {
        Ok(m)
    } else {
        Err(Issue::Unreadable)
    }
}

fn reject_link(key: &Key) -> Result<(), Issue> {
    let mut ty = 0;
    let mut size = 0;
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            wide("SymbolicLinkValue").as_ptr(),
            null_mut(),
            &mut ty,
            null_mut(),
            &mut size,
        )
    };
    match status {
        0 if ty == REG_LINK => Err(Issue::SymbolicLink),
        0 | NOT_FOUND => Ok(()),
        _ => Err(Issue::Unreadable),
    }
}

fn open(parent: isize, component: &str, view: RegistryView) -> Result<Option<Key>, Issue> {
    let flag = match view {
        RegistryView::Registry64 => 0x100,
        RegistryView::Registry32 => 0x200,
    };
    let mut raw = 0;
    let status = unsafe {
        RegOpenKeyExW(
            parent,
            wide(component).as_ptr(),
            OPEN_LINK,
            KEY_QUERY_ENUMERATE | flag,
            &mut raw,
        )
    };
    match status {
        NOT_FOUND => Ok(None),
        0 if raw != 0 => {
            let key = Key(raw);
            reject_link(&key)?;
            Ok(Some(key))
        }
        _ => Err(Issue::Unreadable),
    }
}

fn scopes() -> [RegistryScope; 4] {
    use ApplicationRegistryRoot::{MachineApplication, UserApplication};
    use RegistryView::{Registry32, Registry64};
    [
        RegistryScope {
            root: MachineApplication,
            view: Registry64,
        },
        RegistryScope {
            root: MachineApplication,
            view: Registry32,
        },
        RegistryScope {
            root: UserApplication,
            view: Registry64,
        },
        RegistryScope {
            root: UserApplication,
            view: Registry32,
        },
    ]
}

struct Capture {
    snapshot: ApplicationRegistrySnapshot,
    started: Instant,
    bytes: u64,
}

impl Capture {
    fn check_time(&self) -> Result<(), Issue> {
        if self.started.elapsed() >= TIMEOUT {
            Err(Issue::LimitExceeded)
        } else {
            Ok(())
        }
    }

    fn walk(&mut self, key: &Key, scope: RegistryScope, path: &str) -> Result<(), Issue> {
        self.check_time()?;
        if self.snapshot.keys.len() >= MAX_KEYS {
            return Err(Issue::LimitExceeded);
        }
        reject_link(key)?;
        let before = metadata(key)?;
        if before.subkeys as usize > MAX_KEYS
            || before.values as usize > MAX_VALUES
            || before.max_subkey as usize > MAX_NAME
            || before.max_value_name as usize > MAX_NAME
            || before.max_value_len as usize > MAX_VALUE
        {
            return Err(Issue::LimitExceeded);
        }
        self.snapshot.keys.push(RegistryKeyEntry {
            root: scope.root,
            view: scope.view,
            path: path.to_owned(),
        });
        let mut value_names = BTreeSet::new();
        for index in 0..before.values {
            self.check_time()?;
            if self.snapshot.values.len() >= MAX_VALUES {
                return Err(Issue::LimitExceeded);
            }
            let mut name = [0u16; MAX_NAME + 1];
            let mut name_len = name.len() as u32;
            let mut bytes = vec![0u8; MAX_VALUE];
            let mut size = bytes.len() as u32;
            let mut ty = 0;
            let status = unsafe {
                RegEnumValueW(
                    key.0,
                    index,
                    name.as_mut_ptr(),
                    &mut name_len,
                    null_mut(),
                    &mut ty,
                    bytes.as_mut_ptr(),
                    &mut size,
                )
            };
            if status != 0 {
                return Err(enum_error(status));
            }
            if size as usize > MAX_VALUE || name_len as usize > MAX_NAME {
                return Err(Issue::LimitExceeded);
            }
            let name = checked_name(&name[..name_len as usize], false)?;
            if !value_names.insert(name.to_ascii_lowercase()) {
                return Err(Issue::ChangedDuringRead);
            }
            let next_bytes = self
                .bytes
                .checked_add(u64::from(size))
                .ok_or(Issue::LimitExceeded)?;
            if next_bytes > MAX_TOTAL {
                return Err(Issue::LimitExceeded);
            }
            self.bytes = next_bytes;
            self.snapshot.values.push(RegistryValueEntry {
                root: scope.root,
                view: scope.view,
                path: path.to_owned(),
                name,
                value_type: ty,
                size_bytes: u64::from(size),
                sha256: hex::encode(Sha256::digest(&bytes[..size as usize])),
            });
        }
        let mut key_names = BTreeSet::new();
        for index in 0..before.subkeys {
            self.check_time()?;
            let mut name = [0u16; MAX_NAME + 1];
            let mut size = name.len() as u32;
            let status = unsafe {
                RegEnumKeyExW(
                    key.0,
                    index,
                    name.as_mut_ptr(),
                    &mut size,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            };
            if status != 0 {
                return Err(enum_error(status));
            }
            if size as usize > MAX_NAME {
                return Err(Issue::LimitExceeded);
            }
            let name = checked_name(&name[..size as usize], true)?;
            if !key_names.insert(name.to_ascii_lowercase()) {
                return Err(Issue::ChangedDuringRead);
            }
            let child_path = relative_child(path, &name)?;
            let child = open(key.0, &name, scope.view)?.ok_or(Issue::ChangedDuringRead)?;
            self.walk(&child, scope, &child_path)?;
        }
        self.check_time()?;
        reject_link(key)?;
        if before != metadata(key)? {
            return Err(Issue::ChangedDuringRead);
        }
        Ok(())
    }

    fn scope(
        &mut self,
        scope: RegistryScope,
        context: &StandardUserRuntimeContext,
    ) -> Result<bool, Issue> {
        let (mut parent, components) = match scope.root {
            ApplicationRegistryRoot::MachineApplication => (HKLM, vec!["Software", "Notepad++"]),
            ApplicationRegistryRoot::UserApplication => (
                HKU,
                vec![context.user_sid.as_str(), "Software", "Notepad++"],
            ),
        };
        // Open one component at a time so an ancestor link cannot redirect capture.
        // Keep ancestors and compare metadata even when the requested root is absent.
        let mut ancestors = Vec::new();
        let mut present = true;
        for (index, component) in components.iter().enumerate() {
            self.check_time()?;
            let Some(key) = open(parent, component, scope.view)? else {
                if index == 0 && scope.root == ApplicationRegistryRoot::UserApplication {
                    return Err(Issue::Unreadable); // An unloaded runtime hive is not an absent app key.
                }
                present = false;
                break;
            };
            let before = metadata(&key)?;
            parent = key.0;
            ancestors.push((key, before));
        }
        if present {
            self.walk(&ancestors.last().ok_or(Issue::Unreadable)?.0, scope, "")?;
        }
        for (key, before) in &ancestors {
            self.check_time()?;
            reject_link(key)?;
            if *before != metadata(key)? {
                return Err(Issue::ChangedDuringRead);
            }
        }
        Ok(present)
    }
}

fn enum_error(status: i32) -> Issue {
    if status == MORE_DATA {
        Issue::LimitExceeded
    } else {
        Issue::ChangedDuringRead
    }
}

fn checked_name(units: &[u16], key: bool) -> Result<String, Issue> {
    if units.len() > MAX_NAME {
        return Err(Issue::LimitExceeded);
    }
    // This initial fixed profile deliberately declines non-ASCII names rather than
    // substituting Rust case folding for Windows registry case-insensitive identity.
    if units.iter().any(|c| !(32..=126).contains(c)) {
        return Err(Issue::Unreadable);
    }
    let text: String = units.iter().map(|c| char::from(*c as u8)).collect();
    if key
        && (text.is_empty()
            || text == "."
            || text == ".."
            || text.contains(['\\', '/'])
            || text.ends_with([' ', '.']))
    {
        return Err(Issue::Unreadable);
    }
    Ok(text)
}

fn relative_child(parent: &str, name: &str) -> Result<String, Issue> {
    let path = if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}\\{name}")
    };
    if path.len() > MAX_PATH || path.split('\\').count() > MAX_DEPTH {
        return Err(Issue::LimitExceeded);
    }
    Ok(path)
}

pub(crate) fn snapshot_fixed_notepad_registry(
    context: &StandardUserRuntimeContext,
) -> ApplicationRegistrySnapshot {
    let mut capture = Capture {
        snapshot: ApplicationRegistrySnapshot {
            keys: vec![],
            values: vec![],
            absent_roots: vec![],
            issues: vec![],
        },
        started: Instant::now(),
        bytes: 0,
    };
    for scope in scopes() {
        let keys = capture.snapshot.keys.len();
        let values = capture.snapshot.values.len();
        let result = if context.validate().is_ok() {
            capture.scope(scope, context)
        } else {
            Err(Issue::Unreadable)
        };
        match result {
            Ok(false) => capture.snapshot.absent_roots.push(scope),
            Ok(true) => (),
            Err(reason) => {
                // Discard partial data from this scope; retain consumed-byte budget.
                capture.snapshot.keys.truncate(keys);
                capture.snapshot.values.truncate(values);
                capture.snapshot.issues.push(RegistryCaptureIssue {
                    root: scope.root,
                    view: scope.view,
                    reason,
                });
            }
        }
    }
    capture
        .snapshot
        .keys
        .sort_by_key(|k| (k.root, k.view, k.path.to_ascii_lowercase()));
    capture.snapshot.values.sort_by_key(|v| {
        (
            v.root,
            v.view,
            v.path.to_ascii_lowercase(),
            v.name.to_ascii_lowercase(),
        )
    });
    capture.snapshot
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_names_and_paths_are_incomplete_not_normalized() {
        assert_eq!(checked_name(&[], false).unwrap(), "");
        assert_eq!(
            checked_name(&wide("Settings")[..8], true).unwrap(),
            "Settings"
        );
        for name in ["", ".", "..", "A\\B", "A/B", "tail.", "tail ", "\n", "é"] {
            let units: Vec<_> = name.encode_utf16().collect();
            assert!(checked_name(&units, true).is_err(), "{name:?}");
        }
        assert!(checked_name(&[b'a' as u16; MAX_NAME + 1], false).is_err());
        assert!(relative_child(&"a\\".repeat(MAX_DEPTH), "b").is_err());
        assert!(relative_child(&"a".repeat(MAX_PATH), "b").is_err());
    }

    #[test]
    fn invalid_context_never_opens_registry_and_marks_all_scopes() {
        let context = StandardUserRuntimeContext {
            user_sid: "invalid".into(),
            profile_path: String::new(),
            roaming_app_data: String::new(),
            local_app_data: String::new(),
            administrators_enabled: true,
        };
        let snapshot = snapshot_fixed_notepad_registry(&context);
        snapshot.validate().unwrap();
        assert_eq!(snapshot.issues.len(), 4);
        assert!(
            snapshot.keys.is_empty()
                && snapshot.values.is_empty()
                && snapshot.absent_roots.is_empty()
        );
    }
}
