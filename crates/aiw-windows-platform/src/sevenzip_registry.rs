//! Fixed private registry canary. Integration must guard the disposable-worker
//! roles and correlate each query's actual token SID with the retained creator.
//! No test in this module mutates a registry. Requires Wdk_System_Registry for
//! handle-bound deletion; named deletion could delete a replacement object.
//!
//! Creation is NOT accepted against an arbitrary preexisting user namespace:
//! callers must establish the fresh dedicated disposable-worker account before
//! any application/other process uses it. The RegCreateKeyEx path below has no
//! proven create-only/no-registry-link traversal guarantee. Relative NtCreateKey
//! is documented, but the function's existing-key behavior and the general
//! OBJECT_ATTRIBUTES OPENIF/OPENLINK/DONT_REPARSE wording do not establish a
//! complete registry-link create-only matrix. Do not guess flags or fall back
//! after refusal. Native link/control proof remains required before integration.
use aiw_provider_wsb::sevenzip::SevenZipFileDigest;
use aiw_token::{IntegrityLevel, TokenType};
use serde::Serialize;
use sha2::{Digest, Sha256};
use windows::Wdk::System::Registry::NtDeleteKey;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_NO_TOKEN, HANDLE, HLOCAL, LocalFree, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_REGISTRY_KEY,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
    TOKEN_QUERY,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_USERS, KEY_CREATE_SUB_KEY, KEY_QUERY_VALUE, KEY_READ, KEY_SET_VALUE,
    KEY_WOW64_64KEY, REG_BINARY, REG_CREATE_KEY_DISPOSITION, REG_CREATED_NEW_KEY,
    REG_OPTION_NON_VOLATILE, REG_OPTION_OPEN_LINK, REG_SAM_FLAGS, REG_VALUE_TYPE, RegCloseKey,
    RegCreateKeyExW, RegOpenKeyExW, RegQueryInfoKeyW, RegQueryValueExW, RegSetValueExW,
};
use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
use windows::core::{BOOL, HRESULT, PCWSTR, PWSTR};

const SOFTWARE: &str = "Software";
const LEAF: &str = "AIWSevenZipCanary";
const VALUE: &str = "Canary";
pub(crate) const REGISTRY_CANARY_BYTES: &[u8] = b"AIW 7-Zip private registry canary\0\x01\xff";
const MAX_BYTES: usize = 1024;
type Result<T> = std::result::Result<T, String>;

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        let _ = unsafe { RegCloseKey(self.0) };
    }
}
struct LocalAllocation(*mut core::ffi::c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0))) };
    }
}

/// Once explicit cleanup begins, its returned observation is authoritative for
/// that attempt. Drop may close handles but must never make a hidden retry.
#[derive(Default)]
struct CleanupLifetime {
    explicit_attempted: bool,
}
impl CleanupLifetime {
    fn begin_explicit(&mut self) {
        self.explicit_attempted = true;
    }
    fn may_cleanup_on_drop(&self, has_owned_key: bool) -> bool {
        has_owned_key && !self.explicit_attempted
    }
}

/// Private raw observation: neither a missing key/value nor malformed data is a
/// denial. Only native code 5 is access denied. A success digest is actual bytes.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegistryCanaryQuery {
    pub user_sid: String,
    pub stage: &'static str,
    pub native_code: u32,
    pub value_type: Option<u32>,
    pub read: Option<SevenZipFileDigest>,
    pub matches_fixed_bytes: Option<bool>,
}
impl RegistryCanaryQuery {
    pub(crate) fn baseline_passed(&self) -> bool {
        self.native_code == 0
            && self.value_type == Some(REG_BINARY.0)
            && self.matches_fixed_bytes == Some(true)
            && self.read.as_ref() == Some(&SevenZipFileDigest::for_bytes(REGISTRY_CANARY_BYTES))
    }
    pub(crate) fn denied(&self) -> bool {
        self.native_code == 5 && self.read.is_none()
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegistryCanaryCleanup {
    /// Raw NTSTATUS from deletion of the exact retained key, never a named reopen.
    pub delete_ntstatus: Option<i32>,
    /// Raw Win32 status from a fresh absolute HKU query after closing the key.
    pub absence_native_code: Option<u32>,
    pub absence_verified: bool,
    pub refusal: Option<String>,
}

/// Only a successful REG_CREATED_NEW_KEY disposition grants cleanup authority.
/// The retained handles do not lock registry namespaces; deletion uses the owned
/// key handle, and a recreated named key makes absence verification fail.
pub(crate) struct OwnedSevenZipRegistryCanary {
    _hive: Key,
    _parent: Key,
    key: Option<Key>,
    pub(crate) user_sid: String,
    pub(crate) dacl_sha256: String,
    initialized: bool,
    cleanup_lifetime: CleanupLifetime,
}
impl OwnedSevenZipRegistryCanary {
    pub(crate) fn prepare() -> Result<Self> {
        require_no_thread_token()?;
        let token = aiw_token::collect_current_process_token().map_err(|e| e.to_string())?;
        if token.is_elevated
            || token.is_app_container
            || token.token_type != TokenType::Primary
            || token.impersonation_level.is_some()
            || token.integrity.level != IntegrityLevel::Medium
            || token.integrity.rid != 8192
        {
            return Err("registry canary creator must be the ordinary medium primary user".into());
        }
        let user_sid = token.user_sid;
        validate_user_sid(&user_sid)?;
        let hive = open(HKEY_USERS, &user_sid, KEY_READ | KEY_WOW64_64KEY).map_err(native)?;
        // Never create, repair, delete, or change security on the Software parent.
        let parent = open(
            hive.0,
            SOFTWARE,
            KEY_READ | KEY_CREATE_SUB_KEY | KEY_WOW64_64KEY,
        )
        .map_err(native)?;
        let (descriptor, _allocation) = make_descriptor(&user_sid)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: BOOL(0),
        };
        let mut key = HKEY::default();
        let mut disposition = REG_CREATE_KEY_DISPOSITION::default();
        let name = wide(LEAF);
        let status = unsafe {
            RegCreateKeyExW(
                parent.0,
                PCWSTR(name.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_SET_VALUE | KEY_WOW64_64KEY | REG_SAM_FLAGS(0x0001_0000),
                Some(&attributes),
                &mut key,
                Some(&mut disposition),
            )
        };
        if status.0 != 0 {
            return Err(native(status));
        }
        let key = Key(key);
        if disposition != REG_CREATED_NEW_KEY {
            // Closing an existing key is permitted; adopting/modifying/deleting it is not.
            return Err("fixed registry canary preexists; refused without mutation".into());
        }
        let mut owned = Self {
            _hive: hive,
            _parent: parent,
            key: Some(key),
            user_sid,
            dacl_sha256: String::new(),
            initialized: false,
            cleanup_lifetime: CleanupLifetime::default(),
        };
        owned.dacl_sha256 = verify_security(owned.key.as_ref().unwrap(), &owned.user_sid)?;
        let value = wide(VALUE);
        let status = unsafe {
            RegSetValueExW(
                owned.key.as_ref().unwrap().0,
                PCWSTR(value.as_ptr()),
                None,
                REG_BINARY,
                Some(REGISTRY_CANARY_BYTES),
            )
        };
        if status.0 != 0 {
            return Err(native(status));
        }
        owned.initialized = true;
        if !query_value(owned.key.as_ref().unwrap(), owned.user_sid.clone()).baseline_passed() {
            return Err("fresh registry canary did not retain exact binary bytes".into());
        }
        Ok(owned)
    }

    pub(crate) fn delete(mut self) -> RegistryCanaryCleanup {
        // Set before validation/native calls: even refusal, error or unwinding
        // must not make Drop perform a second, unreported mutation attempt.
        self.cleanup_lifetime.begin_explicit();
        self.delete_owned()
    }

    fn delete_owned(&mut self) -> RegistryCanaryCleanup {
        let mut result = RegistryCanaryCleanup {
            delete_ntstatus: None,
            absence_native_code: None,
            absence_verified: false,
            refusal: None,
        };
        let Some(key) = self.key.as_ref() else {
            result.refusal = Some("owned key handle already released".into());
            return result;
        };
        // Refuse unexpected contents/security rather than deleting unrelated additions.
        let checked = (|| -> Result<()> {
            require_no_thread_token()?;
            verify_security(key, &self.user_sid)?;
            let mut subkeys = 0;
            let mut values = 0;
            let status = unsafe {
                RegQueryInfoKeyW(
                    key.0,
                    None,
                    None,
                    None,
                    Some(&mut subkeys),
                    None,
                    None,
                    Some(&mut values),
                    None,
                    None,
                    None,
                    None,
                )
            };
            if status.0 != 0 {
                return Err(native(status));
            }
            if subkeys != 0 || values != u32::from(self.initialized) {
                return Err("owned registry canary contains unexpected keys/values".into());
            }
            if self.initialized && !query_value(key, self.user_sid.clone()).baseline_passed() {
                return Err("owned registry canary data changed; no deletion".into());
            }
            Ok(())
        })();
        if let Err(error) = checked {
            result.refusal = Some(error);
            return result;
        }
        let status = unsafe { NtDeleteKey(HANDLE(key.0.0)) };
        result.delete_ntstatus = Some(status.0);
        // Closing the deleted key precedes a fresh absolute namespace query.
        drop(self.key.take());
        let probe = query_for_sid(&self.user_sid);
        result.absence_native_code = Some(probe.native_code);
        result.absence_verified =
            status.0 >= 0 && probe.stage == "openKey" && probe.native_code == 2;
        result
    }
}
impl Drop for OwnedSevenZipRegistryCanary {
    fn drop(&mut self) {
        if self
            .cleanup_lifetime
            .may_cleanup_on_drop(self.key.is_some())
        {
            // Best effort only. Drop does not publish or assert verified cleanup.
            let _ = self.delete_owned();
        }
    }
}

/// Uses the actual current token's user hive, not the AppContainer HKCU overlay.
/// Integration must correlate this SID with the retained creator SID and verify
/// the held target token; this function does not turn self-report into proof.
pub(crate) fn query_fixed_registry_canary() -> Result<RegistryCanaryQuery> {
    require_no_thread_token()?;
    let token = aiw_token::collect_current_process_token().map_err(|e| e.to_string())?;
    if token.token_type != TokenType::Primary || token.impersonation_level.is_some() {
        return Err("registry query requires a primary non-impersonating role".into());
    }
    validate_user_sid(&token.user_sid)?;
    Ok(query_for_sid(&token.user_sid))
}

fn query_for_sid(sid: &str) -> RegistryCanaryQuery {
    let path = format!(r"{sid}\{SOFTWARE}\{LEAF}");
    match open(HKEY_USERS, &path, KEY_QUERY_VALUE | KEY_WOW64_64KEY) {
        Ok(key) => query_value(&key, sid.into()),
        Err(status) => observation(sid.into(), "openKey", status.0),
    }
}
fn require_no_thread_token() -> Result<()> {
    // Registry access can honor thread impersonation; process-token evidence
    // alone cannot identify that effective caller. Refuse all thread tokens.
    let mut token = HANDLE::default();
    match unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) } {
        Ok(()) => {
            let _ = unsafe { CloseHandle(token) };
            Err("registry canary refuses an impersonating thread".into())
        }
        Err(error) if error.code() == HRESULT::from_win32(ERROR_NO_TOKEN.0) => Ok(()),
        Err(error) => Err(format!(
            "cannot establish registry thread identity: {error}"
        )),
    }
}
fn query_value(key: &Key, sid: String) -> RegistryCanaryQuery {
    let mut result = observation(sid, "queryValue", 0);
    let mut bytes = [0; MAX_BYTES];
    let mut length = bytes.len() as u32;
    let mut kind = REG_VALUE_TYPE::default();
    let value = wide(VALUE);
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            PCWSTR(value.as_ptr()),
            None,
            Some(&mut kind),
            Some(bytes.as_mut_ptr()),
            Some(&mut length),
        )
    };
    result.native_code = status.0;
    result.value_type = Some(kind.0);
    if status.0 == 0 && (length as usize) <= bytes.len() {
        let bytes = &bytes[..length as usize];
        result.read = Some(SevenZipFileDigest::for_bytes(bytes));
        result.matches_fixed_bytes = Some(kind == REG_BINARY && bytes == REGISTRY_CANARY_BYTES);
    }
    result
}
fn observation(user_sid: String, stage: &'static str, native_code: u32) -> RegistryCanaryQuery {
    RegistryCanaryQuery {
        user_sid,
        stage,
        native_code,
        value_type: None,
        read: None,
        matches_fixed_bytes: None,
    }
}
fn open(root: HKEY, path: &str, access: REG_SAM_FLAGS) -> std::result::Result<Key, WIN32_ERROR> {
    let mut handle = HKEY::default();
    let path = wide(path);
    // Do not follow a final registry symbolic link as the canary object.
    let status = unsafe {
        RegOpenKeyExW(
            root,
            PCWSTR(path.as_ptr()),
            Some(REG_OPTION_OPEN_LINK.0),
            access,
            &mut handle,
        )
    };
    if status.0 == 0 {
        Ok(Key(handle))
    } else {
        Err(status)
    }
}
fn make_descriptor(sid: &str) -> Result<(PSECURITY_DESCRIPTOR, LocalAllocation)> {
    validate_user_sid(sid)?;
    let sddl = wide(&format!(
        "O:{sid}D:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KA;;;{sid})"
    ));
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(|e| e.to_string())?;
    Ok((descriptor, LocalAllocation(descriptor.0)))
}
fn verify_security(key: &Key, sid: &str) -> Result<String> {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let mut owner = PSID::default();
    let status = unsafe {
        GetSecurityInfo(
            HANDLE(key.0.0),
            SE_REGISTRY_KEY,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut descriptor),
        )
    };
    if status.0 != 0 {
        return Err(native(status));
    }
    let _allocation = LocalAllocation(descriptor.0);
    let mut owner_text = PWSTR::null();
    unsafe { ConvertSidToStringSidW(owner, &mut owner_text) }.map_err(|e| e.to_string())?;
    let _owner_allocation = LocalAllocation(owner_text.0.cast());
    let actual_owner = unsafe { owner_text.to_string() }.map_err(|e| e.to_string())?;
    let mut control = 0;
    let mut revision = 0;
    unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }
        .map_err(|e| e.to_string())?;
    if actual_owner != sid || control & SE_DACL_PROTECTED.0 == 0 {
        return Err("registry canary owner/protected DACL differs".into());
    }
    let actual = dacl_bytes(descriptor)?;
    let (expected, _expected_allocation) = make_descriptor(sid)?;
    if actual != dacl_bytes(expected)? {
        return Err("registry canary DACL differs from exact SY/BA/user grants".into());
    }
    Ok(hex::encode(Sha256::digest(&actual)))
}
fn dacl_bytes(descriptor: PSECURITY_DESCRIPTOR) -> Result<Vec<u8>> {
    let mut present = BOOL(0);
    let mut defaulted = BOOL(0);
    let mut acl = std::ptr::null_mut::<ACL>();
    unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) }
        .map_err(|e| e.to_string())?;
    if !present.as_bool() || acl.is_null() {
        return Err("registry canary has absent/null DACL".into());
    }
    // Valid security descriptor allocated by the security API; bound before copying.
    let length = unsafe { (*acl).AclSize as usize };
    if !(size_of::<ACL>()..=65535).contains(&length) {
        return Err("registry canary DACL bounds".into());
    }
    Ok(unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), length) }.to_vec())
}
fn validate_user_sid(sid: &str) -> Result<()> {
    let parts: Vec<_> = sid.split('-').collect();
    if !sid.starts_with("S-1-5-21-")
        || parts.len() != 8
        || sid.len() > 184
        || parts.iter().skip(1).any(|p| {
            p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) || p.parse::<u32>().is_err()
        })
    {
        return Err("registry role actual user SID malformed".into());
    }
    Ok(())
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn native(status: WIN32_ERROR) -> String {
    format!("registry native Win32 status {}", status.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_cleanup_refusal_suppresses_hidden_drop_retry_but_prepare_failure_keeps_best_effort()
    {
        use std::cell::Cell;
        struct InertOwner<'a> {
            lifetime: CleanupLifetime,
            has_key: bool,
            attempts: &'a Cell<u32>,
        }
        impl InertOwner<'_> {
            fn explicit_refusal(mut self) {
                self.lifetime.begin_explicit();
                self.attempts.set(self.attempts.get() + 1);
                // Model a validation refusal: the owned handle remains present.
                // Returning now must not trigger another attempt in Drop.
                assert!(self.has_key);
            }
        }
        impl Drop for InertOwner<'_> {
            fn drop(&mut self) {
                if self.lifetime.may_cleanup_on_drop(self.has_key) {
                    self.attempts.set(self.attempts.get() + 1);
                }
            }
        }
        let attempts = Cell::new(0);
        InertOwner {
            lifetime: CleanupLifetime::default(),
            has_key: true,
            attempts: &attempts,
        }
        .explicit_refusal();
        assert_eq!(
            attempts.get(),
            1,
            "explicit refusal must not cause a hidden retry"
        );
        drop(InertOwner {
            lifetime: CleanupLifetime::default(),
            has_key: true,
            attempts: &attempts,
        });
        assert_eq!(
            attempts.get(),
            2,
            "unfinished prepare retains one best-effort cleanup"
        );
        drop(InertOwner {
            lifetime: CleanupLifetime::default(),
            has_key: false,
            attempts: &attempts,
        });
        assert_eq!(
            attempts.get(),
            2,
            "absent ownership never authorizes cleanup"
        );
    }
    #[test]
    fn fixed_registry_contract_rejects_sid_path_sddl_injection_without_native_calls() {
        assert!(validate_user_sid("S-1-5-21-1-2-3-1001").is_ok());
        for sid in [
            "S-1-15-2-1",
            "S-1-5-21-1-2-3-4\\Other",
            "S-1-5-21-1-2-3-4)(A;;KA;;;WD)",
            "S-1-5-21-1-2-3-4294967296",
        ] {
            assert!(validate_user_sid(sid).is_err());
        }
        assert!(REGISTRY_CANARY_BYTES.len() <= MAX_BYTES);
    }
    #[test]
    fn missing_and_native_errors_never_become_registry_denial_or_baseline_success() {
        for code in [0, 2, 3, 6, 234, 1018] {
            let value = observation("synthetic".into(), "openKey", code);
            assert!(!value.denied());
            assert!(!value.baseline_passed());
        }
        assert!(observation("synthetic".into(), "openKey", 5).denied());
    }
    #[test]
    fn baseline_requires_exact_successful_binary_identity_not_a_summary_flag() {
        let exact = RegistryCanaryQuery {
            user_sid: "synthetic".into(),
            stage: "queryValue",
            native_code: 0,
            value_type: Some(REG_BINARY.0),
            read: Some(SevenZipFileDigest::for_bytes(REGISTRY_CANARY_BYTES)),
            matches_fixed_bytes: Some(true),
        };
        assert!(exact.baseline_passed());
        assert!(!exact.denied());
        let mut changed = exact.clone();
        changed.read = Some(SevenZipFileDigest::for_bytes(b"wrong bytes"));
        assert!(!changed.baseline_passed());
        changed = exact.clone();
        changed.value_type = Some(1);
        assert!(!changed.baseline_passed());
        changed = exact;
        changed.native_code = 5;
        assert!(!changed.baseline_passed());
        assert!(!changed.denied());
    }
}
