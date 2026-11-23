//! Actual standard-token object-access observations for this collector only.
#[path = "protection_token.rs"]
mod token;
use super::{Result, bound_error, guard_no_impersonation};
use aiw_provider_wsb::assessment_observation::*;
use sha2::{Digest, Sha256};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows::{
    Win32::{
        Foundation::{FILETIME, HANDLE, HLOCAL, LocalFree},
        Security::{
            Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
                GetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT,
            },
            DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, PSID,
        },
        System::Threading::{
            GetCurrentProcessId, GetCurrentThreadId, GetProcessIdOfThread, GetProcessTimes,
            OpenProcess, OpenThread, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_LIMITED_INFORMATION,
            THREAD_ACCESS_RIGHTS, THREAD_QUERY_INFORMATION,
        },
    },
    core::{HRESULT, PWSTR},
};

fn raw(h: &OwnedHandle) -> HANDLE {
    HANDLE(h.as_raw_handle())
}
struct Local(HLOCAL);
impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.0.is_null() {
            let _ = unsafe { LocalFree(Some(self.0)) };
        }
    }
}
fn trustee_sids(acl: *const windows::Win32::Security::ACL) -> Result<Vec<String>> {
    use windows::Win32::Security::{
        ACE_HEADER, ACL_SIZE_INFORMATION, AclSizeInformation, GetAce, GetAclInformation,
        IsValidAcl, IsValidSid,
    };
    if acl.is_null() || !unsafe { IsValidAcl(acl) }.as_bool() {
        return Err("NULL or invalid collector DACL".into());
    }
    let mut size = ACL_SIZE_INFORMATION::default();
    unsafe {
        GetAclInformation(
            acl,
            (&mut size as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    }
    .map_err(|_| "collector DACL metadata refused")?;
    if size.AceCount > 64 || size.AclBytesInUse > 65536 {
        return Err("collector DACL bound".into());
    }
    let mut trustees = std::collections::BTreeSet::new();
    for index in 0..size.AceCount {
        let mut ace = std::ptr::null_mut();
        unsafe { GetAce(acl, index, &mut ace) }.map_err(|_| "collector DACL ACE refused")?;
        if ace.is_null() {
            return Err("collector DACL ACE absent".into());
        }
        let header = unsafe { *(ace as *const ACE_HEADER) };
        // Only ordinary ACCESS_ALLOWED_ACE(0)/ACCESS_DENIED_ACE(1), whose SID
        // starts after header+mask. No conditional/object/callback interpretation.
        if header.AceType > 1 || header.AceSize < 16 {
            return Err("collector DACL has unsupported ACE".into());
        }
        let ptr = unsafe { (ace as *mut u8).add(8) };
        let revision = unsafe { *ptr };
        let count = unsafe { *ptr.add(1) } as usize;
        if revision != 1
            || count > 15
            || 8 + 4 * count > header.AceSize as usize - 8
            || !unsafe { IsValidSid(PSID(ptr.cast())) }.as_bool()
        {
            return Err("collector DACL SID layout refused".into());
        }
        let mut text = PWSTR::null();
        unsafe { ConvertSidToStringSidW(PSID(ptr.cast()), &mut text) }
            .map_err(|_| "collector DACL SID text refused")?;
        let _memory = Local(HLOCAL(text.0.cast()));
        let sid = unsafe { text.to_string() }.map_err(|_| "collector DACL SID encoding refused")?;
        if sid.len() > 184 {
            return Err("collector DACL SID bound".into());
        }
        trustees.insert(sid);
    }
    Ok(trustees.into_iter().collect())
}
fn security(handle: HANDLE) -> Result<AssessmentCollectorObjectSecurity> {
    let mut sd = PSECURITY_DESCRIPTOR::default();
    let mut owner = PSID::default();
    let mut dacl = std::ptr::null_mut();
    let flags = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            flags,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            Some(&mut sd),
        )
    };
    let _memory = Local(HLOCAL(sd.0));
    status
        .ok()
        .map_err(|e| format!("collector object security: {e}"))?;
    if sd.0.is_null() || owner.0.is_null() {
        return Err("collector object security descriptor/owner absent".into());
    }
    let mut owner_text = PWSTR::null();
    unsafe { ConvertSidToStringSidW(owner, &mut owner_text) }.map_err(|e| e.to_string())?;
    let _owner_memory = Local(HLOCAL(owner_text.0.cast()));
    let owner_sid = unsafe { owner_text.to_string() }.map_err(|e| e.to_string())?;
    let mut text = PWSTR::null();
    let mut length = 0;
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            flags,
            &mut text,
            Some(&mut length),
        )
    }
    .map_err(|e| e.to_string())?;
    let _text_memory = Local(HLOCAL(text.0.cast()));
    if length == 0 || length > 8193 || text.0.is_null() {
        return Err("collector descriptor string bound".into());
    }
    // The API reports buffer capacity, not string length. Read only through
    // its guaranteed NUL, never include padding as descriptor contents.
    let mut units = Vec::new();
    let mut terminated = false;
    for index in 0..length as usize {
        let unit = unsafe { *text.0.add(index) };
        if unit == 0 {
            terminated = true;
            break;
        }
        units.push(unit);
    }
    if !terminated {
        return Err("collector descriptor terminator absent".into());
    }
    let sddl = String::from_utf16(&units).map_err(|e| e.to_string())?;
    if owner_sid.len() > 184 || sddl.len() > 8192 || sddl.contains('\0') {
        return Err("collector DACL/MIC provenance bound".into());
    }
    let (trustee_sids, parse_error) = match trustee_sids(dacl) {
        Ok(sids) if sddl.contains("D:") && sddl.contains("S:") => (sids, None),
        Ok(sids) => (
            sids,
            Some("collector DACL/MIC component unavailable".into()),
        ),
        Err(error) => (vec![], Some(error)),
    };
    let sha256 = hex::encode(Sha256::digest(sddl.as_bytes()));
    Ok(AssessmentCollectorObjectSecurity {
        owner_sid,
        sddl,
        sha256,
        trustee_sids,
        parse_error,
    })
}
fn birth(handle: HANDLE) -> Result<String> {
    let mut c = FILETIME::default();
    let mut e = FILETIME::default();
    let mut k = FILETIME::default();
    let mut u = FILETIME::default();
    unsafe { GetProcessTimes(handle, &mut c, &mut e, &mut k, &mut u) }
        .map_err(|e| e.to_string())?;
    let n = ((c.dwHighDateTime as u64) << 32) | c.dwLowDateTime as u64;
    if n == 0 {
        return Err("collector creation time absent".into());
    }
    Ok(n.to_string())
}
fn trusted_descriptor(
    d: &AssessmentCollectorObjectSecurity,
    collector_sid: &str,
    logon: Option<&str>,
) -> bool {
    let trusted = |sid: &str| sid == collector_sid || sid == "S-1-5-18" || sid == "S-1-5-32-544";
    d.parse_error.is_none()
        && trusted(&d.owner_sid)
        && d.trustee_sids
            .iter()
            .all(|s| trusted(s) || logon == Some(s.as_str()))
}
fn default_dacl(token: HANDLE) -> Result<AssessmentCollectorDefaultDacl> {
    use windows::Win32::Security::{GetTokenInformation, TOKEN_DEFAULT_DACL, TokenDefaultDacl};
    // u64 alignment covers TOKEN_DEFAULT_DACL and ACL. Fixed capacity; no
    // caller-controlled allocation or retry, and no token/security mutation.
    let mut storage = vec![0u64; 8192];
    let mut returned = 0;
    unsafe {
        GetTokenInformation(
            token,
            TokenDefaultDacl,
            Some(storage.as_mut_ptr().cast()),
            65536,
            &mut returned,
        )
    }
    .map_err(|_| "collector primary default DACL unavailable")?;
    if returned as usize > 65536 || (returned as usize) < std::mem::size_of::<TOKEN_DEFAULT_DACL>()
    {
        return Err("collector primary default DACL buffer refused".into());
    }
    let acl = unsafe { (*(storage.as_ptr().cast::<TOKEN_DEFAULT_DACL>())).DefaultDacl };
    let start = storage.as_ptr() as usize;
    let end = start + returned as usize;
    let address = acl as usize;
    let failed = |message: &str| AssessmentCollectorDefaultDacl {
        acl_hex: String::new(),
        sha256: hex::encode(Sha256::digest([])),
        trustee_sids: vec![],
        parse_error: Some(message.into()),
    };
    if acl.is_null() {
        return Ok(failed("NULL primary default DACL"));
    }
    if address < start || address.checked_add(8).is_none_or(|n| n > end) {
        return Err("primary default DACL pointer refused".into());
    }
    let size = unsafe { (*acl).AclSize } as usize;
    if !(8..=8192).contains(&size) || address.checked_add(size).is_none_or(|n| n > end) {
        return Err("primary default DACL size refused".into());
    }
    let bytes = unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), size) };
    let (trustee_sids, parse_error) = match trustee_sids(acl) {
        Ok(s) => (s, None),
        Err(e) => (vec![], Some(e)),
    };
    Ok(AssessmentCollectorDefaultDacl {
        acl_hex: hex::encode(bytes),
        sha256: hex::encode(Sha256::digest(bytes)),
        trustee_sids,
        parse_error,
    })
}
fn trusted_default(
    d: &AssessmentCollectorDefaultDacl,
    collector_sid: &str,
    logon: Option<&str>,
) -> bool {
    d.parse_error.is_none()
        && !d.acl_hex.is_empty()
        && d.trustee_sids.iter().all(|s| {
            s == collector_sid
                || s == "S-1-5-18"
                || s == "S-1-5-32-544"
                || logon == Some(s.as_str())
        })
}
pub(super) struct ProtectionHold {
    process: OwnedHandle,
    thread: OwnedHandle,
    fact: AssessmentCollectorProtection,
    collector_sid: String,
    tokens: token::Tokens,
}
impl ProtectionHold {
    pub(super) fn observe(collector_sid: &str, standard: HANDLE) -> Result<Self> {
        guard_no_impersonation()?;
        let pid = unsafe { GetCurrentProcessId() };
        let tid = unsafe { GetCurrentThreadId() };
        let process = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_ACCESS_RIGHTS(0x20000),
                false,
                pid,
            )
        }
        .map_err(|e| e.to_string())?;
        let process = unsafe { OwnedHandle::from_raw_handle(process.0) };
        let thread = unsafe {
            OpenThread(
                THREAD_QUERY_INFORMATION | THREAD_ACCESS_RIGHTS(0x20000),
                false,
                tid,
            )
        }
        .map_err(|e| e.to_string())?;
        let thread = unsafe { OwnedHandle::from_raw_handle(thread.0) };
        if unsafe { GetProcessIdOfThread(raw(&thread)) } != pid {
            return Err("signing thread owner differs".into());
        }
        let tokens = token::Tokens::observe(raw(&process), standard)?;
        let fact = AssessmentCollectorProtection {
            schema_version: ASSESSMENT_COLLECTOR_PROTECTION_V5_SCHEMA.into(),
            storage:
                aiw_provider_wsb::assessment_channel::ChannelCollectorStorage::ProtectedGuestLocal,
            collector_process_id: pid,
            collector_creation_time_100ns: birth(raw(&process))?,
            signing_thread_id: tid,
            process_security: security(raw(&process))?,
            thread_security: security(raw(&thread))?,
            primary_default_dacl: default_dacl(tokens.collector())?,
            token_provenance: None,
            system_token_provenance: Some(tokens.system_facts()?),
            primary_token_owner_sid: Some(tokens.primary_owner_sid()?),
            collector_capabilities: Some(tokens.capabilities()),
            access_checks: vec![],
        };
        Ok(Self {
            process,
            thread,
            fact,
            collector_sid: collector_sid.into(),
            tokens,
        })
    }
    /// Called ONLY inside the freshly held standard-token impersonation scope.
    pub(super) fn probe(&mut self, expected_sid: &str) -> Result<AssessmentCollectorProtection> {
        let sid = super::progress::effective_sid()?;
        if sid != expected_sid {
            return Err("key-boundary probe effective SID differs".into());
        }
        let provenance = self
            .fact
            .system_token_provenance
            .as_ref()
            .ok_or("collector token provenance absent")?;
        if provenance.standard_user_sid != expected_sid {
            return Err("held standard token differs from access-probe actor".into());
        }
        if !self.fact.access_checks.is_empty() {
            return Err("collector access probes already consumed".into());
        }
        for (target, masks) in [
            (
                AssessmentCollectorObject::CollectorProcess,
                ASSESSMENT_COLLECTOR_PROCESS_RIGHTS,
            ),
            (
                AssessmentCollectorObject::SigningThread,
                ASSESSMENT_COLLECTOR_THREAD_RIGHTS,
            ),
        ] {
            for mask in masks {
                let opened = match target {
                    AssessmentCollectorObject::CollectorProcess => unsafe {
                        OpenProcess(
                            PROCESS_ACCESS_RIGHTS(mask),
                            false,
                            self.fact.collector_process_id,
                        )
                    },
                    AssessmentCollectorObject::SigningThread => unsafe {
                        OpenThread(
                            THREAD_ACCESS_RIGHTS(mask),
                            false,
                            self.fact.signing_thread_id,
                        )
                    },
                };
                let (code, denied, error) = match opened {
                    Ok(h) => {
                        drop(unsafe { OwnedHandle::from_raw_handle(h.0) });
                        (Some(0), Some(false), None)
                    }
                    Err(e) if e.code() == HRESULT::from_win32(5) => (Some(5), Some(true), None),
                    Err(e) => {
                        let hr = e.code().0 as u32;
                        let code = if (hr >> 16) & 0x1fff == 7 {
                            Some(hr & 0xffff)
                        } else {
                            None
                        };
                        (
                            code,
                            None,
                            Some(bound_error(&format!("collector object access: {e}"))),
                        )
                    }
                };
                self.fact
                    .access_checks
                    .push(AssessmentCollectorObjectAccess {
                        effective_user_sid: sid.clone(),
                        target,
                        access_mask: mask,
                        native_code: code,
                        denied,
                        error,
                    });
            }
        }
        if super::progress::effective_sid()? != expected_sid {
            return Err("key-boundary effective SID changed".into());
        }
        Ok(self.fact.clone())
    }
    pub(super) fn revalidate(&self) -> Result<()> {
        guard_no_impersonation()?;
        if unsafe { GetCurrentProcessId() } != self.fact.collector_process_id
            || unsafe { GetCurrentThreadId() } != self.fact.signing_thread_id
            || birth(raw(&self.process))? != self.fact.collector_creation_time_100ns
            || unsafe { GetProcessIdOfThread(raw(&self.thread)) } != self.fact.collector_process_id
            || security(raw(&self.process))? != self.fact.process_security
            || security(raw(&self.thread))? != self.fact.thread_security
            || default_dacl(self.tokens.collector())? != self.fact.primary_default_dacl
            || self.fact.primary_token_owner_sid.as_deref()
                != Some(self.tokens.primary_owner_sid()?.as_str())
        {
            return Err("collector process/thread/security identity changed".into());
        }
        self.tokens.revalidate_system(
            raw(&self.process),
            self.fact
                .system_token_provenance
                .as_ref()
                .ok_or("collector token provenance absent")?,
        )?;
        Ok(())
    }
    pub(super) fn require_denied(&self) -> Result<()> {
        self.revalidate()?;
        let standard = self
            .fact
            .system_token_provenance
            .as_ref()
            .ok_or("collector token provenance absent")?;
        let logon = validate_collector_token_provenance(
            &self.fact,
            &self.collector_sid,
            &standard.standard_user_sid,
        )?;
        let descriptors = [&self.fact.process_security, &self.fact.thread_security]
            .into_iter()
            .all(|d| {
                if self.fact.schema_version == ASSESSMENT_COLLECTOR_PROTECTION_V5_SCHEMA {
                    d.parse_error.is_none()
                        && system_collector_owner_trusted(&self.fact, &d.owner_sid)
                        && d.trustee_sids.iter().all(|sid| {
                            matches!(sid.as_str(), "S-1-5-18" | "S-1-5-32-544")
                                || system_collector_extra_trustee(&self.fact, &d.owner_sid, sid)
                        })
                } else {
                    trusted_descriptor(d, &self.collector_sid, logon)
                }
            });
        let default_trusted =
            if self.fact.schema_version == ASSESSMENT_COLLECTOR_PROTECTION_V5_SCHEMA {
                let owner = self
                    .fact
                    .primary_token_owner_sid
                    .as_deref()
                    .ok_or("collector primary owner absent")?;
                let default = &self.fact.primary_default_dacl;
                default.parse_error.is_none()
                    && !default.acl_hex.is_empty()
                    && system_collector_owner_trusted(&self.fact, owner)
                    && default.trustee_sids.iter().all(|sid| {
                        matches!(sid.as_str(), "S-1-5-18" | "S-1-5-32-544")
                            || system_collector_extra_trustee(&self.fact, owner, sid)
                    })
            } else {
                trusted_default(&self.fact.primary_default_dacl, &self.collector_sid, logon)
            };
        if !descriptors
            || !default_trusted
            || self.fact.access_checks.len() != 14
            || self
                .fact
                .access_checks
                .iter()
                .any(|f| f.native_code != Some(5) || f.denied != Some(true) || f.error.is_some())
        {
            return Err("collector key confidentiality unmeasured/allowed or descriptor trustee unsupported; no application created".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn held_primary_owner_change_refuses_before_application_dispatch() {
        use windows::Win32::{
            Security::TOKEN_QUERY,
            System::Threading::{GetCurrentProcess, OpenProcessToken},
        };
        let mut handle = HANDLE::default();
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) }.unwrap();
        let token = unsafe { OwnedHandle::from_raw_handle(handle.0) };
        let primary = token::Tokens::observe(unsafe { GetCurrentProcess() }, raw(&token)).unwrap();
        let sid = primary.system_facts().unwrap().collector_user_sid;
        // Read-only observation of this test runner; it does not claim the
        // runner satisfies SYSTEM0 or use an application token for dispatch.
        let mut held = ProtectionHold::observe(&sid, raw(&token)).unwrap();
        held.revalidate().unwrap();
        held.fact.primary_token_owner_sid = None;
        assert!(held.revalidate().is_err());
        held.fact.primary_token_owner_sid = Some("S-1-1-0".into());
        assert!(held.revalidate().is_err());
    }
    #[test]
    fn null_acl_and_unreviewed_principals_cannot_qualify_collector() {
        assert!(trustee_sids(std::ptr::null()).is_err());
        let owner = "S-1-5-21-1-2-3-504";
        let mut d = AssessmentCollectorObjectSecurity {
            owner_sid: owner.into(),
            sddl: "observed-only-test".into(),
            sha256: String::new(),
            trustee_sids: vec![owner.into(), "S-1-5-18".into(), "S-1-5-32-544".into()],
            parse_error: None,
        };
        assert!(trusted_descriptor(&d, owner, None));
        for sid in [
            "S-1-15-2-1",
            "S-1-1-0",
            "S-1-5-5-1-2",
            "S-1-5-21-1-2-3-1000",
        ] {
            let mut altered = d.clone();
            altered.trustee_sids.push(sid.into());
            assert!(!trusted_descriptor(&altered, owner, None));
        }
        d.parse_error = Some("NULL/unsupported DACL".into());
        assert!(!trusted_descriptor(&d, owner, None));
        let mut default = AssessmentCollectorDefaultDacl {
            acl_hex: "0200080000000000".into(),
            sha256: String::new(),
            trustee_sids: vec![owner.into()],
            parse_error: None,
        };
        assert!(trusted_default(&default, owner, None));
        default.trustee_sids.push("S-1-15-2-1".into());
        assert!(!trusted_default(&default, owner, None));
        default.trustee_sids.clear();
        default.parse_error = Some("NULL primary default DACL".into());
        assert!(!trusted_default(&default, owner, None));
    }
    #[test]
    fn owned_descriptor_memory_exposes_package_ace_to_closed_trustee_gate() {
        use windows::Win32::Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityDescriptorDacl,
        };
        let text: Vec<u16> = "D:(A;;GA;;;SY)(A;;GR;;;S-1-15-2-1)"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                windows::core::PCWSTR(text.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )
        }
        .unwrap();
        let _memory = Local(HLOCAL(sd.0));
        let mut present = windows::core::BOOL(0);
        let mut defaulted = windows::core::BOOL(0);
        let mut acl = std::ptr::null_mut();
        unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut acl, &mut defaulted) }.unwrap();
        assert!(present.as_bool());
        let sids = trustee_sids(acl).unwrap();
        assert!(sids.contains(&"S-1-15-2-1".to_string()));
        let d = AssessmentCollectorObjectSecurity {
            owner_sid: "S-1-5-18".into(),
            sddl: String::new(),
            sha256: String::new(),
            trustee_sids: sids,
            parse_error: None,
        };
        assert!(!trusted_descriptor(&d, "S-1-5-21-1-2-3-504", None));
    }
}
