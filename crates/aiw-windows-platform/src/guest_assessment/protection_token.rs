//! Read-only, held-token provenance for the collector's exact logon trustee.
use super::{Local, Result, raw};
use aiw_provider_wsb::assessment_observation::{
    AssessmentCollectorTokenProvenance, AssessmentTokenGroup,
};
use std::{
    mem::{offset_of, size_of},
    os::windows::io::{BorrowedHandle, FromRawHandle, OwnedHandle},
};
use windows::{
    Win32::{
        Foundation::{HANDLE, HLOCAL},
        Security::{
            Authorization::ConvertSidToStringSidW, GetTokenInformation, IsValidSid, PSID,
            SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_QUERY,
            TOKEN_STATISTICS, TOKEN_TYPE, TOKEN_USER, TokenGroups, TokenLogonSid, TokenPrimary,
            TokenStatistics, TokenType, TokenUser,
        },
        System::Threading::OpenProcessToken,
    },
    core::PWSTR,
};

struct Buffer {
    words: Vec<u64>,
    used: usize,
}
impl Buffer {
    fn query(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<Self> {
        let mut words = vec![0u64; 8192];
        let mut used = 0;
        unsafe {
            GetTokenInformation(
                token,
                class,
                Some(words.as_mut_ptr().cast()),
                65536,
                &mut used,
            )
        }
        .map_err(|_| "collector token query refused")?;
        if used == 0 || used > 65536 {
            return Err("collector token query size refused".into());
        }
        Ok(Self {
            words,
            used: used as usize,
        })
    }
    fn read<T: Copy>(&self, offset: usize) -> Result<T> {
        if offset
            .checked_add(size_of::<T>())
            .is_none_or(|end| end > self.used)
        {
            return Err("collector token structure outside buffer".into());
        }
        // The returned byte extent is checked before every read.
        Ok(unsafe {
            self.words
                .as_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<T>()
                .read_unaligned()
        })
    }
    fn sid(&self, sid: PSID) -> Result<String> {
        let start = self.words.as_ptr() as usize;
        let address = sid.0 as usize;
        let offset = address
            .checked_sub(start)
            .ok_or("collector token SID before buffer")?;
        let revision = self.read::<u8>(offset)?;
        let count = self.read::<u8>(offset.checked_add(1).ok_or("SID offset overflow")?)? as usize;
        if revision != 1
            || count > 15
            || offset
                .checked_add(8 + 4 * count)
                .is_none_or(|end| end > self.used)
            || !unsafe { IsValidSid(sid) }.as_bool()
        {
            return Err("collector token SID layout refused".into());
        }
        let mut text = PWSTR::null();
        unsafe { ConvertSidToStringSidW(sid, &mut text) }
            .map_err(|_| "collector token SID text refused")?;
        let _memory = Local(HLOCAL(text.0.cast()));
        let value =
            unsafe { text.to_string() }.map_err(|_| "collector token SID encoding refused")?;
        if value.len() > 184 {
            return Err("collector token SID text bound".into());
        }
        Ok(value)
    }
    fn groups(&self) -> Result<Vec<AssessmentTokenGroup>> {
        let count = self.read::<u32>(0)? as usize;
        let offset = offset_of!(TOKEN_GROUPS, Groups);
        if count > 256
            || offset
                .checked_add(count * size_of::<SID_AND_ATTRIBUTES>())
                .is_none_or(|end| end > self.used)
        {
            return Err("collector token group count refused".into());
        }
        let mut groups = Vec::with_capacity(count);
        for index in 0..count {
            let group =
                self.read::<SID_AND_ATTRIBUTES>(offset + index * size_of::<SID_AND_ATTRIBUTES>())?;
            groups.push(AssessmentTokenGroup {
                sid: self.sid(group.Sid)?,
                attributes: group.Attributes,
            });
        }
        groups.sort_by(|a, b| a.sid.cmp(&b.sid));
        if groups.windows(2).any(|pair| pair[0].sid == pair[1].sid) {
            return Err("collector token duplicate group".into());
        }
        Ok(groups)
    }
}
fn primary_user(token: HANDLE) -> Result<String> {
    if Buffer::query(token, TokenType)?.read::<TOKEN_TYPE>(0)? != TokenPrimary {
        return Err("collector provenance requires primary token".into());
    }
    let buffer = Buffer::query(token, TokenUser)?;
    buffer.sid(buffer.read::<TOKEN_USER>(0)?.User.Sid)
}
fn open(process: HANDLE) -> Result<OwnedHandle> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }
        .map_err(|_| "collector primary token unavailable")?;
    Ok(unsafe { OwnedHandle::from_raw_handle(token.0) })
}
fn identity(token: HANDLE) -> Result<(u32, i32)> {
    let stat = Buffer::query(token, TokenStatistics)?.read::<TOKEN_STATISTICS>(0)?;
    Ok((stat.TokenId.LowPart, stat.TokenId.HighPart))
}
pub(super) struct Tokens {
    collector: OwnedHandle,
    standard: OwnedHandle,
    collector_id: (u32, i32),
}
impl Tokens {
    pub(super) fn observe(process: HANDLE, standard: HANDLE) -> Result<Self> {
        let collector = open(process)?;
        // Duplicate only this already-held standard token; no name lookup,
        // access expansion, token mutation or privilege adjustment.
        let standard = unsafe { BorrowedHandle::borrow_raw(standard.0) }
            .try_clone_to_owned()
            .map_err(|_| "held standard token duplication refused")?;
        let collector_id = identity(raw(&collector))?;
        Ok(Self {
            collector,
            standard,
            collector_id,
        })
    }
    pub(super) fn collector(&self) -> HANDLE {
        raw(&self.collector)
    }
    pub(super) fn facts(&self) -> Result<AssessmentCollectorTokenProvenance> {
        let logon = Buffer::query(raw(&self.collector), TokenLogonSid)?.groups()?;
        if logon.len() != 1 {
            return Err("collector token requires exactly one logon SID".into());
        }
        Ok(AssessmentCollectorTokenProvenance {
            collector_user_sid: primary_user(raw(&self.collector))?,
            collector_token_type: aiw_token::TokenType::Primary,
            collector_logon_sid: logon[0].sid.clone(),
            collector_logon_attributes: logon[0].attributes,
            standard_user_sid: primary_user(raw(&self.standard))?,
            standard_groups: Buffer::query(raw(&self.standard), TokenGroups)?.groups()?,
        })
    }
    pub(super) fn revalidate(
        &self,
        process: HANDLE,
        expected: &AssessmentCollectorTokenProvenance,
    ) -> Result<()> {
        let current = open(process)?;
        if identity(raw(&current))? != self.collector_id
            || identity(raw(&self.collector))? != self.collector_id
            || &self.facts()? != expected
        {
            return Err("collector held-token provenance changed".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_token_buffers_refuse_before_dereference() {
        let mut b = Buffer {
            words: vec![0; 8192],
            used: 4,
        };
        assert!(b.read::<TOKEN_USER>(0).is_err());
        assert!(b.sid(PSID(std::ptr::null_mut())).is_err());
        b.words[0] = 257;
        b.used = 65536;
        assert!(b.groups().is_err());
        b.words[0] = 1;
        b.used = offset_of!(TOKEN_GROUPS, Groups);
        assert!(b.groups().is_err());
        b.words[0] = 0;
        b.used = 4;
        assert!(b.groups().is_err());
        b.used = 65536;
        assert!(
            b.sid(PSID((b.words.as_ptr() as usize + 65535) as *mut _))
                .is_err()
        );
        assert!(
            b.sid(PSID((b.words.as_ptr() as usize + 65536) as *mut _))
                .is_err()
        );
    }
    #[test]
    fn actual_primary_token_logon_and_groups_are_repeatable() {
        let process = unsafe { windows::Win32::System::Threading::GetCurrentProcess() };
        let token = open(process).unwrap();
        let held = Tokens::observe(process, raw(&token)).unwrap();
        let facts = held.facts().unwrap();
        assert!(facts.collector_logon_sid.starts_with("S-1-5-5-"));
        assert_eq!(facts.collector_user_sid, facts.standard_user_sid);
        assert!(
            facts
                .standard_groups
                .iter()
                .any(|g| g.sid == facts.collector_logon_sid)
        );
        held.revalidate(process, &facts).unwrap();
        let mut changed = facts.clone();
        changed.collector_user_sid = "S-1-5-18".into();
        if changed != facts {
            assert!(held.revalidate(process, &changed).is_err());
        }
        // The real same-token observation must NOT qualify as standard-user
        // exclusion, even though querying it is a useful read-only native test.
    }
}
