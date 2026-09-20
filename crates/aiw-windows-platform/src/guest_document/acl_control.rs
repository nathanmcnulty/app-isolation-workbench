//! Fixed control files retained through application exit; no caller-supplied paths.

use super::*;
use crate::workspace::{OwnedSid, create_owner_system_file, verify_owner_system_acl};
use aiw_provider_wsb::{
    STANDARD_USER_ACL_CONTROL_BYTES, STANDARD_USER_ACL_POSITIVE_PATH,
    STANDARD_USER_ACL_PROTECTED_PATH, StandardUserAclObservation,
};
use std::io::{Seek as _, SeekFrom};

const SHARE_ALL: u32 = FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0;

struct HeldControlFile {
    ancestors: Vec<File>,
    file: File,
    identity: BY_HANDLE_FILE_INFORMATION,
    leaf: &'static str,
}

impl HeldControlFile {
    fn revalidate(&self) -> Result<(), String> {
        for ancestor in &self.ancestors {
            if !ordinary_directory(&file_information(ancestor)?) {
                return Err("ACL control ancestor changed type".into());
            }
        }
        let reopened = nt_open_relative(
            self.ancestors.last().ok_or("ACL control parent not held")?,
            self.leaf,
            false,
            FILE_OPEN_DISPOSITION,
            FILE_READ_DATA.0 | FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0 | SYNCHRONIZE.0,
            SHARE_ALL,
        )
        .map_err(|error| relative_error("reopen ACL control", error))?;
        for file in [&self.file, &reopened] {
            let info = file_information(file)?;
            if !ordinary_file(&info) || !same_file_information(&info, &self.identity) {
                return Err("ACL control file identity, links, size, or type changed".into());
            }
            let mut reader = file;
            reader
                .seek(SeekFrom::Start(0))
                .map_err(|e| format!("seek ACL control: {e}"))?;
            let mut bytes = Vec::new();
            reader
                .take(STANDARD_USER_ACL_CONTROL_BYTES.len() as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| format!("read ACL control: {e}"))?;
            if bytes != STANDARD_USER_ACL_CONTROL_BYTES
                || !same_file_information(&file_information(file)?, &self.identity)
            {
                return Err("ACL control bytes changed".into());
            }
        }
        Ok(())
    }
}

pub(crate) struct FixedGuestAclControl {
    protected: HeldControlFile,
    owner: OwnedSid,
    owner_sid: String,
    positive: Option<HeldControlFile>,
    denied_read_error: Option<u32>,
}

impl FixedGuestAclControl {
    /// Runs elevated before installation. Existing files are never adopted or repaired.
    pub(crate) fn prepare() -> Result<Self, String> {
        let token = aiw_token::collect_current_process_token().map_err(|e| e.to_string())?;
        if !token.is_elevated || token.is_app_container {
            return Err("ACL control preparation requires the elevated guest agent".into());
        }
        let ancestors =
            held_directory_chain_with_sharing(Path::new(FIXED_ROOT), FILE_SHARE_READ.0)?;
        let mut file =
            create_owner_system_file(Path::new(STANDARD_USER_ACL_PROTECTED_PATH), &token.user_sid)
                .map_err(|e| format!("create protected ACL control: {e}"))?;
        file.write_all(STANDARD_USER_ACL_CONTROL_BYTES)
            .map_err(|e| format!("write ACL control: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("flush ACL control: {e}"))?;
        let identity = file_information(&file)?;
        let value = Self {
            protected: HeldControlFile {
                ancestors,
                file,
                identity,
                leaf: "acl-canary.txt",
            },
            owner: OwnedSid::from_string(&token.user_sid).map_err(|e| e.to_string())?,
            owner_sid: token.user_sid,
            positive: None,
            denied_read_error: None,
        };
        value.revalidate()?;
        Ok(value)
    }

    /// Caller must impersonate the primary token opened from the held application process.
    /// Uses path-based read access for the negative control, never a privileged file handle.
    pub(crate) fn probe_as_application(&mut self) -> Result<(), String> {
        if self.positive.is_some() {
            return Err("ACL control was already probed".into());
        }
        // Establish that the app can traverse the protected file's ordinary parent.
        let parent = held_directory_chain_with_sharing(Path::new(FIXED_ROOT), FILE_SHARE_READ.0)?;
        if !same_file_information(
            &file_information(parent.last().ok_or("ACL control parent absent")?)?,
            &file_information(
                self.protected
                    .ancestors
                    .last()
                    .ok_or("ACL parent not held")?,
            )?,
        ) {
            return Err("ACL control parent identity changed".into());
        }
        let path = Path::new(STANDARD_USER_ACL_POSITIVE_PATH);
        let ancestors = held_directory_chain_with_sharing(
            path.parent().ok_or("positive ACL parent missing")?,
            FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0,
        )?;
        let mut file = nt_open_relative(
            ancestors.last().ok_or("positive ACL parent not held")?,
            "acl-positive.txt",
            false,
            FILE_CREATE_DISPOSITION,
            FILE_READ_DATA.0
                | FILE_WRITE_DATA.0
                | FILE_READ_ATTRIBUTES.0
                | READ_CONTROL.0
                | SYNCHRONIZE.0,
            FILE_SHARE_READ.0,
        )
        .map_err(|e| relative_error("create positive ACL control as application", e))?;
        file.write_all(STANDARD_USER_ACL_CONTROL_BYTES)
            .map_err(|e| format!("positive ACL write: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("positive ACL flush: {e}"))?;
        let positive = HeldControlFile {
            identity: file_information(&file)?,
            ancestors,
            file,
            leaf: "acl-positive.txt",
        };
        positive.revalidate()?;
        self.positive = Some(positive);

        let denied = OpenOptions::new()
            .access_mode(FILE_READ_DATA.0)
            .share_mode(SHARE_ALL)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(STANDARD_USER_ACL_PROTECTED_PATH);
        match denied {
            Err(error) if error.raw_os_error() == Some(5) => {
                self.denied_read_error = error.raw_os_error().map(|code| code as u32);
                Ok(())
            }
            Err(error) => Err(format!(
                "protected ACL read did not prove access denial: Win32={:?}; {error}",
                error.raw_os_error()
            )),
            Ok(_) => Err(
                "protected ACL control was unexpectedly readable by the application token".into(),
            ),
        }
    }

    pub(crate) fn revalidate(&self) -> Result<(), String> {
        self.protected.revalidate()?;
        verify_owner_system_acl(&self.protected.file, &self.owner, true, false)
            .map_err(|e| format!("protected ACL control DACL changed: {e}"))?;
        if let Some(positive) = &self.positive {
            positive.revalidate()?;
        }
        Ok(())
    }

    pub(crate) fn observation(
        &self,
        process_id: u32,
        user_sid: &str,
    ) -> Result<StandardUserAclObservation, String> {
        self.revalidate()?;
        let positive = self
            .positive
            .as_ref()
            .ok_or("positive ACL control missing")?;
        let identity = |info: &BY_HANDLE_FILE_INFORMATION| {
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow)
        };
        let hash = sha256(STANDARD_USER_ACL_CONTROL_BYTES);
        let value = StandardUserAclObservation {
            process_id,
            user_sid: user_sid.into(),
            protected_path: STANDARD_USER_ACL_PROTECTED_PATH.into(),
            protected_owner_sid: self.owner_sid.clone(),
            protected_volume_serial: self.protected.identity.dwVolumeSerialNumber,
            protected_file_id: identity(&self.protected.identity),
            protected_sha256: hash.clone(),
            protected_size_bytes: STANDARD_USER_ACL_CONTROL_BYTES.len() as u64,
            protected_acl_verified: true,
            denied_read_error: self
                .denied_read_error
                .ok_or("protected ACL denial was not observed")?,
            positive_path: STANDARD_USER_ACL_POSITIVE_PATH.into(),
            positive_volume_serial: positive.identity.dwVolumeSerialNumber,
            positive_file_id: identity(&positive.identity),
            positive_sha256: hash,
            positive_size_bytes: STANDARD_USER_ACL_CONTROL_BYTES.len() as u64,
        };
        value.validate()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acl_control_rejects_changed_bytes_and_blocks_replacement() {
        let root = std::env::temp_dir().join(format!(
            "aiw-acl-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("acl-canary.txt");
        let token = aiw_token::collect_current_process_token().unwrap();
        let owner = OwnedSid::from_string(&token.user_sid).unwrap();
        let mut file = create_owner_system_file(&path, &token.user_sid).unwrap();
        file.write_all(STANDARD_USER_ACL_CONTROL_BYTES).unwrap();
        file.sync_all().unwrap();
        let mut held = HeldControlFile {
            ancestors: vec![open_fixture_root(&root).unwrap()],
            identity: file_information(&file).unwrap(),
            file,
            leaf: "acl-canary.txt",
        };
        held.revalidate().unwrap();
        verify_owner_system_acl(&held.file, &owner, true, false).unwrap();
        // A read with compatible sharing must succeed for the owner: the live
        // negative probe cannot pass merely because our retained handle exists.
        let readable = OpenOptions::new()
            .access_mode(FILE_READ_DATA.0)
            .share_mode(SHARE_ALL)
            .open(&path)
            .unwrap();
        drop(readable);
        assert!(std::fs::rename(&path, root.join("moved.txt")).is_err());
        assert!(create_owner_system_file(&path, &token.user_sid).is_err());
        held.file.seek(SeekFrom::Start(0)).unwrap();
        held.file
            .write_all(&vec![b'X'; STANDARD_USER_ACL_CONTROL_BYTES.len()])
            .unwrap();
        held.file.sync_all().unwrap();
        assert!(held.revalidate().unwrap_err().contains("bytes changed"));
        drop(held);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }
}
