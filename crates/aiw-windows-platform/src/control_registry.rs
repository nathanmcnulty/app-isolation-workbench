//! Fixed, read-only registry control canary. It accepts no caller-supplied hive,
//! view, key, or value input.

use serde::Serialize;
use sha2::{Digest, Sha256};

const HKLM: isize = 0x8000_0002u32 as i32 as isize;
const KEY_QUERY_VALUE: u32 = 0x0001;
const KEY_WOW64_64KEY: u32 = 0x0100;
const REG_BINARY: u32 = 3;
const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_PATH_NOT_FOUND: i32 = 3;
const ERROR_ACCESS_DENIED: i32 = 5;
const MAX_VALUE_BYTES: usize = 1024;
const FIXED_CANARY: &[u8] = b"AIW controlled registry bytes";
const KEY: &str = r"SOFTWARE\AIWControlCanary";
const VALUE: &str = "Canary";

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
    fn RegQueryValueExW(
        key: isize,
        name: *const u16,
        reserved: *mut u32,
        value_type: *mut u32,
        data: *mut u8,
        data_len: *mut u32,
    ) -> i32;
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ControlRegistryReadProbe {
    pub scope: ControlRegistryScope,
    pub outcome: ControlRegistryReadOutcome,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ControlRegistryScope {
    pub hive: &'static str,
    pub view: &'static str,
    pub key: &'static str,
    pub value: &'static str,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ControlRegistryReadStage {
    OpenKey,
    QuerySize,
    QueryValue,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum ControlRegistryReadOutcome {
    Success {
        sha256: String,
        size_bytes: u64,
    },
    AccessDenied {
        native_code: u32,
        stage: ControlRegistryReadStage,
    },
    NotFound {
        native_code: u32,
        stage: ControlRegistryReadStage,
    },
    NativeFailure {
        native_code: u32,
        stage: ControlRegistryReadStage,
    },
    InvalidValue {
        reason: &'static str,
    },
}

struct RegistryKey(isize);
impl Drop for RegistryKey {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

/// Reads only HKLM's 64-bit `SOFTWARE\AIWControlCanary\Canary` value.
pub fn read_fixed_control_registry_canary() -> ControlRegistryReadProbe {
    let scope = ControlRegistryScope {
        hive: "HKLM",
        view: "registry64",
        key: KEY,
        value: VALUE,
    };
    let outcome = match open_fixed_key() {
        Ok(key) => query_fixed_value(&key),
        Err(status) => classify_status(status, ControlRegistryReadStage::OpenKey),
    };
    ControlRegistryReadProbe { scope, outcome }
}

fn open_fixed_key() -> Result<RegistryKey, i32> {
    let mut raw = 0isize;
    let name = wide(KEY);
    let status = unsafe {
        RegOpenKeyExW(
            HKLM,
            name.as_ptr(),
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &mut raw,
        )
    };
    if status == 0 && raw != 0 {
        Ok(RegistryKey(raw))
    } else if status == 0 {
        Err(6)
    } else {
        Err(status)
    }
}

fn query_fixed_value(key: &RegistryKey) -> ControlRegistryReadOutcome {
    let name = wide(VALUE);
    let mut value_type = 0u32;
    let mut size = 0u32;
    let first = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            core::ptr::null_mut(),
            &mut value_type,
            core::ptr::null_mut(),
            &mut size,
        )
    };
    if first != 0 {
        return classify_status(first, ControlRegistryReadStage::QuerySize);
    }
    if value_type != REG_BINARY {
        return ControlRegistryReadOutcome::InvalidValue {
            reason: "valueType",
        };
    }
    if size as usize > MAX_VALUE_BYTES {
        return ControlRegistryReadOutcome::InvalidValue {
            reason: "valueSize",
        };
    }
    let mut bytes = vec![0u8; size as usize];
    let second = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            core::ptr::null_mut(),
            &mut value_type,
            bytes.as_mut_ptr(),
            &mut size,
        )
    };
    if second != 0 {
        return classify_status(second, ControlRegistryReadStage::QueryValue);
    }
    if value_type != REG_BINARY {
        return ControlRegistryReadOutcome::InvalidValue {
            reason: "valueTypeChanged",
        };
    }
    if size as usize > bytes.len() || size as usize > MAX_VALUE_BYTES {
        return ControlRegistryReadOutcome::InvalidValue {
            reason: "valueSizeChanged",
        };
    }
    bytes.truncate(size as usize);
    classify_value(&bytes)
}

fn classify_status(status: i32, stage: ControlRegistryReadStage) -> ControlRegistryReadOutcome {
    match status {
        ERROR_ACCESS_DENIED => ControlRegistryReadOutcome::AccessDenied {
            native_code: status as u32,
            stage,
        },
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => ControlRegistryReadOutcome::NotFound {
            native_code: status as u32,
            stage,
        },
        code => ControlRegistryReadOutcome::NativeFailure {
            native_code: code as u32,
            stage,
        },
    }
}

fn classify_value(bytes: &[u8]) -> ControlRegistryReadOutcome {
    if bytes != FIXED_CANARY {
        return ControlRegistryReadOutcome::InvalidValue {
            reason: "valueBytes",
        };
    }
    ControlRegistryReadOutcome::Success {
        sha256: hex::encode(Sha256::digest(bytes)),
        size_bytes: bytes.len() as u64,
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classifies_fixed_native_statuses() {
        assert_eq!(
            classify_status(ERROR_ACCESS_DENIED, ControlRegistryReadStage::OpenKey),
            ControlRegistryReadOutcome::AccessDenied {
                native_code: 5,
                stage: ControlRegistryReadStage::OpenKey
            }
        );
        assert_eq!(
            classify_status(ERROR_FILE_NOT_FOUND, ControlRegistryReadStage::QuerySize),
            ControlRegistryReadOutcome::NotFound {
                native_code: 2,
                stage: ControlRegistryReadStage::QuerySize
            }
        );
        assert_eq!(
            classify_status(87, ControlRegistryReadStage::QueryValue),
            ControlRegistryReadOutcome::NativeFailure {
                native_code: 87,
                stage: ControlRegistryReadStage::QueryValue
            }
        );
    }
    #[test]
    fn accepts_only_the_fixed_binary_canary() {
        assert!(matches!(
            classify_value(FIXED_CANARY),
            ControlRegistryReadOutcome::Success { size_bytes: 29, .. }
        ));
        assert_eq!(
            classify_value(b"different"),
            ControlRegistryReadOutcome::InvalidValue {
                reason: "valueBytes"
            }
        );
    }
}
