//! Fixed, read-only MSI identity and machine-registration queries in the guest.
//! No installer session, product enumeration, repair, or caller-supplied SQL.
use aiw_provider_wsb::{MsiMachineProductState, validate_msi_product_code};
use windows::core::{PCWSTR, PWSTR, w};

use crate::guest_msi::{GuestMsiExecutionError, GuestMsiProductRegistrationObservation};

#[link(name = "Msi")]
unsafe extern "system" {
    fn MsiOpenDatabaseW(path: PCWSTR, persist: PCWSTR, database: *mut u32) -> u32;
    fn MsiDatabaseOpenViewW(database: u32, query: PCWSTR, view: *mut u32) -> u32;
    fn MsiViewExecute(view: u32, record: u32) -> u32;
    fn MsiViewFetch(view: u32, record: *mut u32) -> u32;
    fn MsiRecordGetStringW(record: u32, field: u32, value: PWSTR, length: *mut u32) -> u32;
    fn MsiCloseHandle(handle: u32) -> u32;
    fn MsiGetProductInfoExW(
        product: PCWSTR,
        user_sid: PCWSTR,
        context: u32,
        property: PCWSTR,
        value: PWSTR,
        length: *mut u32,
    ) -> u32;
}

const ERROR_SUCCESS: u32 = 0;
const ERROR_INVALID_DATA: u32 = 13;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const ERROR_UNKNOWN_PRODUCT: u32 = 1605;
const MSIINSTALLCONTEXT_MACHINE: u32 = 4;

struct MsiHandle(u32);
impl Drop for MsiHandle {
    fn drop(&mut self) {
        // SAFETY: each successful MSI handle acquisition has one owner and is
        // dropped on the acquiring thread, after dependent handles are dropped.
        unsafe {
            MsiCloseHandle(self.0);
        }
    }
}

fn handle_result(
    code: u32,
    handle: u32,
    operation: &str,
) -> Result<MsiHandle, GuestMsiExecutionError> {
    if code == ERROR_SUCCESS && handle != 0 {
        Ok(MsiHandle(handle))
    } else {
        Err(failure(operation, code))
    }
}

fn failure(operation: &str, code: u32) -> GuestMsiExecutionError {
    GuestMsiExecutionError::Process(format!(
        "fixed MSI product {operation} failed with code {code}"
    ))
}

fn canonical_product_code(buffer: &[u16], length: u32) -> Result<String, GuestMsiExecutionError> {
    if length != 38 || buffer.len() <= 38 || buffer[38] != 0 {
        return Err(failure("identity shape", ERROR_INVALID_DATA));
    }
    let code = String::from_utf16(&buffer[..38])
        .map_err(|_| failure("identity encoding", ERROR_INVALID_DATA))?
        .to_ascii_uppercase();
    validate_msi_product_code(&code).map_err(|_| failure("identity format", ERROR_INVALID_DATA))?;
    Ok(code)
}

fn read_fixed_product_code() -> Result<String, GuestMsiExecutionError> {
    let mut database = 0;
    // SAFETY: fixed terminated path; null persist means MSIDBOPEN_READONLY,
    // never MsiOpenPackage or a running installation. Output pointer is valid.
    let result = unsafe {
        MsiOpenDatabaseW(
            w!(r"C:\AIW\Tools\application.msi"),
            PCWSTR::null(),
            &mut database,
        )
    };
    let database = handle_result(result, database, "database open")?;
    let mut view = 0;
    // SAFETY: live database, fixed one-column query, writable handle output.
    let result = unsafe {
        MsiDatabaseOpenViewW(
            database.0,
            w!("SELECT `Value` FROM `Property` WHERE `Property` = 'ProductCode'"),
            &mut view,
        )
    };
    let view = handle_result(result, view, "view open")?;
    // SAFETY: live view and no parameter record; query has no parameters.
    let result = unsafe { MsiViewExecute(view.0, 0) };
    if result != ERROR_SUCCESS {
        return Err(failure("view execute", result));
    }
    let mut record = 0;
    // SAFETY: live executed view and valid record output.
    let result = unsafe { MsiViewFetch(view.0, &mut record) };
    let record = handle_result(result, record, "identity fetch")?;
    let mut buffer = [0u16; 39];
    let mut length = buffer.len() as u32;
    // SAFETY: live record, fixed queried field, buffer length includes its terminator.
    let result =
        unsafe { MsiRecordGetStringW(record.0, 1, PWSTR(buffer.as_mut_ptr()), &mut length) };
    if result != ERROR_SUCCESS {
        return Err(failure("identity read", result));
    }
    let code = canonical_product_code(&buffer, length)?;
    let mut extra = 0;
    // SAFETY: same live view, valid output. Reject more than one row rather than
    // choosing an identity; a second successful handle is still closed.
    let result = unsafe { MsiViewFetch(view.0, &mut extra) };
    if result == ERROR_SUCCESS {
        let _extra = handle_result(result, extra, "extra identity")?;
        return Err(failure("duplicate identity", ERROR_INVALID_DATA));
    }
    if result != ERROR_NO_MORE_ITEMS {
        return Err(failure("identity completion", result));
    }
    Ok(code)
}

fn decode_machine_state(code: u32, buffer: &[u16], length: u32) -> MsiMachineProductState {
    match code {
        ERROR_UNKNOWN_PRODUCT => MsiMachineProductState::NotRegistered,
        ERROR_SUCCESS if length == 1 && buffer.len() >= 2 && buffer[1] == 0 => match buffer[0] {
            49 => MsiMachineProductState::Advertised,
            53 => MsiMachineProductState::Installed,
            _ => MsiMachineProductState::Unavailable {
                error_code: ERROR_INVALID_DATA,
            },
        },
        ERROR_SUCCESS => MsiMachineProductState::Unavailable {
            error_code: ERROR_INVALID_DATA,
        },
        error_code => MsiMachineProductState::Unavailable { error_code },
    }
}

fn machine_state(product_code: &str) -> MsiMachineProductState {
    let product: Vec<u16> = product_code.encode_utf16().chain(Some(0)).collect();
    let mut value = [0u16; 8];
    let mut length = value.len() as u32;
    // SAFETY: canonical terminated GUID, explicit machine context with null
    // SID, fixed INSTALLPROPERTY_PRODUCTSTATE, bounded writable output. This
    // query neither installs nor repairs the product and is called outside MSI execution.
    let code = unsafe {
        MsiGetProductInfoExW(
            PCWSTR(product.as_ptr()),
            PCWSTR::null(),
            MSIINSTALLCONTEXT_MACHINE,
            w!("State"),
            PWSTR(value.as_mut_ptr()),
            &mut length,
        )
    };
    decode_machine_state(code, &value, length)
}

pub(crate) struct ProductCapture {
    product_code: String,
    before_install: MsiMachineProductState,
}

impl ProductCapture {
    pub(crate) fn before_install() -> Result<Self, GuestMsiExecutionError> {
        let product_code = read_fixed_product_code()?;
        let before_install = machine_state(&product_code);
        Ok(Self {
            product_code,
            before_install,
        })
    }

    pub(crate) fn after_install(self) -> GuestMsiProductRegistrationObservation {
        let after_install = machine_state(&self.product_code);
        GuestMsiProductRegistrationObservation {
            product_code: self.product_code,
            before_install: self.before_install,
            after_install,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_identity_requires_one_complete_guid() {
        let text = "{a1234567-89ab-cdef-0123-456789abcdef}";
        let value: Vec<_> = text.encode_utf16().chain(Some(0)).collect();
        assert_eq!(
            canonical_product_code(&value, 38).unwrap(),
            text.to_ascii_uppercase()
        );
        assert!(canonical_product_code(&value, 37).is_err());
        assert!(canonical_product_code(&value[..38], 38).is_err());
        let mut invalid = value.clone();
        invalid[4] = 0;
        assert!(canonical_product_code(&invalid, 38).is_err());
        invalid[4] = 0xd800;
        assert!(canonical_product_code(&invalid, 38).is_err());
    }

    #[test]
    fn registration_errors_are_never_installed_or_not_registered() {
        assert_eq!(
            decode_machine_state(1605, &[], 0),
            MsiMachineProductState::NotRegistered
        );
        assert_eq!(
            decode_machine_state(0, &[49, 0], 1),
            MsiMachineProductState::Advertised
        );
        assert_eq!(
            decode_machine_state(0, &[53, 0], 1),
            MsiMachineProductState::Installed
        );
        for (code, value, length) in [
            (5, vec![53, 0], 1),
            (234, vec![53, 0], 9),
            (0, vec![53, 53], 1),
            (0, vec![50, 0], 1),
            (0, vec![], 0),
        ] {
            assert!(matches!(
                decode_machine_state(code, &value, length),
                MsiMachineProductState::Unavailable { .. }
            ));
        }
    }
}
