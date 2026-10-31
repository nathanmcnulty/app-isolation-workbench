//! Read-only host prerequisites; never creates a partition or invokes Sandbox.
//!
//! PF21 can be false in a running Hyper-V root partition. The supported WHP
//! capability query independently establishes an active Windows hypervisor.
//! Generic hypervisor/CPUID vendor flags cannot establish that capability.
use aiw_probe::ReadinessState;
use std::ffi::c_void;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use windows::Win32::Foundation::{FreeLibrary, HMODULE};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows::Win32::System::Threading::{IsProcessorFeaturePresent, PF_VIRT_FIRMWARE_ENABLED};
use windows::core::{PCWSTR, s};

#[derive(Clone, Copy, Debug)]
struct HypervisorQuery {
    hresult: i32,
    written: u32,
    present: u32,
}
impl HypervisorQuery {
    fn verifies_active_windows_hypervisor(self) -> bool {
        self.hresult == 0 && self.written == 4 && self.present == 1
    }
}
pub(super) struct Observation {
    firmware_flag: bool,
    hypervisor_query: Option<HypervisorQuery>,
}
impl Observation {
    pub(super) fn uses_active_hypervisor(&self) -> bool {
        !self.firmware_flag
            && self
                .hypervisor_query
                .is_some_and(HypervisorQuery::verifies_active_windows_hypervisor)
    }
    pub(super) fn readiness(&self) -> ReadinessState {
        if self.firmware_flag || self.uses_active_hypervisor() {
            ReadinessState::Available
        } else {
            ReadinessState::Unknown
        }
    }
}
pub(super) fn observe() -> Observation {
    // These are capability observations, not a proof that Sandbox can launch.
    let firmware_flag = unsafe { IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED).as_bool() };
    Observation {
        firmware_flag,
        hypervisor_query: if firmware_flag {
            None
        } else {
            query_hypervisor()
        },
    }
}

struct Module(HMODULE);
impl Drop for Module {
    fn drop(&mut self) {
        // SAFETY: successful LoadLibraryExW returned this owned module reference.
        let _ = unsafe { FreeLibrary(self.0) };
    }
}
fn query_hypervisor() -> Option<HypervisorQuery> {
    let mut directory = [0u16; 260];
    // SAFETY: a correctly sized writable buffer; truncation is rejected below.
    let length = unsafe { GetSystemDirectoryW(Some(&mut directory)) } as usize;
    if length == 0 || length >= directory.len() {
        return None;
    }
    let directory = PathBuf::from(std::ffi::OsString::from_wide(&directory[..length]));
    if !directory.is_absolute() {
        return None;
    }
    let path: Vec<u16> = directory
        .join("WinHvPlatform.dll")
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: an OS-supplied absolute System32 path and restricted dependency
    // search. No caller path, PATH search, executable or script is accepted.
    let module = Module(unsafe {
        LoadLibraryExW(PCWSTR(path.as_ptr()), None, LOAD_LIBRARY_SEARCH_SYSTEM32).ok()?
    });
    // SAFETY: module remains held until after the call; fixed documented export.
    let address = unsafe { GetProcAddress(module.0, s!("WHvGetCapability")) }?;
    type Query = unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32;
    // SAFETY: exact ABI of WHvGetCapability, dynamically loaded because WHP is
    // optional. Missing DLL/export is Unknown, never a load-time startup failure.
    let query: Query = unsafe { std::mem::transmute(address) };
    let mut present = 0u32;
    let mut written = 0u32;
    // SAFETY: capability code 0 is HypervisorPresent; both outputs are correctly
    // aligned/sized and initialized. This query creates no partition or process.
    let hresult = unsafe {
        query(
            0,
            (&mut present as *mut u32).cast(),
            std::mem::size_of::<u32>() as u32,
            &mut written,
        )
    };
    Some(HypervisorQuery {
        hresult,
        written,
        present,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_windows_hypervisor_is_an_independent_prerequisite_observation() {
        let active = HypervisorQuery {
            hresult: 0,
            written: 4,
            present: 1,
        };
        let observation = Observation {
            firmware_flag: false,
            hypervisor_query: Some(active),
        };
        assert_eq!(observation.readiness(), ReadinessState::Available);
        assert!(observation.uses_active_hypervisor());
        let firmware = Observation {
            firmware_flag: true,
            hypervisor_query: None,
        };
        assert_eq!(firmware.readiness(), ReadinessState::Available);
        assert!(!firmware.uses_active_hypervisor());
    }

    #[test]
    fn missing_failed_short_or_malformed_queries_cannot_establish_availability() {
        for hypervisor_query in [
            None,
            Some(HypervisorQuery {
                hresult: -1,
                written: 4,
                present: 1,
            }),
            Some(HypervisorQuery {
                hresult: 1,
                written: 4,
                present: 1,
            }),
            Some(HypervisorQuery {
                hresult: 0,
                written: 0,
                present: 1,
            }),
            Some(HypervisorQuery {
                hresult: 0,
                written: 8,
                present: 1,
            }),
            Some(HypervisorQuery {
                hresult: 0,
                written: 4,
                present: 0,
            }),
            Some(HypervisorQuery {
                hresult: 0,
                written: 4,
                present: 2,
            }),
        ] {
            let observation = Observation {
                firmware_flag: false,
                hypervisor_query,
            };
            assert_eq!(observation.readiness(), ReadinessState::Unknown);
            assert!(!observation.uses_active_hypervisor());
        }
    }
}
