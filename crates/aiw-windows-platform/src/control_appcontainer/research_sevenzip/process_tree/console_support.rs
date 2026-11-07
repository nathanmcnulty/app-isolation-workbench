//! Fixed OS support-image custody; never launches a console host.
use super::super::*;
use aiw_provider_wsb::sevenzip_tree_control::SevenZipConsoleSupportObservation;
use windows::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle};
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;

const IMAGE: &str = r"C:\Windows\System32\conhost.exe";

pub(in super::super) struct HeldConsoleSupport {
    _directories: Vec<fs::File>,
    image: HeldApplicationFile,
    legacy_handle: fs::File,
    pub(super) observation: SevenZipConsoleSupportObservation,
}

fn legacy_identity(file: &fs::File) -> Result<(u32, u64, u64)> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: this read-only file reference stays held throughout the query.
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }?;
    if info.dwFileAttributes & 0x450 != 0 || info.nNumberOfLinks != 1 {
        return Err("console support is not an ordinary single-link file".into());
    }
    let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    let size = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
    if index == 0 || info.dwVolumeSerialNumber == 0 {
        return Err("zero console support identity".into());
    }
    Ok((info.dwVolumeSerialNumber, index, size))
}

impl HeldConsoleSupport {
    pub(in super::super) fn open() -> Result<Self> {
        // Parent workflow is ordinary; no contained role performs WinRT or
        // independently authorizes a different OS. Exact guest pin is unchanged.
        let windows = crate::observe_windows_version()?;
        super::validate_preexecution_windows(&windows)?;
        let mut directory = [0_u16; 32768];
        // SAFETY: bounded writable buffer for the native OS directory query.
        let length = unsafe { GetSystemDirectoryW(Some(&mut directory)) } as usize;
        if length == 0
            || length >= directory.len()
            || !String::from_utf16(&directory[..length])?
                .eq_ignore_ascii_case(r"C:\Windows\System32")
        {
            return Err("console support requires the exact native System32 directory".into());
        }
        let directories = hold_directory_chain(Path::new(r"C:\Windows\System32"))?;
        let image = HeldApplicationFile::open_bounded(Path::new(IMAGE), 32 * 1024 * 1024)?;
        // HAF holds the path and single-link file against replacement/writes.
        // This second no-follow read reference obtains the actual legacy ID
        // used by debug-event observations; no 128-to-64-bit layout is assumed.
        let legacy_handle = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ.0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(IMAGE)?;
        let (volume, index, size) = legacy_identity(&legacy_handle)?;
        if size != image.observation().size_bytes {
            return Err("console support handles differ".into());
        }
        image.revalidate()?;
        let observation = SevenZipConsoleSupportObservation {
            schema_version: "aiw.dev/sevenzip-console-support/v0alpha1".into(),
            windows,
            canonical_path: image.observation().canonical_path.clone(),
            identity: image.observation().identity.clone(),
            sha256: image.observation().sha256.clone(),
            size_bytes: size,
            volume_serial_number: volume,
            file_index: index,
        };
        observation.validate_pinned()?;
        Ok(Self {
            _directories: directories,
            image,
            legacy_handle,
            observation,
        })
    }

    pub(super) fn revalidate(&self) -> Result<()> {
        self.image.revalidate()?;
        let (volume, index, size) = legacy_identity(&self.legacy_handle)?;
        if (volume, index, size)
            != (
                self.observation.volume_serial_number,
                self.observation.file_index,
                self.observation.size_bytes,
            )
        {
            return Err("held console support identity changed".into());
        }
        self.observation.validate_pinned()?;
        Ok(())
    }
}
