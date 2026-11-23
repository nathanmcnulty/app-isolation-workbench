//! A suspended child's three stdio objects and one excluded inheritable canary.
//! This is not proof of all possible handle inheritance or post-resume activity.
use super::Result;
use std::{collections::BTreeSet, time::Instant};
use windows::{
    Win32::{
        Foundation::{
            CloseHandle, CompareObjectHandles, DUPLICATE_SAME_ACCESS, DuplicateHandle,
            ERROR_NO_MORE_ITEMS, ERROR_NOT_SAME_OBJECT, GetLastError, HANDLE, SetLastError,
            WIN32_ERROR,
        },
        Security::SECURITY_ATTRIBUTES,
        System::{
            Diagnostics::ProcessSnapshotting::*,
            Threading::{CreateEventW, GetCurrentProcess, GetProcessHandleCount},
        },
    },
    core::{BOOL, PCWSTR},
};

const MAX_HANDLES: u32 = 256;

#[derive(Default)]
struct KernelLease(Option<HANDLE>);
impl KernelLease {
    fn handle(&self) -> HANDLE {
        self.0.expect("owned handle retained until checked close")
    }
    fn close(&mut self) -> Result<()> {
        if let Some(handle) = self.0.take() {
            // SAFETY: one owned, non-pseudo handle. Consume ownership even on
            // failure; its disposition is unknown and must never permit Resume.
            unsafe { CloseHandle(handle) }.map_err(|e| format!("handle close: {e}"))?;
        }
        Ok(())
    }
}
impl Drop for KernelLease {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[derive(Default)]
struct Snapshot {
    snapshot: Option<HPSS>,
    marker: Option<HPSSWALK>,
}
impl Snapshot {
    fn close_marker(&mut self) -> Result<()> {
        if let Some(marker) = self.marker.take() {
            // SAFETY: locally created PSS walk marker, not a kernel HANDLE.
            status("PssWalkMarkerFree", unsafe { PssWalkMarkerFree(marker) })?;
        }
        Ok(())
    }
    fn close_snapshot(&mut self) -> Result<()> {
        if let Some(snapshot) = self.snapshot.take() {
            // SAFETY: captured locally, even though the subject is another
            // process. The owner passed to FreeSnapshot is this collector.
            status("PssFreeSnapshot", unsafe {
                PssFreeSnapshot(GetCurrentProcess(), snapshot)
            })?;
        }
        Ok(())
    }
}
impl Drop for Snapshot {
    fn drop(&mut self) {
        let _ = self.close_marker();
        let _ = self.close_snapshot();
    }
}

fn status(operation: &str, code: u32) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(format!("{operation}: Windows status {code}"))
    }
}
fn comparison(same: bool, error: u32) -> Result<bool> {
    if same {
        Ok(true)
    } else if error == ERROR_NOT_SAME_OBJECT.0 {
        Ok(false)
    } else {
        Err(format!("CompareObjectHandles: Windows status {error}"))
    }
}
fn same_object(first: HANDLE, second: HANDLE) -> Result<bool> {
    // SAFETY: both handles are held local objects; reset thread-local error so
    // an unspecified/failed comparison cannot borrow a stale DIFFERENT result.
    unsafe {
        SetLastError(WIN32_ERROR(0));
        let same = CompareObjectHandles(first, second).as_bool();
        comparison(same, GetLastError().0)
    }
}
fn walk_transition(index: u32, count: u32, code: u32) -> Result<bool> {
    if index < count && code == 0 {
        Ok(true)
    } else if index == count && code == ERROR_NO_MORE_ITEMS.0 {
        Ok(false)
    } else {
        Err(format!(
            "PSS handle walk {index}/{count}: Windows status {code}"
        ))
    }
}

struct Audit {
    expected: [usize; 3],
    count: u32,
    seen: BTreeSet<usize>,
    stdio: u8,
}
impl Audit {
    fn new(count: u32, expected: [usize; 3]) -> Result<Self> {
        if count > MAX_HANDLES
            || expected.iter().any(|v| *v == 0 || *v > isize::MAX as usize)
            || expected.into_iter().collect::<BTreeSet<_>>().len() != 3
        {
            return Err("suspended handle audit extent/stdio refused".into());
        }
        Ok(Self {
            expected,
            count,
            seen: BTreeSet::new(),
            stdio: 0,
        })
    }
    fn visit(&mut self, handle: usize, canary: bool, stdio: Option<bool>) -> Result<()> {
        if handle == 0
            || handle > isize::MAX as usize
            || self.seen.len() >= self.count as usize
            || !self.seen.insert(handle)
        {
            return Err("suspended handle walk repeated/invalid/outside extent".into());
        }
        if canary {
            return Err("excluded inheritable canary reached suspended child".into());
        }
        if let Some(index) = self.expected.iter().position(|v| *v == handle) {
            if stdio != Some(true) {
                return Err("suspended stdio value refers to a different object".into());
            }
            self.stdio |= 1 << index;
        }
        Ok(())
    }
    fn finish(self) -> Result<()> {
        if self.seen.len() != self.count as usize || self.stdio != 7 {
            return Err("suspended handle snapshot lacks exact three stdio objects".into());
        }
        Ok(())
    }
}
fn finish(audit: Result<()>, cleanup: [Result<()>; 3]) -> Result<()> {
    let errors: Vec<_> = std::iter::once(audit)
        .chain(cleanup)
        .filter_map(|r| r.err())
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

pub(super) struct Canary(KernelLease);
impl Canary {
    pub(super) fn new() -> Result<Self> {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            bInheritHandle: BOOL(1),
            ..Default::default()
        };
        // SAFETY: unnamed, unsignaled event; deliberately inheritable, but never
        // included in the three-element startup HANDLE_LIST.
        let handle = unsafe { CreateEventW(Some(&attributes), true, false, PCWSTR::null()) }
            .map_err(|e| format!("inheritance canary creation: {e}"))?;
        Ok(Self(KernelLease(Some(handle))))
    }
    pub(super) fn close(&mut self) -> Result<()> {
        self.0.close()
    }
    pub(super) fn verify(
        &mut self,
        process: HANDLE,
        stdio: [HANDLE; 3],
        deadline: Instant,
    ) -> Result<()> {
        let mut resources = Snapshot::default();
        let checked = (|| {
            if Instant::now() >= deadline {
                return Err("suspended handle audit deadline".into());
            }
            let mut before = 0;
            // SAFETY: exact owned suspended process returned by CreateProcess.
            unsafe { GetProcessHandleCount(process, &mut before) }.map_err(|e| e.to_string())?;
            if before > MAX_HANDLES {
                return Err("suspended process handle count exceeds 256".into());
            }
            let mut snapshot = HPSS::default();
            // SAFETY: handles only, no VA clone, names, contexts or type pointers.
            // The sampled count bounds the walk, not PSS internal time/allocation.
            status("PssCaptureSnapshot", unsafe {
                PssCaptureSnapshot(process, PSS_CAPTURE_HANDLES, None, &mut snapshot)
            })?;
            if snapshot.is_invalid() {
                return Err("invalid PSS snapshot".into());
            }
            resources.snapshot = Some(snapshot);
            let mut info = PSS_HANDLE_INFORMATION::default();
            // SAFETY: actual aligned SDK structure and exact byte extent.
            status("PssQuerySnapshot", unsafe {
                PssQuerySnapshot(
                    snapshot,
                    PSS_QUERY_HANDLE_INFORMATION,
                    (&mut info as *mut PSS_HANDLE_INFORMATION).cast(),
                    std::mem::size_of_val(&info) as u32,
                )
            })?;
            let expected = stdio.map(|h| h.0 as usize);
            let mut audit = Audit::new(info.HandlesCaptured, expected)?;
            let mut marker = HPSSWALK::default();
            // SAFETY: default allocator, immediately owned on successful output.
            status("PssWalkMarkerCreate", unsafe {
                PssWalkMarkerCreate(None, &mut marker)
            })?;
            if marker.is_invalid() {
                return Err("invalid PSS marker".into());
            }
            resources.marker = Some(marker);
            for index in 0..=info.HandlesCaptured {
                if Instant::now() >= deadline {
                    return Err("suspended handle audit deadline".into());
                }
                let mut entry = PSS_HANDLE_ENTRY::default();
                // SAFETY: writable view of the aligned actual SDK structure.
                // Only its integer HANDLE is read; snapshot-owned pointers and
                // union/type-specific fields are never dereferenced.
                let bytes = unsafe {
                    std::slice::from_raw_parts_mut(
                        (&mut entry as *mut PSS_HANDLE_ENTRY).cast::<u8>(),
                        std::mem::size_of_val(&entry),
                    )
                };
                let code =
                    unsafe { PssWalkSnapshot(snapshot, PSS_WALK_HANDLES, marker, Some(bytes)) };
                if !walk_transition(index, info.HandlesCaptured, code)? {
                    break;
                }
                let value = entry.Handle.0 as usize;
                if value == 0 || value > isize::MAX as usize {
                    return Err("invalid child handle value".into());
                }
                let mut duplicate = HANDLE::default();
                // SAFETY: borrow a live child-table handle, duplicate locally
                // without inheritance or CLOSE_SOURCE. Never close entry.Handle.
                unsafe {
                    DuplicateHandle(
                        process,
                        entry.Handle,
                        GetCurrentProcess(),
                        &mut duplicate,
                        0,
                        false,
                        DUPLICATE_SAME_ACCESS,
                    )
                }
                .map_err(|e| e.to_string())?;
                let mut duplicate = KernelLease(Some(duplicate));
                let compared = (|| {
                    let canary = same_object(duplicate.handle(), self.0.handle())?;
                    let matched = match expected.iter().position(|v| *v == value) {
                        Some(i) => Some(same_object(duplicate.handle(), stdio[i])?),
                        None => None,
                    };
                    audit.visit(value, canary, matched)
                })();
                let closed = duplicate.close();
                finish(compared, [closed, Ok(()), Ok(())])?;
            }
            audit.finish()
        })();
        // All fallible releases happen before this method can authorize Resume.
        finish(
            checked,
            [
                resources.close_marker(),
                resources.close_snapshot(),
                self.close(),
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stdio_needs_matching_values_and_objects_not_just_canary_absence() {
        let mut audit = Audit::new(4, [4, 8, 12]).unwrap();
        for h in [4, 8, 12] {
            audit.visit(h, false, Some(true)).unwrap();
        }
        audit.visit(16, false, None).unwrap();
        audit.finish().unwrap();
        let mut wrong = Audit::new(3, [4, 8, 12]).unwrap();
        assert!(wrong.visit(4, false, Some(false)).is_err());
        let mut missing = Audit::new(0, [4, 8, 12]).unwrap();
        assert!(missing.visit(4, false, Some(true)).is_err());
        assert!(missing.finish().is_err());
    }
    #[test]
    fn canary_or_unknown_comparison_cannot_be_admitted_as_different() {
        assert!(
            Audit::new(1, [4, 8, 12])
                .unwrap()
                .visit(16, true, None)
                .is_err()
        );
        assert!(!comparison(false, ERROR_NOT_SAME_OBJECT.0).unwrap());
        for error in [0, 5, 6] {
            assert!(comparison(false, error).is_err());
        }
        assert!(comparison(true, 5).unwrap()); // LastError is immaterial on TRUE.
    }
    #[test]
    fn malformed_extent_duplicates_and_nonterminal_walks_fail_closed() {
        assert!(Audit::new(257, [4, 8, 12]).is_err());
        assert!(Audit::new(3, [4, 4, 12]).is_err());
        let mut audit = Audit::new(3, [4, 8, 12]).unwrap();
        audit.visit(4, false, Some(true)).unwrap();
        assert!(audit.visit(4, false, Some(true)).is_err());
        assert!(audit.finish().is_err());
        assert!(walk_transition(0, 3, ERROR_NO_MORE_ITEMS.0).is_err());
        assert!(walk_transition(3, 3, 0).is_err());
        assert!(walk_transition(0, 3, 234).is_err());
        assert!(!walk_transition(3, 3, ERROR_NO_MORE_ITEMS.0).unwrap());
    }
    #[test]
    fn positive_audit_does_not_override_failed_resource_release() {
        let result = finish(
            Ok(()),
            [
                Err("marker release".into()),
                Ok(()),
                Err("canary release".into()),
            ],
        );
        let error = result.unwrap_err();
        assert!(error.contains("marker release") && error.contains("canary release"));
    }
}
