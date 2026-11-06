//! Closed creation/enforcement experiment. No vendor application is dispatched.
//! The outer owned GuestProcess is the watchdog for every potentially blocking
//! vendor ABI call, including free. A successful ABI return is not job cleanup.
use super::*;
use crate::guest_msi::mxc_child::{ResearchMxcChild, ResearchMxcChildObservation};
use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

const WORKER_READY: &str = r"C:\AIW\MxcProbe\Data\WORKER.DAT";
const WORKER_RESULT: &str = r"C:\AIW\MxcProbe\Data\CREATION.DAT";
const GATE: &str = r"C:\AIW\SevenZip\Work\Mxc\Input\ALLOW.DAT";
const CONTROL_RESULT: &str = r"C:\AIW\SevenZip\Work\Mxc\Output\CONTROL.DAT";
const CONTROL_FAILURE: &str = r"C:\AIW\SevenZip\Work\Mxc\Output\FAILURE.DAT";
const INPUT: &str = r"C:\AIW\SevenZip\Work\Mxc\Input\INPUT.DAT";
const INPUT_BYTES: &[u8] = b"AIW fixed MXC input control\n";
const DENIED_BYTES: &[u8] = b"AIW fixed MXC denied control\n";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ready {
    request_sha256: String,
    helper_sha256: String,
    child: ResearchMxcChildObservation,
}

pub(super) fn is_creation_role() -> bool {
    let a = std::env::args_os().skip(1).collect::<Vec<_>>();
    a == ["--output", crate::research_publication::CREATION_RESULT]
        || a == ["--creation-worker"]
        || a == ["--mxc-driver-control"]
}

pub(super) fn run() -> Result<()> {
    let a = std::env::args_os().skip(1).collect::<Vec<_>>();
    let token = aiw_token::collect_current_process_token()?;
    require_guest_windows(&crate::observe_windows_version()?)?;
    let exe = std::env::current_exe()?;
    let same = |p| crate::control_appcontainer::research_sevenzip::fixed_role_image(&exe, p);
    if a == ["--output", crate::research_publication::CREATION_RESULT]
        && same(TRANSPORT_PROBE)
        && token.is_elevated
        && !token.is_app_container
        && token.user_sid == crate::control_appcontainer::fixed_account_sid("WDAGUtilityAccount")?
    {
        return setup();
    }
    if token.is_elevated || token.is_app_container || token.user_sid != ordinary_sid()? {
        return Err("fixed ordinary creation role required; runtime not loaded".into());
    }
    if a == ["--creation-worker"] && same(PROBE) {
        let report = worker(&token);
        let value = match &report {
            Ok(v) => v.clone(),
            Err(e) => {
                serde_json::json!({"schemaVersion":"aiw.dev/mxc-creation-worker-failure/v0alpha1", "error":bounded(e), "applicationExecutionRequested":false})
            }
        };
        write_new_json(WORKER_RESULT, &value)?;
        return report.map(|_| ());
    }
    if a == ["--mxc-driver-control"] && same(contract::CONTROL_IMAGE) {
        let result = contained();
        if let Err(error) = &result {
            let _ = write_new_json(
                CONTROL_FAILURE,
                &serde_json::json!({"schemaVersion":"aiw.dev/mxc-contained-control-failure/v0alpha1","error":bounded(error),"controlsCompleted":false}),
            );
        }
        return result;
    }
    Err("closed creation image/arguments differ".into())
}

fn ordinary_sid() -> Result<String> {
    Ok(crate::control_appcontainer::fixed_account_sid(
        aiw_provider_wsb::STANDARD_USER_ACCOUNT_NAME,
    )?)
}
fn bounded(e: impl std::fmt::Display) -> String {
    e.to_string().chars().take(4096).collect()
}
fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T> {
    let held = crate::HeldApplicationFile::open_bounded(Path::new(path), 65536)?;
    let v = serde_json::from_slice(&held.read_bounded(65536)?)?;
    held.revalidate()?;
    Ok(v)
}
fn helper_hash() -> Result<String> {
    let held =
        crate::HeldApplicationFile::open_bounded(&std::env::current_exe()?, 16 * 1024 * 1024)?;
    Ok(held.observation().sha256.clone())
}

// These opens never mutate Input or Denied data. The matching baseline has file
// write/delete rights, so candidate access-denied cannot be attributed to ACLs.
fn read_control(path: &str, expected: &[u8]) -> serde_json::Value {
    match fs::File::open(path).and_then(|f| {
        let mut bytes = Vec::new();
        f.take(4097).read_to_end(&mut bytes)?;
        Ok(bytes == expected)
    }) {
        Ok(matches) => serde_json::json!({"opened":true,"bytesMatch":matches}),
        Err(e) => serde_json::json!({"opened":false,"win32Code":e.raw_os_error()}),
    }
}
fn access_control(access: u32) -> serde_json::Value {
    match fs::OpenOptions::new().access_mode(access).open(INPUT) {
        Ok(_) => serde_json::json!({"opened":true}),
        Err(e) => serde_json::json!({"opened":false,"win32Code":e.raw_os_error()}),
    }
}
fn controls(candidate: bool) -> Result<serde_json::Value> {
    let leaf = if candidate {
        "CANDIDATE.DAT"
    } else {
        "BASELINE.DAT"
    };
    let path = Path::new(contract::OUTPUT_ROOT).join(leaf);
    let mut writer = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    writer.write_all(INPUT_BYTES)?;
    writer.sync_all()?;
    drop(writer);
    Ok(
        serde_json::json!({"inputRead":read_control(INPUT,INPUT_BYTES),
        "deniedRead":read_control(contract::DENIED_PATH,DENIED_BYTES),
        "inputWriteAccess":access_control(0x2),"inputDeleteAccess":access_control(0x10000),
        "outputWriteRead":read_control(path.to_str().ok_or("output path encoding")?,INPUT_BYTES),
        "candidate":candidate}),
    )
}
fn baseline_pass(v: &serde_json::Value) -> bool {
    v["candidate"] == false
        && v["inputRead"]["bytesMatch"] == true
        && v["deniedRead"]["bytesMatch"] == true
        && v["inputWriteAccess"]["opened"] == true
        && v["inputDeleteAccess"]["opened"] == true
        && v["outputWriteRead"]["bytesMatch"] == true
}

fn contained() -> Result<()> {
    let request = FixedRequest::new(FixedOperation::Driver)?;
    let hash = helper_hash()?;
    let token = aiw_token::collect_current_process_token()?;
    let creation_time = self_creation_time()?;
    let deadline = Instant::now() + Duration::from_secs(25);
    while !Path::new(GATE).try_exists()? {
        if Instant::now() >= deadline {
            return Err("owner release gate deadline".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let gate: Ready = read_json(GATE)?;
    if gate.request_sha256 != request.sha256()
        || gate.helper_sha256 != hash
        || gate.child.process_id != std::process::id()
        || gate.child.creation_time != creation_time
        || gate.child.token != token
        || gate.child.image_sha256 != hash
    {
        return Err("release gate differs from held contained identity/request".into());
    }
    // Owner/ordinary observers hold the image and process outside PSEC. The
    // contained role only queries itself; it does not need parent enumeration.
    if self_creation_time()? != creation_time {
        return Err("self creation identity changed".into());
    }
    write_new_json(CONTROL_RESULT, &controls(true)?)
}

fn self_creation_time() -> Result<u64> {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
    let (mut c, mut e, mut k, mut u) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    unsafe { GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u) }?;
    Ok((u64::from(c.dwHighDateTime) << 32) | u64::from(c.dwLowDateTime))
}

type Spawn = unsafe extern "C" fn(*const c_char, i32, *mut *mut c_void, *mut ErrorDetail) -> i32;
type Id = unsafe extern "C" fn(*mut c_void) -> u32;
type TryWait = unsafe extern "C" fn(*mut c_void, *mut i32, *mut i32, *mut i32) -> i32;
type Wait = unsafe extern "C" fn(*mut c_void, *mut i32, *mut i32) -> i32;
type Kill = unsafe extern "C" fn(*mut c_void) -> i32;
type Free = unsafe extern "C" fn(*mut c_void);
type Warnings = unsafe extern "C" fn(*mut c_void, *mut *mut c_char) -> i32;
struct Live<'runtime> {
    runtime: &'runtime Runtime,
    handle: *mut c_void,
    id: Id,
    poll: TryWait,
    wait: Wait,
    kill_timeout: Kill,
    free: Free,
    warnings: Warnings,
}
impl Drop for Live<'_> {
    fn drop(&mut self) {
        // Exactly one serialized free while its DLL remains held. This may block;
        // elevated setup independently enforces the outer worker/job deadline.
        let _ = write_new_json(
            &format!(r"{DATA}\FREE_BEGIN.DAT"),
            &serde_json::json!({"freeRequested":true,"innerJobEmpty":"unmeasured"}),
        );
        unsafe { (self.free)(self.handle) };
        let _ = write_new_json(
            &format!(r"{DATA}\FREE_END.DAT"),
            &serde_json::json!({"freeReturned":true,"innerJobEmpty":"unmeasured"}),
        );
    }
}
impl<'a> Live<'a> {
    fn spawn(runtime: &'a Runtime, request: &FixedRequest) -> Result<Self> {
        // Resolve every required export before dispatching the fixed request.
        let spawn: Spawn =
            unsafe { std::mem::transmute(export(runtime.module, c"mxc_spawn_json")?) };
        let id = unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, Id>(export(
                runtime.module,
                c"mxc_sandbox_id",
            )?)
        };
        let poll = unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, TryWait>(export(
                runtime.module,
                c"mxc_sandbox_try_wait",
            )?)
        };
        let wait = unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, Wait>(export(
                runtime.module,
                c"mxc_sandbox_wait",
            )?)
        };
        let kill_timeout = unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, Kill>(export(
                runtime.module,
                c"mxc_sandbox_kill_for_timeout",
            )?)
        };
        let free: Free =
            unsafe { std::mem::transmute(export(runtime.module, c"mxc_sandbox_free")?) };
        let warnings = unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, Warnings>(export(
                runtime.module,
                c"mxc_sandbox_warnings_json",
            )?)
        };
        let input = CString::new(request.json())?;
        let mut handle = std::ptr::null_mut();
        let mut error = ErrorDetail::default();
        runtime.file.revalidate()?;
        let status = unsafe { spawn(input.as_ptr(), 0, &mut handle, &mut error) };
        let details = [
            &error.message,
            &error.operation,
            &error.native_code,
            &error.remediation,
        ]
        .into_iter()
        .map(|p| {
            if p.is_null() {
                Ok(None)
            } else {
                unsafe { read_string(*p, 8192) }.map(Some)
            }
        })
        .collect::<Result<Vec<_>>>();
        unsafe { (runtime.error_free)(&mut error) };
        let prefix = serde_json::json!({"status":status,"handleReturned":!handle.is_null(),"requestSha256":request.sha256(),"errorDetail":details.as_ref().ok(),"errorDetailReadError":details.as_ref().err().map(bounded)});
        if let Err(error) = write_new_json(&format!(r"{DATA}\SPAWN_CALL.DAT"), &prefix) {
            if !handle.is_null() {
                unsafe { free(handle) }
            };
            return Err(error);
        }
        if status != 0 || handle.is_null() {
            if !handle.is_null() {
                unsafe { free(handle) }
            };
            return Err(
                format!("MXC creation refused status={status}; details={details:?}").into(),
            );
        }
        let live = Self {
            runtime,
            handle,
            id,
            poll,
            wait,
            kill_timeout,
            free,
            warnings,
        };
        details?;
        runtime.file.revalidate()?;
        Ok(live)
    }
    fn warnings(&mut self) -> Result<Vec<String>> {
        let mut pointer = std::ptr::null_mut();
        let status = unsafe { (self.warnings)(self.handle, &mut pointer) };
        let raw = if pointer.is_null() {
            Ok(None)
        } else {
            unsafe { read_string(pointer, 65536) }.map(Some)
        };
        if !pointer.is_null() {
            unsafe { (self.runtime.string_free)(pointer) }
        };
        decode_warnings(status, raw)
    }
    fn finish(&mut self) -> Result<serde_json::Value> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let (mut exit, mut running, mut timeout) = (0, 0, 0);
        loop {
            let status = unsafe { (self.poll)(self.handle, &mut exit, &mut running, &mut timeout) };
            if status != 0 {
                return Err(format!("MXC try_wait failed {status}").into());
            }
            if running == 0 {
                break;
            }
            if running != 1 || timeout != 0 {
                return Err("contradictory MXC polling state".into());
            }
            if Instant::now() >= deadline {
                write_new_json(
                    &format!(r"{DATA}\TIMEOUT.DAT"),
                    &serde_json::json!({"callerDeadline":true,"timeoutKillRequested":true}),
                )?;
                let kill = unsafe { (self.kill_timeout)(self.handle) };
                write_new_json(
                    &format!(r"{DATA}\TIMEOUT_END.DAT"),
                    &serde_json::json!({"timeoutKillStatus":kill,"innerJobEmpty":"unmeasured"}),
                )?;
                return Err(format!(
                    "MXC caller deadline; timeoutKillStatus={kill}; inner cleanup unverified"
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        write_new_json(
            &format!(r"{DATA}\POLL_END.DAT"),
            &serde_json::json!({"exitCode":exit,"running":running,"timedOut":timeout,"waitRequested":true}),
        )?;
        let status = unsafe { (self.wait)(self.handle, &mut exit, &mut timeout) };
        write_new_json(
            &format!(r"{DATA}\WAIT_END.DAT"),
            &serde_json::json!({"status":status,"exitCode":exit,"timedOut":timeout}),
        )?;
        if status != 0 || !matches!(timeout, 0 | 1) {
            return Err(format!("MXC wait status={status} timeout={timeout}").into());
        }
        Ok(
            serde_json::json!({"exitCode":exit,"timedOut":timeout==1,"waitStatus":status,"innerJobEmpty":"unmeasured"}),
        )
    }
}

fn decode_warnings(status: i32, raw: Result<Option<String>>) -> Result<Vec<String>> {
    if status != 0 {
        return Err(format!("MXC warnings failed {status}").into());
    }
    let Some(raw) = raw? else {
        return Ok(Vec::new());
    };
    let value: Vec<String> = serde_json::from_str(&raw)?;
    if value.len() > 32 || value.iter().any(|v| v.len() > 2048) {
        return Err("MXC warnings bounds".into());
    }
    Ok(value)
}

fn worker(token: &aiw_token::TokenEvidence) -> Result<serde_json::Value> {
    let baseline = controls(false)?;
    write_new_json(&format!(r"{DATA}\BASELINE.DAT"), &baseline)?;
    if !baseline_pass(&baseline) {
        return Err("ordinary baseline control failed; creation not dispatched".into());
    }
    let runtime = Runtime::open()?;
    let probe = runtime.probe(FixedOperation::Driver)?;
    write_new_json(&format!(r"{DATA}\PROBE.DAT"), &probe)?;
    if probe["disposition"] != "supportedForRequest" {
        return Err("exact Driver request unsupported; no spawn".into());
    }
    let request = FixedRequest::new(FixedOperation::Driver)?;
    let mut live = Live::spawn(&runtime, &request)?;
    let pid = unsafe { (live.id)(live.handle) };
    if pid == 0 {
        return Err("SDK returned zero root PID".into());
    }
    write_new_json(
        &format!(r"{DATA}\SPAWN.DAT"),
        &serde_json::json!({"processId":pid,"requestSha256":request.sha256(),"spawnReturned":true}),
    )?;
    let hash = helper_hash()?;
    // Same-account failure refuses this trial. Owner inspection never rescues it.
    let child = ResearchMxcChild::open(pid, &hash, &token.user_sid)?;
    child.require_running()?;
    let ready = Ready {
        request_sha256: request.sha256().into(),
        helper_sha256: hash,
        child: child.observation().clone(),
    };
    write_new_json(
        &format!(r"{DATA}\BOUND.DAT"),
        &serde_json::to_value(&ready)?,
    )?;
    let warnings = live.warnings()?;
    write_new_json(
        &format!(r"{DATA}\WARNINGS.DAT"),
        &serde_json::to_value(&warnings)?,
    )?;
    if !warnings.is_empty() {
        return Err("MXC creation warnings; controls not authorized".into());
    }
    write_new_json(WORKER_READY, &serde_json::to_value(&ready)?)?;
    let result = live.finish()?;
    let binding = child.revalidate();
    write_new_json(
        &format!(r"{DATA}\COMPLETION.DAT"),
        &serde_json::json!({"sdkCompletion":result,"postExitBindingError":binding.as_ref().err()}),
    )?;
    binding?;
    let controls: serde_json::Value = read_json(CONTROL_RESULT)?;
    runtime.file.revalidate()?;
    Ok(
        serde_json::json!({"schemaVersion":"aiw.dev/mxc-creation-worker/v0alpha1", "ready":ready,"probe":probe,
        "baseline":baseline,"controls":controls,"warnings":warnings,"sdkCompletion":result,
        "selectedTierAttestation":"unmeasured","applicationExecutionRequested":false}),
    )
}

fn setup() -> Result<()> {
    use crate::guest_document::paired_inputs::mxc_probe::FixedMxcProbeInputs;
    use crate::guest_msi::GuestProcess;
    use crate::guest_standard_user::StandardUserSession;
    let mut inputs = FixedMxcProbeInputs::open()?;
    let windows = crate::observe_windows_version()?;
    require_guest_windows(&windows)?;
    let _output = hold_directory(r"C:\AIW\MxcCreationOutput")?;
    if fs::read_dir(r"C:\AIW\MxcCreationOutput")?.next().is_some()
        || Path::new(ROOT).try_exists()?
        || Path::new(r"C:\AIW\SevenZip").try_exists()?
    {
        return Err("fresh creation roots/empty mapped output required".into());
    }
    let operation = (|| -> Result<serde_json::Value> {
        let standard = StandardUserSession::establish()?;
        let sid = &standard.context().user_sid;
        let readonly = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;{sid})");
        let mutable = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})");
        for directory in [
            ROOT,
            DATA,
            r"C:\AIW\SevenZip",
            contract::APP_ROOT,
            r"C:\AIW\SevenZip\Work",
            contract::WORK_ROOT,
            contract::INPUT_ROOT,
            contract::OUTPUT_ROOT,
        ] {
            fs::create_dir(directory)?;
            set_owned_acl(
                directory,
                if directory == DATA || directory == contract::OUTPUT_ROOT {
                    &mutable
                } else {
                    &readonly
                },
            )?;
        }
        let _root = hold_fixed_ancestry()?;
        let _data = hold_directory(DATA)?;
        let mut helper = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(PROBE)?;
        inputs.copy_helper(&mut helper)?;
        drop(helper);
        let mut supervisor = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(contract::CONTROL_IMAGE)?;
        inputs.copy_helper(&mut supervisor)?;
        drop(supervisor);
        let mut dll = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(DLL)?;
        inputs.copy_runtime(&mut dll)?;
        drop(dll);
        for (path, bytes) in [(INPUT, INPUT_BYTES), (contract::DENIED_PATH, DENIED_BYTES)] {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            // Files allow baseline write/delete, parents remain RX without DC.
            set_owned_acl(path, &mutable)?;
        }
        let helper =
            crate::HeldApplicationFile::open_bounded(Path::new(PROBE), inputs.helper_size())?;
        let supervisor = crate::HeldApplicationFile::open_bounded(
            Path::new(contract::CONTROL_IMAGE),
            inputs.helper_size(),
        )?;
        let dll =
            crate::HeldApplicationFile::open_bounded(Path::new(DLL), contract::RUNTIME_DLL_SIZE)?;
        if helper.observation().sha256 != inputs.helper_hash()
            || supervisor.observation().sha256 != inputs.helper_hash()
            || dll.observation().sha256 != contract::RUNTIME_DLL_SHA256
        {
            return Err("creation payload copy differs".into());
        }
        let (child, worker_token) = GuestProcess::start_standard_user_measured(
            PROBE,
            &["--creation-worker".into()],
            &standard,
        )?;
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut owner_observations = serde_json::json!({"releaseGatePublished":false});
        let handshake = (|| -> Result<serde_json::Value> {
            while !Path::new(WORKER_READY).try_exists()? {
                if Path::new(WORKER_RESULT).try_exists()? {
                    return Err("worker completed/refused before release".into());
                }
                if Instant::now() >= deadline {
                    return Err("creation owner watchdog before ready".into());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let ready: Ready = read_json(WORKER_READY)?;
            let request = FixedRequest::new(FixedOperation::Driver)?;
            if ready.request_sha256 != request.sha256()
                || ready.helper_sha256 != inputs.helper_hash()
            {
                return Err("creation readiness binding differs".into());
            }
            let held =
                child.observe_mxc_child(ready.child.process_id, inputs.helper_hash(), sid)?;
            if held.observation() != &ready.child {
                return Err("owner/ordinary root observations differ".into());
            }
            held.require_running()?;
            held.revalidate()?;
            owner_observations = serde_json::json!({"ownerMeasuredChild":held.observation(),"exactOuterJobMembership":true,"releaseGatePublished":false});
            write_new_json(GATE, &serde_json::to_value(&ready)?)?;
            owner_observations["releaseGatePublished"] = true.into();
            let exit = child.wait_for_exit(deadline.saturating_duration_since(Instant::now()))?;
            let binding = held.revalidate();
            owner_observations["postExitBindingError"] =
                serde_json::to_value(binding.as_ref().err())?;
            binding?;
            Ok(
                serde_json::json!({"ownerMeasuredChild":held.observation(),"exactOuterJobMembership":true,"releaseGatePublished":true,"workerExitCode":exit}),
            )
        })();
        let cleanup = child.cleanup();
        let worker = read_json::<serde_json::Value>(WORKER_RESULT);
        let mut prefixes = serde_json::Map::new();
        for (name, path) in [
            ("baseline", format!(r"{DATA}\BASELINE.DAT")),
            ("probe", format!(r"{DATA}\PROBE.DAT")),
            ("spawn", format!(r"{DATA}\SPAWN.DAT")),
            ("boundChild", format!(r"{DATA}\BOUND.DAT")),
            ("warnings", format!(r"{DATA}\WARNINGS.DAT")),
            ("ready", WORKER_READY.into()),
            ("controls", CONTROL_RESULT.into()),
            ("containedFailure", CONTROL_FAILURE.into()),
            ("spawnCall", format!(r"{DATA}\SPAWN_CALL.DAT")),
            ("completion", format!(r"{DATA}\COMPLETION.DAT")),
            ("freeBegin", format!(r"{DATA}\FREE_BEGIN.DAT")),
            ("freeEnd", format!(r"{DATA}\FREE_END.DAT")),
            ("pollEnd", format!(r"{DATA}\POLL_END.DAT")),
            ("waitEnd", format!(r"{DATA}\WAIT_END.DAT")),
            ("timeout", format!(r"{DATA}\TIMEOUT.DAT")),
            ("timeoutEnd", format!(r"{DATA}\TIMEOUT_END.DAT")),
        ] {
            let read = read_json::<serde_json::Value>(&path);
            prefixes.insert(name.into(),serde_json::json!({"value":read.as_ref().ok(),"readError":read.as_ref().err().map(bounded)}));
        }
        let validation = [
            helper.revalidate().map_err(bounded),
            supervisor.revalidate().map_err(bounded),
            dll.revalidate().map_err(bounded),
            inputs.revalidate(),
        ]
        .into_iter()
        .filter_map(std::result::Result::err)
        .collect::<Vec<_>>();
        Ok(
            serde_json::json!({"schemaVersion":"aiw.dev/mxc-creation-trial/v0alpha1","researchOnly":true,
            "helperSha256":inputs.helper_hash(),"helperSizeBytes":inputs.helper_size(),"dllSha256":contract::RUNTIME_DLL_SHA256,
            "windows":windows,"heldWorkerToken":worker_token,"standardContext":standard.context(),
            "handshake":handshake.as_ref().ok(),"handshakeError":handshake.as_ref().err().map(bounded),
            "worker":worker.as_ref().ok(),"workerReadError":worker.as_ref().err().map(bounded),
            "ownerObservations":owner_observations,"retainedPrefixes":prefixes,
            "ownedJobEmpty":cleanup.is_ok(),"cleanupError":cleanup.err().map(bounded),"validationErrors":validation,
            "applicationExecutionRequested":false,"selectedTierAttestation":"unmeasured"}),
        )
    })();
    let report=operation.unwrap_or_else(|e|serde_json::json!({"schemaVersion":"aiw.dev/mxc-creation-setup-failure/v0alpha1","researchOnly":true,"error":bounded(e),"applicationExecutionRequested":false}));
    crate::research_publication::publish_mapped_json(
        crate::research_publication::MappedPublication::Creation,
        &report,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn official_empty_warnings_null_contract_is_success_but_status_and_bounds_still_refuse() {
        assert!(decode_warnings(0, Ok(None)).unwrap().is_empty());
        assert!(
            decode_warnings(0, Ok(Some("[]".into())))
                .unwrap()
                .is_empty()
        );
        assert!(decode_warnings(-1, Ok(None)).is_err());
        assert!(decode_warnings(0, Ok(Some("{}".into()))).is_err());
        assert!(
            decode_warnings(
                0,
                Ok(Some(serde_json::to_string(&vec!["warning"; 33]).unwrap()))
            )
            .is_err()
        );
    }
    #[test]
    fn baseline_requires_every_positive_control_before_spawn() {
        let v = serde_json::json!({"candidate":false,"inputRead":{"bytesMatch":true},"deniedRead":{"bytesMatch":true},"inputWriteAccess":{"opened":true},"inputDeleteAccess":{"opened":true},"outputWriteRead":{"bytesMatch":true}});
        assert!(baseline_pass(&v));
        for name in [
            "inputRead",
            "deniedRead",
            "inputWriteAccess",
            "inputDeleteAccess",
            "outputWriteRead",
        ] {
            let mut bad = v.clone();
            bad[name] = serde_json::Value::Null;
            assert!(!baseline_pass(&bad));
        }
        let mut candidate = v;
        candidate["candidate"] = true.into();
        assert!(!baseline_pass(&candidate));
    }
}
