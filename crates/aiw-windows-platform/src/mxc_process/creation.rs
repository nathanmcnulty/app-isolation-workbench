//! Closed creation/enforcement experiment. No vendor application is dispatched.
//! The outer owned GuestProcess is the watchdog for every potentially blocking
//! vendor ABI call, including free. A successful ABI return is not job cleanup.
use super::*;
use crate::guest_msi::mxc_child::{
    ResearchMxcChild, ResearchMxcChildObservation, ResearchMxcRootToken, self_token_errors,
};
use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

const WORKER_READY: &str = r"C:\AIW\MxcProbe\Data\WORKER.DAT";
const WORKER_RESULT: &str = r"C:\AIW\MxcProbe\Data\CREATION.DAT";
const GATE: &str = r"C:\AIW\SevenZip\Work\Mxc\Input\ALLOW.DAT";
const CONTROL_RESULT: &str = r"C:\AIW\SevenZip\Work\Mxc\Output\CONTROL.DAT";
const CONTROL_FAILURE: &str = r"C:\AIW\SevenZip\Work\Mxc\Output\FAILURE.DAT";
const CONTROL_SELF: &str = r"C:\AIW\SevenZip\Work\Mxc\Output\SELF.DAT";
const CONTROL_ENTRY: &str = r"C:\AIW\SevenZip\Work\Mxc\Output\ENTRY.DAT";
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
    let exe = std::env::current_exe()?;
    let same = |p| crate::control_appcontainer::research_sevenzip::fixed_role_image(&exe, p);
    if a == ["--mxc-driver-control"] && same(contract::CONTROL_IMAGE) {
        return run_contained_role();
    }
    let token = aiw_token::collect_current_process_token()?;
    require_guest_windows(&crate::observe_windows_version()?)?;
    if a == ["--output", crate::research_publication::CREATION_RESULT]
        && same(TRANSPORT_PROBE)
        && token.is_elevated
        && !token.is_app_container
        && token.user_sid == crate::control_appcontainer::fixed_account_sid("WDAGUtilityAccount")?
    {
        return setup();
    }
    if a == ["--creation-worker"] && same(PROBE) {
        if !ordinary_worker_token(&token, &ordinary_sid()?) {
            return Err("fixed ordinary creation worker required; runtime not loaded".into());
        }
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
    Err("closed creation image/arguments differ".into())
}

fn run_contained_role() -> Result<()> {
    let result = (|| -> Result<()> {
        // Exact image/argument dispatch only. These writes precede authorization
        // and prove neither a token boundary nor successful candidate controls.
        write_new_json(
            CONTROL_ENTRY,
            &serde_json::json!({
                "schemaVersion":"aiw.dev/mxc-contained-entry/v0alpha1",
                "identityAuthorization":"pendingOwnerGate","controlsCompleted":false
            }),
        )?;
        let token = aiw_token::collect_current_process_token()?;
        let errors = self_token_errors(std::process::id(), &token);
        write_new_json(
            CONTROL_SELF,
            &serde_json::json!({
                "token":token,"validationErrors":errors,
                "identityAuthorization":"pendingOwnerGate",
                "environmentAuthorization":"pendingVerifiedOwnerGate"
            }),
        )?;
        if !errors.is_empty() {
            return Err(format!(
                "contained self token structure differs: {}",
                errors.join(", ")
            )
            .into());
        }
        // Setup and ordinary worker check Windows before SDK dispatch. Do not
        // repeat WinRT activation or account-name lookup inside PSEC. Actor and
        // environment authorization require the independently verified owner
        // gate; contained() compares the full token, not a self-SID assertion.
        contained()
    })();
    if let Err(error) = &result {
        let _ = write_new_json(
            CONTROL_FAILURE,
            &serde_json::json!({
                "schemaVersion":"aiw.dev/mxc-contained-control-failure/v0alpha1",
                "error":bounded(error),"controlsCompleted":false
            }),
        );
    }
    result
}

fn ordinary_worker_token(token: &aiw_token::TokenEvidence, sid: &str) -> bool {
    !token.is_app_container
        && ResearchMxcRootToken::measure(std::process::id(), sid, token.clone())
            .validate()
            .is_ok()
}

fn ordinary_sid() -> Result<String> {
    Ok(crate::control_appcontainer::fixed_account_sid(
        aiw_provider_wsb::STANDARD_USER_ACCOUNT_NAME,
    )?)
}
fn bounded(e: impl std::fmt::Display) -> String {
    let text = e.to_string();
    let mut end = text.len().min(2048);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

const PREFIX_RECORD_BOUND: usize = 8 * 1024;
const PREFIX_TOTAL_BOUND: usize = 128 * 1024;
const ANCILLARY_BOUND: usize = 64 * 1024;
const OWNER_BOUND: usize = 128 * 1024;
const FIXED_ENVELOPE_BOUND: usize = 128 * 1024;
const MARKER_BOUND: usize = 1024 * 1024;

fn prefix_record(
    read: Result<serde_json::Value>,
    used: &mut usize,
    remaining: usize,
) -> serde_json::Value {
    let mut record = match read {
        Ok(value) => serde_json::json!({"value":value,"readError":null}),
        Err(error) => serde_json::json!({"value":null,"readError":bounded(error)}),
    };
    // Reserve one short explicit refusal for every later fixed key. Measure
    // actual serialized bytes, including escaping and the wrapper itself.
    let available = PREFIX_TOTAL_BOUND.saturating_sub(*used + remaining * 256);
    let mut size = serde_json::to_vec(&record)
        .expect("JSON Value serializes")
        .len();
    if size > PREFIX_RECORD_BOUND || size > available {
        record = serde_json::json!({"value":null,"readError":"parsed prefix refused: serialized record or aggregate budget exceeded"});
        size = serde_json::to_vec(&record)
            .expect("JSON Value serializes")
            .len();
    }
    *used += size;
    record
}

fn bounded_creation_report(mut report: serde_json::Value) -> Result<serde_json::Value> {
    if let Some(error) = report["ownerObservations"]["postExitBindingError"].as_str() {
        let error = bounded(error);
        report["ownerObservations"]["postExitBindingError"] = error.into();
    }
    // These ancillary records may duplicate prefixes. Refusal never removes
    // baseline/probe/spawn/PID prefixes to make room for duplicated data.
    for (field, error) in [
        ("worker", "workerReadError"),
        ("handshake", "handshakeError"),
    ] {
        if serde_json::to_vec(&report[field])?.len() > ANCILLARY_BOUND {
            report[field] = serde_json::Value::Null;
            report[error] = "ancillary observation refused: serialized budget exceeded".into();
        }
    }
    if serde_json::to_vec(&report["ownerObservations"])?.len() > OWNER_BOUND {
        // Preserve actual gate/child facts; the duplicate token has its own
        // separately budgeted prefix. Never turn a published gate into false.
        report["ownerObservations"]["rootTokenMeasurement"] = serde_json::Value::Null;
        report["ownerObservations"]["rootTokenMeasurementReadError"] =
            "duplicate owner token observation refused: serialized budget exceeded".into();
        if serde_json::to_vec(&report["ownerObservations"])?.len() > OWNER_BOUND {
            return Err("fixed owner child binding exceeds serialized contract".into());
        }
    }
    // Actual whole-marker check, before entering the publication function.
    // Prefixes128KiB + raw320KiB + worker/handshake2*64KiB + owner128KiB
    // + fixed128KiB =832KiB, plus <2KiB closed-map overhead: <=834KiB.
    let mut fixed = report.clone();
    for field in [
        "retainedPrefixes",
        "rawContainedDiagnostics",
        "worker",
        "handshake",
        "ownerObservations",
    ] {
        fixed[field] = serde_json::Value::Null;
    }
    if serde_json::to_vec(&fixed)?.len() > FIXED_ENVELOPE_BOUND
        || serde_json::to_vec(&report)?.len() > MARKER_BOUND
    {
        return Err("fixed creation envelope exceeds bounded publication contract".into());
    }
    Ok(report)
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

const RAW_DIAGNOSTIC_BOUND: u64 = 16 * 1024;

// Closed data-only paths. These bytes need not be JSON: interrupted publication
// may leave an empty, malformed or binary .pending file worth preserving.
fn raw_contained_diagnostics() -> serde_json::Value {
    let mut records = serde_json::Map::new();
    for (name, path) in [
        ("ENTRY.DAT", CONTROL_ENTRY),
        ("SELF.DAT", CONTROL_SELF),
        ("CONTROL.DAT", CONTROL_RESULT),
        ("FAILURE.DAT", CONTROL_FAILURE),
    ] {
        for suffix in ["", ".pending"] {
            let captured = capture_raw_diagnostic(&format!("{path}{suffix}"));
            records.insert(format!("{name}{suffix}"), captured);
        }
    }
    records.into()
}

fn captured_raw_diagnostic(
    bytes: &[u8],
    identity: &aiw_probe::WindowsFileIdentity,
    expected_sha256: &str,
) -> Result<serde_json::Value> {
    use sha2::{Digest, Sha256};
    if bytes.len() as u64 > RAW_DIAGNOSTIC_BOUND {
        return Err("raw diagnostic exceeds complete-capture bound".into());
    }
    let hash = hex::encode(Sha256::digest(bytes));
    if hash != expected_sha256 {
        return Err("raw diagnostic held-byte digest differs".into());
    }
    let record = serde_json::json!({"captureComplete":true,"disposition":"captured",
        "rawHex":hex::encode(bytes),"sha256":hash,"sizeBytes":bytes.len(),
        "identity":identity,"readError":null});
    if serde_json::to_vec(&record)?.len() > 40 * 1024 {
        return Err("raw diagnostic serialized record exceeds budget".into());
    }
    Ok(record)
}

fn capture_raw_diagnostic(path: &str) -> serde_json::Value {
    let capture = (|| -> Result<serde_json::Value> {
        // open_bounded checks size before hashing. No unbounded fallback or
        // truncated prefix can masquerade as a complete diagnostic.
        let held = crate::HeldApplicationFile::open_bounded(Path::new(path), RAW_DIAGNOSTIC_BOUND)?;
        if !held
            .observation()
            .identity
            .final_path
            .strip_prefix(r"\\?\")
            .unwrap_or(&held.observation().identity.final_path)
            .eq_ignore_ascii_case(path)
        {
            return Err("raw diagnostic held path differs from fixed role".into());
        }
        let bytes = held.read_bounded(RAW_DIAGNOSTIC_BOUND)?;
        let record = captured_raw_diagnostic(
            &bytes,
            &held.observation().identity,
            &held.observation().sha256,
        )?;
        held.revalidate()?;
        Ok(record)
    })();
    capture.unwrap_or_else(|error| {
        serde_json::json!({"captureComplete":false,
        "disposition":"refused","rawHex":null,"sha256":null,"sizeBytes":null,
        "identity":null,"readError":bounded(error)})
    })
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
    if !gate_matches(&gate, request.sha256(), &hash, &token, creation_time) {
        return Err("release gate differs from held contained identity/request".into());
    }
    // Owner/ordinary observers hold the image and process outside PSEC. The
    // contained role only queries itself; it does not need parent enumeration.
    if self_creation_time()? != creation_time {
        return Err("self creation identity changed".into());
    }
    write_new_json(CONTROL_RESULT, &controls(true)?)
}

fn gate_matches(
    gate: &Ready,
    request_hash: &str,
    hash: &str,
    token: &aiw_token::TokenEvidence,
    creation_time: u64,
) -> bool {
    !(gate.request_sha256 != request_hash
        || gate.helper_sha256 != hash
        || gate.child.process_id != std::process::id()
        || gate.child.creation_time != creation_time
        || &gate.child.token != token
        || gate.child.image_sha256 != hash)
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
    let child = ResearchMxcChild::open(pid, &hash, &token.user_sid, |measured| {
        write_new_json(
            &format!(r"{DATA}\TOKEN.DAT"),
            &serde_json::json!({
                "requestSha256":request.sha256(),"helperSha256":hash,"measured":measured
            }),
        )
        .map_err(bounded)
    })?;
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
            let held = child.observe_mxc_child(
                ready.child.process_id,
                inputs.helper_hash(),
                sid,
                |measured| {
                    owner_observations["rootTokenMeasurement"] =
                        serde_json::to_value(measured).map_err(bounded)?;
                    Ok(())
                },
            )?;
            if held.observation() != &ready.child {
                return Err("owner/ordinary root observations differ".into());
            }
            held.require_running()?;
            held.revalidate()?;
            owner_observations["ownerMeasuredChild"] = serde_json::to_value(held.observation())?;
            owner_observations["exactOuterJobMembership"] = true.into();
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
        let raw_contained_diagnostics = raw_contained_diagnostics();
        let worker = read_json::<serde_json::Value>(WORKER_RESULT);
        let mut prefixes = serde_json::Map::new();
        let mut prefix_bytes = 0;
        for (index, (name, path)) in [
            ("baseline", format!(r"{DATA}\BASELINE.DAT")),
            ("probe", format!(r"{DATA}\PROBE.DAT")),
            ("spawn", format!(r"{DATA}\SPAWN.DAT")),
            ("rootToken", format!(r"{DATA}\TOKEN.DAT")),
            ("containedSelf", CONTROL_SELF.into()),
            ("containedEntry", CONTROL_ENTRY.into()),
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
        ]
        .into_iter()
        .enumerate()
        {
            let read = read_json::<serde_json::Value>(&path);
            prefixes.insert(
                name.into(),
                prefix_record(read, &mut prefix_bytes, 18 - index),
            );
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
        bounded_creation_report(
            serde_json::json!({"schemaVersion":"aiw.dev/mxc-creation-trial/v0alpha1","researchOnly":true,
            "helperSha256":inputs.helper_hash(),"helperSizeBytes":inputs.helper_size(),"dllSha256":contract::RUNTIME_DLL_SHA256,
            "windows":windows,"heldWorkerToken":worker_token,"standardContext":standard.context(),
            "handshake":handshake.as_ref().ok(),"handshakeError":handshake.as_ref().err().map(bounded),
            "worker":worker.as_ref().ok(),"workerReadError":worker.as_ref().err().map(bounded),
            "ownerObservations":owner_observations,"retainedPrefixes":prefixes,
            "rawContainedDiagnostics":raw_contained_diagnostics,
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
    fn serialized_prefix_and_marker_budgets_preserve_earlier_facts() {
        let mut used = 0;
        let mut prefixes = serde_json::Map::new();
        for index in 0..19 {
            let value = if index < 3 {
                serde_json::json!({"measured":true,"processId":42})
            } else {
                // Escaping expands these beyond the per-record budget.
                serde_json::json!("\0".repeat(8192))
            };
            prefixes.insert(
                index.to_string(),
                prefix_record(Ok(value), &mut used, 18 - index),
            );
        }
        assert_eq!(prefixes.len(), 19);
        assert!(used <= PREFIX_TOTAL_BOUND);
        for index in 0..3 {
            assert_eq!(prefixes[&index.to_string()]["value"]["processId"], 42);
        }
        assert!(prefixes["3"]["value"].is_null());
        let mut aggregate_used = 0;
        let records = (0..19)
            .map(|index| {
                prefix_record(
                    Ok(serde_json::json!("x".repeat(8000))),
                    &mut aggregate_used,
                    18 - index,
                )
            })
            .collect::<Vec<_>>();
        assert!(aggregate_used <= PREFIX_TOTAL_BOUND);
        assert!(records.iter().any(|record| record["value"].is_null()));
        let report = serde_json::json!({"retainedPrefixes":prefixes,
            "rawContainedDiagnostics":{},"worker":"x".repeat(70000),"workerReadError":null,
            "handshake":"\0".repeat(70000),"handshakeError":null,
            "ownerObservations":{"releaseGatePublished":true,"binding":{"processId":42}}});
        let report = bounded_creation_report(report).unwrap();
        assert!(report["worker"].is_null());
        assert!(report["handshake"].is_null());
        assert_eq!(report["ownerObservations"]["binding"]["processId"], 42);
        assert_eq!(report["retainedPrefixes"]["0"]["value"]["processId"], 42);
        assert!(serde_json::to_vec(&report).unwrap().len() <= 834 * 1024);
    }

    #[test]
    fn diagnostic_errors_are_utf8_byte_bounded_without_split_characters() {
        for error in [
            "😀".repeat(1000),
            "é".repeat(2000),
            format!("{}😀", "a".repeat(2047)),
        ] {
            let bounded = bounded(error);
            assert!(bounded.len() <= 2048);
            assert!(std::str::from_utf8(bounded.as_bytes()).is_ok());
            let mut used = 0;
            let record = prefix_record(Err(bounded.into()), &mut used, 18);
            assert!(serde_json::to_vec(&record).unwrap().len() <= PREFIX_RECORD_BOUND);
        }
    }

    #[test]
    fn combined_near_limit_report_keeps_raw_prefix_gate_and_post_exit_facts() {
        use sha2::{Digest, Sha256};
        let bytes = vec![0; RAW_DIAGNOSTIC_BOUND as usize];
        let hash = hex::encode(Sha256::digest(&bytes));
        let mut raw = serde_json::Map::new();
        for name in ["ENTRY.DAT", "SELF.DAT", "CONTROL.DAT", "FAILURE.DAT"] {
            for suffix in ["", ".pending"] {
                let key = format!("{name}{suffix}");
                let identity = aiw_probe::WindowsFileIdentity {
                    final_path: format!(r"C:\AIW\SevenZip\Work\Mxc\Output\{key}"),
                    volume_serial_number: "1".repeat(16),
                    file_id: "2".repeat(32),
                };
                raw.insert(
                    key,
                    captured_raw_diagnostic(&bytes, &identity, &hash).unwrap(),
                );
            }
        }
        let mut used = 0;
        let mut prefixes = serde_json::Map::new();
        for index in 0..19 {
            prefixes.insert(
                index.to_string(),
                prefix_record(
                    Ok(serde_json::json!({"processId":42,"diagnostic":"x".repeat(7950)})),
                    &mut used,
                    18 - index,
                ),
            );
        }
        assert!(used > 120 * 1024 && used <= PREFIX_TOTAL_BOUND);
        let post_exit = "QueryFullProcessImageNameW: hresult=0x8007001f";
        let report = bounded_creation_report(serde_json::json!({
            "retainedPrefixes":prefixes,"rawContainedDiagnostics":raw,
            "worker":{"diagnostic":"w".repeat(63000)},"workerReadError":null,
            "handshake":{"diagnostic":"h".repeat(63000)},"handshakeError":null,
            "ownerObservations":{"ownerMeasuredChild":{"processId":42,"diagnostic":"c".repeat(63000)},
                "exactOuterJobMembership":true,"releaseGatePublished":true,
                "postExitBindingError":post_exit,"rootTokenMeasurement":{"diagnostic":"t".repeat(140000)}}
        })).unwrap();
        assert_eq!(
            report["ownerObservations"]["postExitBindingError"],
            post_exit
        );
        assert_eq!(report["ownerObservations"]["releaseGatePublished"], true);
        assert_eq!(
            report["ownerObservations"]["ownerMeasuredChild"]["processId"],
            42
        );
        assert!(report["ownerObservations"]["rootTokenMeasurement"].is_null());
        assert!(report["ownerObservations"]["rootTokenMeasurementReadError"].is_string());
        assert_eq!(report["retainedPrefixes"]["0"]["value"]["processId"], 42);
        assert_eq!(
            report["rawContainedDiagnostics"].as_object().unwrap().len(),
            8
        );
        assert!(!report["worker"].is_null() && !report["handshake"].is_null());
        assert!(serde_json::to_vec(&report).unwrap().len() < 834 * 1024);
    }

    #[test]
    fn raw_capture_preserves_empty_binary_malformed_and_exact_bound_bytes() {
        use sha2::{Digest, Sha256};
        let identity = aiw_probe::WindowsFileIdentity {
            final_path: CONTROL_ENTRY.into(),
            volume_serial_number: "1".repeat(16),
            file_id: "2".repeat(32),
        };
        for bytes in [
            vec![],
            vec![0, 255, 128, b'{'],
            b"{malformed".to_vec(),
            vec![42; 16384],
        ] {
            let hash = hex::encode(Sha256::digest(&bytes));
            let capture = captured_raw_diagnostic(&bytes, &identity, &hash).unwrap();
            assert_eq!(capture["captureComplete"], true);
            assert_eq!(capture["rawHex"], hex::encode(&bytes));
            assert_eq!(capture["sizeBytes"], bytes.len());
            assert_eq!(capture["identity"]["fileId"], identity.file_id);
        }
        assert!(captured_raw_diagnostic(&vec![0; 16385], &identity, "").is_err());
        assert!(captured_raw_diagnostic(b"changed", &identity, &"0".repeat(64)).is_err());
    }
    #[test]
    fn self_diagnostics_cannot_authorize_a_different_gate_actor_or_request() {
        let token: aiw_token::TokenEvidence = serde_json::from_value(serde_json::json!({
            "schemaVersion":aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION,
            "processId":std::process::id(),"tokenType":"primary","isAppContainer":true,
            "userSid":"S-1-5-21-1-2-3-1001","integrity":{"sid":"S-1-16-4096","rid":4096,"level":"low"},
            "elevationType":"default","isElevated":false,"capabilities":[],"restrictedSidCount":0
        })).unwrap();
        assert!(self_token_errors(std::process::id(), &token).is_empty());
        let mut ready: Ready = serde_json::from_value(serde_json::json!({
            "requestSha256":"a".repeat(64),"helperSha256":"b".repeat(64),
            "child":{"schemaVersion":"aiw.dev/research-mxc-child-observation/v0alpha1",
                "processId":std::process::id(),"creationTime":42,"queriedImagePath":contract::CONTROL_IMAGE,
                "imageIdentity":{"finalPath":contract::CONTROL_IMAGE,"volumeSerialNumber":"1","fileId":"2"},
                "imageSha256":"b".repeat(64),"imageSizeBytes":1,"imageAttributes":32,"imageLinkCount":1,
                "imageOnlyUnnamedDataStream":true,"token":token}
        })).unwrap();
        assert!(gate_matches(
            &ready,
            &"a".repeat(64),
            &"b".repeat(64),
            &token,
            42
        ));
        for field in ["requestSha256", "helperSha256"] {
            let mut bad = serde_json::to_value(&ready).unwrap();
            bad[field] = "c".repeat(64).into();
            assert!(!gate_matches(
                &serde_json::from_value(bad).unwrap(),
                &"a".repeat(64),
                &"b".repeat(64),
                &token,
                42
            ));
        }
        for (field, value) in [
            ("processId", serde_json::json!(0)),
            ("creationTime", serde_json::json!(43)),
            ("imageSha256", serde_json::json!("c".repeat(64))),
        ] {
            let mut bad = serde_json::to_value(&ready).unwrap();
            bad["child"][field] = value;
            assert!(!gate_matches(
                &serde_json::from_value(bad).unwrap(),
                &"a".repeat(64),
                &"b".repeat(64),
                &token,
                42
            ));
        }
        ready.child.token.user_sid = "S-1-5-21-1-2-3-1002".into();
        // Structure alone still passes; actor authorization requires equality
        // with the full outside observation in the protected gate.
        assert!(self_token_errors(std::process::id(), &ready.child.token).is_empty());
        assert!(!gate_matches(
            &ready,
            &"a".repeat(64),
            &"b".repeat(64),
            &token,
            42
        ));
    }
    #[test]
    fn ordinary_worker_still_refuses_appcontainer_and_identity_drift() {
        let sid = "S-1-5-21-1-2-3-1001";
        let mut token: aiw_token::TokenEvidence = serde_json::from_value(serde_json::json!({
            "schemaVersion":aiw_token::TOKEN_EVIDENCE_SCHEMA_VERSION,
            "processId":std::process::id(),"tokenType":"primary","isAppContainer":false,
            "userSid":sid,"integrity":{"sid":"S-1-16-8192","rid":8192,"level":"medium"},
            "elevationType":"default","isElevated":false,"capabilities":[],"restrictedSidCount":0
        }))
        .unwrap();
        assert!(ordinary_worker_token(&token, sid));
        token.is_app_container = true;
        assert!(!ordinary_worker_token(&token, sid));
        token.is_app_container = false;
        assert!(!ordinary_worker_token(&token, "S-1-5-21-1-2-3-1002"));
        token.is_elevated = true;
        assert!(!ordinary_worker_token(&token, sid));
    }
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
