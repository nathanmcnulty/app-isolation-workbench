//! Read-only Results Explorer. Projection only: all authority remains in aiw-runner.
use aiw_runner::{ApplicationAssessmentInput, report_application_assessment};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

const LIMIT: u64 = 1024 * 1024;
const FUNCTIONS: [&str; 7] = [
    "install",
    "launch",
    "openDocument",
    "editSaveDocument",
    "close",
    "uninstall",
    "stlTo3mfExport",
];
const STAGES: [&str; 9] = [
    "beforeInstallCapture",
    "install",
    "afterInstallCapture",
    "prepareDocument",
    "launch",
    "openDocument",
    "editSaveDocument",
    "close",
    "afterExerciseCapture",
];
pub const SCOPE: &str = "Fixed workflow observations only. General compatibility and isolation are unmeasured. Cleanup describes historical receipts, not current host or worker state.";

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    schema_version: &'static str,
    scope: &'static str,
    pub rows: Vec<Value>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Loaded {
    pub token: String,
    pub summary: Summary,
    pub selection_labels: Vec<String>,
}
struct Retained {
    loaded: Loaded,
    excluded: Vec<PathBuf>,
    _held: Vec<File>,
}
#[derive(Default)]
pub struct ResultsStore(Mutex<Option<Retained>>);

fn hash(value: &Value) -> Option<&str> {
    value.as_str().filter(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn known<'a>(value: &Value, allowed: &'a [&str], fallback: &'a str) -> &'a str {
    allowed
        .iter()
        .copied()
        .find(|s| value.as_str() == Some(s))
        .unwrap_or(fallback)
}
/// Field allowlist deliberately omits caller IDs, run IDs, free text, paths and account data.
fn project(report: &Value) -> Summary {
    let rows = report["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
        .map(|(index, row)| project_row(report, row, index))
        .collect();
    Summary {
        schema_version: "aiw.dev/results-summary/v0alpha2",
        scope: SCOPE,
        rows,
    }
}
fn project_row(report: &Value, row: &Value, index: usize) -> Value {
    let source = &row["source"];
    let evidence = &source["evidence"];
    let kind = source["kind"].as_str().unwrap_or("");
    let mut paired = Value::Null;
    let is_paired = kind == "windowsSandbox" && evidence["profile"] == "pairedControls";
    let mut stages = vec![];
    let mut gaps = source_gaps(&report["missingEvidence"]);
    if is_paired {
        for gap in &mut gaps {
            let label = match gap.as_str() {
                "ordinaryBaseline" => "ordinary-user application baseline",
                "independentHostMeasurements" => "independent host measurements",
                "filesystemRegistryChanges" => "application filesystem and registry changes",
                "networkUiIpcObservations" => "network, UI and IPC observations",
                "persistenceResidue" => "application persistence residue",
                "descendantCoverage" => "application descendant coverage",
                "offlineCanary" => "application denial canaries",
                "effectiveBackendVerification" => "effective application boundary verification",
                "captureCompleteness" => "full application capture completeness",
                "targetToken" => "application target token",
                other => other,
            };
            *gap = format!("Beyond fixed controls: {label}");
        }
    }

    let mut refs = vec![];
    let mut cleanup = Value::Null;
    let mut outcome = "unavailable";
    let mut reason = "evidenceRejected";
    let mut evidence_status = "unmeasured";
    let (application, workflow, detail) = match kind {
        "msixResearch" => {
            cleanup = json!(evidence["recordedProcessJobTaskCleanupVerified"].as_bool());
            outcome = "insufficientEvidence";
            for item in evidence["evidence"].as_array().into_iter().flatten() {
                if let Some(h) = hash(&item["sha256"]) {
                    refs.push(json!({"kind":"archiveEntrySha256", "sha256":h}));
                }
            }
            ("Notepad++", "Reviewed MSIX research lifecycle", evidence)
        }
        "vmMsix" => {
            cleanup = json!(evidence["cleanupComplete"].as_bool());
            outcome = if evidence["workflowVerified"] == true {
                "insufficientEvidence"
            } else {
                "partial"
            };
            ("Notepad++", "Retained VM MSIX lifecycle", evidence)
        }
        "windowsSandbox" => {
            let result = &evidence["result"];
            if result["kind"] == "notepadMsi" {
                let d = &result["report"]["summary"];
                if result["report"]["status"] != "unavailable" {
                    outcome = known(
                        &d["recordedOutcome"],
                        &["failed", "cancelled", "insufficientEvidence"],
                        "partial",
                    );
                    cleanup = json!(d["recordedCleanupVerified"].as_bool());
                    evidence_status = known(
                        &d["failureEvidence"],
                        &["verified", "absent", "rejected"],
                        "unmeasured",
                    );
                    for stage in d["stageProgress"].as_array().into_iter().flatten() {
                        let name = known(&stage["stage"], &STAGES, "");
                        if !name.is_empty() {
                            stages.push(json!({"stage":name, "status":known(&stage["status"], &["passed", "failed", "notReached"], "unmeasured")}));
                        }
                    }
                } else {
                    reason = known(&result["report"]["summary"], REASONS, "evidenceRejected");
                }
                ("Notepad++", "Sandbox MSI assessment", d)
            } else if result["kind"] == "pairedControls" {
                let d = &result["report"];
                cleanup = json!(d["recordedCleanupVerified"].as_bool());
                outcome = known(
                    &d["recordedOutcome"],
                    &["failed", "cancelled", "insufficientEvidence"],
                    "partial",
                );
                evidence_status = known(
                    &d["evidenceStatus"],
                    &["verified", "driverIncomplete", "absent", "rejected"],
                    "unmeasured",
                );
                paired = project_paired(d);
                gaps.extend(source_gaps(&d["evidenceGaps"]));
                if paired["origin"] == "syntheticRehearsal" {
                    gaps.push("Synthetic offline example; not production acceptance".into());
                }
                (
                    "Fixed AIW controls",
                    "Ordinary user / classic AppContainer",
                    d,
                )
            } else if result["kind"] == "bambuExport" {
                let d = &result["report"];
                cleanup = json!(d["recordedCleanupVerified"].as_bool());
                outcome = known(
                    &d["outcome"],
                    &["failed", "cancelled", "insufficientEvidence"],
                    "partial",
                );
                evidence_status = known(
                    &d["evidenceStatus"],
                    &["verified", "absent", "rejected"],
                    "unmeasured",
                );
                gaps.extend(source_gaps(&d["missingEvidence"]));
                if evidence_status == "verified" {
                    let scenario = &d["scenario"];
                    let mut failed = false;
                    for name in ["install", "prepareFixture", "export", "collectArtifact"] {
                        let completed = scenario["completedStages"]
                            .as_array()
                            .is_some_and(|v| v.iter().any(|s| s == name));
                        let status = if scenario["failedStage"] == name {
                            failed = true;
                            "failed"
                        } else if completed {
                            "passed"
                        } else if failed {
                            "notReached"
                        } else {
                            "unmeasured"
                        };
                        stages.push(json!({"stage":name,"status":status}));
                    }
                }
                ("Bambu Studio", "Sandbox STL-to-3MF export", d)
            } else {
                reason = known(&result["report"], REASONS, "evidenceRejected");
                let bambu = evidence["profile"] == "bambuExport";
                if is_paired {
                    (
                        "Fixed AIW controls",
                        "Ordinary user / classic AppContainer",
                        &Value::Null,
                    )
                } else {
                    (
                        if bambu { "Bambu Studio" } else { "Notepad++" },
                        if bambu {
                            "Sandbox STL-to-3MF export"
                        } else {
                            "Sandbox MSI assessment"
                        },
                        &Value::Null,
                    )
                }
            }
        }
        _ => {
            reason = known(evidence, REASONS, "evidenceRejected");
            ("Unavailable", "Unavailable selection", &Value::Null)
        }
    };
    for key in [
        "receiptSha256",
        "evidenceRootHash",
        "requestSha256",
        "archiveSha256",
    ] {
        if let Some(h) = hash(&detail[key]) {
            refs.push(json!({"kind":key, "sha256":h}));
        }
    }
    if outcome == "unavailable" {
        gaps.push(format!("Selection unavailable: {reason}"));
    }
    if ["absent", "rejected"].contains(&evidence_status) {
        gaps.push(format!("Failure evidence {evidence_status}"));
    }
    gaps.push("General compatibility unmeasured".into());
    gaps.push("Effective isolation unmeasured".into());
    gaps.sort();
    gaps.dedup();
    let functions: serde_json::Map<String, Value> = FUNCTIONS
        .iter()
        .map(|key| {
            (
                (*key).into(),
                json!(match if is_paired {
                    None
                } else {
                    row["functions"][key].as_bool()
                } {
                    Some(true) => "passed",
                    Some(false) => "failed",
                    None => "unmeasured",
                }),
            )
        })
        .collect();
    json!({"selection":index+1, "application":application, "workflow":workflow, "outcome":outcome, "unavailableReason":if outcome=="unavailable" {Some(reason)} else {None}, "functions":functions, "stages":stages, "failureEvidence":evidence_status, "historicalCleanupVerified":cleanup, "evidenceReferences":refs, "evidenceGaps":gaps,"paired":paired})
}
fn project_paired(detail: &Value) -> Value {
    fn process(p: &Value) -> Value {
        let held = &p["heldToken"];
        json!({"heldTokenObserved":held.is_object(),"selfTokenObserved":p["selfToken"].is_object(),"timedOut":p["timedOut"].as_bool(),"jobEmpty":p["jobEmpty"].as_bool(),
            "appContainer":held["isAppContainer"].as_bool(),"elevated":held["isElevated"].as_bool(),"integrity":known(&held["integrity"]["level"],&["low","medium","high","system"],"unmeasured"),
            "noCapabilities":held["capabilities"].as_array().map(Vec::is_empty)})
    }
    let status = known(
        &detail["evidenceStatus"],
        &["verified", "driverIncomplete", "absent", "rejected"],
        "unmeasured",
    );
    let verified = status == "verified" && detail["observations"].is_object();
    let mut cases = vec![];
    for variant in ["baseline", "candidate"] {
        let full = if verified {
            &detail["observations"][variant]
        } else {
            &Value::Null
        };
        for case in ["file", "registry", "child"] {
            let prefix = detail["driverFailure"]["progress"]
                .as_array()
                .filter(|_| status == "driverIncomplete")
                .and_then(|v| {
                    v.iter()
                        .take(6)
                        .find(|p| p["variant"] == variant && p["case"] == case)
                });
            let partial = prefix.map(|p| &p["observation"]).unwrap_or(&Value::Null);
            let reading = if full.is_object() {
                &full[case]
            } else {
                &partial["read"]
            };
            let outcome = if case == "child" {
                if full.is_object() {
                    &full["childOutcome"]
                } else {
                    &partial["outcome"]
                }
            } else {
                &reading["outcome"]
            };
            let process_key = match case {
                "file" => "fileProcess",
                "registry" => "registryProcess",
                _ => "childProcess",
            };
            let root = if full.is_object() {
                &full[process_key]
            } else {
                prefix.map(|p| &p["process"]).unwrap_or(&Value::Null)
            };
            let child = if case != "child" {
                &Value::Null
            } else if full.is_object() {
                &full["childToken"]
            } else {
                &partial["childToken"]
            };
            cases.push(json!({"variant":variant,"case":case,"outcome":known(outcome,&["success","accessDenied","notFound","timeout","failure","unmeasured"],"unmeasured"),
                "nativeCode":reading["nativeCode"].as_u64().filter(|v|[2,3,5].contains(v)),"stage":known(&reading["stage"],&["fileRead","openKey","querySize","queryValue"],"notMeasured"),
                "sha256":hash(&reading["sha256"]),"sizeBytes":reading["sizeBytes"].as_u64().filter(|v|*v==29),"process":process(root),"descendantTokenObserved":child.is_object(),
                "descendantAppContainer":child["isAppContainer"].as_bool(),"descendantIntegrity":known(&child["integrity"]["level"],&["low","medium","high","system"],"unmeasured")}));
        }
    }
    let bindings: serde_json::Map<String, Value> = [
        "fixtureUnchanged",
        "launcherUnchanged",
        "fileUnchanged",
        "fileAclUnchanged",
        "registryValueUnchanged",
        "registryAclUnchanged",
    ]
    .into_iter()
    .map(|key| {
        (
            key.into(),
            json!(if verified {
                detail["observations"][key].as_bool()
            } else {
                None
            }),
        )
    })
    .collect();
    json!({"origin":known(&detail["profile"]["origin"],&["syntheticRehearsal","nativeWorker"],"unmeasured"),"evidenceStatus":status,"observationsVerified":verified,"eligible":verified && detail["comparison"]["eligible"].as_bool().unwrap_or(false),
        "reason":known(&detail["comparison"]["reason"],&["fixedControlsObserved","baselineFailed","candidateFailed","driverIncomplete","cleanupUnknown"],"unmeasured"),
        "driverComplete":if verified {detail["observations"]["driverComplete"].as_bool()} else {None},"innerProfileDeleted":if verified {detail["observations"]["profileDeleted"].as_bool()} else {None},"recordedBindings":bindings,
        "sourceSha256":hash(&detail["profile"]["sourceSha256"]),"fixtureSha256":hash(&detail["profile"]["fixtureSha256"]),"cases":cases})
}
fn source_gaps(value: &Value) -> Vec<String> {
    const GAPS: &[&str] = &[
        "General application compatibility is unmeasured",
        "Network, endpoint and host containment are unmeasured",
        "Cleanup is historical; viewing makes no current-state claim",
        "Committed approval/dispatch provenance unavailable; no execution evidence accepted",
        "Committed approval unavailable; no execution evidence accepted",
        "Approval recorded; Sandbox dispatch not committed; fixed control cases remain unmeasured",
        "No committed completed assessment; retained observations remain inconclusive",
        "ordinaryBaseline",
        "independentHostMeasurements",
        "filesystemRegistryChanges",
        "networkUiIpcObservations",
        "persistenceResidue",
        "descendantCoverage",
        "offlineCanary",
        "effectiveBackendVerification",
        "captureCompleteness",
        "targetToken",
        "ordinary baseline",
        "independent verification of requested assertions (including target token)",
        "application-level isolation comparison",
        "descendant boundary and denial canaries",
        "filesystem and registry changes",
        "slicing, printer and cloud workflows",
    ];
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|gap| {
            let g = known(gap, GAPS, "");
            (!g.is_empty()).then(|| g.to_string())
        })
        .collect()
}
const REASONS: &[&str] = &[
    "projectUnreadable",
    "projectInvalid",
    "evidenceRejected",
    "interactiveSessionNotAssessment",
    "duplicateRun",
];

fn bounded_input(path: &Path) -> Result<ApplicationAssessmentInput, String> {
    if !local_drive_path(path) {
        return Err("Selection manifest requires a local drive path".into());
    }
    let mut bytes = vec![];
    File::open(path)
        .map_err(|_| "Selection manifest unavailable")?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Selection manifest unreadable")?;
    if bytes.len() as u64 > LIMIT {
        return Err("Selection manifest exceeds 1 MiB".into());
    }
    let input: ApplicationAssessmentInput = serde_json::from_slice(&bytes).map_err(|_| "Invalid or unsupported selection manifest; use application-assessment-input/v0alpha1 JSON")?;
    let count = input.msix_research.len()
        + input.msix_vm.len()
        + input
            .windows_sandbox
            .as_ref()
            .map_or(0, |set| set.entries.len());
    if count == 0 {
        return Err("Selection is empty; choose 1-32 retained assessments".into());
    }
    if count > 32 {
        return Err("Selection exceeds the 32-assessment limit".into());
    }
    input.validate()?;
    Ok(input)
}
fn pin_source(
    path: &Path,
    archive: bool,
    held: &mut Vec<File>,
    excluded: &mut Vec<PathBuf>,
) -> Result<bool, String> {
    let chain = hold_local_chain(path)?;
    let excluded_path = if archive && chain.complete {
        chain
            .deepest
            .parent()
            .ok_or("Archive parent unavailable")?
            .to_path_buf()
    } else {
        chain.deepest.clone()
    };
    excluded.push(excluded_path);
    held.extend(chain.files);
    Ok(chain.complete)
}
impl ResultsStore {
    pub fn load(&self, path: &Path) -> Result<Loaded, String> {
        let mut guard = self
            .0
            .try_lock()
            .map_err(|_| "Another Results operation is in progress")?;
        let manifest_chain = hold_local_chain(path)?;
        if !manifest_chain.complete {
            return Err("Selection manifest unavailable".into());
        }
        let mut held = manifest_chain.files;
        let input = bounded_input(path)?;
        let selection_labels: Vec<String> = input
            .windows_sandbox
            .iter()
            .flat_map(|set| set.entries.iter().map(|e| e.run.id.clone()))
            .chain(input.msix_vm.iter().map(|e| e.id.clone()))
            .chain(input.msix_research.iter().map(|e| e.id.clone()))
            .collect();
        let mut excluded = vec![];
        let mut available = input.clone();
        available.msix_research.clear();
        available.msix_vm.clear();
        available.windows_sandbox = None;
        for entry in &input.msix_research {
            if pin_source(&entry.archive, true, &mut held, &mut excluded)? {
                available.msix_research.push(entry.clone());
            }
        }
        for entry in &input.msix_vm {
            if pin_source(&entry.workspace, false, &mut held, &mut excluded)? {
                available.msix_vm.push(entry.clone());
            }
        }
        if let Some(set) = &input.windows_sandbox {
            let mut pinned = set.clone();
            pinned.entries.clear();
            for entry in &set.entries {
                let workspace_ok =
                    pin_source(&entry.run.workspace_root, false, &mut held, &mut excluded)?;
                let project_chain = hold_local_chain(&entry.run.project_path)?;
                let project_ok = project_chain.complete;
                held.extend(project_chain.files);
                if workspace_ok && project_ok {
                    pinned.entries.push(entry.clone());
                }
            }
            if !pinned.entries.is_empty() {
                available.windows_sandbox = Some(pinned);
            }
        }
        // Never dispatch an unpinned missing path: it could appear or become a
        // reparse target between inspection and reading. Keep its row unavailable.
        let any_available = !available.msix_research.is_empty()
            || !available.msix_vm.is_empty()
            || available.windows_sandbox.is_some();
        let mut report = if any_available {
            serde_json::to_value(report_application_assessment(&available)?)
                .map_err(|_| "Report projection failed")?
        } else {
            json!({"entries":[],"missingEvidence":[]})
        };
        let mut verified: std::collections::BTreeMap<String, Value> = report["entries"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|row| (row["id"].as_str().unwrap_or("").to_owned(), row.clone()))
            .collect();
        report["entries"]=json!(selection_labels.iter().map(|id|verified.remove(id).unwrap_or_else(||json!({"id":id,"functions":{},"source":{"kind":"unavailable","evidence":"evidenceRejected"}}))).collect::<Vec<_>>());
        let loaded = Loaded {
            selection_labels,
            token: uuid::Uuid::new_v4().to_string(),
            summary: project(&report),
        };
        *guard = Some(Retained {
            loaded: loaded.clone(),
            excluded,
            _held: held,
        });
        Ok(loaded)
    }
    pub fn export(&self, token: &str, destination: &Path, format: &str) -> Result<(), String> {
        let guard = self
            .0
            .try_lock()
            .map_err(|_| "Another Results operation is in progress")?;
        let retained = guard
            .as_ref()
            .filter(|r| r.loaded.token == token)
            .ok_or("Results selection changed; reload before exporting")?;
        let bytes = match format {
            "json" => serde_json::to_vec_pretty(&retained.loaded.summary)
                .map_err(|_| "Summary encoding failed")?,
            "markdown" => markdown(&retained.loaded.summary).into_bytes(),
            _ => return Err("Unsupported summary format".into()),
        };
        write_new(destination, &retained.excluded, &bytes)
    }
}
fn markdown(summary: &Summary) -> String {
    let mut text = format!("# Results summary\n\n{}\n\n", summary.scope);
    for row in &summary.rows {
        text.push_str(&format!(
            "## Selection {} — {}\n\nWorkflow: {}\n\nOutcome: {}\n\n",
            row["selection"],
            row["application"].as_str().unwrap_or(""),
            row["workflow"].as_str().unwrap_or(""),
            row["outcome"].as_str().unwrap_or("")
        ));
        if let Some(reason) = row["unavailableReason"].as_str() {
            text.push_str(&format!("Unavailable reason: {reason}\n\n"));
        }
        if row["paired"].is_object() {
            let paired = &row["paired"];
            text.push_str(&format!("Fixed paired controls: requested origin {}. Comparison eligible for recorded cases: {}. Reason: {}. General compatibility/isolation and production acceptance remain unmeasured.\n\n",
                paired["origin"].as_str().unwrap_or("unmeasured"),paired["eligible"],paired["reason"].as_str().unwrap_or("unmeasured")));
            if paired["origin"] == "syntheticRehearsal" {
                text.push_str("**SYNTHETIC offline example; not production acceptance.**\n\n");
            }
            text.push_str(&format!("Driver complete: {}. Inner profile deletion recorded: {}. Fixed bindings unchanged: {}. These are retained observations, separate from outer worker cleanup.\n\n",paired["driverComplete"],paired["innerProfileDeleted"],paired["recordedBindings"]));
            text.push_str("| Variant | Control | Observation | Native code | Held/self tokens observed | Integrity | AppContainer | Descendant token observed | Inner job empty |\n|---|---|---|---|---|---|---|---|---|\n");
            for item in paired["cases"].as_array().into_iter().flatten() {
                text.push_str(&format!(
                    "| {} | {} | {} | {} | {}/{} | {} | {} | {} | {} |\n",
                    item["variant"].as_str().unwrap_or(""),
                    item["case"].as_str().unwrap_or(""),
                    item["outcome"].as_str().unwrap_or("unmeasured"),
                    item["nativeCode"],
                    item["process"]["heldTokenObserved"],
                    item["process"]["selfTokenObserved"],
                    item["process"]["integrity"]
                        .as_str()
                        .unwrap_or("unmeasured"),
                    item["process"]["appContainer"],
                    item["descendantTokenObserved"],
                    item["process"]["jobEmpty"]
                ));
            }
            text.push_str("\nOuter worker cleanup is separate. Missing evidence does not establish a denial or a stage not reached.\n\n");
        }
        text.push_str("| Function | Observation |\n|---|---|\n");
        for function in FUNCTIONS {
            text.push_str(&format!(
                "| {function} | {} |\n",
                row["functions"][function].as_str().unwrap_or("unmeasured")
            ));
        }
        text.push_str("\nHistorical cleanup (separate from function outcomes): ");
        text.push_str(match row["historicalCleanupVerified"].as_bool() {
            Some(true) => "verified in retained receipt",
            Some(false) => "not verified in retained receipt",
            None => "unmeasured",
        });
        text.push_str(&format!(
            "\n\nFailure evidence: {}\n\n### Stage progress\n\n",
            row["failureEvidence"].as_str().unwrap_or("unmeasured")
        ));
        for stage in row["stages"].as_array().into_iter().flatten() {
            text.push_str(&format!(
                "- {}: {}\n",
                stage["stage"].as_str().unwrap_or(""),
                stage["status"].as_str().unwrap_or("unmeasured")
            ));
        }
        if row["stages"]
            .as_array()
            .is_none_or(|stages| stages.is_empty())
        {
            text.push_str("Stage progress unmeasured or not exposed by this profile.\n");
        }
        text.push_str("\n### Evidence gaps\n\n");
        for gap in row["evidenceGaps"].as_array().into_iter().flatten() {
            text.push_str(&format!("- {}\n", gap.as_str().unwrap_or("")));
        }
        text.push_str("\n### Evidence references (hashes only)\n\n");
        for reference in row["evidenceReferences"].as_array().into_iter().flatten() {
            text.push_str(&format!(
                "- {}: `{}`\n",
                reference["kind"].as_str().unwrap_or(""),
                reference["sha256"].as_str().unwrap_or("")
            ));
        }
        if row["evidenceReferences"]
            .as_array()
            .is_none_or(|refs| refs.is_empty())
        {
            text.push_str("No verified reference available.\n");
        }
        text.push('\n');
    }
    text
}
fn contains_path(root: &Path, child: &Path) -> bool {
    let root = root.to_string_lossy().trim_end_matches('\\').to_lowercase();
    let child = child
        .to_string_lossy()
        .trim_end_matches('\\')
        .to_lowercase();
    child == root || child.starts_with(&(root + "\\"))
}
fn local_drive_path(path: &Path) -> bool {
    use std::path::{Component, Prefix};
    matches!(path.components().next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
}
/// Open from the drive root down, without following reparse points or sharing
/// deletion. No enumeration: only explicit path ancestors. Keep these handles
/// through the snapshot lifetime (sources) or exclusive output creation (export).
struct LocalChain {
    files: Vec<File>,
    deepest: PathBuf,
    complete: bool,
}
fn hold_local_chain(path: &Path) -> Result<LocalChain, String> {
    use std::os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    };
    use std::path::Component;
    if !path.is_absolute()
        || !local_drive_path(path)
        || path.as_os_str().encode_wide().count() > 32767
        || path.components().any(|c| matches!(c, Component::ParentDir))
    {
        return Err("Results requires bounded local drive paths without parent traversal".into());
    }
    let root = path
        .ancestors()
        .find(|p| p.has_root() && p.file_name().is_none())
        .ok_or("Local drive root unavailable")?;
    let wide: Vec<u16> = root.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: wide is a live NUL-terminated UTF-16 drive-root string.
    let drive_type =
        unsafe { windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(wide.as_ptr()) };
    if ![2, 3, 6].contains(&drive_type) {
        return Err("Results requires a local disk; network drives are unavailable".into());
    }
    let mut held = vec![];
    let mut deepest = root.to_path_buf();
    let mut complete = true;
    for ancestor in path
        .ancestors()
        .filter(|p| p.has_root())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        let file = match OpenOptions::new()
            .read(true)
            .share_mode(3)
            .custom_flags(0x02000000 | 0x00200000)
            .open(ancestor)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                complete = false;
                break;
            }
            Err(_) => return Err("Selected local location unavailable".into()),
        };
        if file
            .metadata()
            .map_err(|_| "Cannot inspect selected location")?
            .file_attributes()
            & 0x400
            != 0
        {
            return Err("Results does not follow reparse points".into());
        }
        held.push(file);
        deepest = ancestor.to_path_buf();
    }
    let deepest = deepest
        .canonicalize()
        .map_err(|_| "Pinned local location unavailable")?;
    Ok(LocalChain {
        files: held,
        deepest,
        complete,
    })
}
fn write_bytes(writer: &mut impl Write, bytes: &[u8]) -> std::io::Result<()> {
    writer.write_all(bytes)
}
fn write_new(destination: &Path, excluded: &[PathBuf], bytes: &[u8]) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    if !destination.is_absolute() || destination.as_os_str().encode_wide().count() > 32767 {
        return Err("Export requires a bounded absolute file path".into());
    }
    let leaf = destination
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("Invalid export filename")?;
    if leaf
        .chars()
        .any(|c| c.is_control() || "<>:\"/\\|?*".contains(c))
        || leaf.ends_with(['.', ' '])
    {
        return Err("Invalid export filename".into());
    }
    let parent_path = destination.parent().ok_or("Export parent unavailable")?;
    let _held = hold_local_chain(parent_path)?;
    if !_held.complete {
        return Err("Export parent unavailable".into());
    }
    let parent = parent_path
        .canonicalize()
        .map_err(|_| "Export parent unavailable")?;
    if !local_drive_path(&parent) {
        return Err("Export requires a local drive destination".into());
    }
    if excluded.iter().any(|p| contains_path(p, &parent)) {
        return Err("Export must be outside all selected retained locations".into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(parent.join(leaf))
        .map_err(|_| "Cannot create export: destination exists or is unavailable")?;
    write_bytes(&mut file, bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| {
            "Export write failed; a partial new file may remain. Choose a new filename.".into()
        })
}

#[cfg(test)]
mod tests {
    #[test]
    fn approved_without_dispatch_gap_is_preserved_without_private_diagnostics() {
        let gap = "Approval recorded; Sandbox dispatch not committed; fixed control cases remain unmeasured";
        assert_eq!(
            source_gaps(&json!([
                gap,
                "private-path-sentinel S-1-5-21 account diagnostic"
            ])),
            vec![gap.to_string()]
        );
    }

    use super::*;
    fn temp() -> PathBuf {
        let path = std::env::temp_dir().join(format!("aiw-results-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        path
    }
    fn selection(root: &Path) -> Value {
        json!({"schemaVersion":"aiw.dev/application-assessment-input/v0alpha1", "msixResearch":[{"id":"fixture", "profile":"worker107NotepadR5", "archive":root.join("worker107-r5.zip")} ]})
    }
    fn fixture() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fixtures/msix-lifecycle/worker107-r5.zip")
            .canonicalize()
            .unwrap()
    }
    #[test]
    fn paired_projection_omits_private_fields_and_never_promotes_application_functions() {
        let observation: Value = serde_json::from_str(include_str!(
            "../../fixtures/paired-controls/synthetic-result.json"
        ))
        .unwrap();
        let detail = json!({"profile":{"origin":"syntheticRehearsal","sourceSha256":"a".repeat(64),"fixtureSha256":"b".repeat(64)},"recordedOutcome":"insufficientEvidence","recordedCleanupVerified":null,"evidenceStatus":"verified","observations":observation,"comparison":{"eligible":false,"reason":"cleanupUnknown"},"operator":"secret-account@example.invalid","privatePath":"private-path-sentinel","rawArtifact":"credential-sentinel"});
        let raw = json!({"missingEvidence":["ordinaryBaseline","descendantCoverage","targetToken"],"entries":[{"id":"secret-account@example.invalid","functions":{"install":true,"launch":true},"source":{"kind":"windowsSandbox","evidence":{"profile":"pairedControls","result":{"kind":"pairedControls","report":detail}}}}]});
        let summary = project(&raw);
        assert_eq!(summary.schema_version, "aiw.dev/results-summary/v0alpha2");
        let row = &summary.rows[0];
        assert_eq!(row["application"], "Fixed AIW controls");
        assert_eq!(row["functions"]["install"], "unmeasured");
        assert_eq!(row["functions"]["launch"], "unmeasured");
        assert_eq!(row["paired"]["origin"], "syntheticRehearsal");
        assert_eq!(row["paired"]["eligible"], false);
        assert!(
            row["evidenceGaps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|g| g == "Beyond fixed controls: ordinary-user application baseline")
        );
        assert!(
            !row["evidenceGaps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|g| g == "ordinaryBaseline")
        );

        assert!(row["historicalCleanupVerified"].is_null());
        let cases = row["paired"]["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 6);
        assert_eq!(cases[0]["outcome"], "success");
        assert_eq!(cases[3]["outcome"], "accessDenied");
        assert_eq!(cases[3]["nativeCode"], 5);
        for index in [0, 1, 3, 4] {
            assert_eq!(cases[index]["descendantTokenObserved"], false);
            assert_eq!(cases[index]["descendantIntegrity"], "unmeasured");
            assert!(cases[index]["descendantAppContainer"].is_null());
        }
        for (index, integrity, app_container) in [(2, "medium", false), (5, "low", true)] {
            assert_eq!(cases[index]["descendantTokenObserved"], true);
            assert_eq!(cases[index]["descendantIntegrity"], integrity);
            assert_eq!(cases[index]["descendantAppContainer"], app_container);
        }
        assert_eq!(row["paired"]["innerProfileDeleted"], true);
        assert_eq!(row["paired"]["recordedBindings"]["fileAclUnchanged"], true);

        let bytes = serde_json::to_string(&summary).unwrap();
        let md = markdown(&summary);
        for output in [&bytes, &md] {
            for secret in [
                "S-1-",
                "secret-account",
                "example.invalid",
                "private-path-sentinel",
                "credential-sentinel",
                "canary.txt",
                "launcherId",
                "runId",
            ] {
                assert!(!output.contains(secret), "leaked {secret}");
            }
        }
        assert!(md.contains("SYNTHETIC"));
        assert!(md.contains("accessDenied"));
        assert!(md.contains("Outer worker cleanup is separate"));
        assert_eq!(bytes, serde_json::to_string(&project(&raw)).unwrap());
        assert_eq!(md, markdown(&project(&raw)));
        let mut rejected = raw["entries"][0]["source"]["evidence"]["result"]["report"].clone();
        rejected["evidenceStatus"] = "rejected".into();
        rejected["profile"]["origin"] = "nativeWorker".into();
        rejected["comparison"]["eligible"] = true.into();
        let projected = project_paired(&rejected);
        assert_eq!(projected["observationsVerified"], false);
        assert_eq!(projected["eligible"], false);
        assert!(
            projected["cases"]
                .as_array()
                .unwrap()
                .iter()
                .all(|c| c["outcome"] == "unmeasured")
        );
    }
    #[test]
    fn paired_partial_projection_preserves_missing_and_timeout_without_inventing_reached_stages() {
        let detail = json!({"evidenceStatus":"driverIncomplete","profile":{"origin":"syntheticRehearsal"},"driverFailure":{"progress":[{"variant":"baseline","case":"file","process":{"heldToken":{},"timedOut":false},"observation":{"read":{"outcome":"notFound","nativeCode":2,"stage":"fileRead"},"outcome":"notFound"}},{"variant":"baseline","case":"registry","process":{"timedOut":true},"observation":{"read":{"outcome":"timeout"},"outcome":"timeout"}}]}});
        let paired = project_paired(&detail);
        assert_eq!(paired["cases"][0]["outcome"], "notFound");
        assert_eq!(paired["cases"][1]["outcome"], "timeout");
        assert_eq!(paired["cases"][2]["outcome"], "unmeasured");
        assert_eq!(paired["eligible"], false);
        assert!(
            !serde_json::to_string(&paired)
                .unwrap()
                .contains("notReached")
        );
    }

    #[test]
    fn paired_partial_descendant_tokens_belong_only_to_child_cases() {
        let mut progress = vec![];
        for (variant, integrity, app_container) in
            [("baseline", "medium", false), ("candidate", "low", true)]
        {
            for case in ["file", "registry", "child"] {
                // Even an unexpected token on another observation cannot become
                // evidence that that case created a descendant.
                progress.push(json!({"variant":variant,"case":case,"observation":{
                    "outcome":"success","read":{"outcome":"success"},
                    "childToken":{"integrity":{"level":integrity},"isAppContainer":app_container}
                }}));
            }
        }
        let paired = project_paired(&json!({"evidenceStatus":"driverIncomplete",
            "driverFailure":{"progress":progress}}));
        for index in [0, 1, 3, 4] {
            assert_eq!(paired["cases"][index]["descendantTokenObserved"], false);
            assert_eq!(paired["cases"][index]["descendantIntegrity"], "unmeasured");
            assert!(paired["cases"][index]["descendantAppContainer"].is_null());
        }
        for (index, integrity, app_container) in [(2, "medium", false), (5, "low", true)] {
            assert_eq!(paired["cases"][index]["descendantTokenObserved"], true);
            assert_eq!(paired["cases"][index]["descendantIntegrity"], integrity);
            assert_eq!(
                paired["cases"][index]["descendantAppContainer"],
                app_container
            );
        }
    }

    #[test]
    fn paired_private_driver_diagnostic_never_reaches_json_markdown_or_case_outcomes() {
        let detail = json!({"profile":{"origin":"nativeWorker"},"recordedOutcome":"failed","recordedCleanupVerified":true,"evidenceStatus":"driverIncomplete","driverFailure":{"schemaVersion":"aiw.dev/paired-controls-driver-failure/v0alpha2","diagnostic":"private-path-sentinel C:\\private\\account credential-sentinel <script>hostile</script>\u{202e}","progress":[],"launcherToken":null}});
        let raw = json!({"entries":[{"id":"local-selector","source":{"kind":"windowsSandbox","evidence":{"profile":"pairedControls","result":{"kind":"pairedControls","report":detail}}}}]});
        let summary = project(&raw);
        let paired = &summary.rows[0]["paired"];
        assert_eq!(paired["evidenceStatus"], "driverIncomplete");
        assert_eq!(paired["eligible"], false);
        assert!(
            paired["cases"]
                .as_array()
                .unwrap()
                .iter()
                .all(|case| case["outcome"] == "unmeasured")
        );
        for output in [serde_json::to_string(&summary).unwrap(), markdown(&summary)] {
            for private in [
                "private-path-sentinel",
                "credential-sentinel",
                "<script>",
                "C:\\private",
                "diagnostic",
            ] {
                assert!(!output.contains(private), "private field leaked: {private}");
            }
        }
    }

    #[test]
    fn fixture_flow_deterministic_unchanged_duplicate_missing_tampered_and_export() {
        let root = temp();
        let inputs = root.join("retained");
        std::fs::create_dir(&inputs).unwrap();
        let original = std::fs::read(fixture()).unwrap();
        std::fs::write(inputs.join("worker107-r5.zip"), &original).unwrap();
        let mut manifest = selection(&inputs);
        let first = manifest["msixResearch"][0].clone();
        let mut duplicate = first.clone();
        duplicate["id"] = json!("duplicate");
        let mut missing = first.clone();
        missing["id"] = json!("missing");
        missing["archive"] = json!(inputs.join("missing.zip"));
        let mut tampered = first.clone();
        tampered["id"] = json!("tampered");
        tampered["archive"] = json!(inputs.join("tampered.zip"));
        std::fs::write(inputs.join("tampered.zip"), b"not an archive").unwrap();
        manifest["msixResearch"] = json!([first, duplicate, missing, tampered]);
        let path = root.join("selection.json");
        std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let manifest_before = std::fs::read(&path).unwrap();
        let store = ResultsStore::default();
        let one = store.load(&path).unwrap();
        let two = store.load(&path).unwrap();
        let bytes = serde_json::to_vec(&one.summary).unwrap();
        assert_eq!(bytes, serde_json::to_vec(&two.summary).unwrap());
        assert_eq!(two.summary.rows[0]["functions"]["install"], "passed");
        assert_eq!(two.summary.rows[1]["unavailableReason"], "duplicateRun");
        for index in [2, 3] {
            assert_eq!(two.summary.rows[index]["outcome"], "unavailable");
        }
        assert!(
            store
                .export(&one.token, &root.join("stale.json"), "json")
                .is_err()
        );
        assert!(
            store
                .export(&two.token, &inputs.join("blocked.json"), "json")
                .is_err()
        );
        assert!(!inputs.join("blocked.json").exists());
        assert!(
            std::fs::rename(&inputs, root.join("moved-retained")).is_err(),
            "selected retained location must stay pinned while loaded"
        );
        let output = root.join("summary.json");
        store.export(&two.token, &output, "json").unwrap();
        let exported = std::fs::read(&output).unwrap();
        assert!(store.export(&two.token, &output, "json").is_err());
        assert_eq!(exported, std::fs::read(&output).unwrap());
        store
            .export(&two.token, &root.join("summary.md"), "markdown")
            .unwrap();
        assert!(
            store
                .export(&two.token, &root.join("absent/summary.json"), "json")
                .is_err()
        );
        assert!(
            store
                .export(&two.token, &root.join("bad.json:stream"), "json")
                .is_err()
        );
        assert!(
            store
                .export(&two.token, &root.join("other"), "html")
                .is_err()
        );
        assert_eq!(
            original,
            std::fs::read(inputs.join("worker107-r5.zip")).unwrap()
        );
        let text = String::from_utf8(exported).unwrap();
        for secret in [
            "workerUuid",
            "observedUserSid",
            "archiveEntry\"",
            "runNonce",
            "C:\\\\",
            "fixture",
            "retained",
        ] {
            assert!(!text.contains(secret), "unexpected {secret}");
        }
        assert_eq!(std::fs::read_dir(&inputs).unwrap().count(), 2);
        assert_eq!(
            std::fs::read(inputs.join("tampered.zip")).unwrap(),
            b"not an archive"
        );
        assert_eq!(manifest_before, std::fs::read(&path).unwrap());
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn strict_manifest_bounds_and_unavailable_are_explicit() {
        let root = temp();
        let path = root.join("input.json");
        for bad in [
            json!({}),
            json!({"schemaVersion":"future", "msixResearch":[]}),
            json!({"schemaVersion":"aiw.dev/application-assessment-input/v0alpha1", "msixResearch":[]}),
        ] {
            std::fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();
            assert!(bounded_input(&path).is_err());
        }
        let mut input = selection(&root);
        input["extra"] = json!("hostile");
        std::fs::write(&path, serde_json::to_vec(&input).unwrap()).unwrap();
        assert!(bounded_input(&path).is_err());
        input = selection(&root);
        input["msixResearch"][0]["id"] = json!("<script>alert(1)</script>");
        std::fs::write(&path, serde_json::to_vec(&input).unwrap()).unwrap();
        assert!(bounded_input(&path).is_err());
        input = selection(&root);
        input["msixResearch"] = json!(
            (0..33)
                .map(|i| {
                    let mut e = input["msixResearch"][0].clone();
                    e["id"] = json!(format!("s{i}"));
                    e
                })
                .collect::<Vec<_>>()
        );
        std::fs::write(&path, serde_json::to_vec(&input).unwrap()).unwrap();
        assert!(bounded_input(&path).is_err());
        std::fs::write(&path, vec![b' '; LIMIT as usize + 1]).unwrap();
        assert!(bounded_input(&path).is_err());
        assert!(bounded_input(&root.join("missing.json")).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn synthetic_mixed_projection_distinguishes_stage_failure_from_functions_and_strips_hostile_text()
     {
        let mut msi = json!({"id":"secret-account", "functions":{"install":true}, "source":{"kind":"windowsSandbox", "evidence":{"profile":"notepadMsi", "result":{"kind":"notepadMsi", "report":{"status":"unsuccessfulAttempt"}}}}});
        msi["source"]["evidence"]["result"]["report"]["summary"] = json!({"recordedOutcome":"failed", "recordedCleanupVerified":true, "failureEvidence":"verified", "stageProgress":[{"stage":"install","status":"passed"},{"stage":"launch","status":"failed"},{"stage":"close","status":"notReached"}],"applicationName":"<img src=x onerror=alert(1)>","diagnostic":"credential-secret", "receiptSha256":"a".repeat(64)});
        let bambu = json!({"functions":{"stlTo3mfExport":true},"source":{"kind":"windowsSandbox","evidence":{"profile":"bambuExport","result":{"kind":"bambuExport","report":{"outcome":"insufficientEvidence","evidenceStatus":"verified", "scenario":{"completedStages":["install"],"failedStage":"prepareFixture"},"missingEvidence":["slicing, printer and cloud workflows"]}}}}});
        let report = json!({"missingEvidence":["captureCompleteness"], "entries":[msi,bambu]});
        let summary = project(&report);
        assert_eq!(summary.rows.len(), 2);
        assert_eq!(summary.rows[0]["functions"]["launch"], "unmeasured");
        assert_eq!(summary.rows[0]["stages"][1]["status"], "failed");
        assert_eq!(summary.rows[0]["stages"][2]["status"], "notReached");
        assert_eq!(summary.rows[1]["application"], "Bambu Studio");
        assert_eq!(summary.rows[1]["functions"]["openDocument"], "unmeasured");
        let output = markdown(&summary);
        for private in ["secret-account", "<img", "credential-secret"] {
            assert!(!output.contains(private));
        }
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    #[test]
    fn drive_root_and_case_insensitive_component_boundaries() {
        assert!(contains_path(
            Path::new(r"\\?\C:\"),
            Path::new(r"\\?\C:\elsewhere\child")
        ));
        assert!(contains_path(
            Path::new(r"\\?\C:\Retained"),
            Path::new(r"\\?\c:\retained\nested")
        ));
        assert!(!contains_path(
            Path::new(r"\\?\C:\Retained"),
            Path::new(r"\\?\C:\Retained-other")
        ));
        assert!(!local_drive_path(Path::new(r"\\server\share\summary.json")));
    }
    #[test]
    fn backend_rejects_overlapping_operations_before_reading() {
        let store = ResultsStore::default();
        let _guard = store.0.lock().unwrap();
        assert_eq!(
            store.load(Path::new(r"C:\never-read.json")).err().unwrap(),
            "Another Results operation is in progress"
        );
        assert_eq!(
            store
                .export("any", Path::new(r"C:\never-created.json"), "json")
                .err()
                .unwrap(),
            "Another Results operation is in progress"
        );
    }
    #[test]
    #[ignore = "requires an explicit local junction fixture in AIW_RESULTS_TEST_JUNCTION; no privilege changes"]
    fn local_reparse_paths_are_rejected_without_reading_target() {
        let link = PathBuf::from(
            std::env::var_os("AIW_RESULTS_TEST_JUNCTION").expect("explicit local junction fixture"),
        );
        assert_eq!(
            hold_local_chain(&link.join("never-read.json"))
                .err()
                .unwrap(),
            "Results does not follow reparse points"
        );
    }
    #[test]
    fn writer_failure_is_reported_without_claiming_success() {
        struct Fails;
        impl Write for Fails {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("synthetic disk-full"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(write_bytes(&mut Fails, b"summary").is_err());
    }
}

#[cfg(test)]
mod demo {
    use super::*;
    fn fixture_bytes(path: &Path, limit: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        File::open(path)
            .unwrap()
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .unwrap();
        assert!(
            bytes.len() as u64 <= limit,
            "fixture exceeds its read bound"
        );
        bytes
    }
    fn separate_demo_parent(parent: &Path, fixtures: &[PathBuf]) -> bool {
        fixtures.iter().all(|root| !contains_path(root, parent))
    }
    #[test]
    fn paired_demo_rejects_output_inside_fixture_before_creating_files() {
        let fixtures = vec![PathBuf::from(r"C:\fresh\fixture")];
        assert!(!separate_demo_parent(
            Path::new(r"c:\fresh\fixture"),
            &fixtures
        ));
        assert!(!separate_demo_parent(
            Path::new(r"C:\fresh\fixture\w1-run\output"),
            &fixtures
        ));
        assert!(separate_demo_parent(Path::new(r"C:\exports"), &fixtures));
    }

    #[test]
    #[ignore = "opens only two explicitly supplied fresh synthetic fixture selections; never executes a run"]
    fn demonstrate_paired_results() {
        let selections: Vec<PathBuf> = serde_json::from_str(
            &std::env::var("AIW_PAIRED_DEMO_SELECTIONS")
                .expect("two explicit synthetic selections"),
        )
        .unwrap();
        assert_eq!(selections.len(), 2);
        let mut entries = Vec::new();
        let mut before = Vec::new();
        let mut fixture_roots = Vec::new();
        for selection in &selections {
            let parent = selection.parent().unwrap();
            assert!(
                parent
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("aiw-w1-runner-")
                    || parent
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .starts_with("aiw-paired-service-")
            );
            let marker_path = parent.join("synthetic-demo.json");
            let marker: Value =
                serde_json::from_slice(&fixture_bytes(&marker_path, 16384)).unwrap();
            assert_eq!(
                marker["schemaVersion"],
                "aiw.dev/paired-synthetic-demo/v0alpha1"
            );
            assert_eq!(marker["origin"], "syntheticRehearsal");
            assert_eq!(marker["realProviderApplicationControlCalls"], 0);
            let bytes = fixture_bytes(selection, LIMIT);
            fixture_roots.push(parent.canonicalize().unwrap());
            let input: Value = serde_json::from_slice(&bytes).unwrap();
            let rows = input["windowsSandbox"]["entries"].as_array().unwrap();
            assert_eq!(rows.len(), 2);
            for row in rows {
                assert_eq!(row["profile"], "pairedControls");
                let workspace = PathBuf::from(row["run"]["workspaceRoot"].as_str().unwrap())
                    .canonicalize()
                    .unwrap();
                assert_eq!(workspace.parent().unwrap(), parent.canonicalize().unwrap());
                let mut row = row.clone();
                row["run"]["id"] = json!(format!("SYNTHETIC-pair-{}", entries.len() + 1));
                entries.push(row);
            }
            before.push((selection.clone(), bytes));
        }
        let parent =
            PathBuf::from(std::env::var_os("AIW_RESULTS_DEMO").expect("explicit output parent"));
        let parent = parent.canonicalize().unwrap();
        assert!(
            separate_demo_parent(&parent, &fixture_roots),
            "demo output parent overlaps retained fixture"
        );
        let root = parent.join(format!("results-explorer-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let selection = root.join("selection.json");
        let input = json!({"schemaVersion":aiw_runner::APPLICATION_ASSESSMENT_INPUT_SCHEMA,"windowsSandbox":{"schemaVersion":aiw_runner::WSB_REPORT_SET_INPUT_SCHEMA,"entries":entries}});
        write_new(&selection, &[], &serde_json::to_vec_pretty(&input).unwrap()).unwrap();
        let store = ResultsStore::default();
        let loaded = store.load(&selection).unwrap();
        assert_eq!(loaded.summary.rows.len(), 4);
        assert_eq!(
            loaded
                .summary
                .rows
                .iter()
                .filter(|r| r["paired"]["origin"] == "syntheticRehearsal")
                .count(),
            2
        );
        assert_eq!(
            loaded
                .summary
                .rows
                .iter()
                .filter(|r| r["unavailableReason"] == "duplicateRun")
                .count(),
            2
        );
        assert_eq!(
            loaded
                .summary
                .rows
                .iter()
                .filter(|r| r["paired"]["eligible"] == true)
                .count(),
            1
        );
        assert_eq!(
            loaded
                .summary
                .rows
                .iter()
                .filter(|r| r["paired"]["reason"] == "cleanupUnknown")
                .count(),
            1
        );
        store
            .export(&loaded.token, &root.join("verified-summary.json"), "json")
            .unwrap();
        store
            .export(&loaded.token, &root.join("verified-summary.md"), "markdown")
            .unwrap();
        assert!(
            store
                .export(&loaded.token, &root.join("verified-summary.json"), "json")
                .is_err()
        );
        let again = store.load(&selection).unwrap();
        assert_eq!(
            serde_json::to_vec(&loaded.summary).unwrap(),
            serde_json::to_vec(&again.summary).unwrap()
        );
        for (path, bytes) in before {
            assert_eq!(std::fs::read(path).unwrap(), bytes);
        }
        let mut demo = again;
        demo.summary.scope = "DEMONSTRATION: SYNTHETIC paired controls produced by the actual shared kernel with inert bytes and fake transports; one clean completion, one unknown outer cleanup, and duplicates. Zero real provider/application/control calls. No production acceptance.";
        write_new(
            &root.join("demo-view.json"),
            &[],
            &serde_json::to_vec_pretty(&demo).unwrap(),
        )
        .unwrap();
        println!("PAIRED_RESULTS_DEMONSTRATION={}", root.display());
    }

    #[test]
    #[ignore = "writes a fresh offline fixture demonstration to AIW_RESULTS_DEMO; never executes a run"]
    fn demonstrate_results() {
        let parent = std::env::var_os("AIW_RESULTS_DEMO").expect("explicit demo parent");
        let root = PathBuf::from(parent).join(format!("results-explorer-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let retained = root.join("retained");
        std::fs::create_dir(&retained).unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fixtures/msix-lifecycle/worker107-r5.zip");
        let original = std::fs::read(&fixture).unwrap();
        std::fs::write(retained.join("fixture.zip"), &original).unwrap();
        std::fs::write(retained.join("tampered.zip"), b"synthetic corrupted copy").unwrap();
        let manifest = json!({"schemaVersion":"aiw.dev/application-assessment-input/v0alpha1", "msixResearch":[
            {"id":"REAL-reviewed-r5-fixture", "profile":"worker107NotepadR5", "archive":retained.join("fixture.zip")},
            {"id":"REAL-duplicate-selection", "profile":"worker107NotepadR5", "archive":retained.join("fixture.zip")},
            {"id":"SYNTHETIC-missing-archive", "profile":"worker107NotepadR5", "archive":retained.join("missing.zip")},
            {"id":"SYNTHETIC-tampered-copy", "profile":"worker107NotepadR5", "archive":retained.join("tampered.zip")}
        ]});
        let input = root.join("selection.json");
        std::fs::write(&input, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
        let store = ResultsStore::default();
        let real = store.load(&input).unwrap();
        store
            .export(&real.token, &root.join("verified-summary.json"), "json")
            .unwrap();
        store
            .export(&real.token, &root.join("verified-summary.md"), "markdown")
            .unwrap();
        let again = store.load(&input).unwrap();
        assert_eq!(
            serde_json::to_vec(&real.summary).unwrap(),
            serde_json::to_vec(&again.summary).unwrap()
        );
        assert_eq!(
            original,
            std::fs::read(retained.join("fixture.zip")).unwrap()
        );
        assert!(
            store
                .export(&again.token, &retained.join("must-not-exist.json"), "json")
                .is_err()
        );
        assert!(
            store
                .export(&again.token, &root.join("verified-summary.json"), "json")
                .is_err()
        );
        let synthetic: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/results-synthetic-report.json"
        ))
        .unwrap();
        let synthetic_summary = project(&synthetic);
        assert_eq!(synthetic_summary.rows[2]["stages"][1]["status"], "failed");
        assert_eq!(
            synthetic_summary.rows[2]["stages"][2]["status"],
            "notReached"
        );
        assert!(
            synthetic_summary.rows[1]["evidenceGaps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "slicing, printer and cloud workflows")
        );
        let mut combined = again.clone();
        combined.summary.scope = "DEMONSTRATION: selections 1-4 use the pinned reviewed archive and deliberately missing/tampered copies. Selections 5-10 are SYNTHETIC projection examples, not retained assessments. General compatibility and isolation remain unmeasured.";
        combined.summary.rows.extend(synthetic_summary.rows);
        combined.selection_labels.extend(
            synthetic["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["id"].as_str().unwrap().to_owned()),
        );
        for (i, row) in combined.summary.rows.iter_mut().enumerate() {
            row["selection"] = json!(i + 1);
        }
        write_new(
            &root.join("demo-view.json"),
            &[],
            &serde_json::to_vec_pretty(&combined).unwrap(),
        )
        .unwrap();
        write_new(
            &root.join("demo-summary.json"),
            &[],
            &serde_json::to_vec_pretty(&combined.summary).unwrap(),
        )
        .unwrap();
        write_new(
            &root.join("demo-summary.md"),
            &[],
            markdown(&combined.summary).as_bytes(),
        )
        .unwrap();
        println!("DEMONSTRATION={}", root.display());
    }
}
