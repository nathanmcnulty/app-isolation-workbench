//! Opt-in, closed offline harness. Fresh inert files only; no native provider acquisition.
//! This module is absent from default builds. It reuses the real preparation,
//! journal, approval, dispatch, receipt, reporting and exact recovery services.
use super::*;
use std::io::Read;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

const RUN: &str = "w1-run";
static NEXT: AtomicU64 = AtomicU64::new(1);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scenario {
    Valid,
    BaselineMissing,
    CandidateMissing,
    DriverIncomplete,
    InvalidDeniedCode,
    DuplicateEvidence,
    OutOfOrderEvidence,
    DriverFailed,
    TamperedDriver,
    UnknownCleanup,
    InterruptedDispatch,
    CancelDuringDispatch,
    WaitForOwnedCancellation,
    ProviderDrift,
    InputDrift,
}
/// Owns only a newly created synthetic fixture. Never opens a supplied workspace.
pub struct Fixture {
    parent: PathBuf,
    held: aiw_windows_platform::HeldRunWorkspace,
    pub project: Project,
    pub artifacts: preparation::PreparedWsbArtifacts,
    readiness: WindowsSandboxReadiness,
    start: WsbGoldenProbeStart,
    calls: Arc<Mutex<Vec<Vec<String>>>>,
    owned_cancellation_committed: Arc<AtomicBool>,
}
impl Fixture {
    pub fn prepare(project_factory: impl FnOnce(&str) -> Project) -> Self {
        let parent = std::env::temp_dir().join(format!(
            "aiw-paired-service-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&parent).expect("fresh synthetic parent");
        let canonical = parent.canonicalize().unwrap();
        let text = canonical.to_string_lossy();
        let parent = PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text));
        let (held, project, artifacts, readiness) =
            preparation::synthetic::protected_paired_fixture(&parent, RUN, project_factory);
        let project_path = parent.join("paired-project.yaml");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&project_path)
            .unwrap();
        file.write_all(serde_yaml::to_string(&project).unwrap().as_bytes())
            .unwrap();
        file.sync_all().unwrap();
        let workspace = PathBuf::from(&artifacts.receipt.workspace.root.final_path);
        let layout = RunLayout::new(&workspace, RUN).unwrap();
        let receipt = aiw_orchestrator::WsbPlanningImportReceipt {
            schema_version: aiw_orchestrator::WSB_PAIRED_CONTROL_IMPORT_SCHEMA.into(),
            run_id: RUN.into(),
            imported_at: "synthetic-time".into(),
            status: aiw_orchestrator::WsbPlanningImportStatus::PendingApproval,
            project_revision_sha256: artifacts.receipt.project_revision_sha256.clone(),
            workspace_root: artifacts.receipt.workspace.root.final_path.clone(),
            workspace_identity_sha256: artifacts.receipt.workspace_identity_sha256.clone(),
            preparation_receipt_sha256: canonical_hash(&artifacts.receipt).unwrap(),
            run_plan_sha256: artifacts.receipt.run_plan_sha256.clone(),
            windows_sandbox_plan_sha256: artifacts.receipt.wsb_plan_sha256.clone(),
            guest_agent_sha256: artifacts.receipt.guest_agent.sha256.clone(),
            provider_sha256: artifacts.receipt.provider.sha256.clone(),
            run_root: artifacts.receipt.workspace.root.final_path.clone(),
            journal_sequence: 1,
            approval_present: false,
            provider_acquired: false,
            provider_mutated: false,
        };
        layout
            .create_or_verify_pending_wsb_import_bound(&held, &artifacts.run_plan, &receipt)
            .unwrap();
        let start = WsbGoldenProbeStart {
            schema_version: "aiw.dev/wsb-paired-controls-start/v0alpha1".into(),
            run_root: artifacts.receipt.workspace.root.final_path.clone(),
            project_path: project_path.to_string_lossy().into_owned(),
            wsb_plan: artifacts.wsb_plan.clone(),
            provider: artifacts.receipt.provider.clone(),
            guest_agent: artifacts.receipt.guest_agent.clone(),
            workspace: artifacts.receipt.workspace.clone(),
            workspace_identity_sha256: artifacts.receipt.workspace_identity_sha256.clone(),
            timeout_seconds: 1,
            msi: None,
            bambu: None,
            paired_controls: artifacts.receipt.paired_controls.clone(),
        };
        Self {
            parent,
            held,
            project,
            artifacts,
            readiness,
            start,
            calls: Arc::new(Mutex::new(vec![])),
            owned_cancellation_committed: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn evidence_root(&self) -> &Path {
        &self.parent
    }
    pub fn workspace(&self) -> &Path {
        self.held.root_path()
    }
    pub fn project_path(&self) -> PathBuf {
        self.parent.join("paired-project.yaml")
    }
    pub fn layout(&self) -> RunLayout {
        RunLayout::new(self.workspace(), RUN).unwrap()
    }
    pub fn calls(&self) -> Vec<Vec<String>> {
        self.calls.lock().unwrap().clone()
    }
    /// Test-only handshake after the real service has finished publication.
    /// This observes cancellation; it cannot request it or grant execution.
    pub fn observe_committed_cancellation(&self) -> Result<(), RunnerError> {
        if !cancellation_requested(&self.layout())? {
            return Err(RunnerError::Process(
                "offline cancellation is not committed".into(),
            ));
        }
        self.owned_cancellation_committed
            .store(true, Ordering::Release);
        Ok(())
    }
    /// Inventory only this harness's fresh owned tree, never disk discovery.
    pub fn retained_bytes(&self) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
        fn collect(
            root: &Path,
            path: &Path,
            out: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>,
        ) {
            for item in fs::read_dir(path).unwrap() {
                let item = item.unwrap();
                let kind = item.file_type().unwrap();
                assert!(!kind.is_symlink());
                if kind.is_dir() {
                    collect(root, &item.path(), out);
                } else {
                    assert!(out.len() < 256);
                    let mut bytes = vec![];
                    fs::File::open(item.path())
                        .unwrap()
                        .take(2 * 1024 * 1024 + 1)
                        .read_to_end(&mut bytes)
                        .unwrap();
                    assert!(bytes.len() <= 2 * 1024 * 1024);
                    out.insert(item.path().strip_prefix(root).unwrap().to_owned(), bytes);
                }
            }
        }
        let mut out = std::collections::BTreeMap::new();
        collect(&self.parent, &self.parent, &mut out);
        out
    }
    fn synthetic(&self) -> Result<(), RunnerError> {
        if self.start.paired_controls.as_ref().is_none_or(|p| {
            p.profile.origin != aiw_probe::ControlEvidenceOrigin::SyntheticRehearsal
        }) {
            return Err(RunnerError::ApprovalBinding);
        }
        Ok(())
    }
    pub fn dispatch(&self, scenario: Scenario) -> Result<(), RunnerError> {
        self.synthetic()?;
        let mut readiness = self.readiness.clone();
        if scenario == Scenario::ProviderDrift {
            readiness.provider_binary.as_mut().unwrap().sha256 = "f".repeat(64);
        }
        if scenario == Scenario::InputDrift {
            fs::write(
                &self
                    .start
                    .paired_controls
                    .as_ref()
                    .unwrap()
                    .fixture
                    .staged_payload
                    .canonical_path,
                b"synthetic drift",
            )
            .unwrap();
        }
        preparation::runtime_identity_matches_receipt(&self.artifacts.receipt, &readiness)
            .map_err(|e| RunnerError::Preparation(e.to_string()))?;
        let mut process = Fake::new(self.start.clone(), scenario, self.calls.clone(), false);
        process.owned_cancellation_committed = Some(self.owned_cancellation_committed.clone());
        execute_wsb_golden_probe(
            &self.start,
            &readiness,
            &self.layout(),
            &process,
            &OfflineLease::default(),
            &self.held,
        )
        .map(|_| ())
    }
    pub fn recover_exact(&self) -> Result<(), RunnerError> {
        self.synthetic()?;
        let process = Fake::new(
            self.start.clone(),
            Scenario::Valid,
            self.calls.clone(),
            true,
        );
        recover_wsb_session(
            &self.start,
            &self.readiness,
            &self.layout(),
            &process,
            &OfflineLease::default(),
        )
        .map(|_| ())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // The held root prevents removal until its handle is dropped. Leave fresh
        // fixtures for diagnosis rather than altering ACLs or releasing identity.
    }
}
#[derive(Default)]
struct OfflineLease(Mutex<()>);
impl LeaseBoundary for OfflineLease {
    fn try_acquire(&self) -> Result<Box<dyn LeaseGuard + '_>, RunnerError> {
        self.0
            .try_lock()
            .map(|g| Box::new(g) as Box<dyn LeaseGuard>)
            .map_err(|_| RunnerError::LeaseUnavailable)
    }
}
struct Fake {
    start: WsbGoldenProbeStart,
    scenario: Scenario,
    calls: Arc<Mutex<Vec<Vec<String>>>>,
    responses: Mutex<std::collections::VecDeque<(&'static str, serde_json::Value)>>,
    lifecycle: WindowsSandboxCliLifecyclePlan,
    recovery: bool,
    owned_cancellation_committed: Option<Arc<AtomicBool>>,
}
impl Fake {
    fn new(
        start: WsbGoldenProbeStart,
        scenario: Scenario,
        calls: Arc<Mutex<Vec<Vec<String>>>>,
        recovery: bool,
    ) -> Self {
        let id = deterministic_sandbox_id(RUN);
        let empty = serde_json::json!({"WindowsSandboxEnvironments":[]});
        let present = serde_json::json!({"WindowsSandboxEnvironments":[{"Id":id}]});
        let responses = if recovery {
            vec![
                ("list", present.clone()),
                ("stop", serde_json::json!({"Id":id})),
                ("list", empty),
            ]
        } else {
            let mut responses = vec![
                ("list", empty.clone()),
                ("start", serde_json::json!({"Id":id})),
            ];
            if scenario != Scenario::InterruptedDispatch {
                responses.push(("list", present.clone()));
                if !matches!(
                    scenario,
                    Scenario::CancelDuringDispatch | Scenario::WaitForOwnedCancellation
                ) {
                    responses.push(("connect", serde_json::json!({})));
                }
            }
            responses.extend([
                ("list", present.clone()),
                ("stop", serde_json::json!({"Id":id})),
                (
                    "list",
                    if matches!(
                        scenario,
                        Scenario::UnknownCleanup | Scenario::InterruptedDispatch
                    ) {
                        present
                    } else {
                        empty
                    },
                ),
            ]);
            responses
        };
        let lifecycle =
            plan_cli_lifecycle(&start.provider.canonical_path, &id, &start.wsb_plan).unwrap();
        Self {
            start,
            scenario,
            calls,
            responses: Mutex::new(responses.into()),
            lifecycle,
            recovery,
            owned_cancellation_committed: None,
        }
    }
}
impl ProcessBoundary for Fake {
    fn invoke(
        &self,
        executable: &Path,
        args: &[String],
        _timeout: u32,
    ) -> Result<ProcessResult, RunnerError> {
        let command = args.first().map(String::as_str).unwrap_or("");
        let expected = match command {
            "list" => &self.lifecycle.list,
            "start" if !self.recovery => &self.lifecycle.start,
            "connect" if !self.recovery => &self.lifecycle.connect,
            "stop" => &self.lifecycle.stop,
            _ => return Err(RunnerError::ProviderFailure),
        };
        if executable != Path::new(&expected.executable) || args != expected.arguments {
            return Err(RunnerError::ProviderFailure);
        }
        let mut pending = self.responses.lock().unwrap();
        if pending.front().is_none_or(|(next, _)| *next != command) {
            return Err(RunnerError::ProviderFailure);
        }
        let (_, value) = pending.pop_front().unwrap();
        drop(pending);
        if command != "start" {
            self.calls.lock().unwrap().push(args.to_vec());
        }
        if command == "start" {
            let tx =
                session::observe_transaction(&RunLayout::new(&self.start.run_root, RUN).unwrap())
                    .unwrap()
                    .transaction
                    .unwrap();
            assert_eq!(tx.current_state(), SessionTransactionState::StartIntent);
            assert_eq!(tx.session_id, deterministic_sandbox_id(RUN));
            self.calls.lock().unwrap().push(args.to_vec());
            if self.scenario == Scenario::InterruptedDispatch {
                return Err(RunnerError::ProviderFailure);
            }
            if self.scenario == Scenario::CancelDuringDispatch {
                self.start_layout()
                    .request_cancellation("synthetic-owned-cancel", "synthetic-time")
                    .unwrap();
            }
            if self.scenario == Scenario::WaitForOwnedCancellation {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
                // Do not read a lock-free journal during the service's multi-file
                // publication. Observe only after the actual request returns.
                let committed = self
                    .owned_cancellation_committed
                    .as_ref()
                    .ok_or(RunnerError::ProviderFailure)?;
                while !committed.load(Ordering::Acquire) {
                    if std::time::Instant::now() >= deadline {
                        return Err(RunnerError::Process(
                            "offline cancellation handshake timed out".into(),
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
            if self.scenario == Scenario::WaitForOwnedCancellation
                && !cancellation_requested(&self.start_layout())?
            {
                return Err(RunnerError::Process(
                    "offline cancellation was not durable".into(),
                ));
            }
            let mutation = match self.scenario {
                Scenario::BaselineMissing => 1,
                Scenario::CandidateMissing => 2,
                Scenario::DriverIncomplete => 3,
                Scenario::InvalidDeniedCode => 4,
                Scenario::DuplicateEvidence => 5,
                Scenario::OutOfOrderEvidence => 6,
                Scenario::DriverFailed => 7,
                Scenario::TamperedDriver => 8,
                _ => 0,
            };
            synthetic_receipt::write_pair_completion(&self.start, mutation);
        }
        Ok(ProcessResult {
            exit_code: 0,
            stdout: if matches!(command, "connect" | "stop") {
                vec![]
            } else {
                serde_json::to_vec(&value).unwrap()
            },
            stderr: vec![],
        })
    }
}
impl Fake {
    fn start_layout(&self) -> RunLayout {
        RunLayout::new(&self.start.run_root, RUN).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fake_rejects_foreign_executable_uuid_config_and_order_without_accepting_any_call() {
        let fixture = Fixture::prepare(|_| {
            serde_yaml::from_str(include_str!("../../../examples/minimal.aiw.yaml")).unwrap()
        });
        assert!(fixture.observe_committed_cancellation().is_err());
        let fake = Fake::new(
            fixture.start.clone(),
            Scenario::Valid,
            fixture.calls.clone(),
            false,
        );
        let lifecycle = &fake.lifecycle;
        let exe = Path::new(&lifecycle.list.executable);
        assert!(
            fake.invoke(
                Path::new(r"C:\foreign\wsb.exe"),
                &lifecycle.list.arguments,
                1
            )
            .is_err()
        );
        assert!(fake.invoke(exe, &lifecycle.stop.arguments, 1).is_err());
        let mut foreign = lifecycle.stop.arguments.clone();
        foreign[3] = "00000000-0000-0000-0000-000000000000".into();
        assert!(fake.invoke(exe, &foreign, 1).is_err());
        let mut config = lifecycle.start.arguments.clone();
        config[5] = "<foreign/>".into();
        assert!(fake.invoke(exe, &config, 1).is_err());
        assert!(fixture.calls().is_empty());
        let recovery = Fake::new(
            fixture.start.clone(),
            Scenario::Valid,
            fixture.calls.clone(),
            true,
        );
        assert!(recovery.invoke(exe, &lifecycle.start.arguments, 1).is_err());
        assert!(fixture.calls().is_empty());
    }
}
