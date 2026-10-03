//! Elapsed waiting is presentation only, never an application observation.
use std::io::{self, IsTerminal, Write};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

pub(crate) struct RunProgress {
    stop: Option<Sender<()>>,
    finished: Option<Receiver<()>>,
}

impl RunProgress {
    /// Call only after exact-plan approval has been recorded.
    pub(crate) fn start(enabled: bool, interactive: bool) -> Self {
        let output = io::stderr();
        if !enabled || !output.is_terminal() {
            return Self {
                stop: None,
                finished: None,
            };
        }
        let guidance = if interactive {
            "When Notepad++ appears, edit, save, and close the editor within the approved editing time. The editing timer starts after the editor is ready; closing only the Sandbox viewer does not finish the trial."
        } else {
            "The application checks run automatically. Results are verified after cleanup."
        };
        let introduction = format!(
            "Approved. Starting the Sandbox workflow.\nSandbox startup and application installation can take several minutes.\n{guidance}\n"
        );
        Self::with_output(output, Duration::from_secs(30), Some(introduction))
    }

    fn with_output(
        mut output: impl Write + Send + 'static,
        interval: Duration,
        introduction: Option<String>,
    ) -> Self {
        let (stop, receiver) = mpsc::channel();
        let (finished_sender, finished) = mpsc::channel();
        let started = Instant::now();
        let worker = thread::Builder::new().name("aiw-console-progress".into()).spawn(move || {
            // Completion is signaled by disconnect even on an early I/O error.
            let _finished_sender = finished_sender;
            if let Some(introduction) = introduction {
                if receiver.try_recv() != Err(mpsc::TryRecvError::Empty) {
                    return;
                }
                if output.write_all(introduction.as_bytes()).and_then(|()| output.flush()).is_err() {
                    return;
                }
            }
            while let Err(mpsc::RecvTimeoutError::Timeout) = receiver.recv_timeout(interval) {
                let elapsed = started.elapsed().as_secs();
                if writeln!(output, "Waiting for the Sandbox workflow ({:02}:{:02} elapsed). No result has been verified yet.", elapsed / 60, elapsed % 60).and_then(|()| output.flush()).is_err() {
                    // Console failure does not cancel execution or bypass cleanup.
                    break;
                }
            }
        });
        if worker.is_err() {
            return Self {
                stop: None,
                finished: None,
            };
        }
        // The thread has no execution authority. Never join a blocked console writer.
        Self {
            stop: Some(stop),
            finished: Some(finished),
        }
    }
}

impl Drop for RunProgress {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(finished) = self.finished.take() {
            // Normally finish before the result is printed. A stalled terminal
            // must not prevent saving reports or returning the run outcome.
            let _ = finished.recv_timeout(Duration::from_millis(100));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SignalOutput(Sender<String>);
    impl Write for SignalOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0
                .send(String::from_utf8_lossy(bytes).into_owned())
                .map_err(io::Error::other)?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn progress_stops_promptly_without_waiting_for_next_interval() {
        let (sender, receiver) = mpsc::channel();
        let progress =
            RunProgress::with_output(SignalOutput(sender), Duration::from_secs(30), None);
        drop(progress);
        assert!(matches!(
            receiver.recv_timeout(Duration::from_secs(1)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));
    }

    #[test]
    fn console_failure_does_not_prevent_progress_shutdown() {
        let (sender, receiver) = mpsc::channel();
        struct FailingOutput(Sender<()>);
        impl Write for FailingOutput {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                self.0.send(()).unwrap();
                Err(io::Error::other("console unavailable"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let progress =
            RunProgress::with_output(FailingOutput(sender), Duration::from_millis(1), None);
        receiver.recv_timeout(Duration::from_secs(2)).unwrap();
        drop(progress);
        assert!(matches!(
            receiver.recv_timeout(Duration::from_secs(1)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));
    }

    #[test]
    fn heartbeat_describes_waiting_without_claiming_a_verified_result() {
        let (sender, receiver) = mpsc::channel();
        let progress =
            RunProgress::with_output(SignalOutput(sender), Duration::from_millis(1), None);
        let mut line = String::new();
        while !line.contains('\n') {
            line.push_str(&receiver.recv_timeout(Duration::from_secs(2)).unwrap());
        }
        assert!(line.starts_with("Waiting for the Sandbox workflow ("));
        assert!(line.contains("elapsed). No result has been verified yet."));
        drop(progress);
    }

    #[test]
    fn stalled_initial_output_cannot_block_workflow_or_shutdown() {
        struct BlockedOutput {
            entered: Sender<()>,
            release: Receiver<()>,
        }
        impl Write for BlockedOutput {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                self.entered.send(()).unwrap();
                self.release.recv().unwrap();
                Err(io::Error::other("stalled terminal released"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (entered, observed) = mpsc::channel();
        let (release, blocked) = mpsc::channel();
        let progress = RunProgress::with_output(
            BlockedOutput {
                entered,
                release: blocked,
            },
            Duration::from_secs(30),
            Some("Approved\n".into()),
        );
        observed.recv_timeout(Duration::from_secs(2)).unwrap();
        let (stopped, stopped_receiver) = mpsc::channel();
        let shutdown = thread::spawn(move || {
            drop(progress);
            stopped.send(()).unwrap();
        });
        let result = stopped_receiver.recv_timeout(Duration::from_secs(2));
        // Release the test writer even if shutdown regresses, then join the test driver.
        release.send(()).unwrap();
        shutdown.join().unwrap();
        assert!(result.is_ok(), "stalled output blocked shutdown");
        assert!(matches!(
            observed.recv_timeout(Duration::from_secs(1)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));
    }
}
