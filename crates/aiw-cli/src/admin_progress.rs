//! Elapsed waiting is presentation only, never an application observation.
use std::io::{self, Write};
use std::sync::mpsc::{self, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub(crate) struct RunProgress {
    stop: Option<Sender<()>>,
    worker: Option<JoinHandle<()>>,
}

impl RunProgress {
    /// Call only after exact-plan approval has been recorded.
    pub(crate) fn start(enabled: bool, interactive: bool) -> Self {
        if !enabled {
            return Self {
                stop: None,
                worker: None,
            };
        }
        let mut output = io::stderr();
        let _ = writeln!(output, "Approved. Starting the Sandbox workflow.");
        let _ = writeln!(
            output,
            "Sandbox startup and application installation can take several minutes."
        );
        if interactive {
            let _ = writeln!(
                output,
                "When Notepad++ appears, edit, save, and close the editor within the approved editing time. The editing timer starts after the editor is ready; closing only the Sandbox viewer does not finish the trial."
            );
        } else {
            let _ = writeln!(
                output,
                "The application checks run automatically. Results are verified after cleanup."
            );
        }
        Self::with_output(output, Duration::from_secs(30))
    }

    fn with_output(mut output: impl Write + Send + 'static, interval: Duration) -> Self {
        let (stop, receiver) = mpsc::channel();
        let started = Instant::now();
        let worker = thread::Builder::new().name("aiw-console-progress".into()).spawn(move || {
            while let Err(mpsc::RecvTimeoutError::Timeout) = receiver.recv_timeout(interval) {
                let elapsed = started.elapsed().as_secs();
                if writeln!(output, "Waiting for the Sandbox workflow ({:02}:{:02} elapsed). No result has been verified yet.", elapsed / 60, elapsed % 60).and_then(|()| output.flush()).is_err() {
                    // Console failure does not cancel execution or bypass cleanup.
                    break;
                }
            }
        }).ok();
        Self {
            stop: Some(stop),
            worker,
        }
    }
}

impl Drop for RunProgress {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
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
        let progress = RunProgress::with_output(SignalOutput(sender), Duration::from_secs(30));
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
        let progress = RunProgress::with_output(FailingOutput(sender), Duration::from_millis(1));
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
        let progress = RunProgress::with_output(SignalOutput(sender), Duration::from_millis(1));
        let mut line = String::new();
        while !line.contains('\n') {
            line.push_str(&receiver.recv_timeout(Duration::from_secs(2)).unwrap());
        }
        assert!(line.starts_with("Waiting for the Sandbox workflow ("));
        assert!(line.contains("elapsed). No result has been verified yet."));
        drop(progress);
    }
}
