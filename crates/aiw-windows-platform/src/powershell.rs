//! Read-only machine runtime proof. No PATH, alias or caller supplied image.
use crate::HeldApplicationFile;
use aiw_probe::powershell::{
    POWERSHELL_EXECUTABLE, POWERSHELL_RUNTIME_GUARD, POWERSHELL_RUNTIME_OBSERVATION,
    PowerShellRuntimeIdentity,
};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub struct HeldPowerShell {
    _directory: File,
    image: HeldApplicationFile,
    engine: HeldApplicationFile,
    pub identity: PowerShellRuntimeIdentity,
}
impl HeldPowerShell {
    pub fn observe() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x02200000)
            .open(aiw_probe::powershell::POWERSHELL_PSHOME)?;
        if !directory.metadata()?.is_dir() || directory.metadata()?.file_attributes() & 0x400 != 0 {
            return Err("Non-reparse machine PowerShell directory required".into());
        }
        let image = HeldApplicationFile::open_bounded(
            std::path::Path::new(POWERSHELL_EXECUTABLE),
            128 * 1024 * 1024,
        )?;
        if !image
            .observation()
            .canonical_path
            .trim_start_matches(r"\\?\")
            .eq_ignore_ascii_case(POWERSHELL_EXECUTABLE)
        {
            return Err("Machine PowerShell canonical image path differs".into());
        }
        let command = format!("{POWERSHELL_RUNTIME_GUARD}\n{POWERSHELL_RUNTIME_OBSERVATION}");
        let mut child = Command::new(POWERSHELL_EXECUTABLE)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &command,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdout = child.stdout.take().ok_or("Runtime stdout absent")?;
        let stderr = child.stderr.take().ok_or("Runtime stderr absent")?;
        let (output_send, output) = std::sync::mpsc::channel();
        let (error_send, error) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stdout.take(65537).read_to_end(&mut bytes).map(|_| bytes);
            let _ = output_send.send(result);
        });
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stderr.take(65537).read_to_end(&mut bytes).map(|_| bytes);
            let _ = error_send.send(result);
        });
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if start.elapsed() > Duration::from_secs(45) {
                let _ = child.kill();
                let _ = child.wait();
                return Err("PowerShell runtime proof exceeded 45 seconds".into());
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        let bytes = output
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| "Runtime output pipe did not close within bound")??;
        let errors = error
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| "Runtime error pipe did not close within bound")??;
        if !status.success() || bytes.len() > 65536 || errors.len() > 65536 {
            return Err(format!(
                "Native PowerShell runtime proof failed: {}",
                String::from_utf8_lossy(&errors)
            )
            .into());
        }
        let identity: PowerShellRuntimeIdentity = serde_json::from_slice(&bytes)?;
        identity.validate_execution()?;
        let engine = HeldApplicationFile::open_bounded(
            std::path::Path::new(aiw_probe::powershell::POWERSHELL_ENGINE),
            128 * 1024 * 1024,
        )?;
        if !engine
            .observation()
            .canonical_path
            .trim_start_matches(r"\\?\")
            .eq_ignore_ascii_case(aiw_probe::powershell::POWERSHELL_ENGINE)
            || engine.observation().sha256
                != identity
                    .engine
                    .as_ref()
                    .ok_or("Engine identity missing")?
                    .assembly_sha256
        {
            return Err("Observed loaded engine differs from held machine engine".into());
        }
        image.revalidate()?;
        if image.observation().sha256 != identity.executable_sha256 {
            return Err("Observed PowerShell image differs from held image".into());
        }
        Ok(Self {
            _directory: directory,
            image,
            engine,
            identity,
        })
    }
    pub fn revalidate(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.image.revalidate()?;
        self.engine.revalidate()?;
        Ok(())
    }
}
pub fn observe_machine_powershell() -> Result<HeldPowerShell, Box<dyn std::error::Error>> {
    HeldPowerShell::observe()
}

/// Owned fragments retain their standalone requirements. Assembled files have
/// one entry-point requirement block: duplicate PSEdition directives are errors.
pub(crate) fn compiled_script_entry(source: &str) -> String {
    let body = source
        .lines()
        .filter(|line| {
            !line
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("#requires ")
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!("#Requires -Version 7.6\n#Requires -PSEdition Core\n{body}\n")
}

#[cfg(test)]
pub(crate) fn test_executable() -> std::path::PathBuf {
    let path = std::env::var_os("AIW_TEST_PWSH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| POWERSHELL_EXECUTABLE.into());
    assert!(
        path.is_absolute()
            && path
                .file_name()
                .is_some_and(|name| name.eq_ignore_ascii_case("pwsh.exe")),
        "Inert tests require an explicitly selected absolute pwsh.exe"
    );
    path
}

/// Serialized inert PowerShell checks. This override is never used by execution.
#[cfg(test)]
static INERT_TEST_STARTUP: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) fn inert_test_output(command: &mut Command) -> std::io::Result<std::process::Output> {
    let _startup = INERT_TEST_STARTUP
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let executable = test_executable();
    if command.get_program() != executable.as_os_str() {
        return Err(std::io::Error::other(
            "Inert PowerShell test executable differs from explicit selection",
        ));
    }
    let mut proof = Command::new(&executable);
    proof.args(["-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop';if($PSVersionTable.PSEdition -cne 'Core' -or $PSVersionTable.PSVersion -lt [version]'7.6' -or $PSVersionTable.PSVersion.ToString() -match '-' -or [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString() -cne 'X64'){throw 'Inert tests require stable x64 Core 7.6+'}"]);
    let identity = bounded_test_output(&mut proof, Duration::from_secs(60), "runtime-proof")?;
    if !identity.status.success() {
        return Err(std::io::Error::other(format!(
            "Inert runtime proof failed: {}",
            String::from_utf8_lossy(&identity.stderr)
        )));
    }
    bounded_test_output(command, Duration::from_secs(60), "inert-test")
}

#[cfg(test)]
fn bounded_test_output(
    command: &mut Command,
    timeout: Duration,
    phase: &str,
) -> std::io::Result<std::process::Output> {
    const LIMIT: usize = 1024 * 1024;
    let description = format!("{command:?}");
    let started = Instant::now();
    let deadline = started + timeout;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    fn capture(
        reader: impl Read + Send + 'static,
    ) -> std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>> {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = reader
                .take((LIMIT + 1) as u64)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = sender.send(result);
        });
        receiver
    }
    let stdout = capture(
        child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("Missing inert stdout"))?,
    );
    let stderr = capture(
        child
            .stderr
            .take()
            .ok_or_else(|| std::io::Error::other("Missing inert stderr"))?,
    );
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                let diagnostic = stderr
                    .recv_timeout(Duration::from_millis(500))
                    .ok()
                    .and_then(Result::ok)
                    .unwrap_or_default();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "PowerShell {phase} wait failed after {:?}: {description}; status={result:?}; stderr={}",
                        started.elapsed(),
                        String::from_utf8_lossy(&diagnostic[..diagnostic.len().min(8192)])
                    ),
                ));
            }
        }
    };
    // Process exit is insufficient: a descendant can retain inherited pipes.
    // Both channels have one shared finite deadline, independent of test threads.
    let pipe_deadline = Instant::now() + Duration::from_secs(1);
    let receive = |receiver: std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>,
                   stream: &str|
     -> std::io::Result<Vec<u8>> {
        let bytes = receiver
            .recv_timeout(pipe_deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "PowerShell {phase} {stream} pipe did not close after {:?}: {description}",
                        started.elapsed()
                    ),
                )
            })??;
        if bytes.len() > LIMIT {
            return Err(std::io::Error::other(format!(
                "PowerShell {phase} {stream} exceeded {LIMIT} bytes: {description}"
            )));
        }
        Ok(bytes)
    };
    Ok(std::process::Output {
        status,
        stdout: receive(stdout, "stdout")?,
        stderr: receive(stderr, "stderr")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_fragments_have_one_requirement_block_without_losing_runtime_guards() {
        let source = compiled_script_entry(&format!(
            "{POWERSHELL_RUNTIME_GUARD}\n#Requires -PSEdition Core\n#Requires -Version 7.6\nthrow 'guard retained'"
        ));
        assert_eq!(
            source
                .lines()
                .filter(|line| line.eq_ignore_ascii_case("#Requires -PSEdition Core"))
                .count(),
            1
        );
        assert_eq!(
            source
                .lines()
                .filter(|line| line.eq_ignore_ascii_case("#Requires -Version 7.6"))
                .count(),
            1
        );
        assert!(source.contains("Stable machine x64 PowerShell Core >=7.6 required"));
        assert!(source.contains("throw 'guard retained'"));
        assert!(POWERSHELL_RUNTIME_GUARD.contains("#Requires -PSEdition Core"));
    }

    #[test]
    fn inert_test_output_preserves_native_status_and_both_streams() {
        let result = inert_test_output(Command::new(test_executable()).args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Console]::Out.Write('inert-out');[Console]::Error.Write('inert-error');exit 42",
        ]))
        .unwrap();
        assert_eq!(result.status.code(), Some(42));
        assert_eq!(result.stdout, b"inert-out");
        assert_eq!(result.stderr, b"inert-error");
    }

    #[test]
    fn inert_test_timeout_is_bounded_and_names_its_phase() {
        let _startup = INERT_TEST_STARTUP
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let started = Instant::now();
        let error = bounded_test_output(
            Command::new(test_executable()).args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[Console]::Error.Write('inert-timeout');Start-Sleep -Seconds 30",
            ]),
            Duration::from_secs(2),
            "timeout-regression",
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("timeout-regression"));
        assert!(error.to_string().contains("pwsh.exe"));
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}
