//! Bounded diagnostics from Windows Installer text. These observations are
//! independent of the client process, transaction, and registration evidence.
use std::borrow::Cow;

use serde::{Deserialize, Serialize};

pub const MSI_INSTALL_LOG_PATH: &str = r"C:\AIW\Tools\install.log";
pub const MSI_INSTALL_LOG_ARGUMENT: &str = "/L*V!";
pub const MAX_MSI_INSTALL_LOG_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MsiLoggedAction {
    pub name: String,
    /// Windows Installer action return value, distinct from a process exit.
    pub return_value: u8,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MsiInstallLogSummary {
    schema_version: &'static str,
    bytes: usize,
    last_action_started: Option<String>,
    last_action_ended: Option<MsiLoggedAction>,
    client_records_observed: bool,
    server_records_observed: bool,
    server_package_policy_check_observed: bool,
    client_engine_return: Option<u32>,
    server_engine_return: Option<u32>,
}

impl MsiInstallLogSummary {
    /// Recognizes an intentionally small set of English log records. Other
    /// messages and an unterminated final line grant no observation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > MAX_MSI_INSTALL_LOG_BYTES {
            return Err("MSI log exceeds the 8 MiB diagnostic limit");
        }
        let text = match bytes {
            [0xff, 0xfe, body @ ..] => Cow::Owned(String::from_utf16_lossy(
                &body
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .copied()
                    .map(u16::from_le_bytes)
                    .collect::<Vec<_>>(),
            )),
            [0xfe, 0xff, body @ ..] => Cow::Owned(String::from_utf16_lossy(
                &body
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .copied()
                    .map(u16::from_be_bytes)
                    .collect::<Vec<_>>(),
            )),
            [0xef, 0xbb, 0xbf, body @ ..] => String::from_utf8_lossy(body),
            _ => String::from_utf8_lossy(bytes),
        };
        let mut summary = Self {
            schema_version: "aiw.dev/msi-install-log-diagnostics/v0alpha1",
            bytes: bytes.len(),
            last_action_started: None,
            last_action_ended: None,
            client_records_observed: false,
            server_records_observed: false,
            server_package_policy_check_observed: false,
            client_engine_return: None,
            server_engine_return: None,
        };
        // split_terminator would include an unfinished nonempty line at EOF.
        for line in text
            .split_inclusive('\n')
            .filter_map(|line| line.strip_suffix('\n'))
        {
            summary.observe(line.trim_end_matches('\r'));
        }
        Ok(summary)
    }

    fn observe(&mut self, line: &str) {
        if let Some(start) = action_message(line, "Action start ")
            .and_then(|message| message.strip_suffix('.'))
            .filter(|name| action_name(name))
        {
            self.last_action_started = Some(start.to_owned());
        }
        if let Some((name, value)) = action_message(line, "Action ended ")
            .and_then(|message| message.strip_suffix('.'))
            .and_then(|message| message.split_once(". Return value "))
            .filter(|(name, _)| action_name(name))
            && let Ok(return_value) = value.parse::<u8>()
        {
            self.last_action_ended = Some(MsiLoggedAction {
                name: name.to_owned(),
                return_value,
            });
        }
        let (seen, code, record) = if let Some(record) = line.strip_prefix("MSI (c) ") {
            (
                &mut self.client_records_observed,
                &mut self.client_engine_return,
                record,
            )
        } else if let Some(record) = line.strip_prefix("MSI (s) ") {
            (
                &mut self.server_records_observed,
                &mut self.server_engine_return,
                record,
            )
        } else {
            return;
        };
        let Some((_, message)) = record.split_once("]: ") else {
            return;
        };
        *seen = true;
        if line.starts_with("MSI (s) ")
            && message.starts_with("SOFTWARE RESTRICTION POLICY: Verifying package --> ")
        {
            self.server_package_policy_check_observed = true;
        }
        if let Some(result) = message
            .trim_start()
            .strip_prefix("MainEngineThread is returning ")
            && let Ok(result) = result.trim().parse::<u32>()
        {
            *code = Some(result);
        }
    }
}

fn action_message<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    let (time, message) = line.strip_prefix(prefix)?.split_once(": ")?;
    let valid_time = time.len() == 8
        && time.bytes().enumerate().all(|(index, byte)| {
            if index == 2 || index == 5 {
                byte == b':'
            } else {
                byte.is_ascii_digit()
            }
        });
    valid_time.then_some(message)
}

fn action_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 72
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_client_and_server_engine_returns_separately_from_action_returns() {
        let log = b"Action start 18:05:06: InstallInitialize.\r\n\
                    Action ended 18:05:06: InstallInitialize. Return value 1.\r\n\
                    MSI (s) (88:74) [18:05:06:151]: MainEngineThread is returning 1603\r\n\
                    MSI (c) (80:A4) [18:05:06:152]: MainEngineThread is returning 1603\r\n\
                    Action ended 18:05:06: C:\\private. Return value 1.\r\n\
                    Action start 18:05:07: Unfinished.";
        let summary = MsiInstallLogSummary::from_bytes(log).unwrap();
        assert_eq!(
            summary.last_action_started.as_deref(),
            Some("InstallInitialize")
        );
        assert_eq!(summary.last_action_ended.unwrap().return_value, 1);
        assert!(summary.client_records_observed);
        assert!(summary.server_records_observed);
        assert_eq!(summary.client_engine_return, Some(1603));
        assert_eq!(summary.server_engine_return, Some(1603));
    }

    #[test]
    fn package_policy_check_reports_the_phase_without_retaining_its_payload() {
        let input = b"MSI (s) (58:AC) [09:23:54:535]: SOFTWARE RESTRICTION POLICY: Verifying package --> 'C:\\private\\input.msi' against software restriction policy\r\n";
        let summary = MsiInstallLogSummary::from_bytes(input).unwrap();
        assert!(summary.server_package_policy_check_observed);
        assert!(summary.server_records_observed);
        assert_eq!(summary.server_engine_return, None);
        assert_eq!(summary.last_action_ended, None);
        assert!(!serde_json::to_string(&summary).unwrap().contains("private"));
    }

    #[test]
    fn bom_diagnostics_preserve_a_boundary_without_inventing_an_exit() {
        let text = "MSI (c) (80:A4) [18:05:06:152]: Waiting\r\n";
        let mut bytes = vec![0xff, 0xfe];
        bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        let summary = MsiInstallLogSummary::from_bytes(&bytes).unwrap();
        assert!(summary.client_records_observed);
        assert!(!summary.server_records_observed);
        assert_eq!(summary.client_engine_return, None);
        assert_eq!(summary.server_engine_return, None);
        assert_eq!(summary.last_action_ended, None);
        let oversized = vec![0; MAX_MSI_INSTALL_LOG_BYTES + 1];
        assert!(MsiInstallLogSummary::from_bytes(&oversized).is_err());
    }
}
