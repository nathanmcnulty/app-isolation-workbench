#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

const PROBED_TOOLS: &[&str] = &[
    "wsl.exe",
    "WindowsSandbox.exe",
    "MakeAppx.exe",
    "SignTool.exe",
    "wpr.exe",
    "wpa.exe",
    "gh.exe",
    "cargo.exe",
    "pwsh.exe",
];

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostProbe {
    pub schema_version: String,
    pub os: String,
    pub os_family: String,
    pub process_architecture: String,
    pub environment_architecture: BTreeMap<String, String>,
    pub discovered_tools: BTreeMap<String, Option<String>>,
    pub limitations: Vec<String>,
}

#[must_use]
pub fn probe_host() -> HostProbe {
    let environment_architecture = ["PROCESSOR_ARCHITECTURE", "PROCESSOR_ARCHITEW6432"]
        .into_iter()
        .filter_map(|key| env::var(key).ok().map(|value| (key.to_owned(), value)))
        .collect();
    let discovered_tools = PROBED_TOOLS
        .iter()
        .map(|name| {
            (
                name.trim_end_matches(".exe").to_owned(),
                find_command(name).map(|path| path.to_string_lossy().into_owned()),
            )
        })
        .collect();

    HostProbe {
        schema_version: "aiw.dev/host-probe/v0alpha1".to_owned(),
        os: env::consts::OS.to_owned(),
        os_family: env::consts::FAMILY.to_owned(),
        process_architecture: env::consts::ARCH.to_owned(),
        environment_architecture,
        discovered_tools,
        limitations: vec![
            "This bootstrap probe discovers paths only; it does not verify Windows features, exports, versions, tokens, or effective isolation backends."
                .to_owned(),
        ],
    }
}

#[must_use]
pub fn find_command(name: &str) -> Option<PathBuf> {
    let candidate = Path::new(name);
    if candidate.components().count() > 1 {
        return candidate.is_file().then(|| candidate.to_path_buf());
    }

    let path = env::var_os("PATH")?;
    let has_extension = candidate.extension().is_some();
    let extensions = if cfg!(windows) && !has_extension {
        env::var_os("PATHEXT")
            .map(|value| {
                value
                    .to_string_lossy()
                    .split(';')
                    .filter(|item| !item.is_empty())
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec![".COM".to_owned(), ".EXE".to_owned()])
    } else {
        vec![String::new()]
    };

    for directory in env::split_paths(&path) {
        for extension in &extensions {
            let path = directory.join(format!("{name}{extension}"));
            if path.is_file() {
                return Some(path);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_has_an_explicit_limitation() {
        let probe = probe_host();
        assert_eq!(probe.schema_version, "aiw.dev/host-probe/v0alpha1");
        assert!(!probe.limitations.is_empty());
        assert!(probe.discovered_tools.contains_key("cargo"));
    }

    #[test]
    fn impossible_tool_is_not_found() {
        assert!(find_command("aiw-this-tool-does-not-exist-8f197f32").is_none());
    }
}
