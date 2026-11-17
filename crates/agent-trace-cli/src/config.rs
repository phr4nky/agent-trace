//! `agent-trace.toml`: policy additions and proxy settings.
//!
//! Lookup order: `--config`, `$AGENT_TRACE_CONFIG`, `./agent-trace.toml`, then
//! `<data dir>/agent-trace.toml`. An explicitly named file must exist; the implicit ones are
//! optional. A file that exists but is invalid is an error, never silently ignored.

use std::path::{Path, PathBuf};

use agent_trace_core::{Analyzer, PolicyConfig, ToolPolicy};
use agent_trace_mcp::ProxyMode;
use anyhow::{Context as _, bail};
use serde::Deserialize;

/// File name looked up in the working directory and the data directory.
pub const FILE_NAME: &str = "agent-trace.toml";
/// Larger files are rejected (a config file is a few lines).
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub proxy: ProxySection,
    #[serde(default)]
    pub hooks: HooksSection,
}

/// What `agent-trace hook` does when it cannot record or decide (e.g. the database is down).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnError {
    /// Let the tool call proceed (fail open). The error is printed on stderr.
    #[default]
    Allow,
    /// Deny tool calls while recording fails (fail closed; enforce mode only).
    Deny,
}

/// The `[hooks]` table (Claude Code hooks, `agent-trace hook`).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HooksSection {
    /// `observe` (default) or `enforce`.
    pub mode: Option<ProxyMode>,
    /// Tools whose results count as untrusted session context
    /// (default: [`DEFAULT_HOOK_TAINT_SOURCES`]).
    pub taint_sources: Option<Vec<String>>,
    /// Behavior when recording fails (default: allow).
    #[serde(default)]
    pub on_error: OnError,
}

/// Content from outside the machine: web pages, search results and every MCP tool.
pub const DEFAULT_HOOK_TAINT_SOURCES: &[&str] = &["WebFetch", "WebSearch", "mcp__*"];

/// The `[proxy]` table.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxySection {
    /// `observe` (default) or `enforce`.
    pub mode: Option<ProxyMode>,
    /// Sources whose content counts as untrusted session context (default: `["*"]`).
    pub taint_sources: Option<Vec<String>>,
    /// Maximum seconds to wait for a `tools/call` response from the upstream server.
    pub call_timeout_secs: Option<u64>,
}

/// A loaded configuration and the file it came from (`None` = built-in defaults).
#[derive(Debug, Default)]
pub struct Loaded {
    pub config: Config,
    pub path: Option<PathBuf>,
}

impl Loaded {
    pub fn policy(&self) -> ToolPolicy {
        ToolPolicy::default().with_config(&self.config.policy)
    }

    pub fn analyzer(&self) -> Analyzer {
        Analyzer::new(self.policy())
    }

    /// Say on stderr which file changed the defaults, so a gate's result can be explained.
    pub fn announce(&self) {
        if let Some(path) = &self.path {
            eprintln!(
                "config: {}",
                crate::output::term_safe(&path.display().to_string())
            );
        }
    }
}

/// Find and parse the configuration.
pub fn load(explicit: Option<&Path>, data_dir: Option<&Path>) -> anyhow::Result<Loaded> {
    let named = explicit.map(Path::to_path_buf).or_else(|| {
        std::env::var_os("AGENT_TRACE_CONFIG")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    });
    if let Some(path) = named {
        return parse_file(&path).map(|config| Loaded {
            config,
            path: Some(path),
        });
    }
    let implicit =
        std::iter::once(PathBuf::from(FILE_NAME)).chain(data_dir.map(|d| d.join(FILE_NAME)));
    for path in implicit {
        if path.is_file() {
            return parse_file(&path).map(|config| Loaded {
                config,
                path: Some(path),
            });
        }
    }
    Ok(Loaded::default())
}

fn parse_file(path: &Path) -> anyhow::Result<Config> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("cannot read config file {}", path.display()))?;
    if !meta.is_file() {
        bail!("config {} is not a regular file", path.display());
    }
    if meta.len() > MAX_CONFIG_BYTES {
        bail!(
            "config {} is larger than {MAX_CONFIG_BYTES} bytes",
            path.display()
        );
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read config file {}", path.display()))?;
    parse(&text).with_context(|| format!("invalid config file {}", path.display()))
}

pub fn parse(text: &str) -> anyhow::Result<Config> {
    Ok(toml::from_str(text)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_documented_example() {
        let c = parse(
            r#"
            [policy]
            privileged = ["create_pull_request", "push_files", "create_or_update_file"]
            allow_destinations = ["*.corp.example"]

            [proxy]
            mode = "enforce"
            taint_sources = ["get_issue", "list_issues", "search_*"]
            call_timeout_secs = 60

            [hooks]
            mode = "enforce"
            taint_sources = ["WebFetch", "mcp__github__get_issue"]
            on_error = "deny"
            "#,
        )
        .unwrap();
        assert_eq!(c.proxy.mode, Some(ProxyMode::Enforce));
        assert_eq!(c.proxy.call_timeout_secs, Some(60));
        assert_eq!(c.hooks.mode, Some(ProxyMode::Enforce));
        assert_eq!(c.hooks.on_error, OnError::Deny);
        let policy = ToolPolicy::default().with_config(&c.policy);
        assert!(policy.is_privileged("push_files"));
        assert!(policy.destination_allowed("https://git.corp.example/"));
    }

    #[test]
    fn empty_file_means_defaults() {
        let c = parse("").unwrap();
        assert_eq!(c.policy, PolicyConfig::default());
        assert_eq!(c.proxy.mode, None);
    }

    #[test]
    fn typos_are_errors() {
        for bad in [
            "[policy]\nprivilegd = [\"x\"]",
            "[proxy]\nmode = \"block\"",
            "[proxi]\nmode = \"enforce\"",
            "[policy]\nprivileged = \"x\"",
            "[hooks]\non_error = \"ignore\"",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn explicit_file_must_exist() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.toml");
        assert!(load(Some(&missing), None).is_err());
        let present = dir.path().join("c.toml");
        std::fs::write(&present, "[proxy]\nmode = \"observe\"\n").unwrap();
        let loaded = load(Some(&present), None).unwrap();
        assert_eq!(loaded.path.as_deref(), Some(present.as_path()));
    }
}
