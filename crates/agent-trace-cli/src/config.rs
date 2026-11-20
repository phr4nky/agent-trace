//! `agent-trace.toml`: policy additions, proxy and hook settings, task profiles.
//!
//! Lookup order: `--config`, `$AGENT_TRACE_CONFIG`, `./agent-trace.toml`, then
//! `<data dir>/agent-trace.toml`. An explicitly named file must exist; the implicit ones are
//! optional. A file that exists but is invalid is an error, never silently ignored.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use agent_trace_core::canary::{self, CanaryConfig};
use agent_trace_core::redact::{self, RedactionConfig};
use agent_trace_core::rules::{CustomRule, CustomRuleConfig};
use agent_trace_core::{Analyzer, PolicyConfig, ProfileConfig, ToolPolicy, ToolProfile};
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
    /// Additional secret patterns and field names (added to the built-in rules).
    #[serde(default)]
    pub redaction: RedactionConfig,
    /// Defaults for `agent-trace prune`.
    #[serde(default)]
    pub retention: RetentionSection,
    /// Declarative detection rules (`[[rules]]`), run after the built-in ones.
    #[serde(default)]
    pub rules: Vec<CustomRuleConfig>,
    /// Canary tokens (`[[canaries]]`): decoy secrets reported by AT-007.
    #[serde(default)]
    pub canaries: Vec<CanaryConfig>,
    /// Task profiles (`[profiles.<name>]`): the tools a task may use, selected with
    /// `--profile` or `$AGENT_TRACE_PROFILE`.
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfileConfig>,
}

/// Environment variable that selects a profile when `--profile` is not given.
pub const PROFILE_ENV: &str = "AGENT_TRACE_PROFILE";

/// The `[retention]` table.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionSection {
    /// Delete traces older than this many days.
    pub max_age_days: Option<u64>,
    /// Keep at most this many traces (the newest).
    pub max_traces: Option<usize>,
}

/// What `agent-trace hook` does when it cannot record or decide (e.g. the database is down).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnError {
    /// Let the tool call proceed (fail open). The error is printed on stderr.
    #[default]
    Allow,
    /// Deny tool calls while recording fails (fail closed; enforce and ask mode only).
    Deny,
}

/// The `[hooks]` table (Claude Code hooks, `agent-trace hook`).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HooksSection {
    /// `observe` (default), `enforce` or `ask`.
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
    /// `observe` (default), `enforce` or `ask`.
    pub mode: Option<ProxyMode>,
    /// Sources whose content counts as untrusted session context (default: `["*"]`).
    pub taint_sources: Option<Vec<String>>,
    /// Maximum seconds to wait for a `tools/call` response from the upstream server.
    pub call_timeout_secs: Option<u64>,
    /// Pin tool definitions per server and report changes (default: true).
    pub pin_tools: Option<bool>,
    /// Ask mode: maximum seconds to wait for the user's answer (default 300); then the call
    /// is denied.
    pub ask_timeout_secs: Option<u64>,
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

    /// The analyzer: built-in rules with the configured policy, then the `[[rules]]`.
    pub fn analyzer(&self) -> Analyzer {
        let mut analyzer = Analyzer::new(self.policy());
        for config in &self.config.rules {
            // Validated when the file was loaded.
            if let Ok(rule) = CustomRule::new(config.clone()) {
                analyzer = analyzer.with_rule(Box::new(rule));
            }
        }
        analyzer
    }

    /// The task profile selected by `explicit` (`--profile`) or `$AGENT_TRACE_PROFILE`.
    /// A name that is not defined in the configuration is an error.
    pub fn profile(&self, explicit: Option<&str>) -> anyhow::Result<Option<ToolProfile>> {
        let from_env = std::env::var(PROFILE_ENV).ok();
        select_profile(&self.config.profiles, explicit, from_env.as_deref())
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

/// The profile named by `explicit`, else by the environment value (blank = none).
fn select_profile(
    profiles: &BTreeMap<String, ProfileConfig>,
    explicit: Option<&str>,
    from_env: Option<&str>,
) -> anyhow::Result<Option<ToolProfile>> {
    let (name, source) = match (explicit, from_env.map(str::trim).filter(|v| !v.is_empty())) {
        (Some(name), _) => (name.trim(), "--profile"),
        (None, Some(name)) => (name, PROFILE_ENV),
        (None, None) => return Ok(None),
    };
    match profiles.get(name) {
        Some(config) => Ok(Some(ToolProfile::new(name, config))),
        None => {
            let known: Vec<&str> = profiles.keys().map(String::as_str).collect();
            bail!(
                "unknown profile {name:?} (from {source}); defined profiles: {}",
                if known.is_empty() {
                    "none (add a [profiles.<name>] table to agent-trace.toml)".to_owned()
                } else {
                    known.join(", ")
                }
            )
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
    let config: Config = toml::from_str(text)?;
    redact::validate_config(&config.redaction).map_err(anyhow::Error::msg)?;
    // Values from `env` are read here too, so a missing variable is reported by every command.
    canary::resolve(&config.canaries).map_err(anyhow::Error::msg)?;
    for (name, profile) in &config.profiles {
        if name.trim().is_empty() || name.trim() != name {
            bail!("profile name {name:?} must not be blank or have surrounding spaces");
        }
        if profile.tools.iter().all(|t| t.trim().is_empty()) {
            bail!("profile {name:?} allows no tools; list at least one in `tools`");
        }
    }
    let mut ids = std::collections::HashSet::new();
    for rule in &config.rules {
        CustomRule::new(rule.clone()).map_err(anyhow::Error::msg)?;
        if !ids.insert(rule.id.as_str()) {
            bail!("rule id {} is defined twice", rule.id);
        }
    }
    Ok(config)
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
    fn canaries_are_validated() {
        let c = parse(
            r#"
            [[canaries]]
            name = "aws-decoy"
            value = "AKIAZ7Q3CANARY4X2LMN"
            "#,
        )
        .unwrap();
        assert_eq!(c.canaries.len(), 1);
        for bad in [
            "[[canaries]]\nname = \"x\"\nvalue = \"short\"",
            "[[canaries]]\nname = \"Bad Name\"\nvalue = \"long-enough-value\"",
            "[[canaries]]\nname = \"x\"",
            "[[canaries]]\nname = \"x\"\nenv = \"AGENT_TRACE_TEST_UNSET_CANARY_VAR\"",
            "[[canaries]]\nname = \"x\"\nvalue = \"long-enough-value\"\nlabel = \"y\"",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn profiles_are_parsed_and_selected() {
        let c = parse(
            r#"
            [proxy]
            mode = "ask"
            ask_timeout_secs = 30

            [hooks]
            mode = "ask"

            [profiles.read-only]
            tools = ["Read", "Grep", "mcp__github__get_*"]
            "#,
        )
        .unwrap();
        assert_eq!(c.proxy.mode, Some(ProxyMode::Ask));
        assert_eq!(c.hooks.mode, Some(ProxyMode::Ask));
        assert_eq!(c.proxy.ask_timeout_secs, Some(30));
        let p = select_profile(&c.profiles, Some("read-only"), None)
            .unwrap()
            .unwrap();
        assert!(p.allows("mcp__github__get_issue"));
        assert!(!p.allows("Bash"));
        // The flag wins over the environment; a blank environment value selects nothing.
        let p = select_profile(&c.profiles, None, Some("read-only")).unwrap();
        assert_eq!(p.unwrap().name, "read-only");
        assert!(
            select_profile(&c.profiles, None, Some(" "))
                .unwrap()
                .is_none()
        );
        assert!(select_profile(&c.profiles, None, None).unwrap().is_none());
        // Unknown names are errors, from either source.
        let e = select_profile(&c.profiles, Some("write"), None).unwrap_err();
        assert!(e.to_string().contains("read-only"), "{e}");
        assert!(select_profile(&c.profiles, None, Some("nope")).is_err());
        assert!(select_profile(&BTreeMap::new(), Some("x"), None).is_err());
        for bad in [
            "[profiles.x]\ntools = []",
            "[profiles.x]\ntool = [\"Read\"]",
            "[profiles.x]",
            "[profiles.x]\ntools = [\"Read\"]\nmode = \"ask\"",
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
