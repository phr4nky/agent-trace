//! What the server takes from an `agent-trace.toml` (`--config`): the policy additions
//! (`[policy]`), custom rules (`[[rules]]`) and redaction additions (`[redaction]`), so findings
//! on the server match those of the recorders. The file's other tables (`[hooks]`, `[proxy]`,
//! `[ship]`, …) are ignored, so recorders and server can share one file.

use std::path::Path;

use agent_trace_core::redact::{self, RedactionConfig};
use agent_trace_core::rules::{CustomRule, CustomRuleConfig};
use agent_trace_core::{Analyzer, PolicyConfig, ToolPolicy};
use anyhow::Context as _;
use serde::Deserialize;

/// The tables of `agent-trace.toml` the server uses.
#[derive(Debug, Default, Deserialize)]
pub struct ServerConfig {
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub rules: Vec<CustomRuleConfig>,
    #[serde(default)]
    pub redaction: RedactionConfig,
}

impl ServerConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config file {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("invalid config file {}", path.display()))
    }

    /// Install the redaction additions for this process (before any request).
    pub fn install_redaction(&self) -> anyhow::Result<()> {
        redact::configure(&self.redaction).map_err(anyhow::Error::msg)
    }

    /// The analyzer with the policy additions and custom rules.
    pub fn analyzer(&self) -> anyhow::Result<Analyzer> {
        let mut analyzer = Analyzer::new(ToolPolicy::default().with_config(&self.policy));
        for rule in &self.rules {
            let rule = CustomRule::new(rule.clone()).map_err(anyhow::Error::msg)?;
            analyzer = analyzer.with_rule(Box::new(rule));
        }
        Ok(analyzer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_server_tables_and_ignores_the_others() {
        let c: ServerConfig = toml::from_str(
            r#"
            [hooks]
            mode = "enforce"

            [ship]
            url = "https://trace.example"

            [policy]
            privileged = ["push_files"]

            [[rules]]
            id = "CORP-001"
            title = "Shell tool"
            severity = "high"
            tools = ["run_command*"]
            "#,
        )
        .unwrap();
        assert_eq!(c.policy.privileged, vec!["push_files".to_owned()]);
        let analyzer = c.analyzer().unwrap();
        assert!(analyzer.rules().any(|r| r.id() == "CORP-001"));
        // Typos inside the tables the server uses are still errors.
        assert!(toml::from_str::<ServerConfig>("[policy]\nprivilegd = [\"x\"]").is_err());
    }
}
