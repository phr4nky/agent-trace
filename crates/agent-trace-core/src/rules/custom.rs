//! Declarative rules (the `[[rules]]` tables of `agent-trace.toml`): detections without
//! writing Rust.
//!
//! Two kinds:
//! * `on = "tool_call"`: a tool request whose name matches `tools` (globs) and whose
//!   arguments match `arguments` (regex per argument). With `after_untrusted`, only requests
//!   with an explicit causal or context path back to lower-trust content (like AT-002).
//!   The attempt status comes from the recorded lifecycle (attempted / blocked / executed).
//! * `on = "content"`: lower-trust content (tool results, documents, other agents' messages)
//!   matching `pattern` (status `suspected`, like AT-001).

use std::collections::BTreeMap;

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{FindingDraft, Rule, RuleContext, outcome_text, tool_name, tool_outcome};
use crate::event::{EventKind, TrustLevel};
use crate::finding::{AttemptStatus, Confidence, Finding, Severity};
use crate::policy::glob_match;

/// What a custom rule looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleTarget {
    #[default]
    ToolCall,
    Content,
}

/// A `[[rules]]` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomRuleConfig {
    /// `PREFIX-NNN`, e.g. `CORP-001`. The `AT-` prefix is reserved for built-in rules.
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub severity: Severity,
    #[serde(default = "default_confidence")]
    pub confidence: Confidence,
    /// Bump when the rule changes meaning (part of the finding IDs).
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub remediation: String,
    #[serde(default)]
    pub on: RuleTarget,
    /// `tool_call`: tool names or `*` patterns; empty = any tool.
    #[serde(default)]
    pub tools: Vec<String>,
    /// `tool_call`: argument name → regex; every listed argument must exist and match.
    #[serde(default)]
    pub arguments: BTreeMap<String, String>,
    /// `tool_call`: only requests with a causal/context path to lower-trust content.
    #[serde(default)]
    pub after_untrusted: bool,
    /// `content`: regex on the lower-trust content.
    #[serde(default)]
    pub pattern: Option<String>,
}

fn default_confidence() -> Confidence {
    Confidence::Medium
}

fn default_version() -> u32 {
    1
}

const MAX_REGEX_BYTES: usize = 1 << 20;

fn regex(rule: &str, what: &str, source: &str) -> Result<Regex, String> {
    RegexBuilder::new(source)
        .size_limit(MAX_REGEX_BYTES)
        .build()
        .map_err(|e| format!("rule {rule}: {what}: {e}"))
}

/// A compiled custom rule.
#[derive(Debug, Clone)]
pub struct CustomRule {
    config: CustomRuleConfig,
    arguments: Vec<(String, Regex)>,
    pattern: Option<Regex>,
}

impl CustomRule {
    pub fn new(config: CustomRuleConfig) -> Result<Self, String> {
        let id = config.id.as_str();
        let valid_id = id.split_once('-').is_some_and(|(prefix, number)| {
            !prefix.is_empty()
                && prefix.len() <= 16
                && prefix
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                && prefix.starts_with(|c: char| c.is_ascii_uppercase())
                && (1..=6).contains(&number.len())
                && number.chars().all(|c| c.is_ascii_digit())
        });
        if !valid_id {
            return Err(format!(
                "rule id {id:?}: use PREFIX-NNN, e.g. CORP-001 (uppercase letters and digits)"
            ));
        }
        if id.starts_with("AT-") {
            return Err(format!(
                "rule id {id:?}: the AT- prefix is reserved for built-in rules"
            ));
        }
        if config.title.trim().is_empty() {
            return Err(format!("rule {id}: title is empty"));
        }
        let (arguments, pattern) = match config.on {
            RuleTarget::ToolCall => {
                if config.pattern.is_some() {
                    return Err(format!("rule {id}: `pattern` is for on = \"content\""));
                }
                let args = config
                    .arguments
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), regex(id, &format!("argument {k}"), v)?)))
                    .collect::<Result<Vec<_>, String>>()?;
                (args, None)
            }
            RuleTarget::Content => {
                if !config.tools.is_empty()
                    || !config.arguments.is_empty()
                    || config.after_untrusted
                {
                    return Err(format!(
                        "rule {id}: `tools`, `arguments` and `after_untrusted` are for on = \"tool_call\""
                    ));
                }
                let Some(p) = &config.pattern else {
                    return Err(format!("rule {id}: on = \"content\" needs a `pattern`"));
                };
                let re = regex(id, "pattern", p)?;
                if re.is_match("") {
                    return Err(format!("rule {id}: pattern matches the empty string"));
                }
                (Vec::new(), Some(re))
            }
        };
        Ok(Self {
            config,
            arguments,
            pattern,
        })
    }

    pub fn config(&self) -> &CustomRuleConfig {
        &self.config
    }

    fn tool_matches(&self, tool: &str) -> bool {
        self.config.tools.is_empty() || self.config.tools.iter().any(|p| glob_match(p, tool))
    }

    fn arguments_match(&self, arguments: Option<&Value>) -> bool {
        self.arguments
            .iter()
            .all(|(key, re)| match arguments.and_then(|a| a.get(key)) {
                Some(Value::String(s)) => re.is_match(s),
                Some(Value::Null) | None => false,
                Some(other) => re.is_match(&other.to_string()),
            })
    }

    fn draft(
        &self,
        description: String,
        evidence: Vec<uuid::Uuid>,
        status: AttemptStatus,
    ) -> FindingDraft {
        FindingDraft {
            title: self.config.title.clone(),
            description,
            severity: self.config.severity,
            confidence: self.config.confidence,
            evidence,
            status,
            remediation: "",
        }
    }
}

impl Rule for CustomRule {
    fn id(&self) -> &str {
        &self.config.id
    }
    fn version(&self) -> u32 {
        self.config.version
    }
    fn title(&self) -> &str {
        &self.config.title
    }
    fn description(&self) -> &str {
        self.config.description.trim_end()
    }
    fn default_severity(&self) -> Severity {
        self.config.severity
    }
    fn evaluate(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let intro = if self.config.description.is_empty() {
            String::new()
        } else {
            format!("{} ", self.config.description.trim_end())
        };
        let mut out = Vec::new();
        match self.config.on {
            RuleTarget::Content => {
                let Some(pattern) = &self.pattern else {
                    return out;
                };
                for e in
                    ctx.record.events.iter().filter(|e| {
                        e.kind.carries_content() && e.trust_level == TrustLevel::LowerTrust
                    })
                {
                    if pattern.is_match(&e.payload_text()) {
                        let description = format!(
                            "{intro}Lower-trust content at event #{} ({}, `{}`) matches the rule's pattern.",
                            e.sequence,
                            e.kind.as_str(),
                            e.name
                        );
                        out.push(self.with_remediation(
                            self.draft(description, vec![e.event_id], AttemptStatus::Suspected),
                            ctx,
                        ));
                    }
                }
            }
            RuleTarget::ToolCall => {
                let causes = self.config.after_untrusted.then(|| {
                    ctx.index
                        .nearest_causes(|e| e.trust_level == TrustLevel::LowerTrust)
                });
                for request in ctx
                    .record
                    .events
                    .iter()
                    .filter(|e| e.kind == EventKind::ToolCallRequested)
                {
                    let tool = tool_name(request);
                    if !self.tool_matches(tool)
                        || !self.arguments_match(request.payload.get("arguments"))
                    {
                        continue;
                    }
                    let path = match &causes {
                        Some(c) => match c.path(request.event_id, None) {
                            Some(path) => Some(path),
                            None => continue,
                        },
                        None => None,
                    };
                    let (status, outcome_ids) = tool_outcome(ctx, request);
                    let mut evidence: Vec<_> = path.iter().flatten().map(|e| e.event_id).collect();
                    if evidence.last() != Some(&request.event_id) {
                        evidence.push(request.event_id);
                    }
                    evidence.extend(outcome_ids.iter().copied());
                    let source = path
                        .as_ref()
                        .and_then(|p| p.first())
                        .map(|s| {
                            format!(
                                " It has a causal path back to lower-trust event #{} ({}).",
                                s.sequence,
                                s.kind.as_str()
                            )
                        })
                        .unwrap_or_default();
                    let description = format!(
                        "{intro}Tool `{tool}` was requested at event #{} and matches the rule.{source} {}",
                        request.sequence,
                        outcome_text(ctx, status, &outcome_ids),
                    );
                    out.push(self.with_remediation(self.draft(description, evidence, status), ctx));
                }
            }
        }
        out
    }
}

impl CustomRule {
    fn with_remediation(&self, draft: FindingDraft, ctx: &RuleContext<'_>) -> Finding {
        let mut finding = draft.build(self, ctx);
        finding.remediation = self.config.remediation.clone();
        finding
    }
}
