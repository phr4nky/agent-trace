//! Deterministic, typed security rules. Findings are forensic indicators.

mod canary;
pub mod custom;
mod exfiltration;
mod injection;
pub mod tool_pins;
mod trust_boundary;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::event::{Event, EventKind, ExecutionMode, ToolState, TraceRecord};
use crate::finding::{AttemptStatus, Confidence, Finding, Severity};
use crate::policy::ToolPolicy;
use crate::provenance::TraceIndex;

pub use canary::CanaryLeakRule;
pub use custom::{CustomRule, CustomRuleConfig, RuleTarget};
pub use exfiltration::{BlockedActionRule, ExfiltrationRule};
pub use injection::{
    AuthoritySpoofingRule, CONTENT_INDICATORS_KEY, PromptInjectionRule, record_content_indicators,
};
pub use tool_pins::{
    TOOL_PINS_ACTION_BLOCKED, TOOL_PINS_ACTION_KEY, TOOL_PINS_ACTION_OBSERVED, TOOL_PINS_ADDED_KEY,
    TOOL_PINS_CHANGED, TOOL_PINS_CHANGED_KEY, TOOL_PINS_KEY, ToolPinRule,
};
pub use trust_boundary::{
    CrossAgentTaintRule, LINK_BASIS_KEY, LINK_BASIS_SESSION_CONTEXT, TAINT_SOURCE_KEY,
    TrustBoundaryRule,
};

/// Input for rule evaluation.
pub struct RuleContext<'a> {
    pub record: &'a TraceRecord,
    pub index: TraceIndex<'a>,
    pub policy: &'a ToolPolicy,
    pub created_at: OffsetDateTime,
}

/// A single security rule.
pub trait Rule: Send + Sync {
    fn id(&self) -> &str;
    fn version(&self) -> u32;
    fn title(&self) -> &str;
    /// What the rule detects, for reports and SARIF rule metadata.
    fn description(&self) -> &str {
        ""
    }
    /// The severity of the rule's typical finding (a finding may be higher).
    fn default_severity(&self) -> Severity {
        Severity::Medium
    }
    /// Taxonomy tags (OWASP LLM Top 10 2025, MITRE ATLAS, or your own) copied onto every
    /// finding. Defaults to the central mapping in [`crate::taxonomy`] by rule ID.
    fn tags(&self) -> Vec<String> {
        crate::taxonomy::builtin_tags(self.id())
            .iter()
            .map(|t| (*t).to_owned())
            .collect()
    }
    fn evaluate(&self, ctx: &RuleContext<'_>) -> Vec<Finding>;
}

/// Runs all rules over a trace.
pub struct Analyzer {
    rules: Vec<Box<dyn Rule>>,
    policy: ToolPolicy,
}

impl Default for Analyzer {
    fn default() -> Self {
        Self::new(ToolPolicy::default())
    }
}

impl Analyzer {
    pub fn new(policy: ToolPolicy) -> Self {
        Self {
            rules: vec![
                Box::new(PromptInjectionRule),
                Box::new(TrustBoundaryRule),
                Box::new(ExfiltrationRule),
                Box::new(BlockedActionRule),
                Box::new(AuthoritySpoofingRule),
                Box::new(CrossAgentTaintRule),
                Box::new(CanaryLeakRule),
                Box::new(ToolPinRule),
            ],
            policy,
        }
    }

    /// Add a rule (a declarative [`custom::CustomRule`] or your own [`Rule`]) after the
    /// built-in ones.
    pub fn with_rule(mut self, rule: Box<dyn Rule>) -> Self {
        self.rules.push(rule);
        self
    }

    pub fn rules(&self) -> impl Iterator<Item = &dyn Rule> {
        self.rules.iter().map(AsRef::as_ref)
    }

    /// Analyze a trace. Output is deterministic for the same trace and rule versions
    /// (apart from `created_at`, which the caller supplies).
    pub fn analyze(&self, record: &TraceRecord, created_at: OffsetDateTime) -> Vec<Finding> {
        let ctx = RuleContext {
            record,
            index: TraceIndex::new(&record.events),
            policy: &self.policy,
            created_at,
        };
        let mut findings: Vec<Finding> = self.rules.iter().flat_map(|r| r.evaluate(&ctx)).collect();
        let seq = |f: &Finding| {
            f.evidence_event_ids
                .iter()
                .filter_map(|id| ctx.index.get(*id).map(|e| e.sequence))
                .max()
                .unwrap_or(0)
        };
        findings.sort_by(|a, b| seq(a).cmp(&seq(b)).then_with(|| a.rule_id.cmp(&b.rule_id)));
        findings.dedup_by_key(|f| f.finding_id);
        findings
    }
}

/// Builder used by rules so every finding is constructed consistently.
pub(crate) struct FindingDraft {
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub evidence: Vec<Uuid>,
    pub status: AttemptStatus,
    pub remediation: &'static str,
}

impl FindingDraft {
    pub fn build(self, rule: &dyn Rule, ctx: &RuleContext<'_>) -> Finding {
        let mut evidence = Vec::new();
        for id in self.evidence {
            if !evidence.contains(&id) {
                evidence.push(id);
            }
        }
        let mut description = self.description;
        if ctx.record.trace.execution_mode == ExecutionMode::Simulated {
            description.push_str(
                " Trace execution mode is SIMULATED: decisions come from a scripted demo agent, \
                 not a live model, and privileged tools are mocks.",
            );
        }
        Finding {
            finding_id: Finding::derive_id(
                ctx.record.trace.trace_id,
                rule.id(),
                rule.version(),
                &evidence,
            ),
            trace_id: ctx.record.trace.trace_id,
            rule_id: rule.id().to_owned(),
            rule_version: rule.version(),
            title: self.title,
            description,
            severity: self.severity,
            confidence: self.confidence,
            evidence_event_ids: evidence,
            attempt_status: self.status,
            remediation: self.remediation.to_owned(),
            created_at: ctx.created_at,
            tags: rule.tags(),
        }
    }
}

/// Lifecycle events of a tool call: events whose *parent* is the request.
pub(crate) fn lifecycle<'a>(ctx: &RuleContext<'a>, request: &Event) -> Vec<&'a Event> {
    ctx.index
        .dependents(request.event_id)
        .iter()
        .copied()
        .filter(|e| e.parent_event_id == Some(request.event_id))
        .collect()
}

/// Outcome of a tool call, derived only from recorded lifecycle events.
/// `executed` requires an explicit execution event; a request alone is `attempted`.
pub(crate) fn tool_outcome(ctx: &RuleContext<'_>, request: &Event) -> (AttemptStatus, Vec<Uuid>) {
    let events = lifecycle(ctx, request);
    let pick = |pred: &dyn Fn(&Event) -> bool| -> Vec<Uuid> {
        events
            .iter()
            .filter(|e| pred(e))
            .map(|e| e.event_id)
            .collect()
    };
    let executed = pick(&|e| e.kind == EventKind::ToolCallExecuted);
    if !executed.is_empty() {
        return (AttemptStatus::Executed, executed);
    }
    let blocked = pick(&|e| is_denial(e));
    if !blocked.is_empty() {
        return (AttemptStatus::Blocked, blocked);
    }
    let failed = pick(&|e| e.kind == EventKind::ToolCallFailed);
    (AttemptStatus::Attempted, failed)
}

pub(crate) fn is_denial(event: &Event) -> bool {
    event.kind == EventKind::ToolPolicyDecision
        && (event.tool_state == Some(ToolState::Blocked)
            || event.payload.get("decision").and_then(|d| d.as_str()) == Some("deny"))
}

/// Human-readable outcome of a tool call, noting mock tools explicitly.
pub(crate) fn outcome_text(
    ctx: &RuleContext<'_>,
    status: AttemptStatus,
    outcome_ids: &[Uuid],
) -> String {
    match status {
        AttemptStatus::Blocked => {
            "The request was blocked by policy; no execution was recorded.".into()
        }
        AttemptStatus::Executed => {
            let mock = outcome_ids
                .iter()
                .filter_map(|id| ctx.index.get(*id))
                .any(|e| {
                    e.metadata
                        .get("mock_tool")
                        .and_then(serde_json::Value::as_bool)
                        == Some(true)
                        || e.execution_mode == ExecutionMode::Simulated
                });
            let mut text: String = if mock {
                "An execution event was recorded; the executed tool is a MOCK (no real side effects).".into()
            } else {
                "An execution event was recorded for the request; verify its result before assuming impact.".into()
            };
            if let Some(note) = approval_note(ctx, outcome_ids) {
                text.push(' ');
                text.push_str(note);
            }
            text
        }
        _ => "No execution or policy decision was recorded; treat as attempted only.".into(),
    }
}

/// Payload key on a `tool_policy_decision` that resolves an `ask` decision: `accepted`,
/// `declined`, `cancelled`, `timeout`, `unsupported` or `error` (MCP proxy, ask mode).
pub const HUMAN_APPROVAL_KEY: &str = "human_approval";
/// Payload key on a `tool_call_executed` that follows an `ask` decision (Claude Code hooks):
/// the call ran after the hook asked Claude Code to confirm it with the user.
pub const AFTER_ASK_KEY: &str = "after_ask";

/// What the trace records about human approval of the executed call, if anything. Only
/// recorded facts are used: an accepted elicitation, or an execution after an `ask` answer.
fn approval_note(ctx: &RuleContext<'_>, executed_ids: &[Uuid]) -> Option<&'static str> {
    let executed: Vec<&Event> = executed_ids
        .iter()
        .filter_map(|id| ctx.index.get(*id))
        .collect();
    let accepted = executed.iter().any(|e| {
        e.caused_by_event_id
            .and_then(|id| ctx.index.get(id))
            .and_then(|d| d.payload.get(HUMAN_APPROVAL_KEY))
            .and_then(|v| v.as_str())
            == Some("accepted")
    });
    if accepted {
        return Some("A human approved the call (MCP elicitation) before it ran.");
    }
    executed
        .iter()
        .any(|e| {
            e.payload
                .get(AFTER_ASK_KEY)
                .and_then(serde_json::Value::as_bool)
                == Some(true)
        })
        .then_some(
            "The call ran after the hook answered \"ask\" (Claude Code asks the user to \
             confirm such a call).",
        )
}

pub(crate) fn tool_name(event: &Event) -> &str {
    event
        .payload
        .get("tool")
        .and_then(|t| t.as_str())
        .unwrap_or(&event.name)
}
