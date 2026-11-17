//! Deterministic, typed security rules. Findings are forensic indicators.

mod exfiltration;
mod injection;
mod trust_boundary;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::event::{Event, EventKind, ExecutionMode, ToolState, TraceRecord};
use crate::finding::{AttemptStatus, Confidence, Finding, Severity};
use crate::policy::ToolPolicy;
use crate::provenance::TraceIndex;

pub use exfiltration::{BlockedActionRule, ExfiltrationRule};
pub use injection::{
    AuthoritySpoofingRule, CONTENT_INDICATORS_KEY, PromptInjectionRule, record_content_indicators,
};
pub use trust_boundary::{
    CrossAgentTaintRule, LINK_BASIS_KEY, LINK_BASIS_SESSION_CONTEXT, TrustBoundaryRule,
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
    fn id(&self) -> &'static str;
    fn version(&self) -> u32;
    fn title(&self) -> &'static str;
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
            ],
            policy,
        }
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
                    e.metadata.get("mock_tool").and_then(|v| v.as_bool()) == Some(true)
                        || e.execution_mode == ExecutionMode::Simulated
                });
            if mock {
                "An execution event was recorded; the executed tool is a MOCK (no real side effects).".into()
            } else {
                "An execution event was recorded for the request; verify its result before assuming impact.".into()
            }
        }
        _ => "No execution or policy decision was recorded; treat as attempted only.".into(),
    }
}

pub(crate) fn tool_name(event: &Event) -> &str {
    event
        .payload
        .get("tool")
        .and_then(|t| t.as_str())
        .unwrap_or(&event.name)
}
