//! AT-002: privileged tool request with an explicit causal path from lower-trust content.
//! AT-006: the same, where the lower-trust content entered through a *different agent*.

use super::{FindingDraft, Rule, RuleContext, outcome_text, tool_name, tool_outcome};
use crate::event::{Event, EventKind, TrustLevel};
use crate::finding::{Confidence, Finding, Severity};

/// Metadata key on a tool request that says how its `context_event_ids` were obtained.
pub const LINK_BASIS_KEY: &str = "link_basis";
/// [`LINK_BASIS_KEY`] value of an adapter that sees tool traffic but not the model's context
/// (the MCP proxy): the links are the untrusted content returned earlier in the same session,
/// which the model may or may not have used.
pub const LINK_BASIS_SESSION_CONTEXT: &str = "session_context";

/// Metadata key on lower-trust content that adapters link as session context (the MCP
/// proxy, Claude Code hooks): the value names its source, e.g. `github:get_issue`.
pub const TAINT_SOURCE_KEY: &str = "taint_source";

/// Confidence and an explanatory sentence for a finding on `request`. Links that only state
/// "this content was in the same session" are weaker evidence than a recorded cause.
fn link_strength(request: &Event) -> (Confidence, &'static str) {
    let session_only = request
        .metadata
        .get(LINK_BASIS_KEY)
        .and_then(|v| v.as_str())
        == Some(LINK_BASIS_SESSION_CONTEXT);
    if session_only {
        (
            Confidence::Medium,
            " The link is session context recorded by an MCP proxy: the lower-trust content was \
             returned earlier in the same session; the proxy cannot see whether the model used it.",
        )
    } else {
        (Confidence::High, "")
    }
}

fn privileged_requests<'a>(ctx: &RuleContext<'a>) -> impl Iterator<Item = &'a Event> {
    ctx.record.events.iter().filter(|e| {
        e.kind == EventKind::ToolCallRequested && ctx.policy.is_privileged(tool_name(e))
    })
}

pub struct TrustBoundaryRule;

impl Rule for TrustBoundaryRule {
    fn id(&self) -> &'static str {
        "AT-002"
    }
    fn version(&self) -> u32 {
        4
    }
    fn title(&self) -> &'static str {
        "Privileged tool request caused by lower-trust content"
    }
    fn evaluate(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        let causes = ctx
            .index
            .nearest_causes(|e| e.trust_level == TrustLevel::LowerTrust);
        for request in privileged_requests(ctx) {
            let tool = tool_name(request);
            let Some(path) = causes.path(request.event_id, None) else {
                continue;
            };
            let source = path[0];
            let (status, outcome_ids) = tool_outcome(ctx, request);
            let (confidence, link_note) = link_strength(request);
            let mut evidence: Vec<_> = path.iter().map(|e| e.event_id).collect();
            evidence.extend(outcome_ids.iter().copied());
            out.push(
                FindingDraft {
                    title: self.title().to_owned(),
                    description: format!(
                        "Privileged tool `{tool}` was requested at event #{} with an explicit causal \
                         path back to lower-trust event #{} ({}, origin {}). This marks a trust-boundary \
                         crossing. {}{link_note}",
                        request.sequence,
                        source.sequence,
                        source.kind.as_str(),
                        source.origin.as_str(),
                        outcome_text(ctx, status, &outcome_ids),
                    ),
                    severity: Severity::High,
                    confidence,
                    evidence,
                    status,
                    remediation: "Require human approval or a stricter policy for privileged tools \
                                  whose request is derived from untrusted content.",
                }
                .build(self, ctx),
            );
        }
        out
    }
}

/// AT-006: untrusted content crossed an agent boundary and led to a privileged request.
pub struct CrossAgentTaintRule;

impl Rule for CrossAgentTaintRule {
    fn id(&self) -> &'static str {
        "AT-006"
    }
    fn version(&self) -> u32 {
        3
    }
    fn title(&self) -> &'static str {
        "Untrusted content crossed an agent boundary into a privileged action"
    }
    fn evaluate(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        // Trace back to the *original* untrusted content (a tool result, document or model
        // output) observed by another agent, not just the relayed message.
        let causes = ctx.index.nearest_causes(|e| {
            e.trust_level == TrustLevel::LowerTrust && e.kind.carries_content()
        });
        for request in privileged_requests(ctx) {
            let agent = request.agent();
            let Some(path) = causes.path(request.event_id, Some(agent)) else {
                continue;
            };
            let source = path[0];
            let (status, outcome_ids) = tool_outcome(ctx, request);
            let (confidence, link_note) = link_strength(request);
            let mut evidence: Vec<_> = path.iter().map(|e| e.event_id).collect();
            evidence.extend(outcome_ids.iter().copied());
            let hops: Vec<String> = path.iter().fold(Vec::<String>::new(), |mut acc, e| {
                if acc.last().map(String::as_str) != Some(e.agent()) {
                    acc.push(e.agent().to_owned());
                }
                acc
            });
            out.push(
                FindingDraft {
                    title: self.title().to_owned(),
                    description: format!(
                        "Agent `{agent}` requested privileged tool `{}` at event #{}. The request has \
                         an explicit causal path to lower-trust content observed by agent `{}` at \
                         event #{} ({}). Agent path: {}. Taint propagated across agents. {}{link_note}",
                        tool_name(request),
                        request.sequence,
                        source.agent(),
                        source.sequence,
                        source.kind.as_str(),
                        hops.join(" → "),
                        outcome_text(ctx, status, &outcome_ids),
                    ),
                    severity: Severity::High,
                    confidence,
                    evidence,
                    status,
                    remediation: "Treat messages from other agents as untrusted when they are derived \
                                  from untrusted content; propagate trust labels across delegation \
                                  and require approval for privileged follow-up actions.",
                }
                .build(self, ctx),
            );
        }
        out
    }
}
