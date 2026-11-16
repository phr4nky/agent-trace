//! AT-002: privileged tool request with an explicit causal path from lower-trust content.
//! AT-006: the same, where the lower-trust content entered through a *different agent*.

use super::{FindingDraft, Rule, RuleContext, outcome_text, tool_name, tool_outcome};
use crate::event::{Event, EventKind, TrustLevel};
use crate::finding::{Confidence, Finding, Severity};

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
        2
    }
    fn title(&self) -> &'static str {
        "Privileged tool request caused by lower-trust content"
    }
    fn evaluate(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for request in privileged_requests(ctx) {
            let tool = tool_name(request);
            let Some(path) = ctx.index.cause_path(request.event_id, |e| {
                e.trust_level == TrustLevel::LowerTrust
            }) else {
                continue;
            };
            let source = path[0];
            let (status, outcome_ids) = tool_outcome(ctx, request);
            let mut evidence: Vec<_> = path.iter().map(|e| e.event_id).collect();
            evidence.extend(outcome_ids.iter().copied());
            out.push(
                FindingDraft {
                    title: self.title().to_owned(),
                    description: format!(
                        "Privileged tool `{tool}` was requested at event #{} with an explicit causal \
                         path back to lower-trust event #{} ({}, origin {}). This marks a trust-boundary \
                         crossing. {}",
                        request.sequence,
                        source.sequence,
                        source.kind.as_str(),
                        source.origin.as_str(),
                        outcome_text(ctx, status, &outcome_ids),
                    ),
                    severity: Severity::High,
                    confidence: Confidence::High,
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
        1
    }
    fn title(&self) -> &'static str {
        "Untrusted content crossed an agent boundary into a privileged action"
    }
    fn evaluate(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for request in privileged_requests(ctx) {
            let agent = request.agent();
            // Trace back to the *original* untrusted content (a tool result, document or model
            // output) observed by another agent, not just the relayed message.
            let Some(path) = ctx.index.cause_path(request.event_id, |e| {
                e.trust_level == TrustLevel::LowerTrust
                    && e.agent() != agent
                    && e.kind.carries_content()
            }) else {
                continue;
            };
            let source = path[0];
            let (status, outcome_ids) = tool_outcome(ctx, request);
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
                         event #{} ({}). Agent path: {}. Taint propagated across agents. {}",
                        tool_name(request),
                        request.sequence,
                        source.agent(),
                        source.sequence,
                        source.kind.as_str(),
                        hops.join(" → "),
                        outcome_text(ctx, status, &outcome_ids),
                    ),
                    severity: Severity::High,
                    confidence: Confidence::High,
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
