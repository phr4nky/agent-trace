//! AT-007: a canary token (decoy secret) in the arguments of a tool call.

use std::collections::HashMap;

use super::{FindingDraft, Rule, RuleContext, outcome_text, tool_name, tool_outcome};
use crate::canary;
use crate::event::{Event, EventKind};
use crate::finding::{AttemptStatus, Confidence, Finding, Severity};

/// AT-007: a tool call carried a canary token. Canaries are decoys no legitimate task uses,
/// so this is evidence of a leak attempt, not an indicator.
pub struct CanaryLeakRule;

impl Rule for CanaryLeakRule {
    fn id(&self) -> &'static str {
        "AT-007"
    }
    fn version(&self) -> u32 {
        1
    }
    fn title(&self) -> &'static str {
        "Canary token in a tool call"
    }
    fn description(&self) -> &'static str {
        "A tool call carried a canary token (a configured decoy secret) in its arguments. No legitimate task uses a canary, so the agent was moving a secret: evidence of a leak attempt."
    }
    fn default_severity(&self) -> Severity {
        Severity::Critical
    }
    fn evaluate(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        // Where each canary entered the trace first (events are in sequence order).
        let mut first_seen: HashMap<&str, &Event> = HashMap::new();
        for event in &ctx.record.events {
            for name in canary::stored(event) {
                first_seen.entry(name).or_insert(event);
            }
        }
        if first_seen.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        for request in ctx
            .record
            .events
            .iter()
            .filter(|e| e.kind == EventKind::ToolCallRequested)
        {
            let names = canary::stored(request);
            if names.is_empty() {
                continue;
            }
            let tool = tool_name(request);
            let mut sources: Vec<&Event> = names
                .iter()
                .filter_map(|n| first_seen.get(n).copied())
                .filter(|e| e.event_id != request.event_id)
                .collect();
            sources.sort_by_key(|e| e.sequence);
            sources.dedup_by_key(|e| e.event_id);
            let (status, outcome_ids) = tool_outcome(ctx, request);
            let mut evidence: Vec<_> = sources.iter().map(|e| e.event_id).collect();
            evidence.push(request.event_id);
            evidence.extend(outcome_ids.iter().copied());

            let listed = names
                .iter()
                .map(|n| format!("`{n}`"))
                .collect::<Vec<_>>()
                .join(", ");
            let plural = if names.len() > 1 { "s" } else { "" };
            let origin = if sources.is_empty() {
                " It does not appear in any earlier event of the trace.".to_owned()
            } else {
                format!(
                    " It entered the trace at {}.",
                    sources
                        .iter()
                        .map(|e| format!("event #{} (`{}`)", e.sequence, e.name))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            let outbound = if ctx.policy.is_outbound(tool) {
                " The tool is outbound."
            } else {
                ""
            };
            out.push(
                FindingDraft {
                    title: self.title().to_owned(),
                    description: format!(
                        "Tool `{tool}` was requested at event #{} with canary token{plural} \
                         {listed} in its arguments.{origin}{outbound} Canaries are decoys that no \
                         legitimate task uses, so the agent was moving a secret it read. {}",
                        request.sequence,
                        outcome_text(ctx, status, &outcome_ids)
                    ),
                    // A blocked attempt proves the agent was steered, but nothing left.
                    severity: if status == AttemptStatus::Blocked {
                        Severity::High
                    } else {
                        Severity::Critical
                    },
                    confidence: Confidence::High,
                    evidence,
                    status,
                    remediation: "Follow the evidence path to the content that steered the agent. \
                                  Treat every real secret the agent could read in this session \
                                  as exposed and rotate it. Run the proxy or hooks in enforce \
                                  mode, which deny tool calls that carry a canary.",
                }
                .build(self, ctx),
            );
        }
        out
    }
}
