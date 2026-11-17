//! AT-003 (potential exfiltration attempt) and AT-004 (action blocked by policy).

use serde_json::Value;

use super::{FindingDraft, Rule, RuleContext, is_denial, tool_name, tool_outcome};
use crate::event::EventKind;
use crate::finding::{AttemptStatus, Confidence, Finding, Severity};
use crate::policy::host_of;

/// AT-003: outbound request to a non-allowlisted destination while handling sensitive data.
pub struct ExfiltrationRule;

impl Rule for ExfiltrationRule {
    fn id(&self) -> &'static str {
        "AT-003"
    }
    fn version(&self) -> u32 {
        3
    }
    fn title(&self) -> &'static str {
        "Potential exfiltration attempt to non-allowlisted destination"
    }
    fn evaluate(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        let sensitive_causes = ctx.index.sensitive_causes();
        for request in ctx
            .record
            .events
            .iter()
            .filter(|e| e.kind == EventKind::ToolCallRequested)
        {
            let tool = tool_name(request);
            if !ctx.policy.is_outbound(tool) {
                continue;
            }
            let args = request
                .payload
                .get("arguments")
                .unwrap_or(&request.payload)
                .as_object()
                .cloned()
                .unwrap_or_default();
            let Some(destination) = ctx.policy.disallowed_destination(&args) else {
                continue;
            };
            let destination = destination.as_str();
            let (mut sensitive, more) = sensitive_causes
                .get(&request.event_id)
                .cloned()
                .unwrap_or_default();
            if request.is_sensitive() {
                sensitive.push(request);
            }
            sensitive.sort_by_key(|e| e.sequence);
            if sensitive.is_empty() {
                continue;
            }
            let (status, outcome_ids) = tool_outcome(ctx, request);
            let mut evidence: Vec<_> = sensitive.iter().map(|e| e.event_id).collect();
            evidence.push(request.event_id);
            evidence.extend(outcome_ids);
            let host = host_of(destination).unwrap_or_else(|| "<none>".into());
            let outcome_text = match status {
                AttemptStatus::Blocked => {
                    "The transmission was BLOCKED by policy; the trace records no outbound request."
                }
                AttemptStatus::Executed => {
                    "An execution event was recorded; check the tool result before assuming any data left the system."
                }
                _ => "No outcome was recorded; this is an attempt, not a confirmed transfer.",
            };
            out.push(
                FindingDraft {
                    title: self.title().to_owned(),
                    description: format!(
                        "Outbound tool `{tool}` requested destination host `{host}` (not allowlisted) \
                         at event #{} while the causal chain contains data marked sensitive \
                         (redacted values in {}{} event(s)). {outcome_text}",
                        request.sequence,
                        sensitive.len(),
                        if more { "+" } else { "" }
                    ),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    evidence,
                    status,
                    remediation: "Keep outbound tools behind a destination allowlist and never let \
                                  untrusted content choose a destination or payload.",
                }
                .build(self, ctx),
            );
        }
        out
    }
}

/// AT-004: a tool operation was denied by policy.
pub struct BlockedActionRule;

impl Rule for BlockedActionRule {
    fn id(&self) -> &'static str {
        "AT-004"
    }
    fn version(&self) -> u32 {
        2
    }
    fn title(&self) -> &'static str {
        "Risky tool action blocked by policy"
    }
    fn evaluate(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        ctx.record
            .events
            .iter()
            .filter(|e| is_denial(e))
            .map(|decision| {
                let request = decision
                    .parent_event_id
                    .or(decision.caused_by_event_id)
                    .and_then(|id| ctx.index.get(id));
                let mut evidence = Vec::new();
                if let Some(r) = request {
                    evidence.push(r.event_id);
                }
                evidence.push(decision.event_id);
                let tool = request.map(tool_name).unwrap_or(&decision.name);
                let reason = decision
                    .payload
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("no reason recorded");
                // The outcome comes from the recorded lifecycle: an execution recorded after
                // the denial means the decision was not enforced.
                let executed = request
                    .map(|r| tool_outcome(ctx, r))
                    .filter(|(status, _)| *status == AttemptStatus::Executed);
                let (description, severity, status, remediation) = match executed {
                    Some((_, outcome_ids)) => {
                        evidence.extend(outcome_ids);
                        (
                            format!(
                                "Policy denied `{tool}` at event #{}: {reason}. An execution of the \
                                 same request was recorded afterwards, so the denial was not enforced.",
                                decision.sequence
                            ),
                            Severity::High,
                            AttemptStatus::Executed,
                            "Check why the action ran despite the policy decision (audit-only or \
                             fail-open gate) and enforce denials before execution.",
                        )
                    }
                    None => (
                        format!(
                            "Policy denied `{tool}` at event #{}: {reason}. The action was not executed.",
                            decision.sequence
                        ),
                        Severity::Medium,
                        AttemptStatus::Blocked,
                        "Investigate why the agent attempted this action; the policy \
                         worked as intended.",
                    ),
                };
                FindingDraft {
                    title: self.title().to_owned(),
                    description,
                    severity,
                    confidence: Confidence::High,
                    evidence,
                    status,
                    remediation,
                }
                .build(self, ctx)
            })
            .collect()
    }
}
