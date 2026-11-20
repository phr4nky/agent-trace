//! AT-008: the definition of an MCP tool changed after it was pinned (rug pull), or a tool
//! appeared on a server whose tools were pinned.
//!
//! The MCP proxy compares every `tools/list` answer with the pins of the server and records
//! a change event: metadata [`TOOL_PINS_KEY`] = [`TOOL_PINS_CHANGED`], the changed and added
//! tool names under [`TOOL_PINS_CHANGED_KEY`] / [`TOOL_PINS_ADDED_KEY`], the proxy name under
//! `proxy`, and what the proxy did under [`TOOL_PINS_ACTION_KEY`].

use serde_json::Value;

use super::{FindingDraft, Rule, RuleContext, tool_name, tool_outcome};
use crate::event::{Event, EventKind};
use crate::finding::{AttemptStatus, Confidence, Finding, Severity};

/// Event metadata key marking a tool pin check result.
pub const TOOL_PINS_KEY: &str = "tool_pins";
/// Value of [`TOOL_PINS_KEY`] on an event that records changed or added tools.
pub const TOOL_PINS_CHANGED: &str = "changed";
/// Names of tools whose definitions differ from their pins.
pub const TOOL_PINS_CHANGED_KEY: &str = "tool_pins_changed";
/// Names of tools that were not pinned before.
pub const TOOL_PINS_ADDED_KEY: &str = "tool_pins_added";
/// What the proxy did: [`TOOL_PINS_ACTION_BLOCKED`] (enforce) or [`TOOL_PINS_ACTION_OBSERVED`].
pub const TOOL_PINS_ACTION_KEY: &str = "tool_pins_action";
pub const TOOL_PINS_ACTION_BLOCKED: &str = "hidden_and_denied";
pub const TOOL_PINS_ACTION_OBSERVED: &str = "observed";

fn names<'a>(event: &'a Event, key: &str) -> Vec<&'a str> {
    let mut names: Vec<&str> = event
        .metadata
        .get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    names.sort_unstable();
    names.dedup();
    names
}

fn proxy_of(event: &Event) -> Option<&str> {
    event.metadata.get("proxy").and_then(Value::as_str)
}

fn listed(names: &[&str]) -> String {
    const SHOWN: usize = 5;
    let mut s = names
        .iter()
        .take(SHOWN)
        .map(|n| format!("`{n}`"))
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > SHOWN {
        s.push_str(&format!(" and {} more", names.len() - SHOWN));
    }
    s
}

/// AT-008: tool definition changed since it was pinned, or a new tool appeared.
pub struct ToolPinRule;

impl Rule for ToolPinRule {
    fn id(&self) -> &'static str {
        "AT-008"
    }
    fn version(&self) -> u32 {
        1
    }
    fn title(&self) -> &'static str {
        "MCP tool definition changed since it was pinned"
    }
    fn description(&self) -> &'static str {
        "An MCP server announced a tool whose description or schema differs from the definition pinned when the tool was first seen (a possible rug pull or tool poisoning), or a new tool on a server whose tools were pinned."
    }
    fn default_severity(&self) -> Severity {
        Severity::High
    }
    fn evaluate(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for change in ctx.record.events.iter().filter(|e| {
            e.metadata.get(TOOL_PINS_KEY).and_then(Value::as_str) == Some(TOOL_PINS_CHANGED)
        }) {
            let changed = names(change, TOOL_PINS_CHANGED_KEY);
            let added = names(change, TOOL_PINS_ADDED_KEY);
            if changed.is_empty() && added.is_empty() {
                continue;
            }
            let proxy = proxy_of(change);
            let server = proxy.map(|p| format!(" `{p}`")).unwrap_or_default();
            let blocked_by_proxy = change
                .metadata
                .get(TOOL_PINS_ACTION_KEY)
                .and_then(Value::as_str)
                == Some(TOOL_PINS_ACTION_BLOCKED);

            if changed.is_empty() {
                out.push(
                    FindingDraft {
                        title: "New tool on a pinned MCP server".to_owned(),
                        description: format!(
                            "MCP server{server} announced {} tool(s) that were not there when its \
                             tools were pinned: {} (event #{}). They were pinned now. A tool \
                             added later can shadow or poison others; check its description.",
                            added.len(),
                            listed(&added),
                            change.sequence
                        ),
                        severity: Severity::Low,
                        confidence: Confidence::High,
                        evidence: vec![change.event_id],
                        status: AttemptStatus::Suspected,
                        remediation: "Review the new tool's description and schema. Remove the \
                                      server if you did not expect the change.",
                    }
                    .build(self, ctx),
                );
                continue;
            }

            // Calls of a changed tool on the same server after the change was seen.
            let calls: Vec<&Event> = ctx
                .record
                .events
                .iter()
                .filter(|e| {
                    e.kind == EventKind::ToolCallRequested
                        && e.sequence > change.sequence
                        && changed.contains(&tool_name(e))
                        && (proxy.is_none() || proxy_of(e) == proxy)
                })
                .collect();
            let mut evidence = vec![change.event_id];
            let mut statuses = Vec::new();
            for call in &calls {
                let (status, ids) = tool_outcome(ctx, call);
                evidence.push(call.event_id);
                evidence.extend(ids);
                statuses.push(status);
            }
            let status = if statuses.contains(&AttemptStatus::Executed) {
                AttemptStatus::Executed
            } else if blocked_by_proxy || statuses.contains(&AttemptStatus::Blocked) {
                AttemptStatus::Blocked
            } else if !statuses.is_empty() {
                AttemptStatus::Attempted
            } else {
                AttemptStatus::Suspected
            };
            let what = match status {
                AttemptStatus::Executed => format!(
                    "A changed tool was called and an execution was recorded ({} call(s)).",
                    calls.len()
                ),
                AttemptStatus::Blocked if blocked_by_proxy => "The proxy hid the changed tools \
                    from the client and denies their calls (enforce mode)."
                    .to_owned(),
                AttemptStatus::Blocked => "Calls of the changed tools were blocked.".to_owned(),
                AttemptStatus::Attempted => {
                    "A changed tool was requested; no execution was recorded.".to_owned()
                }
                _ => "The changed definitions reached the client (observe mode): a poisoned \
                      description acts when the model reads it, even before any call."
                    .to_owned(),
            };
            let added_text = if added.is_empty() {
                String::new()
            } else {
                format!(" New tool(s): {}.", listed(&added))
            };
            out.push(
                FindingDraft {
                    title: self.title().to_owned(),
                    description: format!(
                        "MCP server{server} changed the definition of {} pinned tool(s) at event \
                         #{}: {}. Their descriptions or schemas differ from what was pinned when \
                         they were first seen.{added_text} {what}",
                        changed.len(),
                        change.sequence,
                        listed(&changed)
                    ),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    evidence,
                    status,
                    remediation: "Compare the pinned and current descriptions in the change event. \
                                  If the change is expected (a server update), accept it with \
                                  `agent-trace pins reset <server> --tool <tool>`; otherwise \
                                  remove the server. Run the proxy in enforce mode to keep \
                                  changed tools away from the model.",
                }
                .build(self, ctx),
            );
        }
        out
    }
}
