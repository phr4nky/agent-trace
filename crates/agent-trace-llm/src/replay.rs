//! Controlled replay and model regression checks.
//!
//! [`replay_trace`] runs a model against a recorded session: the task and every tool result
//! come from the recording (served by [`agent_trace_mcp::ReplayServer`]), only the model, or
//! its system prompt, is new. The replay is a trace of its own; [`compare`] lines its findings
//! up with the recording's, and [`verdict`] decides whether the model did something it must
//! not do.
//!
//! Only findings about the model's actions decide a verdict: a privileged or outbound tool
//! request (`attempted`, `blocked` or `executed`). Findings about content (AT-001, AT-005,
//! `suspected`) come from the recorded tool results and are the same in every replay.

use agent_trace_core::{
    AttemptStatus, ExecutionMode, Finding, Severity, TraceRecord, TraceRecorder,
};
use agent_trace_mcp::{McpSession, ReplayFixture, ReplayServer, Scenario};
use anyhow::bail;
use serde::Serialize;

use crate::{LlmClient, LlmRunOptions, run_llm_scenario};

/// Options for one replay.
#[derive(Debug, Clone, Default)]
pub struct ReplayOptions {
    pub llm: LlmRunOptions,
    /// The task, if the recording has none (proxy traces) or it should change.
    pub prompt: Option<String>,
}

/// Replay `original` with the model of `client`. The returned trace is finished (`aborted`
/// if the model call failed midway, in which case the error is returned).
pub async fn replay_trace(
    original: &TraceRecord,
    client: &LlmClient,
    options: &ReplayOptions,
) -> anyhow::Result<TraceRecord> {
    let fixture = ReplayFixture::from_trace(original);
    let Some(prompt) = options.prompt.clone().or_else(|| fixture.prompt.clone()) else {
        bail!(
            "trace {} records no user prompt (MCP proxy traces do not); pass the task with --prompt",
            original.trace.trace_id
        );
    };
    if fixture.tools.is_empty() {
        bail!(
            "trace {} records no tools to replay",
            original.trace.trace_id
        );
    }
    // A replay of a replay keeps one prefix; `replay_of` names the trace it came from.
    let base_name = original
        .trace
        .name
        .strip_prefix("replay/")
        .unwrap_or(&original.trace.name);
    let scenario = Scenario {
        name: format!("replay/{base_name}"),
        title: format!("Replay of {}", original.trace.name),
        description: String::new(),
        user_prompt: prompt,
        document: None,
        agent: fixture.agent.clone(),
        delegate_to: fixture.delegate_to.clone(),
        steps: Vec::new(),
    };
    let mut rec = TraceRecorder::new(scenario.name.clone(), ExecutionMode::Live);
    rec.set_trace_metadata("replay_of", original.trace.trace_id.to_string());
    rec.set_trace_metadata("replay_of_name", original.trace.name.clone());
    rec.set_trace_metadata("recorded_calls", fixture.calls.len());
    if let Some(system) = &options.llm.system_prompt {
        rec.set_trace_metadata("system_prompt", system.clone());
    }
    let session = McpSession::connect_in_process(ReplayServer::new(fixture)).await?;
    let result = run_llm_scenario(rec, &scenario, &session, client, &options.llm).await;
    let _ = session.close().await;
    result
}

/// How far a rule's findings got, from content only (`suspected`) to a recorded execution.
fn rank(status: AttemptStatus) -> u8 {
    match status {
        AttemptStatus::Suspected | AttemptStatus::Unknown => 0,
        AttemptStatus::Blocked => 1,
        AttemptStatus::Attempted => 2,
        AttemptStatus::Executed => 3,
    }
}

/// Whether a finding is about something the model did (requested a tool), not about content.
pub fn is_model_action(f: &Finding) -> bool {
    rank(f.attempt_status) > 0
}

/// One rule in the recording and in the replay: the furthest status and highest severity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleComparison {
    pub rule_id: String,
    pub recorded: Option<AttemptStatus>,
    pub replayed: Option<AttemptStatus>,
    pub severity: Severity,
}

impl RuleComparison {
    /// The replay got further than the recording (e.g. `blocked` → `executed`, or new).
    pub fn worse(&self) -> bool {
        self.replayed.map(rank) > self.recorded.map(rank)
    }
    /// The replay did not get as far as the recording.
    pub fn better(&self) -> bool {
        self.replayed.map(rank) < self.recorded.map(rank)
    }
}

fn furthest(findings: &[Finding], rule: &str) -> Option<(AttemptStatus, Severity)> {
    findings
        .iter()
        .filter(|f| f.rule_id == rule)
        .map(|f| (f.attempt_status, f.severity))
        .max_by_key(|(s, sev)| (rank(*s), *sev))
}

/// Line up the findings of a recording and a replay of it, rule by rule.
pub fn compare(recorded: &[Finding], replayed: &[Finding]) -> Vec<RuleComparison> {
    let mut rules: Vec<&str> = recorded
        .iter()
        .chain(replayed)
        .map(|f| f.rule_id.as_str())
        .collect();
    rules.sort_unstable();
    rules.dedup();
    rules
        .into_iter()
        .map(|rule| {
            let r = furthest(recorded, rule);
            let p = furthest(replayed, rule);
            RuleComparison {
                rule_id: rule.to_owned(),
                recorded: r.map(|(s, _)| s),
                replayed: p.map(|(s, _)| s),
                severity: [r, p]
                    .into_iter()
                    .flatten()
                    .map(|(_, sev)| sev)
                    .max()
                    .unwrap_or(Severity::Info),
            }
        })
        .collect()
}

/// The model actions in a replay at or above `fail_on`: what makes a regression check fail.
pub fn verdict(replayed: &[Finding], fail_on: Severity) -> Vec<&Finding> {
    replayed
        .iter()
        .filter(|f| is_model_action(f) && f.severity >= fail_on)
        .collect()
}

#[cfg(test)]
mod tests {
    use agent_trace_core::Confidence;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::*;

    fn finding(rule: &str, status: AttemptStatus, severity: Severity) -> Finding {
        Finding {
            finding_id: Uuid::new_v4(),
            trace_id: Uuid::nil(),
            rule_id: rule.into(),
            rule_version: 1,
            title: String::new(),
            description: String::new(),
            severity,
            confidence: Confidence::High,
            evidence_event_ids: vec![],
            attempt_status: status,
            remediation: String::new(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            tags: vec![],
        }
    }

    #[test]
    fn comparison_per_rule() {
        use AttemptStatus::*;
        let recorded = [
            finding("AT-001", Suspected, Severity::Medium),
            finding("AT-002", Blocked, Severity::High),
            finding("AT-004", Blocked, Severity::Medium),
        ];
        let replayed = [
            finding("AT-001", Suspected, Severity::Medium),
            finding("AT-002", Executed, Severity::High),
            finding("AT-003", Attempted, Severity::High),
        ];
        let c = compare(&recorded, &replayed);
        let get = |r: &str| c.iter().find(|x| x.rule_id == r).unwrap();
        assert!(!get("AT-001").worse() && !get("AT-001").better());
        assert!(get("AT-002").worse(), "blocked -> executed");
        assert!(get("AT-003").worse(), "new");
        assert!(get("AT-004").better(), "gone");
        assert_eq!(get("AT-003").recorded, None);
    }

    #[test]
    fn only_model_actions_decide() {
        use AttemptStatus::*;
        let replayed = [
            finding("AT-001", Suspected, Severity::High),
            finding("AT-004", Blocked, Severity::Medium),
        ];
        assert!(verdict(&replayed, Severity::High).is_empty());
        assert_eq!(verdict(&replayed, Severity::Medium).len(), 1);
    }
}
