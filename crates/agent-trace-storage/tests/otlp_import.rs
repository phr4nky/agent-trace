//! OTLP/JSON (GenAI semantic conventions) → agent-trace, with the example file.

use agent_trace_core::{Analyzer, AttemptStatus, EventKind, TrustLevel};
use agent_trace_storage::otlp::read_otlp;

fn example() -> Vec<agent_trace_storage::otlp::OtlpTrace> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/otlp/agent-injection.otlp.jsonl"
    );
    read_otlp(std::fs::File::open(path).unwrap()).unwrap()
}

fn findings(t: &agent_trace_storage::otlp::OtlpTrace) -> Vec<agent_trace_core::Finding> {
    Analyzer::default().analyze(&t.record, t.record.trace.created_at)
}

fn by_service<'a>(
    traces: &'a [agent_trace_storage::otlp::OtlpTrace],
    otel_id: &str,
) -> &'a agent_trace_storage::otlp::OtlpTrace {
    traces
        .iter()
        .find(|t| t.record.trace.metadata["otel_trace_id"] == otel_id)
        .unwrap()
}

#[test]
fn single_agent_with_content_links_injection_to_shell() {
    let traces = example();
    assert_eq!(traces.len(), 3);
    let t = by_service(&traces, "5b8efff798038103d269b633813fc60c");
    assert!(t.content_captured);
    assert_eq!(t.ignored_spans, 1, "the HTTP span");
    assert_eq!(t.record.trace.name, "otel/issue-bot/invoke_agent assistant");
    assert_eq!(t.record.trace.metadata["otel_mapping"], "otel-genai/1");
    let events = &t.record.events;
    let kinds: Vec<EventKind> = events.iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds
            .iter()
            .filter(|k| **k == EventKind::ToolCallRequested)
            .count(),
        2,
        "MCP child span merged"
    );
    assert!(kinds.contains(&EventKind::UserPromptReceived));
    let result = events
        .iter()
        .find(|e| e.kind == EventKind::ToolResultReceived && e.name == "fetch_issue")
        .unwrap();
    assert_eq!(result.trust_level, TrustLevel::LowerTrust);
    assert_eq!(result.origin, agent_trace_core::Origin::McpTool);
    // Timestamps come from the spans, not the import.
    assert_eq!(t.record.trace.created_at.year(), 2026);
    // The shell request is caused by the model response that asked for call_2.
    let shell = events
        .iter()
        .find(|e| e.kind == EventKind::ToolCallRequested && e.name == "shell")
        .unwrap();
    let cause = events
        .iter()
        .find(|e| Some(e.event_id) == shell.caused_by_event_id)
        .unwrap();
    assert_eq!(cause.kind, EventKind::ModelResponse);

    let f = findings(t);
    let rule = |id: &str| f.iter().find(|x| x.rule_id == id);
    assert!(rule("AT-001").is_some(), "the injected issue text");
    let at002 = rule("AT-002").expect("shell after the injected issue");
    assert_eq!(at002.attempt_status, AttemptStatus::Executed);
}

#[test]
fn without_content_capture_nothing_is_linked() {
    let traces = example();
    let t = by_service(&traces, "0af7651916cd43dd8448eb211c80319c");
    assert!(!t.content_captured);
    assert_eq!(t.record.trace.metadata["content_captured"], false);
    let f = findings(t);
    assert!(
        !f.iter().any(|x| x.rule_id == "AT-002"),
        "no causal links are invented from timing: {f:?}"
    );
    // The tool calls are still recorded.
    assert!(
        t.record
            .events
            .iter()
            .any(|e| e.kind == EventKind::ToolCallExecuted && e.name == "shell")
    );
}

#[test]
fn agent_as_tool_carries_taint_across_agents() {
    let traces = example();
    let t = by_service(&traces, "4bf92f3577b34da6a3ce929d0e0e4736");
    let events = &t.record.events;
    assert!(events.iter().any(|e| e.kind == EventKind::AgentDelegated));
    let fetched = events
        .iter()
        .find(|e| e.kind == EventKind::ToolResultReceived && e.name == "web_fetch")
        .unwrap();
    assert_eq!(fetched.agent_id.as_deref(), Some("researcher"));
    let report = events
        .iter()
        .find(|e| e.kind == EventKind::AgentMessageSent)
        .unwrap();
    assert_eq!(
        report.trust_level,
        TrustLevel::LowerTrust,
        "the researcher saw the page"
    );
    let f = findings(t);
    let at006 = f
        .iter()
        .find(|x| x.rule_id == "AT-006")
        .expect("cross-agent taint");
    assert_eq!(at006.attempt_status, AttemptStatus::Executed);
    assert!(
        at006.description.contains("researcher"),
        "{}",
        at006.description
    );
}

#[test]
fn malformed_input_is_rejected() {
    for (input, expected) in [
        ("{}", "resourceSpans"),
        ("not json\n", "line 1"),
        (
            "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":[{\"traceId\":\"zz\",\"spanId\":\"01\"}]}]}]}",
            "hex",
        ),
        ("{\"resourceSpans\":[]}", "no spans"),
    ] {
        let e = read_otlp(input.as_bytes()).unwrap_err().to_string();
        assert!(e.contains(expected), "{expected}: {e}");
    }
}

#[test]
fn hostile_parent_cycles_terminate() {
    let span = |id: &str, parent: &str| {
        format!(
            "{{\"traceId\":\"aa\",\"spanId\":\"{id}\",\"parentSpanId\":\"{parent}\",\"name\":\"x\",\
             \"startTimeUnixNano\":\"1\",\"endTimeUnixNano\":\"2\",\"attributes\":[{{\"key\":\"gen_ai.operation.name\",\"value\":{{\"stringValue\":\"execute_tool\"}}}}]}}"
        )
    };
    let input = format!(
        "{{\"resourceSpans\":[{{\"scopeSpans\":[{{\"spans\":[{},{}]}}]}}]}}",
        span("01", "02"),
        span("02", "01")
    );
    // Must return (either way) instead of looping.
    let _ = read_otlp(input.as_bytes());
}

/// Every recorded cause is backed by the data: a tool call ID in the messages, the
/// tool-call lifecycle, a delegation or report, or the prompt. Nothing links "the previous
/// event" by time.
#[test]
fn every_cause_comes_from_the_data() {
    for t in example() {
        let events = &t.record.events;
        for e in events {
            let Some(cause) = e.caused_by_event_id else {
                continue;
            };
            let c = events.iter().find(|x| x.event_id == cause).unwrap();
            let explained = match e.kind {
                // The model response that asked for this call (gen_ai.tool.call.id).
                EventKind::ToolCallRequested => c.kind == EventKind::ModelResponse,
                // The prompt or a tool response named in the input messages.
                EventKind::ModelRequest => {
                    matches!(
                        c.kind,
                        EventKind::UserPromptReceived | EventKind::ToolResultReceived
                    )
                }
                EventKind::ModelResponse => c.kind == EventKind::ModelRequest,
                EventKind::ToolCallExecuted => c.kind == EventKind::ToolCallRequested,
                // Its own execution, or the report of the agent the tool ran.
                EventKind::ToolResultReceived => {
                    matches!(
                        c.kind,
                        EventKind::ToolCallExecuted | EventKind::AgentMessageReceived
                    )
                }
                EventKind::ToolCallCompleted | EventKind::ToolCallFailed => {
                    c.kind == EventKind::ToolResultReceived
                }
                EventKind::AgentDelegated => c.kind == EventKind::ToolCallRequested,
                EventKind::AgentStarted => c.kind == EventKind::AgentDelegated,
                EventKind::AgentMessageReceived | EventKind::AgentCompleted => {
                    c.kind == EventKind::AgentMessageSent
                }
                _ => false,
            };
            assert!(
                explained,
                "#{} {:?} caused by #{} {:?}",
                e.sequence, e.kind, c.sequence, c.kind
            );
        }
    }
}
