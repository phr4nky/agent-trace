//! Import OpenTelemetry traces (OTLP JSON) of AI agents, mapped from the GenAI semantic
//! conventions onto agent-trace events.
//!
//! Input: an OTLP/JSON `ExportTraceServiceRequest` (`{"resourceSpans": [...]}`), or the
//! newline-delimited form the OpenTelemetry Collector's `file` exporter writes (one request per
//! line). Every OTel trace becomes one agent-trace trace.
//!
//! Mapping [`MAPPING_VERSION`] (GenAI conventions as released in semantic-conventions v1.41.0
//! and as of the semantic-conventions-genai repository, November 2026; status Development):
//!
//! | span (`gen_ai.operation.name`) | events |
//! |---|---|
//! | `invoke_agent`, `invoke_workflow`, `invoke_*` | `agent_started` … `agent_completed`; nested under another agent: `agent_delegated`, and the sub-agent's output as `agent_message_sent` / `agent_message_received` |
//! | `chat`, `generate_content`, `text_completion`, `realtime_inference` | the first user message as `user_prompt_received`; `model_request` at the start, `model_response` at the end |
//! | `execute_tool` (or an MCP `tools/call` span without one) | `tool_call_requested`, `tool_call_executed`, `tool_result_received` (lower-trust), `tool_call_completed` / `tool_call_failed` |
//!
//! Links are only taken from the data, never from timing: a tool request is caused by the model
//! response whose output messages contain its `gen_ai.tool.call.id`; a model request's context
//! is the tool results whose IDs appear in its input messages; a tool that runs an agent
//! (`invoke_agent` inside `execute_tool`) has the sub-agent's report as the cause of its result.
//! Message content is opt-in in OpenTelemetry (`OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT`);
//! without it the events are recorded but carry no links, and causal rules cannot fire.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;

use agent_trace_core::{
    EventKind, EventSpec, ExecutionMode, Origin, ToolState, TraceRecord, TraceRecorder, TrustLevel,
    validate,
};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::StorageError;
use crate::jsonl::MAX_IMPORT_BYTES;

/// Identifies the mapping in the trace metadata (`otel_mapping`).
pub const MAPPING_VERSION: &str = "otel-genai/1";
/// At most this many spans per file.
pub const MAX_SPANS: usize = 100_000;
const NAMESPACE: Uuid = Uuid::from_u128(0x3c1e_5f2a_8d47_4b90_a6e1_9f0c_7b24_d815);

/// One imported OTel trace.
#[derive(Debug)]
pub struct OtlpTrace {
    pub record: TraceRecord,
    /// Whether any message content (prompts, messages, tool arguments or results) was present.
    pub content_captured: bool,
    /// Spans that are not GenAI spans (HTTP, database, framework internals) and were skipped.
    pub ignored_spans: usize,
}

fn err(message: impl Into<String>) -> StorageError {
    StorageError::Import {
        line: 0,
        message: message.into(),
    }
}

/// An OTLP `AnyValue` as JSON.
fn any_value(v: &Value) -> Value {
    let Some(obj) = v.as_object() else {
        return Value::Null;
    };
    if let Some(s) = obj.get("stringValue") {
        return s.clone();
    }
    if let Some(b) = obj.get("boolValue") {
        return b.clone();
    }
    if let Some(i) = obj.get("intValue") {
        // int64 is a decimal string in OTLP/JSON; numbers are accepted too.
        return match i {
            Value::String(s) => s.parse::<i64>().map(Value::from).unwrap_or(Value::Null),
            other => other.clone(),
        };
    }
    if let Some(d) = obj.get("doubleValue") {
        return d.clone();
    }
    if let Some(a) = obj.get("arrayValue") {
        return Value::Array(
            a.get("values")
                .and_then(Value::as_array)
                .map(|vs| vs.iter().map(any_value).collect())
                .unwrap_or_default(),
        );
    }
    if let Some(kv) = obj.get("kvlistValue") {
        return Value::Object(attributes(kv.get("values")));
    }
    if let Some(b) = obj.get("bytesValue") {
        return b.clone();
    }
    Value::Null
}

fn attributes(list: Option<&Value>) -> Map<String, Value> {
    list.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|kv| {
            let key = kv.get("key")?.as_str()?.to_owned();
            Some((key, kv.get("value").map(any_value).unwrap_or(Value::Null)))
        })
        .collect()
}

fn nanos(v: Option<&Value>) -> Option<i128> {
    match v? {
        Value::String(s) => s.parse().ok(),
        Value::Number(n) => n.as_u64().map(i128::from),
        _ => None,
    }
}

#[derive(Debug, Clone)]
struct Span {
    trace_id: String,
    span_id: String,
    parent: Option<String>,
    name: String,
    start: i128,
    end: i128,
    attrs: Map<String, Value>,
    error: bool,
    service: Option<String>,
}

impl Span {
    fn str(&self, key: &str) -> Option<&str> {
        self.attrs.get(key).and_then(Value::as_str)
    }

    /// A structured attribute: an AnyValue array/map, or (semconv v1.41) its JSON as a string.
    fn structured(&self, key: &str) -> Option<Value> {
        match self.attrs.get(key)? {
            Value::String(s) => Some(serde_json::from_str(s).unwrap_or(Value::String(s.clone()))),
            Value::Null => None,
            other => Some(other.clone()),
        }
    }
}

fn hex_id(v: Option<&Value>) -> Option<String> {
    let s = v?.as_str()?.trim().to_ascii_lowercase();
    (!s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit()) && !s.chars().all(|c| c == '0'))
        .then_some(s)
}

fn collect_spans(request: &Value, spans: &mut Vec<Span>) -> Result<(), StorageError> {
    let resource_spans = request
        .get("resourceSpans")
        .and_then(Value::as_array)
        .ok_or_else(|| err("not an OTLP trace request: no \"resourceSpans\""))?;
    for rs in resource_spans {
        let resource = attributes(rs.get("resource").and_then(|r| r.get("attributes")));
        let service = resource
            .get("service.name")
            .and_then(Value::as_str)
            .map(str::to_owned);
        for ss in rs
            .get("scopeSpans")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            for s in ss
                .get("spans")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if spans.len() >= MAX_SPANS {
                    return Err(err(format!("more than {MAX_SPANS} spans")));
                }
                let (Some(trace_id), Some(span_id)) =
                    (hex_id(s.get("traceId")), hex_id(s.get("spanId")))
                else {
                    return Err(err("a span without a valid hex traceId/spanId"));
                };
                let start = nanos(s.get("startTimeUnixNano")).unwrap_or(0);
                spans.push(Span {
                    trace_id,
                    span_id,
                    parent: hex_id(s.get("parentSpanId")),
                    name: s
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned(),
                    start,
                    end: nanos(s.get("endTimeUnixNano")).unwrap_or(start).max(start),
                    attrs: attributes(s.get("attributes")),
                    error: s
                        .get("status")
                        .and_then(|st| st.get("code"))
                        .is_some_and(|c| c == 2 || c == "STATUS_CODE_ERROR"),
                    service: service.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Parse OTLP/JSON: one request, or one request per line.
pub fn read_otlp(input: impl Read) -> Result<Vec<OtlpTrace>, StorageError> {
    read_otlp_all([input])
}

/// Parse several OTLP/JSON files as one: spans are grouped by trace across all of them, so a
/// trace whose spans the Collector wrote to more than one file (rotation, an import while the
/// agent was still running) is mapped from all its spans. Each file has the size limit of
/// [`read_otlp`]; the span limit applies to all files together.
pub fn read_otlp_all<R: Read>(
    inputs: impl IntoIterator<Item = R>,
) -> Result<Vec<OtlpTrace>, StorageError> {
    let mut spans = Vec::new();
    for input in inputs {
        collect_file(input, &mut spans)?;
    }
    if spans.is_empty() {
        return Err(err("no spans found"));
    }
    let mut by_trace: BTreeMap<String, Vec<Span>> = BTreeMap::new();
    let mut seen = std::collections::HashSet::new();
    for s in spans {
        // A span in two inputs (overlapping files, a file passed twice) is mapped once.
        if seen.insert((s.trace_id.clone(), s.span_id.clone())) {
            by_trace.entry(s.trace_id.clone()).or_default().push(s);
        }
    }
    by_trace.into_values().map(map_trace).collect()
}

/// The OTel span IDs an imported trace was mapped from (`otel_span_id` of its events).
pub fn span_ids(record: &TraceRecord) -> std::collections::BTreeSet<String> {
    record
        .events
        .iter()
        .filter_map(|e| e.metadata.get("otel_span_id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect()
}

fn collect_file(mut input: impl Read, spans: &mut Vec<Span>) -> Result<(), StorageError> {
    let mut text = String::new();
    (&mut input)
        .take(MAX_IMPORT_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|_| err("the file is not UTF-8 text"))?;
    if text.len() as u64 > MAX_IMPORT_BYTES {
        return Err(err(format!("file exceeds {MAX_IMPORT_BYTES} bytes")));
    }
    match serde_json::from_str::<Value>(&text) {
        Ok(request) => collect_spans(&request, spans)?,
        Err(_) => {
            for (i, line) in text
                .lines()
                .enumerate()
                .filter(|(_, l)| !l.trim().is_empty())
            {
                let request: Value =
                    serde_json::from_str(line).map_err(|e| StorageError::Import {
                        line: i + 1,
                        message: format!("not OTLP JSON: {e}"),
                    })?;
                collect_spans(&request, spans).map_err(|e| match e {
                    StorageError::Import { message, .. } => StorageError::Import {
                        line: i + 1,
                        message,
                    },
                    other => other,
                })?;
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Agent,
    Inference,
    Tool,
    Other,
}

fn op(span: &Span) -> Op {
    match span.str("gen_ai.operation.name") {
        Some("chat" | "generate_content" | "text_completion" | "realtime_inference") => {
            Op::Inference
        }
        Some("execute_tool") => Op::Tool,
        Some(o) if o.starts_with("invoke_") => Op::Agent,
        // An MCP client `tools/call` span without GenAI operation name.
        None if span.str("mcp.method.name") == Some("tools/call") => Op::Tool,
        _ => Op::Other,
    }
}

fn tool_name(span: &Span) -> String {
    span.str("gen_ai.tool.name")
        .map(str::to_owned)
        .unwrap_or_else(|| {
            span.name
                .strip_prefix("execute_tool ")
                .or_else(|| span.name.strip_prefix("tools/call "))
                .unwrap_or(&span.name)
                .to_owned()
        })
}

fn agent_label(span: &Span) -> String {
    span.str("gen_ai.agent.name")
        .or_else(|| span.str("gen_ai.agent.id"))
        .map(str::to_owned)
        .unwrap_or_else(|| span.name.clone())
}

/// Text of the parts of messages with one of `roles`.
fn message_text(messages: &Value, roles: &[&str]) -> Vec<String> {
    messages
        .as_array()
        .into_iter()
        .flatten()
        .filter(|m| {
            m.get("role")
                .and_then(Value::as_str)
                .is_some_and(|r| roles.contains(&r))
        })
        .flat_map(|m| {
            m.get("parts")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .filter(|p| p.get("type").and_then(Value::as_str) == Some("text"))
        .filter_map(|p| p.get("content").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

/// IDs of parts of `kind` (`tool_call` or `tool_call_response`) in messages.
fn part_ids(messages: &Value, kind: &str) -> Vec<String> {
    messages
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|m| {
            m.get("parts")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .filter(|p| p.get("type").and_then(Value::as_str) == Some(kind))
        .filter_map(|p| p.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

fn time_of(nanos: i128) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp_nanos(nanos).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Phase {
    End = 0,
    Start = 1,
}

fn map_trace(mut spans: Vec<Span>) -> Result<OtlpTrace, StorageError> {
    spans.sort_by(|a, b| (a.start, &a.span_id).cmp(&(b.start, &b.span_id)));
    let otel_trace_id = spans[0].trace_id.clone();
    let index: HashMap<&str, usize> = spans
        .iter()
        .enumerate()
        .map(|(i, s)| (s.span_id.as_str(), i))
        .collect();
    let parent_of = |i: usize| {
        spans[i]
            .parent
            .as_deref()
            .and_then(|p| index.get(p).copied())
    };
    let ancestor = |mut i: usize, want: Op| -> Option<usize> {
        let mut guard = 0;
        while let Some(p) = parent_of(i) {
            if op(&spans[p]) == want {
                return Some(p);
            }
            i = p;
            guard += 1;
            if guard > spans.len() {
                return None; // a cycle in hostile input
            }
        }
        None
    };
    // The agent a span belongs to: the nearest agent span, inclusive.
    let owner = |i: usize| -> Option<usize> {
        if op(&spans[i]) == Op::Agent {
            Some(i)
        } else {
            ancestor(i, Op::Agent)
        }
    };
    // An MCP `tools/call` span inside an `execute_tool` span is the same call, unless an agent
    // span lies between them (a tool that runs an agent, which makes its own tool calls).
    let is_nested_tool = |i: usize| {
        op(&spans[i]) == Op::Tool && ancestor(i, Op::Tool).is_some_and(|t| owner(t) == owner(i))
    };

    let root = spans
        .iter()
        .position(|s| {
            s.parent
                .as_ref()
                .is_none_or(|p| !index.contains_key(p.as_str()))
        })
        .unwrap_or(0);
    let service = spans.iter().find_map(|s| s.service.clone());
    let name = format!(
        "otel/{}{}",
        service
            .as_deref()
            .map(|s| format!("{s}/"))
            .unwrap_or_default(),
        spans[root].name
    );
    let trace_id = Uuid::new_v5(&NAMESPACE, otel_trace_id.as_bytes());
    let mut rec = TraceRecorder::with_trace_id(name, ExecutionMode::Live, trace_id);
    rec.set_trace_metadata("otel_trace_id", otel_trace_id.clone());
    rec.set_trace_metadata("otel_mapping", MAPPING_VERSION);
    if let Some(s) = &service {
        rec.set_trace_metadata("service_name", s.clone());
    }

    let mut actions: Vec<(i128, Phase, usize)> = Vec::new();
    let mut ignored = 0;
    for (i, s) in spans.iter().enumerate() {
        match op(s) {
            Op::Other => ignored += 1,
            Op::Tool if is_nested_tool(i) => {}
            _ => {
                actions.push((s.start, Phase::Start, i));
                actions.push((s.end, Phase::End, i));
            }
        }
    }
    // Causes end before their effects start; at equal times ends go first.
    actions.sort();

    let mut times: Vec<i128> = Vec::new();
    let mut record = |rec: &mut TraceRecorder, t: i128, spec: EventSpec| -> Uuid {
        times.push(t);
        rec.record(spec)
    };
    let agent_id = |i: Option<usize>| -> Option<String> {
        // The outermost agent is the default agent; nested agents are named.
        i.filter(|a| ancestor(*a, Op::Agent).is_some())
            .map(|a| agent_label(&spans[a]))
    };
    let main_name = spans
        .iter()
        .find(|s| op(s) == Op::Agent)
        .map(agent_label)
        .unwrap_or_else(|| "otel-agent".into());
    let main = record(
        &mut rec,
        spans[root].start,
        EventSpec::new(
            EventKind::AgentStarted,
            Origin::System,
            TrustLevel::Trusted,
            main_name.clone(),
        )
        .payload(json!({"otel_trace_id": otel_trace_id, "service": service})),
    );

    let mut content_captured = false;
    let mut started: HashMap<usize, Uuid> = HashMap::new(); // agent span → agent_started
    let mut prompted = false;
    let mut response_by_call: HashMap<String, Uuid> = HashMap::new();
    let mut result_by_call: HashMap<String, Uuid> = HashMap::new();
    let mut request_of: HashMap<usize, Uuid> = HashMap::new(); // tool span → request
    let mut model_request_of: HashMap<usize, Uuid> = HashMap::new();
    let mut lower_trust_of: HashMap<Option<usize>, Vec<Uuid>> = HashMap::new();
    let mut report_of: HashMap<usize, Uuid> = HashMap::new(); // agent span → message sent
    let mut executed_of: HashMap<usize, Uuid> = HashMap::new(); // tool span → executed

    for (t, phase, i) in actions {
        let s = &spans[i];
        let own = owner(i);
        let parent_event = own.and_then(|a| started.get(&a).copied()).unwrap_or(main);
        let agent = agent_id(own);
        let meta = |spec: EventSpec| {
            spec.meta("otel_span_id", s.span_id.clone())
                .meta("otel_span_name", s.name.clone())
        };
        match (op(s), phase) {
            (Op::Agent, Phase::Start) => {
                let outer = ancestor(i, Op::Agent);
                if outer.is_none() {
                    started.insert(i, main);
                    continue;
                }
                let outer_event = outer.and_then(|o| started.get(&o).copied()).unwrap_or(main);
                let delegated = record(
                    &mut rec,
                    t,
                    meta(
                        EventSpec::new(EventKind::AgentDelegated, Origin::Agent, TrustLevel::Unknown, agent_label(s))
                            .payload(json!({"to_agent": agent_label(s), "description": s.str("gen_ai.agent.description")}))
                            .agent(agent_id(outer))
                            .parent(outer_event)
                            // Run by a tool call: that request (span structure); otherwise
                            // no cause is recorded.
                            .caused_by(ancestor(i, Op::Tool).and_then(|t| request_of.get(&t).copied())),
                    ),
                );
                let id = record(
                    &mut rec,
                    t,
                    meta(
                        EventSpec::new(
                            EventKind::AgentStarted,
                            Origin::System,
                            TrustLevel::Trusted,
                            agent_label(s),
                        )
                        .agent(agent.clone())
                        .parent(outer_event)
                        .caused_by(delegated),
                    ),
                );
                started.insert(i, id);
            }
            (Op::Agent, Phase::End) => {
                let Some(outer) = ancestor(i, Op::Agent) else {
                    continue;
                };
                let tainted = lower_trust_of.get(&Some(i)).cloned().unwrap_or_default();
                let trust = if tainted.is_empty() {
                    TrustLevel::Unknown
                } else {
                    TrustLevel::LowerTrust
                };
                let output = s.structured("gen_ai.output.messages");
                content_captured |= output.is_some();
                let text = output
                    .as_ref()
                    .map(|o| message_text(o, &["assistant"]).join("\n"));
                let sent = record(
                    &mut rec,
                    t,
                    meta(
                        EventSpec::new(
                            EventKind::AgentMessageSent,
                            Origin::Agent,
                            trust,
                            agent_label(s),
                        )
                        .payload(json!({"text": text}))
                        .agent(agent.clone())
                        .parent(started.get(&i).copied().unwrap_or(main))
                        .context(tainted.iter().rev().take(256).copied()),
                    ),
                );
                let received = record(
                    &mut rec,
                    t,
                    meta(
                        EventSpec::new(
                            EventKind::AgentMessageReceived,
                            Origin::Agent,
                            trust,
                            agent_label(s),
                        )
                        .payload(json!({"from": agent_label(s), "text": text}))
                        .agent(agent_id(Some(outer)))
                        .parent(started.get(&outer).copied().unwrap_or(main))
                        .caused_by(sent),
                    ),
                );
                if trust == TrustLevel::LowerTrust {
                    lower_trust_of
                        .entry(Some(outer))
                        .or_default()
                        .push(received);
                }
                report_of.insert(i, received);
                record(
                    &mut rec,
                    t,
                    meta(
                        EventSpec::new(
                            EventKind::AgentCompleted,
                            Origin::System,
                            TrustLevel::Trusted,
                            agent_label(s),
                        )
                        .agent(agent.clone())
                        .parent(started.get(&i).copied().unwrap_or(main))
                        .caused_by(sent),
                    ),
                );
            }
            (Op::Inference, Phase::Start) => {
                let input = s.structured("gen_ai.input.messages");
                content_captured |= input.is_some();
                let mut context: Vec<Uuid> = Vec::new();
                // Only what the input messages show: the prompt and tool responses by call id.
                let mut cause = None;
                if let Some(input) = &input {
                    let is_top = own.is_none_or(|a| ancestor(a, Op::Agent).is_none());
                    if !prompted && is_top {
                        let user = message_text(input, &["user"]);
                        if let Some(text) = user.first() {
                            let p = record(
                                &mut rec,
                                t,
                                meta(
                                    EventSpec::new(
                                        EventKind::UserPromptReceived,
                                        Origin::User,
                                        TrustLevel::Trusted,
                                        "user_prompt",
                                    )
                                    .payload(json!({"text": text}))
                                    .parent(parent_event),
                                ),
                            );
                            prompted = true;
                            context.push(p);
                            cause = Some(p);
                        }
                    }
                    for id in part_ids(input, "tool_call_response") {
                        if let Some(r) = result_by_call.get(&id) {
                            context.push(*r);
                            cause = Some(*r);
                        }
                    }
                }
                let id = record(
                    &mut rec,
                    t,
                    meta(
                        EventSpec::new(
                            EventKind::ModelRequest,
                            Origin::Agent,
                            TrustLevel::Unknown,
                            s.str("gen_ai.request.model").unwrap_or("model"),
                        )
                        .payload(json!({
                            "provider": s.str("gen_ai.provider.name").or_else(|| s.str("gen_ai.system")),
                            "model": s.str("gen_ai.request.model"),
                            "operation": s.str("gen_ai.operation.name"),
                            "messages": input.as_ref().and_then(Value::as_array).map(Vec::len),
                        }))
                        .agent(agent.clone())
                        .parent(parent_event)
                        .caused_by(cause)
                        .context(context),
                    ),
                );
                model_request_of.insert(i, id);
            }
            (Op::Inference, Phase::End) => {
                let output = s.structured("gen_ai.output.messages");
                content_captured |= output.is_some();
                let calls = output
                    .as_ref()
                    .map(|o| part_ids(o, "tool_call"))
                    .unwrap_or_default();
                let id = record(
                    &mut rec,
                    t,
                    meta(
                        EventSpec::new(
                            EventKind::ModelResponse,
                            Origin::Model,
                            TrustLevel::Unknown,
                            s.str("gen_ai.response.model").or_else(|| s.str("gen_ai.request.model")).unwrap_or("model"),
                        )
                        .payload(json!({
                            "text": output.as_ref().map(|o| message_text(o, &["assistant"]).join("\n")),
                            "tool_call_ids": calls,
                            "finish_reasons": s.attrs.get("gen_ai.response.finish_reasons"),
                            "usage": {
                                "input_tokens": s.attrs.get("gen_ai.usage.input_tokens"),
                                "output_tokens": s.attrs.get("gen_ai.usage.output_tokens"),
                            },
                            "error": s.error,
                        }))
                        .agent(agent.clone())
                        .parent(parent_event)
                        .caused_by(model_request_of.get(&i).copied()),
                    ),
                );
                for call in calls {
                    response_by_call.insert(call, id);
                }
            }
            (Op::Tool, Phase::Start) => {
                let tool = tool_name(s);
                let call_id = s.str("gen_ai.tool.call.id").map(str::to_owned);
                let arguments = s.structured("gen_ai.tool.call.arguments");
                content_captured |= arguments.is_some();
                let cause = call_id
                    .as_ref()
                    .and_then(|c| response_by_call.get(c).copied());
                let mut spec = EventSpec::new(
                    EventKind::ToolCallRequested,
                    Origin::Agent,
                    TrustLevel::Unknown,
                    &tool,
                )
                .payload(json!({"tool": tool, "arguments": arguments}))
                .agent(agent.clone())
                .parent(parent_event)
                .caused_by(cause)
                .tool_state(ToolState::Requested);
                if let Some(c) = &call_id {
                    spec = spec.meta("tool_call_id", c.clone());
                }
                if let Some(m) = s.str("mcp.method.name") {
                    spec = spec.meta("mcp_method", m);
                }
                let request = record(&mut rec, t, meta(spec));
                let executed = record(
                    &mut rec,
                    t,
                    meta(
                        EventSpec::new(
                            EventKind::ToolCallExecuted,
                            Origin::System,
                            TrustLevel::Trusted,
                            &tool,
                        )
                        .payload(json!({"tool": tool}))
                        .agent(agent.clone())
                        .parent(request)
                        .caused_by(request)
                        .tool_state(ToolState::Executed),
                    ),
                );
                request_of.insert(i, request);
                executed_of.insert(i, executed);
            }
            (Op::Tool, Phase::End) => {
                let tool = tool_name(s);
                let Some(request) = request_of.get(&i).copied() else {
                    continue;
                };
                let result = s.structured("gen_ai.tool.call.result");
                content_captured |= result.is_some();
                // A tool that ran an agent: its result is that agent's report.
                let sub_report = spans
                    .iter()
                    .enumerate()
                    .filter(|(j, x)| op(x) == Op::Agent && ancestor(*j, Op::Tool) == Some(i))
                    .find_map(|(j, _)| report_of.get(&j).copied());
                let origin =
                    if s.str("mcp.method.name").is_some() || is_mcp_child(&spans, i, &parent_of) {
                        Origin::McpTool
                    } else {
                        Origin::System
                    };
                let content = match &result {
                    Some(Value::String(text)) => Value::String(text.clone()),
                    Some(other) => Value::String(other.to_string()),
                    None => Value::Null,
                };
                let id = record(
                    &mut rec,
                    t,
                    meta(
                        EventSpec::new(EventKind::ToolResultReceived, origin, TrustLevel::LowerTrust, &tool)
                            .payload(json!({"tool": tool, "is_error": s.error, "content": content, "content_captured": result.is_some()}))
                            .agent(agent.clone())
                            .parent(request)
                            .caused_by(sub_report.or_else(|| executed_of.get(&i).copied())),
                    ),
                );
                if let Some(c) = s.str("gen_ai.tool.call.id") {
                    result_by_call.insert(c.to_owned(), id);
                }
                lower_trust_of.entry(own).or_default().push(id);
                let (kind, state) = if s.error {
                    (EventKind::ToolCallFailed, ToolState::Failed)
                } else {
                    (EventKind::ToolCallCompleted, ToolState::Completed)
                };
                record(
                    &mut rec,
                    t,
                    meta(
                        EventSpec::new(kind, Origin::System, TrustLevel::Trusted, &tool)
                            .payload(json!({"tool": tool, "is_error": s.error, "error_type": s.str("error.type")}))
                            .agent(agent.clone())
                            .parent(request)
                            .caused_by(id)
                            .tool_state(state),
                    ),
                );
            }
            (Op::Other, _) => {}
        }
    }
    let end = spans
        .iter()
        .map(|s| s.end)
        .max()
        .unwrap_or(spans[root].start);
    record(
        &mut rec,
        end,
        EventSpec::new(
            EventKind::AgentCompleted,
            Origin::System,
            TrustLevel::Trusted,
            main_name.clone(),
        )
        .parent(main),
    );
    rec.set_trace_metadata("content_captured", content_captured);
    rec.set_trace_metadata("ignored_spans", ignored);

    let mut record = rec.finish();
    record.trace.created_at = time_of(spans[root].start);
    for (event, t) in record.events.iter_mut().zip(&times) {
        event.timestamp = time_of(*t);
    }
    validate(&record).map_err(StorageError::Invalid)?;
    Ok(OtlpTrace {
        record,
        content_captured,
        ignored_spans: ignored,
    })
}

/// Whether an MCP `tools/call` span sits inside tool span `i`.
fn is_mcp_child(spans: &[Span], i: usize, parent_of: &dyn Fn(usize) -> Option<usize>) -> bool {
    spans.iter().enumerate().any(|(j, s)| {
        s.str("mcp.method.name") == Some("tools/call") && {
            let mut k = j;
            let mut found = false;
            for _ in 0..spans.len() {
                match parent_of(k) {
                    Some(p) if p == i => {
                        found = true;
                        break;
                    }
                    Some(p) => k = p,
                    None => break,
                }
            }
            found
        }
    })
}
