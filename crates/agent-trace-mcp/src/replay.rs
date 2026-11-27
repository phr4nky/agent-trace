//! Controlled replay: an MCP server that answers from a recorded trace.
//!
//! [`ReplayFixture::from_trace`] extracts what an agent saw in a recorded session: the task
//! prompt, the tools it was offered and the result of every tool call. [`ReplayServer`] serves
//! exactly that over MCP, so a new model or prompt can be run against the same environment:
//! the same injected issue, the same document, the same tool results. Nothing is executed and
//! nothing leaves the machine; a call that has no recorded result gets a tool error saying so.
//!
//! Recorded results are already redacted. Secrets appear as `[REDACTED:<kind>]`, which the
//! rules still treat as sensitive, so an attempt to send them somewhere is still found.

use std::sync::{Arc, Mutex};

use agent_trace_core::{EventKind, TraceRecord};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::adapter::ToolSpec;

/// Name the replay server reports in the MCP handshake (and so in the replayed trace).
pub const REPLAY_SERVER_NAME: &str = "agent-trace-replay";

/// One recorded tool call and its result.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordedCall {
    pub tool: String,
    pub arguments: Map<String, Value>,
    /// The text the agent received.
    pub text: String,
    pub structured: Option<Value>,
    pub is_error: bool,
}

/// What an agent saw in a recorded session.
#[derive(Debug, Clone, Default)]
pub struct ReplayFixture {
    /// The recorded trace.
    pub trace_id: Uuid,
    pub trace_name: String,
    /// The task, from the first `user_prompt_received` (absent in proxy traces).
    pub prompt: Option<String>,
    /// The top-level agent.
    pub agent: Option<String>,
    /// A sub-agent the top-level agent delegated to.
    pub delegate_to: Option<String>,
    /// Tools offered, with descriptions and schemas where the trace has them.
    pub tools: Vec<ToolSpec>,
    /// Recorded tool calls with results, in trace order.
    pub calls: Vec<RecordedCall>,
}

fn str_field<'a>(payload: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|k| payload.get(*k).and_then(Value::as_str))
}

/// A JSON schema that accepts the recorded arguments (for tools whose schema the trace lacks).
fn inferred_schema(arguments: Option<&Map<String, Value>>) -> Value {
    let mut properties = Map::new();
    for (key, value) in arguments.into_iter().flatten() {
        let ty = match value {
            Value::String(_) => "string",
            Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
            Value::Number(_) => "number",
            Value::Bool(_) => "boolean",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
            Value::Null => "string",
        };
        properties.insert(key.clone(), json!({ "type": ty }));
    }
    json!({ "type": "object", "properties": properties })
}

fn response_text(payload: &Value) -> String {
    // MCP results (lab, proxy) carry `content`; Claude Code hook results carry `response`.
    match payload.get("content").or_else(|| payload.get("response")) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => payload
            .get("structured_content")
            .map(Value::to_string)
            .unwrap_or_default(),
        Some(other) => other.to_string(),
    }
}

impl ReplayFixture {
    pub fn from_trace(record: &TraceRecord) -> Self {
        let events = &record.events;
        let by_id = |id: Uuid| events.iter().find(|e| e.event_id == id);
        let prompt = events
            .iter()
            .find(|e| e.kind == EventKind::UserPromptReceived)
            .and_then(|e| str_field(&e.payload, &["text", "prompt"]).map(str::to_owned));
        let agent = events
            .iter()
            .find(|e| e.kind == EventKind::AgentStarted)
            .and_then(|e| e.agent_id.clone());
        let delegate_to = events
            .iter()
            .find(|e| e.kind == EventKind::AgentDelegated)
            .and_then(|e| str_field(&e.payload, &["to_agent"]).map(str::to_owned));

        // Tools: a recorded tools/list answer has descriptions and schemas.
        let mut tools: Vec<ToolSpec> = Vec::new();
        let add = |spec: ToolSpec, tools: &mut Vec<ToolSpec>| {
            if !spec.name.is_empty()
                && !spec.name.starts_with("delegate_to_")
                && !tools.iter().any(|t| t.name == spec.name)
            {
                tools.push(spec);
            }
        };
        for e in events
            .iter()
            .filter(|e| e.kind == EventKind::ExternalContentObserved && e.name == "tools/list")
        {
            for t in e
                .payload
                .get("tools")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let Some(name) = t.get("name").and_then(Value::as_str) else {
                    continue;
                };
                let schema = match t.get("input_schema") {
                    Some(Value::Object(s)) => Value::Object(s.clone()),
                    _ => inferred_schema(None),
                };
                add(
                    ToolSpec {
                        name: name.to_owned(),
                        description: t
                            .get("description")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        input_schema: schema,
                    },
                    &mut tools,
                );
            }
        }
        // Otherwise: tools named in requests and in an LLM agent's start event.
        let described = |name: &str| {
            format!(
                "Tool `{name}` as recorded in trace {}. Answers come from the recording; \
                 nothing is executed.",
                record.trace.trace_id
            )
        };
        for e in events
            .iter()
            .filter(|e| e.kind == EventKind::ToolCallRequested)
        {
            let name = str_field(&e.payload, &["tool"])
                .unwrap_or(&e.name)
                .to_owned();
            let args = e.payload.get("arguments").and_then(Value::as_object);
            add(
                ToolSpec {
                    description: described(&name),
                    input_schema: inferred_schema(args),
                    name,
                },
                &mut tools,
            );
        }
        for e in events.iter().filter(|e| e.kind == EventKind::AgentStarted) {
            for name in e
                .payload
                .get("tools")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                add(
                    ToolSpec {
                        name: name.to_owned(),
                        description: described(name),
                        input_schema: inferred_schema(None),
                    },
                    &mut tools,
                );
            }
        }

        let calls = events
            .iter()
            .filter(|e| e.kind == EventKind::ToolResultReceived)
            .map(|result| {
                let request = result.parent_event_id.and_then(by_id);
                let tool = str_field(&result.payload, &["tool"])
                    .unwrap_or(&result.name)
                    .to_owned();
                RecordedCall {
                    arguments: request
                        .and_then(|r| r.payload.get("arguments"))
                        .and_then(Value::as_object)
                        .cloned()
                        .unwrap_or_default(),
                    text: response_text(&result.payload),
                    structured: result.payload.get("structured_content").cloned(),
                    is_error: result.payload.get("is_error").and_then(Value::as_bool) == Some(true),
                    tool,
                }
            })
            .collect();

        Self {
            trace_id: record.trace.trace_id,
            trace_name: record.trace.name.clone(),
            prompt,
            agent,
            delegate_to,
            tools,
            calls,
        }
    }
}

/// An MCP server that answers tool calls from a [`ReplayFixture`].
///
/// Matching, in this order: a recorded call of the same tool with the same arguments; the
/// next not yet used recorded call of the same tool; otherwise a tool error. Answers are
/// deterministic for the same sequence of calls.
#[derive(Clone)]
pub struct ReplayServer {
    fixture: Arc<ReplayFixture>,
    used: Arc<Mutex<Vec<bool>>>,
}

impl ReplayServer {
    pub fn new(fixture: ReplayFixture) -> Self {
        let used = vec![false; fixture.calls.len()];
        Self {
            fixture: Arc::new(fixture),
            used: Arc::new(Mutex::new(used)),
        }
    }

    /// The recorded call that answers `tool` with `arguments`.
    pub fn answer(&self, tool: &str, arguments: &Map<String, Value>) -> Option<RecordedCall> {
        let mut used = self
            .used
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let calls = &self.fixture.calls;
        let same_tool = |i: &usize| calls[*i].tool == tool;
        let exact = |i: &usize| same_tool(i) && calls[*i].arguments == *arguments;
        let index = (0..calls.len())
            .filter(exact)
            .find(|i| !used[*i])
            .or_else(|| (0..calls.len()).find(exact))
            .or_else(|| (0..calls.len()).filter(same_tool).find(|i| !used[*i]))?;
        used[index] = true;
        Some(calls[index].clone())
    }
}

impl ServerHandler for ReplayServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_server_info(
            Implementation::new(REPLAY_SERVER_NAME, env!("CARGO_PKG_VERSION")).with_title(format!(
                "replay of trace {} (recorded results only)",
                self.fixture.trace_id
            )),
        )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let tools = self
            .fixture
            .tools
            .iter()
            .map(|t| {
                let schema = match &t.input_schema {
                    Value::Object(m) => m.clone(),
                    _ => Map::new(),
                };
                Tool::new(t.name.clone(), t.description.clone(), Arc::new(schema))
            })
            .collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let arguments = request.arguments.clone().unwrap_or_default();
        let result = match self.answer(&request.name, &arguments) {
            Some(call) => {
                let mut result = if call.is_error {
                    CallToolResult::error(vec![ContentBlock::text(call.text)])
                } else {
                    CallToolResult::success(vec![ContentBlock::text(call.text)])
                };
                result.structured_content = call.structured;
                result
            }
            None => CallToolResult::error(vec![ContentBlock::text(format!(
                "agent-trace replay: the recording has no result for `{}`; nothing was executed.",
                request.name
            ))]),
        };
        Ok(result.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(tool: &str, args: Value, text: &str) -> RecordedCall {
        RecordedCall {
            tool: tool.into(),
            arguments: args.as_object().unwrap().clone(),
            text: text.into(),
            structured: None,
            is_error: false,
        }
    }

    fn server() -> ReplayServer {
        ReplayServer::new(ReplayFixture {
            calls: vec![
                call("read", json!({"path": "a.md"}), "A"),
                call("read", json!({"path": "b.md"}), "B"),
                call("read", json!({"path": "c.md"}), "C"),
            ],
            ..ReplayFixture::default()
        })
    }

    fn args(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn exact_arguments_win_then_recording_order() {
        let s = server();
        assert_eq!(
            s.answer("read", &args(json!({"path": "b.md"})))
                .unwrap()
                .text,
            "B"
        );
        // Unknown arguments: the next unused recorded call of the tool.
        assert_eq!(
            s.answer("read", &args(json!({"path": "x.md"})))
                .unwrap()
                .text,
            "A"
        );
        assert_eq!(
            s.answer("read", &args(json!({"path": "y.md"})))
                .unwrap()
                .text,
            "C"
        );
        // All used: an exact match is still answered again...
        assert_eq!(
            s.answer("read", &args(json!({"path": "a.md"})))
                .unwrap()
                .text,
            "A"
        );
        // ...anything else has no recorded result.
        assert!(s.answer("read", &args(json!({"path": "z.md"}))).is_none());
        assert!(s.answer("write", &args(json!({}))).is_none());
    }

    #[test]
    fn schemas_are_inferred_from_recorded_arguments() {
        let schema = inferred_schema(Some(&args(
            json!({"path": "a", "n": 1, "x": 1.5, "on": true, "list": []}),
        )));
        assert_eq!(schema["properties"]["path"]["type"], "string");
        assert_eq!(schema["properties"]["n"]["type"], "integer");
        assert_eq!(schema["properties"]["x"]["type"], "number");
        assert_eq!(schema["properties"]["on"]["type"], "boolean");
        assert_eq!(schema["properties"]["list"]["type"], "array");
    }
}
