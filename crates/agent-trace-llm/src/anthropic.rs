//! Anthropic Messages API wire format (`POST {base}/v1/messages`).

use serde_json::{Value, json};

use crate::LlmError;
use crate::types::{Block, Message, ModelReply, ModelRequest, Role, ToolCall, Usage};

pub const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
pub const DEFAULT_MODEL: &str = "claude-sonnet-5-5";
pub const API_VERSION: &str = "2023-06-01";

pub fn endpoint(base_url: &str) -> String {
    format!("{}/v1/messages", base_url.trim_end_matches('/'))
}

fn block_json(block: &Block) -> Value {
    match block {
        Block::Text(text) => json!({"type": "text", "text": text}),
        Block::ToolUse { id, name, input } => {
            json!({"type": "tool_use", "id": id, "name": name, "input": input})
        }
        Block::ToolResult {
            tool_use_id,
            content,
            is_error,
        } => json!({
            "type": "tool_result",
            "tool_use_id": tool_use_id,
            "content": content,
            "is_error": is_error,
        }),
    }
}

pub fn request_body(model: &str, req: &ModelRequest<'_>) -> Value {
    let messages: Vec<Value> = req
        .messages
        .iter()
        .map(|m: &Message| {
            json!({
                "role": match m.role { Role::User => "user", Role::Assistant => "assistant" },
                "content": m.content.iter().map(block_json).collect::<Vec<_>>(),
            })
        })
        .collect();
    let mut body = json!({
        "model": model,
        "max_tokens": req.max_tokens,
        "system": req.system,
        "messages": messages,
    });
    if !req.tools.is_empty() {
        body["tools"] = req
            .tools
            .iter()
            .map(|t| json!({"name": t.name, "description": t.description, "input_schema": t.input_schema}))
            .collect();
    }
    body
}

pub fn parse_reply(body: &Value) -> Result<ModelReply, LlmError> {
    let content = body
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| LlmError::Parse("anthropic: missing `content` array".into()))?;
    let mut text = Vec::new();
    let mut tool_calls = Vec::new();
    for block in content {
        match block.get("type").and_then(Value::as_str) {
            Some("text") => {
                if let Some(t) = block.get("text").and_then(Value::as_str) {
                    text.push(t.to_owned());
                }
            }
            Some("tool_use") => tool_calls.push(ToolCall {
                id: str_field(block, "id")?,
                name: str_field(block, "name")?,
                input: block.get("input").cloned().unwrap_or_else(|| json!({})),
            }),
            _ => {} // thinking and other block types are not needed for the trace
        }
    }
    let usage = body.get("usage");
    Ok(ModelReply {
        text: text.join("\n"),
        tool_calls,
        stop_reason: body
            .get("stop_reason")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned(),
        usage: Usage {
            input_tokens: usage
                .and_then(|u| u.get("input_tokens"))
                .and_then(Value::as_u64)
                .unwrap_or(0),
            output_tokens: usage
                .and_then(|u| u.get("output_tokens"))
                .and_then(Value::as_u64)
                .unwrap_or(0),
        },
        model: body
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    })
}

/// Extract the error message of an API error response.
pub fn error_message(body: &Value) -> Option<String> {
    body.get("error")?
        .get("message")?
        .as_str()
        .map(str::to_owned)
}

fn str_field(v: &Value, key: &str) -> Result<String, LlmError> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| LlmError::Parse(format!("anthropic: tool_use without `{key}`")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ToolDef;

    #[test]
    fn builds_messages_with_tools_and_results() {
        let messages = vec![
            Message::user_text("hi"),
            Message {
                role: Role::Assistant,
                content: vec![
                    Block::Text("reading".into()),
                    Block::ToolUse {
                        id: "tu_1".into(),
                        name: "read_document".into(),
                        input: json!({"path": "a.md"}),
                    },
                ],
            },
            Message {
                role: Role::User,
                content: vec![Block::ToolResult {
                    tool_use_id: "tu_1".into(),
                    content: "text".into(),
                    is_error: false,
                }],
            },
        ];
        let tools = vec![ToolDef {
            name: "read_document".into(),
            description: "d".into(),
            input_schema: json!({"type": "object"}),
        }];
        let body = request_body(
            "m",
            &ModelRequest {
                system: "sys",
                messages: &messages,
                tools: &tools,
                max_tokens: 100,
            },
        );
        assert_eq!(body["system"], "sys");
        assert_eq!(body["messages"][1]["content"][1]["type"], "tool_use");
        assert_eq!(body["messages"][2]["content"][0]["tool_use_id"], "tu_1");
        assert_eq!(body["tools"][0]["input_schema"]["type"], "object");
    }

    #[test]
    fn parses_tool_use_reply() {
        let reply = parse_reply(&json!({
            "model": "claude-x",
            "stop_reason": "tool_use",
            "content": [
                {"type": "text", "text": "Let me read it."},
                {"type": "tool_use", "id": "tu_9", "name": "read_document", "input": {"path": "x.md"}}
            ],
            "usage": {"input_tokens": 12, "output_tokens": 5}
        }))
        .unwrap();
        assert_eq!(reply.tool_calls[0].name, "read_document");
        assert_eq!(reply.tool_calls[0].input["path"], "x.md");
        assert_eq!(reply.usage.input_tokens, 12);
        assert_eq!(reply.stop_reason, "tool_use");
    }
}
