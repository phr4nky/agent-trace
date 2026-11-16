//! OpenAI Chat Completions wire format (`POST {base}/chat/completions`).
//! Also used by OpenAI-compatible servers (Ollama, vLLM, LM Studio, …).

use serde_json::{Value, json};

use crate::LlmError;
use crate::types::{Block, ModelReply, ModelRequest, Role, ToolCall, Usage};

pub const DEFAULT_BASE_URL: &str = "https://api.openai.com/v1";

pub fn endpoint(base_url: &str) -> String {
    format!("{}/chat/completions", base_url.trim_end_matches('/'))
}

pub fn request_body(model: &str, req: &ModelRequest<'_>) -> Value {
    let mut messages = vec![json!({"role": "system", "content": req.system})];
    for m in req.messages {
        match m.role {
            Role::Assistant => {
                let text: Vec<&str> = m
                    .content
                    .iter()
                    .filter_map(|b| match b {
                        Block::Text(t) => Some(t.as_str()),
                        _ => None,
                    })
                    .collect();
                let calls: Vec<Value> = m
                    .content
                    .iter()
                    .filter_map(|b| match b {
                        Block::ToolUse { id, name, input } => Some(json!({
                            "id": id,
                            "type": "function",
                            "function": {"name": name, "arguments": input.to_string()},
                        })),
                        _ => None,
                    })
                    .collect();
                let mut msg = json!({
                    "role": "assistant",
                    "content": if text.is_empty() { Value::Null } else { Value::String(text.join("\n")) },
                });
                if !calls.is_empty() {
                    msg["tool_calls"] = Value::Array(calls);
                }
                messages.push(msg);
            }
            Role::User => {
                // Tool results become separate `tool` messages; text stays a user message.
                let mut text = Vec::new();
                for b in &m.content {
                    match b {
                        Block::Text(t) => text.push(t.clone()),
                        Block::ToolResult {
                            tool_use_id,
                            content,
                            is_error,
                        } => messages.push(json!({
                            "role": "tool",
                            "tool_call_id": tool_use_id,
                            "content": if *is_error { format!("ERROR: {content}") } else { content.clone() },
                        })),
                        Block::ToolUse { .. } => {}
                    }
                }
                if !text.is_empty() {
                    messages.push(json!({"role": "user", "content": text.join("\n")}));
                }
            }
        }
    }
    let mut body = json!({"model": model, "messages": messages});
    if !req.tools.is_empty() {
        body["tools"] = req
            .tools
            .iter()
            .map(|t| {
                json!({
                    "type": "function",
                    "function": {"name": t.name, "description": t.description, "parameters": t.input_schema},
                })
            })
            .collect();
    }
    body
}

pub fn parse_reply(body: &Value) -> Result<ModelReply, LlmError> {
    let choice = body
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|c| c.first())
        .ok_or_else(|| LlmError::Parse("openai: missing `choices[0]`".into()))?;
    let message = choice
        .get("message")
        .ok_or_else(|| LlmError::Parse("openai: missing `message`".into()))?;
    let mut tool_calls = Vec::new();
    for call in message
        .get("tool_calls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let function = call.get("function").unwrap_or(&Value::Null);
        let name = function
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| LlmError::Parse("openai: tool call without name".into()))?;
        let raw = function
            .get("arguments")
            .and_then(Value::as_str)
            .unwrap_or("{}");
        // Models sometimes emit invalid JSON; keep it visible instead of guessing.
        let input =
            serde_json::from_str(raw).unwrap_or_else(|_| json!({"_unparsed_arguments": raw}));
        tool_calls.push(ToolCall {
            id: call
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("call")
                .to_owned(),
            name: name.to_owned(),
            input,
        });
    }
    let usage = body.get("usage");
    Ok(ModelReply {
        text: message
            .get("content")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        tool_calls,
        stop_reason: choice
            .get("finish_reason")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned(),
        usage: Usage {
            input_tokens: usage
                .and_then(|u| u.get("prompt_tokens"))
                .and_then(Value::as_u64)
                .unwrap_or(0),
            output_tokens: usage
                .and_then(|u| u.get("completion_tokens"))
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

pub fn error_message(body: &Value) -> Option<String> {
    body.get("error")?
        .get("message")?
        .as_str()
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Message, ToolDef};

    #[test]
    fn converts_tool_round_trip() {
        let messages = vec![
            Message::user_text("hi"),
            Message {
                role: Role::Assistant,
                content: vec![Block::ToolUse {
                    id: "call_1".into(),
                    name: "read_document".into(),
                    input: json!({"path": "a.md"}),
                }],
            },
            Message {
                role: Role::User,
                content: vec![Block::ToolResult {
                    tool_use_id: "call_1".into(),
                    content: "blocked".into(),
                    is_error: true,
                }],
            },
        ];
        let tools = vec![ToolDef {
            name: "read_document".into(),
            description: "d".into(),
            input_schema: json!({"type": "object"}),
        }];
        let body = request_body(
            "gpt-x",
            &ModelRequest {
                system: "sys",
                messages: &messages,
                tools: &tools,
                max_tokens: 100,
            },
        );
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs[0]["role"], "system");
        assert_eq!(msgs[2]["content"], Value::Null);
        assert_eq!(
            msgs[2]["tool_calls"][0]["function"]["arguments"],
            "{\"path\":\"a.md\"}"
        );
        assert_eq!(msgs[3]["role"], "tool");
        assert_eq!(msgs[3]["content"], "ERROR: blocked");
        assert_eq!(body["tools"][0]["function"]["parameters"]["type"], "object");
    }

    #[test]
    fn parses_tool_calls_and_bad_arguments() {
        let reply = parse_reply(&json!({
            "model": "gpt-x",
            "choices": [{
                "finish_reason": "tool_calls",
                "message": {"role": "assistant", "content": null, "tool_calls": [
                    {"id": "c1", "type": "function", "function": {"name": "a", "arguments": "{\"x\":1}"}},
                    {"id": "c2", "type": "function", "function": {"name": "b", "arguments": "not json"}}
                ]}
            }],
            "usage": {"prompt_tokens": 3, "completion_tokens": 4}
        }))
        .unwrap();
        assert_eq!(reply.tool_calls[0].input["x"], 1);
        assert_eq!(reply.tool_calls[1].input["_unparsed_arguments"], "not json");
        assert_eq!(reply.usage.output_tokens, 4);
    }
}
