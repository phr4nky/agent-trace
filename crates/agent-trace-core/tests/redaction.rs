//! Token-like values are redacted in prompts, tool arguments and tool responses
//! before an event leaves the recorder. (Logs: agent-trace-cli `logging` tests;
//! exports/imports: agent-trace-storage and the demo smoke test.)

use agent_trace_core::{EventKind, EventSpec, ExecutionMode, Origin, TraceRecorder, TrustLevel};
use serde_json::json;

const SECRETS: &[&str] = &[
    "FAKE_SECRET_FOR_TESTING_ONLY",
    "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWX",
    "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "AKIAABCDEFGHIJKLMNOP",
    "abcdefghijklmnopqrstuvwxyz0123",
];

fn assert_clean(text: &str) {
    for s in SECRETS {
        assert!(!text.contains(s), "secret {s} leaked in {text}");
    }
}

#[test]
fn prompts_arguments_and_responses_are_redacted() {
    let mut r = TraceRecorder::new("redaction", ExecutionMode::Simulated);
    r.record(
        EventSpec::new(
            EventKind::UserPromptReceived,
            Origin::User,
            TrustLevel::Trusted,
            "p",
        )
        .payload(json!({"text": "use key sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWX please"})),
    );
    r.record(
        EventSpec::new(
            EventKind::ToolCallRequested,
            Origin::Agent,
            TrustLevel::Unknown,
            "send",
        )
        .payload(json!({
            "tool": "send_webhook_mock",
            "arguments": {
                "body": "API_TOKEN=FAKE_SECRET_FOR_TESTING_ONLY",
                "headers": {"Authorization": "Bearer abcdefghijklmnopqrstuvwxyz0123"}
            }
        })),
    );
    r.record(
        EventSpec::new(
            EventKind::ToolResultReceived,
            Origin::McpTool,
            TrustLevel::LowerTrust,
            "read",
        )
        .payload(json!({"content": "aws AKIAABCDEFGHIJKLMNOP gh ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"}))
        .meta("note", "token=FAKE_SECRET_FOR_TESTING_ONLY"),
    );
    let rec = r.finish();
    let serialized = serde_json::to_string(&rec).unwrap();
    assert_clean(&serialized);
    assert!(rec.events.iter().all(|e| e.redaction_count() > 0));
    assert!(rec.events.iter().all(|e| e.is_sensitive()));
}
