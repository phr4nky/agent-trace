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
    assert!(rec.events.iter().all(agent_trace_core::Event::is_sensitive));
}

mod regressions {
    use agent_trace_core::Redactor;
    use serde_json::{Value, json};

    fn redacted_text(v: &Value) -> String {
        Redactor::new().redact_value(v).0.to_string()
    }

    // JSON text inside a string, and single-quoted assignments.
    #[test]
    fn quoted_assignments_are_redacted() {
        let r = Redactor::new();
        for (input, secret) in [
            (r#"{"password": "hunter2xyz"}"#, "hunter2xyz"),
            (r#"{"db_password":"S3cretValue!"}"#, "S3cretValue!"),
            ("API_KEY='abc123secret'", "abc123secret"),
            (r#"export TOKEN="tok_live_9876""#, "tok_live_9876"),
        ] {
            let (out, report) = r.redact_str(input);
            assert!(!out.contains(secret), "{input} -> {out}");
            assert!(report.redactions >= 1, "{input}");
        }
        // Prose and ordinary key/value text stay untouched.
        for text in [
            "max_tokens: 5",
            r#"{"tokenizer": "bpe"}"#,
            "the password policy",
        ] {
            let (out, report) = r.redact_str(text);
            assert_eq!((out.as_str(), report.redactions), (text, 0), "{text}");
        }
    }

    // Compound credential field names, not only exact ones.
    #[test]
    fn compound_secret_keys_are_redacted() {
        let v = json!({
            "db_password": "S3cret!",
            "aws_secret_access_key": "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
            "secret_key": "plainvalue1",
            "auth_token": "plainvalue2",
            "OPENAI_API_KEY": "plainvalue3",
            "x-auth-token": "plainvalue4",
            "max_tokens": 512,
            "token_count": 3,
            "tokenizer": "bpe",
        });
        let out = redacted_text(&v);
        for s in [
            "S3cret!",
            "wJalrXUtnFEMI",
            "plainvalue1",
            "plainvalue2",
            "plainvalue3",
            "plainvalue4",
        ] {
            assert!(!out.contains(s), "{s} leaked: {out}");
        }
        assert!(out.contains("512") && out.contains("bpe"), "{out}");
    }

    // Object keys are content too.
    #[test]
    fn secrets_in_object_keys_are_redacted() {
        let v = json!({"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789": 1, "ok": {"sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWX": true}});
        let (out, report) = Redactor::new().redact_value(&v);
        let text = out.to_string();
        assert!(
            !text.contains("ghp_ABCDEF") && !text.contains("sk-ant-api03"),
            "{text}"
        );
        assert_eq!(report.redactions, 2);
    }

    // Passwords containing an unencoded '@' (drivers split at the last '@').
    #[test]
    fn url_password_with_at_sign_is_fully_redacted() {
        let (out, _) = Redactor::new().redact_str("mysql://u:pX@ssMARKER@host/db and more");
        assert!(!out.contains("ssMARKER"), "{out}");
        assert!(out.contains("@host/db"), "{out}");
    }

    // A value that merely starts with the placeholder prefix is still a secret.
    #[test]
    fn placeholder_lookalikes_are_redacted() {
        let r = Redactor::new();
        let (out, _) = r.redact_str("password=[REDACTEDhunter2hunter2");
        assert!(!out.contains("hunter2hunter2"), "{out}");
        let out = redacted_text(&json!({"token": "[REDACTEDhunter2hunter2"}));
        assert!(!out.contains("hunter2hunter2"), "{out}");
        // Real placeholders stay idempotent.
        let (once, _) = r.redact_str("password=hunter2hunter2");
        let (twice, rep) = r.redact_str(&once);
        assert_eq!((once.as_str(), rep.redactions), (twice.as_str(), 0));
    }
}

mod hunt_regressions {
    use agent_trace_core::Redactor;
    use serde_json::{Map, Value, json};

    // Regression: keys that redact to the same text were renamed by probing "#2", "#3", ...
    // from 1 each time, so k colliding keys cost O(k^2); one import line stalled for minutes.
    #[test]
    fn many_colliding_keys_redact_in_linear_time() {
        let k = 20_000;
        let mut obj = Map::new();
        for i in 0..k {
            obj.insert(format!("pwd={i:08}"), Value::from(0));
        }
        let start = std::time::Instant::now();
        let (out, report) = Redactor::new().redact_value(&Value::Object(obj));
        let elapsed = start.elapsed();
        // Generous for debug builds and slow runners; the quadratic version took minutes.
        assert!(
            elapsed < std::time::Duration::from_secs(30),
            "took {elapsed:?}"
        );
        assert_eq!(report.redactions, k as u64);
        // Over the payload limit the value becomes a preview; below it every key survives.
        let small: Map<String, Value> = (0..300)
            .map(|i| (format!("pwd={i:08}"), Value::from(i)))
            .collect();
        let (out_small, _) = Redactor::new().redact_value(&Value::Object(small));
        assert_eq!(out_small.as_object().unwrap().len(), 300);
        assert!(out.is_object());
    }

    // Regression: a truncated string (16 KiB + marker) was truncated again by every later
    // redaction pass (export, re-import), and the marker then reported the old marker's size.
    #[test]
    fn redaction_of_truncated_text_is_idempotent() {
        let r = Redactor::new();
        let (once, rep1) = r.redact_str(&"A".repeat(100_000));
        assert!(rep1.truncated);
        assert!(
            once.ends_with("…[TRUNCATED 83616 bytes]"),
            "{}",
            &once[once.len() - 30..]
        );
        let (twice, rep2) = r.redact_str(&once);
        assert_eq!(once, twice);
        assert!(!rep2.truncated);
        let v = json!({"content": once});
        let (a, _) = r.redact_value(&v);
        assert_eq!(a, v);
        // A marker-like suffix on text that is still too long is truncated normally.
        let fake = format!("{}…[TRUNCATED 1 bytes]", "B".repeat(20_000));
        assert!(r.redact_str(&fake).1.truncated);
    }
}
