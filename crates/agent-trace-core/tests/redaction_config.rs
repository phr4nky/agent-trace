//! Configured redaction rules (process-wide, so they get their own test binary).

use agent_trace_core::Redactor;
use agent_trace_core::redact::{PatternConfig, RedactionConfig, configure, validate_config};
use serde_json::json;

#[test]
fn configured_patterns_and_keys_are_redacted_everywhere() {
    // Invalid configurations are rejected before anything is installed.
    for bad in [
        RedactionConfig {
            patterns: vec![PatternConfig {
                label: "Corp".into(),
                regex: "x".into(),
            }],
            keys: vec![],
        },
        RedactionConfig {
            patterns: vec![PatternConfig {
                label: "corp".into(),
                regex: "(".into(),
            }],
            keys: vec![],
        },
        RedactionConfig {
            patterns: vec![PatternConfig {
                label: "corp".into(),
                regex: "a*".into(),
            }],
            keys: vec![],
        },
    ] {
        assert!(validate_config(&bad).is_err(), "{bad:?}");
        assert!(configure(&bad).is_err());
    }

    let r = Redactor::new();
    let before = r.scrub("ticket CORP-ABCDEFGHIJKLMNOPQRST and pin 4711-0815");
    assert!(
        before.contains("CORP-ABCDEFGHIJKLMNOPQRST"),
        "not configured yet"
    );

    let config = RedactionConfig {
        patterns: vec![
            PatternConfig {
                label: "corp_token".into(),
                regex: r"\bCORP-[A-Z0-9]{20}\b".into(),
            },
            PatternConfig {
                label: "pin".into(),
                regex: r"pin (?P<value>\d{4}-\d{4})".into(),
            },
        ],
        keys: vec!["X-Corp-Auth".into()],
    };
    configure(&config).unwrap();
    configure(&config).unwrap(); // the same configuration again is fine
    assert!(
        configure(&RedactionConfig::default()).is_err(),
        "no silent replacement"
    );

    let after = r.scrub("ticket CORP-ABCDEFGHIJKLMNOPQRST and pin 4711-0815");
    assert_eq!(after, "ticket [REDACTED:corp_token] and pin [REDACTED:pin]");
    // Idempotent: placeholders are not redacted again.
    assert_eq!(r.scrub(&after), after);

    let (value, report) = r.redact_value(&json!({
        "headers": {"x_corp_auth": "abc", "accept": "text/plain"},
        "note": "use CORP-ABCDEFGHIJKLMNOPQRST"
    }));
    assert_eq!(value["headers"]["x_corp_auth"], "[REDACTED:field]");
    assert_eq!(value["headers"]["accept"], "text/plain");
    assert_eq!(value["note"], "use [REDACTED:corp_token]");
    assert_eq!(report.redactions, 2);
    // Built-in rules still apply.
    assert!(
        r.scrub("API_TOKEN=FAKE_SECRET_FOR_TESTING_ONLY")
            .contains("[REDACTED")
    );
}
