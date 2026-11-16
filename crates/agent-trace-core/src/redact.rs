//! Default-on redaction and payload size limiting.
//!
//! Every output path (storage, JSONL, exports, logs, TUI) must go through the
//! same [`Redactor`]. Redaction is pattern based and therefore best effort:
//! unknown secret formats can slip through (documented residual risk).

use std::sync::OnceLock;

use regex::{Captures, Regex};
use serde_json::{Map, Value};

/// Maximum size of a single string value inside a payload.
pub const MAX_STRING_BYTES: usize = 16 * 1024;
/// Maximum serialized size of a whole payload after string truncation.
pub const MAX_PAYLOAD_BYTES: usize = 256 * 1024;
/// Prefix of all redaction placeholders.
pub const REDACTED_PREFIX: &str = "[REDACTED";

/// Result of redacting one value.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RedactionReport {
    /// Number of secret values that were replaced.
    pub redactions: u64,
    /// Whether any data was truncated because of size limits.
    pub truncated: bool,
}

impl RedactionReport {
    fn merge(&mut self, other: RedactionReport) {
        self.redactions += other.redactions;
        self.truncated |= other.truncated;
    }
}

struct Pattern {
    label: &'static str,
    regex: Regex,
    /// Capture group holding the secret value; `0` replaces the whole match.
    value_group: usize,
    /// Extra check on the captured value (e.g. "looks like a token", not an English word).
    accept: fn(&str) -> bool,
}

fn any_value(_: &str) -> bool {
    true
}

/// Credentials after `Bearer`/`Basic` are long and contain digits or token punctuation;
/// ordinary words ("basic configuration", "bearer bonds") do not.
fn looks_like_token(value: &str) -> bool {
    value.len() >= 12
        && value
            .chars()
            .any(|c| c.is_ascii_digit() || "._~+/=-".contains(c))
}

fn patterns() -> &'static [Pattern] {
    static PATTERNS: OnceLock<Vec<Pattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let p = |label, re: &str, value_group| Pattern {
            label,
            regex: Regex::new(re).expect("valid redaction regex"),
            value_group,
            accept: any_value,
        };
        let checked = |label, re: &str, value_group, accept: fn(&str) -> bool| Pattern {
            label,
            regex: Regex::new(re).expect("valid redaction regex"),
            value_group,
            accept,
        };
        vec![
            p(
                "private_key",
                r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
                0,
            ),
            // Header context: everything after the scheme is a credential.
            p(
                "auth_header",
                r#"(?i)\b(?:proxy-)?authorization\s*[:=]\s*"?(?:bearer|basic|token|digest)?\s*([^\s"',;]{6,})"#,
                1,
            ),
            // Free text: only values that look like tokens.
            checked(
                "bearer",
                r"(?i)\b(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{8,})",
                1,
                looks_like_token,
            ),
            p(
                "jwt",
                r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
                0,
            ),
            p("api_key", r"\bsk-(?:ant-)?[A-Za-z0-9_-]{16,}", 0),
            p(
                "github_token",
                r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}",
                0,
            ),
            p("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b", 0),
            p("slack_token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}", 0),
            p(
                "url_credentials",
                // Greedy up to the *last* '@' of the authority: drivers split there, so a
                // password with an unencoded '@' must be covered completely.
                r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]*:([^\s/]+)@",
                1,
            ),
            p(
                "test_secret",
                r"\b(?:FAKE|TEST|DUMMY)_SECRET[A-Z0-9_]*\b",
                0,
            ),
            p(
                "assignment",
                // The key may be quoted (JSON text, `KEY='v'`), and so may the value.
                r#"(?i)\b[A-Z0-9_.-]*(?:api[_-]?key|token|secret|passw(?:or)?d|pwd|credential)[A-Z0-9_.-]*["']?\s*[:=]\s*["']?([^\s"',;]{4,})"#,
                1,
            ),
        ]
    })
}

fn sensitive_key() -> &'static Regex {
    static KEY: OnceLock<Regex> = OnceLock::new();
    KEY.get_or_init(|| {
        Regex::new(
            r"(?i)^(?:authorization|proxy[-_]authorization|cookie|set[-_]cookie|password|passwd|secret|client[-_]secret|api[-_]?key|x[-_]api[-_]key|access[-_]token|refresh[-_]token|id[-_]token|token|private[-_]key|session[-_]?id)$",
        )
        .expect("valid key regex")
    })
}

/// Words that mark a key as holding a secret when they appear as one of its segments
/// (`db_password`, `aws_secret_access_key`, `x-auth-token`, `githubToken`).
const SECRET_KEY_WORDS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "secret",
    "token",
    "apikey",
    "credential",
    "credentials",
    "cookie",
    "authorization",
];
/// Adjacent segment pairs with the same meaning (`api_key`, `private-key`, `access_key`).
const SECRET_KEY_PAIRS: &[(&str, &str)] = &[
    ("api", "key"),
    ("private", "key"),
    ("access", "key"),
    ("session", "id"),
];

/// Split a key into lowercase segments at punctuation and camelCase boundaries.
fn key_segments(key: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in key.chars() {
        if !c.is_ascii_alphanumeric() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            prev_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && prev_lower && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        cur.push(c.to_ascii_lowercase());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Whether a key names a secret by one of its segments. Counters such as `max_tokens` or
/// `token_count` only match when their value is a string (see `redact_inner`).
fn secret_key_by_segment(key: &str) -> bool {
    let segs = key_segments(key);
    segs.iter().any(|s| SECRET_KEY_WORDS.contains(&s.as_str()))
        || segs
            .windows(2)
            .any(|w| SECRET_KEY_PAIRS.contains(&(w[0].as_str(), w[1].as_str())))
}

/// Whether `value` is one of our placeholders (`[REDACTED:<label>]`), optionally followed by
/// punctuation picked up by a pattern. A value that only *starts* with the prefix, or that
/// carries more text after the placeholder, is redacted like any other.
fn is_placeholder(value: &str) -> bool {
    let Some(rest) = value
        .strip_prefix(REDACTED_PREFIX)
        .and_then(|rest| rest.strip_prefix(':'))
    else {
        return false;
    };
    let Some((label, tail)) = rest.split_once(']') else {
        return false;
    };
    !label.is_empty()
        && label.chars().all(|c| c.is_ascii_lowercase() || c == '_')
        && !tail.chars().any(char::is_alphanumeric)
}

/// Redacts secrets and enforces size limits.
#[derive(Debug, Clone, Default)]
pub struct Redactor;

impl Redactor {
    pub fn new() -> Self {
        Self
    }

    /// Redact secrets inside a free-form string.
    pub fn redact_str(&self, input: &str) -> (String, RedactionReport) {
        let mut report = RedactionReport::default();
        let mut text = input.to_owned();
        for pattern in patterns() {
            let placeholder = format!("{REDACTED_PREFIX}:{}]", pattern.label);
            let replaced = pattern.regex.replace_all(&text, |caps: &Captures<'_>| {
                let whole = caps.get(0).expect("group 0");
                let Some(value) = caps.get(pattern.value_group) else {
                    return whole.as_str().to_owned();
                };
                if is_placeholder(value.as_str()) || !(pattern.accept)(value.as_str()) {
                    return whole.as_str().to_owned();
                }
                report.redactions += 1;
                let start = value.start() - whole.start();
                let end = value.end() - whole.start();
                let w = whole.as_str();
                format!("{}{}{}", &w[..start], placeholder, &w[end..])
            });
            if let std::borrow::Cow::Owned(new_text) = replaced {
                text = new_text;
            }
        }
        if text.len() > MAX_STRING_BYTES {
            let original = text.len();
            let cut = floor_char_boundary(&text, MAX_STRING_BYTES);
            text.truncate(cut);
            text.push_str(&format!("…[TRUNCATED {} bytes]", original - cut));
            report.truncated = true;
        }
        (text, report)
    }

    /// Convenience wrapper returning only the redacted text (for logs / UI).
    pub fn scrub(&self, input: &str) -> String {
        self.redact_str(input).0
    }

    /// Redact a JSON value recursively (keys and values) and enforce the payload size limit.
    pub fn redact_value(&self, value: &Value) -> (Value, RedactionReport) {
        let mut report = RedactionReport::default();
        let mut redacted = self.redact_inner(value, &mut report);
        let size = serde_json::to_vec(&redacted).map(|v| v.len()).unwrap_or(0);
        if size > MAX_PAYLOAD_BYTES {
            let text = redacted.to_string();
            let cut = floor_char_boundary(&text, 4096);
            let mut preview = Map::new();
            preview.insert("truncated".into(), Value::Bool(true));
            preview.insert("original_bytes".into(), Value::from(size as u64));
            preview.insert("preview".into(), Value::String(text[..cut].to_owned()));
            redacted = Value::Object(preview);
            report.truncated = true;
        }
        (redacted, report)
    }

    fn redact_inner(&self, value: &Value, report: &mut RedactionReport) -> Value {
        match value {
            Value::String(s) => {
                let (text, r) = self.redact_str(s);
                report.merge(r);
                Value::String(text)
            }
            Value::Array(items) => {
                Value::Array(items.iter().map(|v| self.redact_inner(v, report)).collect())
            }
            Value::Object(map) => {
                let mut out = Map::new();
                for (key, v) in map {
                    let is_secret_key = sensitive_key().is_match(key)
                        || (v.is_string() && secret_key_by_segment(key));
                    let already = v.as_str().is_some_and(is_placeholder);
                    let new_value = if is_secret_key && !v.is_null() && !already {
                        report.redactions += 1;
                        Value::String(format!("{REDACTED_PREFIX}:field]"))
                    } else {
                        self.redact_inner(v, report)
                    };
                    // Keys are content too: a token used as a key must not survive.
                    let (redacted_key, key_report) = self.redact_str(key);
                    report.merge(key_report);
                    let mut new_key = redacted_key.clone();
                    let mut n = 1;
                    while out.contains_key(&new_key) {
                        n += 1;
                        new_key = format!("{redacted_key}#{n}");
                    }
                    out.insert(new_key, new_value);
                }
                Value::Object(out)
            }
            other => other.clone(),
        }
    }
}

fn floor_char_boundary(s: &str, mut index: usize) -> usize {
    if index >= s.len() {
        return s.len();
    }
    while !s.is_char_boundary(index) {
        index -= 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_common_token_formats() {
        let r = Redactor::new();
        let cases = [
            "Authorization: Bearer abcdefghijklmnop1234",
            "key sk-ant-api03-ABCDEFGHIJKLMNOPQRST",
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
            "AKIAABCDEFGHIJKLMNOP",
            "postgres://trace:S3cretPassw0rd@db.example:5432/traces",
            "API_TOKEN=FAKE_SECRET_FOR_TESTING_ONLY",
            "password: hunter2hunter2",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlMTIz",
        ];
        for case in cases {
            let (out, report) = r.redact_str(case);
            assert!(report.redactions >= 1, "not redacted: {case} -> {out}");
            assert!(out.contains(REDACTED_PREFIX), "{out}");
        }
    }

    #[test]
    fn no_false_positives_in_prose() {
        let r = Redactor::new();
        for text in [
            "It documents basic configuration for local use.",
            "Bearer bonds are an old financial instrument.",
            "Basic Authentication is described in RFC 7617.",
        ] {
            let (out, report) = r.redact_str(text);
            assert_eq!(out, text, "over-redacted: {out}");
            assert_eq!(report.redactions, 0);
        }
        // ...but real credentials are still caught, with or without header context.
        for secret in [
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
            "curl -H 'authorization: Basic dXNlcjpwYXNzd29yZA=='",
            "use Bearer eyJhbGciOiJI.abc.def to call it",
            "token Basic dXNlcjpwYXNzd29yZA== here",
        ] {
            let (out, report) = r.redact_str(secret);
            assert!(report.redactions >= 1, "not redacted: {secret} -> {out}");
            assert!(
                !out.contains("abcdefghijklmnopqrstuvwxyz") && !out.contains("dXNlcjpwYXNzd29yZA"),
                "{out}"
            );
        }
    }

    #[test]
    fn leaves_normal_text_alone() {
        let r = Redactor::new();
        let text = "This project summarizes README files. max_tokens: 5";
        let (out, report) = r.redact_str(text);
        assert_eq!(out, text);
        assert_eq!(report.redactions, 0);
    }

    #[test]
    fn redaction_is_idempotent() {
        let r = Redactor::new();
        let (once, _) =
            r.redact_str("API_TOKEN=FAKE_SECRET_FOR_TESTING_ONLY and Bearer abcdefghijkl");
        let (twice, report) = r.redact_str(&once);
        assert_eq!(once, twice);
        assert_eq!(report.redactions, 0);
        let v = json!({"authorization": "x", "nested": [{"token": "abc"}]});
        let (a, _) = r.redact_value(&v);
        let (b, rep) = r.redact_value(&a);
        assert_eq!(a, b);
        assert_eq!(rep.redactions, 0);
    }

    #[test]
    fn redacts_sensitive_keys() {
        let r = Redactor::new();
        let (v, report) = r.redact_value(&json!({
            "headers": {"Authorization": "whatever", "Cookie": "a=b"},
            "destination": "https://example.invalid"
        }));
        assert_eq!(report.redactions, 2);
        assert_eq!(v["destination"], "https://example.invalid");
        assert_eq!(v["headers"]["Cookie"], "[REDACTED:field]");
    }

    #[test]
    fn truncates_large_strings_and_payloads() {
        let r = Redactor::new();
        let big = "a".repeat(MAX_STRING_BYTES + 10);
        let (out, report) = r.redact_str(&big);
        assert!(report.truncated);
        assert!(out.ends_with("[TRUNCATED 10 bytes]"));

        let many: Vec<Value> = (0..40).map(|_| Value::String("b".repeat(10_000))).collect();
        let (v, report) = r.redact_value(&Value::Array(many));
        assert!(report.truncated);
        assert_eq!(v["truncated"], true);
    }
}
