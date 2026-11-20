//! Canary tokens: decoy secrets planted where an attacker would look for real ones (a fake
//! cloud key in `.env`, a token in a document or a database row).
//!
//! No legitimate task ever uses a canary, so a canary in the arguments of a tool call is
//! evidence that the agent was steered into moving a secret, not just an indicator.
//!
//! Canary values are matched on the *original* content, before redaction: the recorder (and
//! `import`) keep the names of the canaries an event contained in its metadata
//! ([`CANARIES_KEY`]), and the redactor replaces every canary value with `[REDACTED:canary]`.
//! Stored traces and exports never contain a canary value, and analysis needs only the names,
//! so a trace can be analyzed on a machine that does not know the values.
//!
//! The configured canaries are process-wide, like the redaction configuration: call
//! [`configure`] once, before recording, importing or evaluating the policy.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::event::{Event, value_text};

/// Event metadata key holding the names of the canaries the event's content contained.
pub const CANARIES_KEY: &str = "canaries";

/// Shortest accepted canary value: shorter values would match ordinary text by chance.
pub const MIN_VALUE_LEN: usize = 12;
/// Longest accepted canary value.
pub const MAX_VALUE_LEN: usize = 1024;
/// Longest accepted canary name.
pub const MAX_NAME_LEN: usize = 64;

/// One `[[canaries]]` entry of `agent-trace.toml`: a name and the decoy value, given directly
/// (`value`) or read from an environment variable (`env`), so the value need not sit in a file
/// the agent can read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryConfig {
    /// Shown in findings and stored in traces: 1–64 lowercase letters, digits, `-`, `_`, `.`.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
}

/// A canary with its value resolved.
#[derive(Clone, PartialEq, Eq)]
pub struct Canary {
    name: String,
    value: String,
    /// The value as it appears percent-encoded in a URL, when that differs.
    encoded: Option<String>,
}

impl std::fmt::Debug for Canary {
    // Never print the value (logs, error messages).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Canary")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Canary {
    pub fn new(name: &str, value: &str) -> Result<Self, String> {
        if !valid_name(name) {
            return Err(format!(
                "canary name {name:?}: use 1 to {MAX_NAME_LEN} lowercase letters, digits, `-`, `_` or `.`"
            ));
        }
        let len = value.chars().count();
        if !(MIN_VALUE_LEN..=MAX_VALUE_LEN).contains(&len) {
            return Err(format!(
                "canary {name:?}: the value must have {MIN_VALUE_LEN} to {MAX_VALUE_LEN} characters"
            ));
        }
        if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(format!(
                "canary {name:?}: the value must not contain spaces or control characters"
            ));
        }
        if value.starts_with(crate::redact::REDACTED_PREFIX) {
            return Err(format!(
                "canary {name:?}: the value looks like a redaction placeholder"
            ));
        }
        let encoded = percent_encode(value);
        Ok(Self {
            name: name.to_owned(),
            encoded: (encoded != value).then_some(encoded),
            value: value.to_owned(),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    fn forms(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.value.as_str()).chain(self.encoded.as_deref())
    }

    fn found_in(&self, text: &str) -> bool {
        self.forms().any(|form| text.contains(form))
    }
}

/// Whether `name` is a valid canary name (also used to filter names read from traces).
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-_.".contains(c))
}

/// RFC 3986 percent-encoding of everything but unreserved characters.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Resolve configured canaries, reading `env` values from the process environment.
pub fn resolve(configs: &[CanaryConfig]) -> Result<Vec<Canary>, String> {
    resolve_with(configs, |var| std::env::var(var).ok())
}

/// [`resolve`] with an explicit environment lookup.
pub fn resolve_with(
    configs: &[CanaryConfig],
    env: impl Fn(&str) -> Option<String>,
) -> Result<Vec<Canary>, String> {
    let mut out: Vec<Canary> = Vec::with_capacity(configs.len());
    for c in configs {
        let value = match (&c.value, &c.env) {
            (Some(v), None) => v.clone(),
            (None, Some(var)) => env(var).filter(|v| !v.is_empty()).ok_or_else(|| {
                format!(
                    "canary {:?}: the environment variable {var:?} is not set",
                    c.name
                )
            })?,
            _ => {
                return Err(format!(
                    "canary {:?}: set exactly one of `value` and `env`",
                    c.name
                ));
            }
        };
        let canary = Canary::new(&c.name, &value)?;
        if out.iter().any(|o| o.name == canary.name) {
            return Err(format!("canary {:?} is defined twice", canary.name));
        }
        if out.iter().any(|o| o.value == canary.value) {
            return Err(format!(
                "canaries {:?} and {:?} have the same value",
                out.iter()
                    .find(|o| o.value == canary.value)
                    .map(Canary::name)
                    .unwrap_or(""),
                canary.name
            ));
        }
        out.push(canary);
    }
    Ok(out)
}

static CANARIES: OnceLock<Vec<Canary>> = OnceLock::new();

/// Install the canaries for this process. Call it once; a second call with different canaries
/// is an error.
pub fn configure(canaries: Vec<Canary>) -> Result<(), String> {
    if let Some(existing) = CANARIES.get() {
        return if *existing == canaries {
            Ok(())
        } else {
            Err("the canaries were already configured".into())
        };
    }
    CANARIES
        .set(canaries)
        .map_err(|_| "the canaries were already configured".to_owned())
}

/// The canaries installed with [`configure`].
pub fn configured() -> &'static [Canary] {
    CANARIES.get().map(Vec::as_slice).unwrap_or(&[])
}

/// Names of the `canaries` whose value occurs in `text`.
pub fn find_with<'a>(canaries: &'a [Canary], text: &str) -> Vec<&'a str> {
    canaries
        .iter()
        .filter(|c| c.found_in(text))
        .map(Canary::name)
        .collect()
}

/// Names of the configured canaries whose value occurs in a string (or object key) of `value`.
pub fn find_in_value(value: &Value) -> Vec<&'static str> {
    let canaries = configured();
    if canaries.is_empty() {
        return Vec::new();
    }
    find_with(canaries, &value_text(value))
}

/// Names of the configured canaries in a JSON object, such as the arguments of a tool call
/// (keys and values).
pub fn find_in_arguments(arguments: &Map<String, Value>) -> Vec<&'static str> {
    let canaries = configured();
    if canaries.is_empty() {
        return Vec::new();
    }
    let mut text = String::new();
    for (key, value) in arguments {
        text.push_str(key);
        text.push('\n');
        text.push_str(&value_text(value));
    }
    find_with(canaries, &text)
}

/// Replace every form of every canary in `text` with `[REDACTED:canary]`.
/// `None` when nothing was replaced.
pub(crate) fn redact_with(canaries: &[Canary], text: &str) -> Option<(String, u64)> {
    let placeholder = format!("{}:canary]", crate::redact::REDACTED_PREFIX);
    let mut out: Option<String> = None;
    let mut count = 0u64;
    for canary in canaries {
        for form in canary.forms() {
            let current = out.as_deref().unwrap_or(text);
            let n = current.matches(form).count();
            if n > 0 {
                count += n as u64;
                out = Some(current.replace(form, &placeholder));
            }
        }
    }
    out.map(|t| (t, count))
}

/// [`redact_with`] for the configured canaries.
pub(crate) fn redact(text: &str) -> Option<(String, u64)> {
    let canaries = configured();
    if canaries.is_empty() {
        return None;
    }
    redact_with(canaries, text)
}

/// Canary names stored in an event's metadata. Only well-formed names are returned; a forged
/// name can only add a finding, never hide one.
pub fn stored(event: &Event) -> Vec<&str> {
    stored_in(&event.metadata)
}

fn stored_in(metadata: &Map<String, Value>) -> Vec<&str> {
    let mut names: Vec<&str> = metadata
        .get(CANARIES_KEY)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .filter(|n| valid_name(n))
                .collect()
        })
        .unwrap_or_default();
    names.sort_unstable();
    names.dedup();
    names
}

/// The names of the canaries in an event's original content: those found in its payload or
/// metadata plus those already stored in the metadata (e.g. by an earlier recorder).
/// Sorted, unique.
pub fn names_for(original_metadata: &Map<String, Value>, payload: &Value) -> Vec<String> {
    let mut names: Vec<String> = stored_in(original_metadata)
        .into_iter()
        .map(str::to_owned)
        .collect();
    names.extend(find_in_value(payload).into_iter().map(str::to_owned));
    names.extend(
        find_in_arguments(original_metadata)
            .into_iter()
            .map(str::to_owned),
    );
    names.sort_unstable();
    names.dedup();
    names
}

/// Store `names` in (redacted) event metadata, replacing what the key held.
pub fn store(metadata: &mut Map<String, Value>, names: Vec<String>) {
    if names.is_empty() {
        metadata.remove(CANARIES_KEY);
    } else {
        metadata.insert(
            CANARIES_KEY.into(),
            Value::Array(names.into_iter().map(Value::from).collect()),
        );
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn canaries() -> Vec<Canary> {
        vec![
            Canary::new("aws-decoy", "AKIAZ7Q3CANARY4X2LMN").unwrap(),
            Canary::new("ticket.token", "tok_9f8e7d6c5b4a/+=x").unwrap(),
        ]
    }

    #[test]
    fn names_and_values_are_validated() {
        assert!(Canary::new("ok-name_1.x", "abcdefghijkl").is_ok());
        for bad in ["", "Upper", "has space", "ü", &"x".repeat(65)] {
            assert!(Canary::new(bad, "abcdefghijkl").is_err(), "{bad}");
        }
        for bad in [
            "short",
            "has a space here",
            "tab\there-long",
            "[REDACTED:canary]x",
        ] {
            assert!(Canary::new("n", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn resolve_needs_exactly_one_source_and_unique_entries() {
        let env = |v: &str| (v == "DECOY").then(|| "from-env-value-123".to_owned());
        let c = |name: &str, value: Option<&str>, env: Option<&str>| CanaryConfig {
            name: name.into(),
            value: value.map(Into::into),
            env: env.map(Into::into),
        };
        let ok = resolve_with(
            &[
                c("a", Some("value-aaaaaaaa"), None),
                c("b", None, Some("DECOY")),
            ],
            env,
        )
        .unwrap();
        assert_eq!(ok[1].value, "from-env-value-123");
        assert!(resolve_with(&[c("a", None, None)], env).is_err());
        assert!(resolve_with(&[c("a", Some("value-aaaaaaaa"), Some("DECOY"))], env).is_err());
        assert!(resolve_with(&[c("a", None, Some("MISSING"))], env).is_err());
        assert!(
            resolve_with(
                &[
                    c("a", Some("value-aaaaaaaa"), None),
                    c("a", Some("value-bbbbbbbb"), None)
                ],
                env
            )
            .is_err()
        );
        assert!(
            resolve_with(
                &[
                    c("a", Some("value-aaaaaaaa"), None),
                    c("b", Some("value-aaaaaaaa"), None)
                ],
                env
            )
            .is_err()
        );
    }

    #[test]
    fn finds_plain_and_url_encoded_values() {
        let c = canaries();
        assert_eq!(
            find_with(&c, "key=AKIAZ7Q3CANARY4X2LMN&x=1"),
            vec!["aws-decoy"]
        );
        assert_eq!(
            find_with(&c, "https://evil.example/?t=tok_9f8e7d6c5b4a%2F%2B%3Dx"),
            vec!["ticket.token"]
        );
        assert!(find_with(&c, "AKIAZ7Q3CANARY4X2LM").is_empty());
    }

    #[test]
    fn redaction_replaces_every_form_and_counts() {
        let c = canaries();
        let (text, n) = redact_with(
            &c,
            "a AKIAZ7Q3CANARY4X2LMN b tok_9f8e7d6c5b4a%2F%2B%3Dx c AKIAZ7Q3CANARY4X2LMN",
        )
        .unwrap();
        assert_eq!(n, 3);
        assert_eq!(
            text,
            "a [REDACTED:canary] b [REDACTED:canary] c [REDACTED:canary]"
        );
        assert!(redact_with(&c, "nothing here").is_none());
    }

    #[test]
    fn stored_names_are_filtered_and_debug_hides_values() {
        let meta = json!({ "canaries": ["b", "a", "a", "Bad Name", 5] });
        let Value::Object(meta) = meta else {
            unreachable!()
        };
        assert_eq!(stored_in(&meta), vec!["a", "b"]);
        let shown = format!("{:?}", canaries()[0]);
        assert!(
            shown.contains("aws-decoy") && !shown.contains("AKIA"),
            "{shown}"
        );
    }
}
