//! Tool classification and a small deterministic tool policy.
//!
//! The same configuration is used by the demo's policy gate and by the rules,
//! so "privileged" and "outbound" mean the same thing everywhere.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Argument names that carry where an outbound tool sends data.
pub const DESTINATION_KEYS: &[&str] = &[
    "destination",
    "url",
    "uri",
    "endpoint",
    "webhook_url",
    "to",
    "recipient",
    "recipients",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolPolicy {
    /// Tools that change state or act with the agent's privileges.
    pub privileged_tools: Vec<String>,
    /// Tools that transmit data outside the local machine.
    pub outbound_tools: Vec<String>,
    /// Hosts outbound tools may send to.
    pub destination_allowlist: Vec<String>,
}

impl Default for ToolPolicy {
    fn default() -> Self {
        Self {
            privileged_tools: [
                "run_command",
                "run_command_mock",
                "exec",
                "shell",
                "write_file",
                "delete_file",
                "send_webhook",
                "send_webhook_mock",
                "http_request",
                "send_email",
            ]
            .map(String::from)
            .to_vec(),
            outbound_tools: [
                "send_webhook",
                "send_webhook_mock",
                "http_request",
                "send_email",
                "upload_file",
            ]
            .map(String::from)
            .to_vec(),
            destination_allowlist: ["localhost", "127.0.0.1", "::1"].map(String::from).to_vec(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyOutcome {
    pub decision: Decision,
    pub reason: String,
}

impl ToolPolicy {
    pub fn is_privileged(&self, tool: &str) -> bool {
        self.privileged_tools.iter().any(|t| t == tool) || self.is_outbound(tool)
    }

    pub fn is_outbound(&self, tool: &str) -> bool {
        self.outbound_tools.iter().any(|t| t == tool)
    }

    /// The first destination argument of an outbound call that is not allowlisted.
    /// Every destination-like argument is checked, because the tool may use any of them;
    /// a call without a readable destination is reported as disallowed (empty string).
    pub fn disallowed_destination(&self, arguments: &Map<String, Value>) -> Option<String> {
        let mut found = false;
        for key in DESTINATION_KEYS {
            let Some(value) = arguments.get(*key) else {
                continue;
            };
            let values: Vec<&Value> = match value {
                Value::Array(items) => items.iter().collect(),
                other => vec![other],
            };
            for v in values {
                found = true;
                match v.as_str() {
                    Some(d) if self.destination_allowed(d) => {}
                    Some(d) => return Some(d.to_owned()),
                    None => return Some(String::new()),
                }
            }
        }
        (!found).then(String::new)
    }

    pub fn destination_allowed(&self, destination: &str) -> bool {
        host_of(destination).is_some_and(|host| {
            self.destination_allowlist
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(&host))
        })
    }

    /// Evaluate a tool request. Outbound tools are denied unless the destination is allowlisted.
    pub fn evaluate(&self, tool: &str, arguments: &Map<String, Value>) -> PolicyOutcome {
        if self.is_outbound(tool) {
            if let Some(destination) = self.disallowed_destination(arguments) {
                return PolicyOutcome {
                    decision: Decision::Deny,
                    reason: format!(
                        "outbound destination host {:?} is not on the allowlist",
                        host_of(&destination).unwrap_or_default()
                    ),
                };
            }
            return PolicyOutcome {
                decision: Decision::Allow,
                reason: "destination allowlisted".into(),
            };
        }
        if self.is_privileged(tool) {
            return PolicyOutcome {
                decision: Decision::Allow,
                reason: "privileged tool allowed (mock-only implementation in this environment)"
                    .into(),
            };
        }
        PolicyOutcome {
            decision: Decision::Allow,
            reason: "read-only tool".into(),
        }
    }
}

/// Extract the host of a URL-like destination without any network resolution.
///
/// The authority ends at `/`, `\\`, `?` or `#`, as in WHATWG URL parsing for http(s), so the
/// host agrees with what real HTTP clients connect to. Authorities containing whitespace or
/// control characters are ambiguous between parsers and yield `None` (callers deny).
pub fn host_of(destination: &str) -> Option<String> {
    let rest = destination
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(destination);
    let authority = rest.split(['/', '\\', '?', '#']).next()?;
    if authority
        .chars()
        .any(|c| c.is_whitespace() || c.is_control())
    {
        return None;
    }
    let authority = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        stripped.split(']').next()?.to_owned()
    } else {
        authority.split(':').next()?.to_owned()
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn host_parsing() {
        assert_eq!(
            host_of("https://example.invalid/mock").as_deref(),
            Some("example.invalid")
        );
        assert_eq!(
            host_of("http://user:pw@LOCALHOST:8080/x").as_deref(),
            Some("localhost")
        );
        assert_eq!(host_of("http://[::1]:80/").as_deref(), Some("::1"));
        assert_eq!(host_of(""), None);
    }

    // Regression: WHATWG parsers (browsers, Node, the `url` crate behind reqwest) end the
    // authority at a backslash for http(s), so `http://evil\\@localhost/` goes to `evil`.
    #[test]
    fn host_parsing_matches_real_clients_on_ambiguous_input() {
        assert_eq!(
            host_of("https://marker.invalid\\@localhost/x").as_deref(),
            Some("marker.invalid")
        );
        assert_eq!(
            host_of("http://marker.invalid/@localhost").as_deref(),
            Some("marker.invalid")
        );
        assert_eq!(
            host_of("http://localhost@marker.invalid/").as_deref(),
            Some("marker.invalid")
        );
        // Whitespace or control characters in the authority: no host, so outbound is denied.
        assert_eq!(host_of("http://marker.invalid\t@localhost/"), None);
        assert_eq!(host_of("http://local host/"), None);
        let p = ToolPolicy::default();
        assert!(!p.destination_allowed("https://marker.invalid\\@localhost/x"));
        assert!(!p.destination_allowed("http://marker.invalid\t@localhost/"));
    }

    // Regression: a request carrying an allowlisted `destination` and a different `url`
    // was judged only on `destination`.
    #[test]
    fn every_destination_argument_must_be_allowlisted() {
        let p = ToolPolicy::default();
        for args in [
            json!({"destination": "http://localhost/", "url": "https://marker.invalid/x"}),
            json!({"url": "http://localhost/", "endpoint": "https://marker.invalid/x"}),
            json!({"to": ["ops@localhost", "someone@marker.invalid"]}),
            json!({"destination": 42}),
            json!({}),
        ] {
            let out = p.evaluate("http_request", args.as_object().unwrap());
            assert_eq!(out.decision, Decision::Deny, "{args}");
        }
        let args = json!({"destination": "http://localhost/", "url": "http://127.0.0.1:8080/"});
        let out = p.evaluate("http_request", args.as_object().unwrap());
        assert_eq!(out.decision, Decision::Allow);
    }

    #[test]
    fn denies_unlisted_outbound() {
        let p = ToolPolicy::default();
        let args = json!({"destination": "https://example.invalid/mock-endpoint"});
        let out = p.evaluate("send_webhook_mock", args.as_object().unwrap());
        assert_eq!(out.decision, Decision::Deny);
        let args = json!({"destination": "http://localhost/hook"});
        let out = p.evaluate("send_webhook_mock", args.as_object().unwrap());
        assert_eq!(out.decision, Decision::Allow);
    }
}
