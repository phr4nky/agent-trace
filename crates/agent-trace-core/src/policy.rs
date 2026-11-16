//! Tool classification and a small deterministic tool policy.
//!
//! The same configuration is used by the demo's policy gate and by the rules,
//! so "privileged" and "outbound" mean the same thing everywhere.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

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
            let destination = arguments
                .get("destination")
                .or_else(|| arguments.get("url"))
                .and_then(Value::as_str)
                .unwrap_or("");
            if !self.destination_allowed(destination) {
                return PolicyOutcome {
                    decision: Decision::Deny,
                    reason: format!(
                        "outbound destination host {:?} is not on the allowlist",
                        host_of(destination).unwrap_or_default()
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
pub fn host_of(destination: &str) -> Option<String> {
    let rest = destination
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(destination);
    let authority = rest.split(['/', '?', '#']).next()?;
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
