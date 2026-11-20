//! Tool classification and a small deterministic tool policy.
//!
//! The same configuration is used by the demo's policy gate and by the rules,
//! so "privileged" and "outbound" mean the same thing everywhere.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Argument names that carry where an outbound tool sends data. Matching is by
/// [`is_destination_key`]: case-insensitive, `-`/`_` alike, plus any `*_url` / `*_uri` /
/// `*_endpoint` name.
pub const DESTINATION_KEYS: &[&str] = &[
    "destination",
    "url",
    "uri",
    "endpoint",
    "webhook",
    "webhook_url",
    "host",
    "to",
    "cc",
    "bcc",
    "reply_to",
    "recipient",
    "recipients",
];

/// Argument names whose string value may be a list of mail recipients (`a@x, b@y`).
const RECIPIENT_KEYS: &[&str] = &["to", "cc", "bcc", "reply_to", "recipient", "recipients"];

fn normalize_key(key: &str) -> String {
    key.trim().to_ascii_lowercase().replace('-', "_")
}

/// Whether an argument name designates a destination (see [`DESTINATION_KEYS`]).
pub fn is_destination_key(key: &str) -> bool {
    let k = normalize_key(key);
    DESTINATION_KEYS.contains(&k.as_str())
        || ["_url", "_uri", "_endpoint"].iter().any(|s| k.ends_with(s))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolPolicy {
    /// Tools that change state or act with the agent's privileges.
    /// Entries may use `*` as a wildcard (see [`glob_match`]).
    pub privileged_tools: Vec<String>,
    /// Tools that transmit data outside the local machine (`*` wildcards allowed).
    pub outbound_tools: Vec<String>,
    /// Hosts outbound tools may send to. `*.example.com` allows every subdomain of
    /// `example.com` (not `example.com` itself).
    pub destination_allowlist: Vec<String>,
}

/// User additions to the default [`ToolPolicy`] (the `[policy]` table of `agent-trace.toml`).
/// Entries are added to the defaults; the defaults cannot be removed, so a config file can
/// make the policy stricter for tool classes but only widen the destination allowlist.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Additional privileged tool names or patterns.
    #[serde(default)]
    pub privileged: Vec<String>,
    /// Additional outbound tool names or patterns.
    #[serde(default)]
    pub outbound: Vec<String>,
    /// Additional allowed destination hosts (`*.example.com` for subdomains).
    #[serde(default)]
    pub allow_destinations: Vec<String>,
}

/// Match `name` against `pattern`, where `*` matches any run of characters (also none).
/// There are no other special characters; matching is case-sensitive, as MCP tool names are.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let (p, n) = (pattern.as_bytes(), name.as_bytes());
    let (mut pi, mut ni) = (0, 0);
    // Position after the last `*` in the pattern and the name position it was tried at.
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some((pi + 1, ni));
            pi += 1;
        } else if pi < p.len() && p[pi] == n[ni] {
            pi += 1;
            ni += 1;
        } else if let Some((sp, sn)) = star {
            pi = sp;
            ni = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
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
                // Claude Code's built-in tools that run commands or change files.
                "Bash",
                "PowerShell",
                "Write",
                "Edit",
                "MultiEdit",
                "NotebookEdit",
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
    /// The default policy plus the additions of `config`.
    pub fn with_config(mut self, config: &PolicyConfig) -> Self {
        for (list, extra) in [
            (&mut self.privileged_tools, &config.privileged),
            (&mut self.outbound_tools, &config.outbound),
            (&mut self.destination_allowlist, &config.allow_destinations),
        ] {
            for entry in extra {
                let entry = entry.trim();
                if !entry.is_empty() && !list.iter().any(|e| e == entry) {
                    list.push(entry.to_owned());
                }
            }
        }
        self
    }

    pub fn is_privileged(&self, tool: &str) -> bool {
        self.privileged_tools.iter().any(|t| glob_match(t, tool)) || self.is_outbound(tool)
    }

    pub fn is_outbound(&self, tool: &str) -> bool {
        self.outbound_tools.iter().any(|t| glob_match(t, tool))
    }

    /// The first destination argument of an outbound call that is not allowlisted.
    /// Every destination-like argument is checked, because the tool may use any of them;
    /// a call without a readable destination is reported as disallowed (empty string).
    pub fn disallowed_destination(&self, arguments: &Map<String, Value>) -> Option<String> {
        let mut found = false;
        for (key, value) in arguments {
            if !is_destination_key(key) {
                continue;
            }
            let values: Vec<&Value> = match value {
                Value::Array(items) => items.iter().collect(),
                other => vec![other],
            };
            for v in values {
                let Some(d) = v.as_str() else {
                    return Some(String::new());
                };
                // A recipient string may list several addresses; every one must be allowed.
                let parts = if RECIPIENT_KEYS.contains(&normalize_key(key).as_str()) {
                    recipients(d)
                } else {
                    vec![d]
                };
                if parts.is_empty() {
                    return Some(d.to_owned());
                }
                found = true;
                if let Some(bad) = parts.iter().find(|p| !self.destination_allowed(p)) {
                    return Some((*bad).to_owned());
                }
            }
        }
        (!found).then(String::new)
    }

    pub fn destination_allowed(&self, destination: &str) -> bool {
        host_of(destination).is_some_and(|host| {
            self.destination_allowlist.iter().any(|allowed| {
                match allowed.strip_prefix("*.") {
                    // Subdomains only: `*.example.com` allows `a.example.com`, and neither
                    // `example.com` nor `evilexample.com`.
                    Some(parent) if !parent.is_empty() => {
                        host.len().checked_sub(parent.len() + 1).is_some_and(|dot| {
                            host.as_bytes()[dot] == b'.'
                                && host[dot + 1..].eq_ignore_ascii_case(parent)
                                && dot > 0
                        })
                    }
                    _ => allowed.eq_ignore_ascii_case(&host),
                }
            })
        })
    }

    /// Evaluate a tool request. Outbound tools are denied unless the destination is allowlisted.
    pub fn evaluate(&self, tool: &str, arguments: &Map<String, Value>) -> PolicyOutcome {
        if let Some(denied) = canary_denial(arguments) {
            return denied;
        }
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

impl ToolPolicy {
    /// The verdict on a tool call in a recorded session, used by the MCP proxy and the
    /// Claude Code hooks. `tainted` names the sources of the lower-trust content that entered
    /// the session so far (oldest first). Denied: an outbound call to a destination that is
    /// not allowlisted, and a privileged call after any tainted content.
    pub fn evaluate_in_session(
        &self,
        tool: &str,
        arguments: &Map<String, Value>,
        tainted: &[&str],
    ) -> PolicyOutcome {
        let deny = |reason: String| PolicyOutcome {
            decision: Decision::Deny,
            reason,
        };
        if let Some(denied) = canary_denial(arguments) {
            return denied;
        }
        if self.is_outbound(tool)
            && let Some(destination) = self.disallowed_destination(arguments)
        {
            return deny(format!(
                "outbound destination host {:?} is not on the allowlist",
                host_of(&destination).unwrap_or_default()
            ));
        }
        if self.is_privileged(tool) && !tainted.is_empty() {
            let mut sources: Vec<&str> = Vec::new();
            for s in tainted.iter().rev() {
                if !sources.contains(s) {
                    sources.push(s);
                }
            }
            let shown = sources[..sources.len().min(3)].join(", ");
            let more = if sources.len() > 3 { ", …" } else { "" };
            return deny(format!(
                "privileged tool requested after lower-trust content entered the session \
                 (from {shown}{more})"
            ));
        }
        PolicyOutcome {
            decision: Decision::Allow,
            reason: if self.is_outbound(tool) {
                "destination allowlisted; no lower-trust content in the session".into()
            } else if self.is_privileged(tool) {
                "privileged tool; no lower-trust content in the session".into()
            } else {
                "not a privileged tool".into()
            },
        }
    }
}

/// A tool call whose arguments carry a canary token is denied, whatever the tool: no
/// legitimate task uses a decoy secret, so the call can only be moving it somewhere.
fn canary_denial(arguments: &Map<String, Value>) -> Option<PolicyOutcome> {
    let names = crate::canary::find_in_arguments(arguments);
    (!names.is_empty()).then(|| PolicyOutcome {
        decision: Decision::Deny,
        reason: format!(
            "the arguments contain canary token {}: decoy secrets are never used by legitimate work",
            names
                .iter()
                .map(|n| format!("{n:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    })
}

/// Schemes whose destinations are parsed as URLs (everything else is a host or mailbox).
const URL_SCHEMES: &[&str] = &["http", "https", "ws", "wss", "ftp", "file", "mailto"];

/// Extract the host of a URL-like destination without any network resolution.
///
/// URLs (`http:`, `https:`, ... or any `scheme://`) are parsed with the WHATWG parser of the
/// `url` crate, the one real HTTP clients such as reqwest use, so the host is the one a client
/// would connect to (`http:host/x`, backslashes and userinfo included). Other values are taken
/// as `host[:port][/path]` or a mailbox `user@host`. Ambiguous or unparsable values (spaces,
/// control characters, `,`/`;`, several `@`) yield `None`, which callers treat as disallowed.
pub fn host_of(destination: &str) -> Option<String> {
    let d = destination.trim();
    if d.is_empty() || d.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    let url_like = d.split_once(':').is_some_and(|(scheme, rest)| {
        URL_SCHEMES.iter().any(|s| s.eq_ignore_ascii_case(scheme)) || rest.starts_with("//")
    });
    if url_like {
        let url = url::Url::parse(d).ok()?;
        return match url.host() {
            Some(url::Host::Domain(h)) => Some(h.to_ascii_lowercase()),
            Some(url::Host::Ipv4(ip)) => Some(ip.to_string()),
            Some(url::Host::Ipv6(ip)) => Some(ip.to_string()),
            // `mailto:user@host` has no URL host; its path is the mailbox.
            None if url.scheme() == "mailto" => plain_host(url.path()),
            None => None,
        };
    }
    plain_host(d)
}

/// Host of `host[:port][/path]` or `user@host` (no scheme).
fn plain_host(value: &str) -> Option<String> {
    let authority = value.split(['/', '\\', '?', '#']).next()?;
    if authority.contains([',', ';', '<', '>', '"']) || authority.matches('@').count() > 1 {
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

/// The addresses of a recipient value: split at `,` and `;`, display names removed
/// (`Name <user@host>` -> `user@host`). Empty entries are dropped.
fn recipients(value: &str) -> Vec<&str> {
    value
        .split([',', ';'])
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(|r| match (r.rfind('<'), r.ends_with('>')) {
            (Some(start), true) => &r[start + 1..r.len() - 1],
            _ => r,
        })
        .collect()
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

    // Regression: host_of split at the first "://" anywhere, so a URL without slashes after
    // its scheme took its "host" from the path, query or fragment; real clients (WHATWG,
    // the url crate behind reqwest) connect to the actual host.
    #[test]
    fn slashless_and_embedded_schemes_use_the_real_host() {
        for d in [
            "http:marker.invalid/?r=://localhost",
            "http:/marker.invalid/x://localhost",
            "http:\\\\marker.invalid\\://localhost",
            "https:marker.invalid#://127.0.0.1",
            "marker.invalid/?r=http://localhost",
        ] {
            assert_ne!(host_of(d).as_deref(), Some("localhost"), "{d}");
            assert_ne!(host_of(d).as_deref(), Some("127.0.0.1"), "{d}");
            assert!(!ToolPolicy::default().destination_allowed(d), "{d}");
        }
        assert_eq!(
            host_of("http:marker.invalid/x").as_deref(),
            Some("marker.invalid")
        );
        // Unchanged for ordinary forms.
        assert_eq!(
            host_of("http://LOCALHOST:8080/x").as_deref(),
            Some("localhost")
        );
        assert_eq!(host_of("http://[::1]:80/").as_deref(), Some("::1"));
        assert_eq!(host_of("ops@localhost").as_deref(), Some("localhost"));
        assert_eq!(host_of("localhost/hook").as_deref(), Some("localhost"));
        assert_eq!(
            host_of("mailto:ops@localhost").as_deref(),
            Some("localhost")
        );
        // Unparsable URLs give no host (the caller denies).
        assert_eq!(host_of("http://[::1"), None);
    }

    // Regression: a recipient list in one string was judged by its last address only.
    #[test]
    fn every_recipient_in_a_list_must_be_allowlisted() {
        let p = ToolPolicy::default();
        for to in [
            "attacker@marker.invalid,ops@localhost",
            "attacker@marker.invalid;ops@localhost",
            "attacker@marker.invalid, ops@localhost",
            "Attacker <attacker@marker.invalid>, ops@localhost",
        ] {
            let args = json!({ "to": to });
            let out = p.evaluate("send_email", args.as_object().unwrap());
            assert_eq!(out.decision, Decision::Deny, "{to}");
        }
        let args = json!({"to": "ops@localhost, admin@127.0.0.1"});
        assert_eq!(
            p.evaluate("send_email", args.as_object().unwrap()).decision,
            Decision::Allow
        );
    }

    // Regression: only eight exact-case keys were read, so cc/bcc, `URL` or `callback_url`
    // next to an allowlisted `to`/`url` were never checked.
    #[test]
    fn destination_like_keys_are_found_by_name_pattern() {
        let p = ToolPolicy::default();
        for args in [
            json!({"to": "ops@localhost", "cc": "someone@marker.invalid"}),
            json!({"to": "ops@localhost", "bcc": ["someone@marker.invalid"]}),
            json!({"url": "http://localhost/", "URL": "https://marker.invalid/"}),
            json!({"destination": "http://localhost/hook", "callback_url": "https://marker.invalid/"}),
            json!({"to": "ops@localhost", "Reply-To": "someone@marker.invalid"}),
        ] {
            let out = p.evaluate("send_email", args.as_object().unwrap());
            assert_eq!(out.decision, Decision::Deny, "{args}");
        }
        let args = json!({"to": "ops@localhost", "cc": "admin@localhost", "subject": "hi"});
        assert_eq!(
            p.evaluate("send_email", args.as_object().unwrap()).decision,
            Decision::Allow
        );
    }

    #[test]
    fn glob_patterns() {
        for (p, n, want) in [
            ("create_*", "create_pull_request", true),
            ("create_*", "create_", true),
            ("create_*", "list_issues", false),
            ("*_file", "write_file", true),
            ("*_file*", "push_files", true),
            ("a*b*c", "aXbYc", true),
            ("a*b*c", "aXbY", false),
            ("*", "", true),
            ("", "", true),
            ("", "x", false),
            ("exact", "exact", true),
            ("exact", "Exact", false),
            ("**x", "abx", true),
        ] {
            assert_eq!(glob_match(p, n), want, "{p} vs {n}");
        }
    }

    #[test]
    fn config_adds_to_the_defaults() {
        let config = PolicyConfig {
            privileged: vec!["create_*".into(), "push_files".into()],
            outbound: vec!["send_webhook".into(), "post_*".into()],
            allow_destinations: vec!["*.corp.example".into(), " ".into()],
        };
        let p = ToolPolicy::default().with_config(&config);
        assert!(p.is_privileged("create_pull_request"));
        assert!(p.is_privileged("push_files"));
        assert!(p.is_privileged("run_command"), "defaults are kept");
        assert!(p.is_outbound("post_message"));
        assert!(
            p.is_privileged("post_message"),
            "outbound tools are privileged"
        );
        assert!(!p.is_privileged("get_issue"));
        assert_eq!(
            p.outbound_tools
                .iter()
                .filter(|t| *t == "send_webhook")
                .count(),
            1,
            "no duplicates"
        );
        assert!(!p.destination_allowlist.iter().any(|d| d.trim().is_empty()));
    }

    #[test]
    fn wildcard_destinations_allow_subdomains_only() {
        let p = ToolPolicy::default().with_config(&PolicyConfig {
            allow_destinations: vec!["*.corp.example".into()],
            ..PolicyConfig::default()
        });
        assert!(p.destination_allowed("https://api.corp.example/x"));
        assert!(p.destination_allowed("https://A.B.CORP.example/x"));
        assert!(p.destination_allowed("ops@mail.corp.example"));
        assert!(!p.destination_allowed("https://corp.example/x"));
        assert!(!p.destination_allowed("https://evilcorp.example/x"));
        assert!(!p.destination_allowed("https://corp.example.evil.invalid/x"));
        assert!(!p.destination_allowed("https://.corp.example/x"));
        // A bare `*.` entry allows nothing.
        let p = ToolPolicy::default().with_config(&PolicyConfig {
            allow_destinations: vec!["*.".into()],
            ..PolicyConfig::default()
        });
        assert!(!p.destination_allowed("https://marker.invalid/"));
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
