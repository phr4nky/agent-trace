//! `agent-trace-net`: network transports for agent-trace.
//!
//! Connects the MCP proxy to an upstream server over MCP streamable HTTP, using rmcp's
//! reqwest-based client (same-origin redirects only, bounded responses and SSE events).
//!
//! This is the only crate besides the opt-in `agent-trace-llm` that may open network
//! connections. `agent-trace-mcp` (lab, proxy logic) stays free of networking code: it gets
//! the finished connection as an [`McpSession`].

pub mod ship;

use std::collections::HashMap;

use agent_trace_core::Redactor;
use agent_trace_mcp::McpSession;
use anyhow::{Context as _, bail};
use http::{HeaderName, HeaderValue};
use rmcp::ServiceExt;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;

/// Transport name recorded in the trace for HTTP upstreams.
pub const TRANSPORT: &str = "streamable-http";

/// Where and how to reach an upstream MCP server over HTTP.
#[derive(Clone, Default)]
pub struct HttpUpstream {
    /// Endpoint URL, e.g. `https://api.githubcopilot.com/mcp/`.
    pub url: String,
    /// Sent as `Authorization: Bearer <token>`.
    pub bearer_token: Option<String>,
    /// Additional request headers (name, value), e.g. an API key header.
    pub headers: Vec<(String, String)>,
}

impl std::fmt::Debug for HttpUpstream {
    // Never print the token or header values.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpUpstream")
            .field("url", &display_url(&self.url))
            .field("bearer_token", &self.bearer_token.as_ref().map(|_| "…"))
            .field(
                "headers",
                &self.headers.iter().map(|(n, _)| n).collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// The URL without credentials, query or fragment, for traces and messages.
pub fn display_url(url: &str) -> String {
    match url::Url::parse(url.trim()) {
        Ok(mut u) => {
            let _ = u.set_username("");
            let _ = u.set_password(None);
            u.set_query(None);
            u.set_fragment(None);
            u.to_string()
        }
        Err(_) => Redactor::new().scrub(url),
    }
}

/// Accept `https://` URLs, and `http://` only for a loopback host: tool arguments, results and
/// credentials must not cross a network in clear text.
pub fn check_url(url: &str) -> anyhow::Result<()> {
    let parsed = url::Url::parse(url.trim())
        .with_context(|| format!("invalid upstream URL {:?}", display_url(url)))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" => {
            let loopback = match parsed.host() {
                Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
                Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                None => false,
            };
            if loopback {
                Ok(())
            } else {
                bail!(
                    "refusing plain http to {}: use https:// (http is only allowed for localhost)",
                    display_url(url)
                )
            }
        }
        other => bail!("unsupported upstream URL scheme {other:?}: use https://"),
    }
}

/// Connect to `upstream` and complete the MCP initialize handshake.
pub async fn connect(upstream: &HttpUpstream) -> anyhow::Result<McpSession> {
    check_url(&upstream.url)?;
    // reqwest is built without a default TLS provider; use the one the workspace pins.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut config = StreamableHttpClientTransportConfig::with_uri(upstream.url.trim());
    config.auth_header = upstream.bearer_token.clone();
    let mut headers = HashMap::new();
    for (name, value) in &upstream.headers {
        let name = HeaderName::from_bytes(name.trim().as_bytes())
            .with_context(|| format!("invalid header name {name:?}"))?;
        let mut value = HeaderValue::from_str(value.trim())
            .with_context(|| format!("invalid value for header {name}"))?;
        value.set_sensitive(true);
        headers.insert(name, value);
    }
    config.custom_headers = headers;
    let transport = StreamableHttpClientTransport::from_config(config);
    let client = ().serve(transport).await.with_context(|| {
        format!(
            "MCP initialize handshake with {} failed",
            display_url(&upstream.url)
        )
    })?;
    Ok(McpSession::from_service(client, TRANSPORT))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_or_loopback_http() {
        for ok in [
            "https://api.example.com/mcp/",
            "http://localhost:8080/mcp",
            "http://127.0.0.1:3000/mcp",
            "http://[::1]:3000/mcp",
        ] {
            assert!(check_url(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://api.example.com/mcp",
            "http://localhost.marker.invalid/mcp",
            "http://127.0.0.1.marker.invalid/",
            "ftp://example.com/",
            "file:///etc/passwd",
            "not a url",
        ] {
            assert!(check_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn displayed_urls_carry_no_credentials() {
        assert_eq!(
            display_url("https://user:secret@api.example.com/mcp/?token=abc#x"),
            "https://api.example.com/mcp/"
        );
        let debug = format!(
            "{:?}",
            HttpUpstream {
                url: "https://api.example.com/mcp?key=k".into(),
                bearer_token: Some("FAKE_SECRET_TOKEN".into()),
                headers: vec![("X-Api-Key".into(), "FAKE_SECRET_HEADER".into())],
            }
        );
        assert!(!debug.contains("FAKE_SECRET"), "{debug}");
        assert!(!debug.contains("key=k"), "{debug}");
    }
}
