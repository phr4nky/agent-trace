//! Sending recorded traces to `agent-trace-server` (`agent-trace ship`).
//!
//! One request per batch, authenticated with the token of the source. Only `https://` (or
//! plain http to a loopback host) is accepted, and redirects are never followed, so the token
//! cannot be sent anywhere else.

use std::time::Duration;

use agent_trace_core::Redactor;
use agent_trace_storage::ingest::{IngestBatch, IngestReply};
use serde::Deserialize;

use crate::{check_url, display_url};

/// Largest answer read from the server (answers are small JSON objects).
const MAX_REPLY_BYTES: usize = 1024 * 1024;

/// Why the server did not take a batch.
#[derive(Debug)]
pub enum ShipError {
    /// The batch does not continue the stored trace. `stored_seq`: where to continue, when the
    /// trace belongs to this source.
    Conflict {
        message: String,
        stored_seq: Option<u64>,
    },
    /// The server does not know the token.
    Unauthorized(String),
    /// The server rejected the batch or failed.
    Rejected { status: u16, message: String },
    /// No usable answer (network, TLS, timeout).
    Transport(String),
}

impl std::fmt::Display for ShipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict { message, .. } => write!(f, "conflict: {message}"),
            Self::Unauthorized(m) => write!(f, "the server did not accept the token: {m}"),
            Self::Rejected { status, message } => write!(f, "rejected ({status}): {message}"),
            Self::Transport(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for ShipError {}

/// A client for one server and source token.
pub struct ShipClient {
    base: String,
    endpoint: String,
    token: String,
    http: reqwest::Client,
}

impl std::fmt::Debug for ShipClient {
    // Never print the token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShipClient")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

/// The source a token belongs to.
#[derive(Debug, Clone, Deserialize)]
pub struct SourceInfo {
    pub source_id: String,
    pub name: String,
}

#[derive(Default, Deserialize)]
struct ErrorBody {
    error: Option<String>,
    stored_seq: Option<u64>,
}

impl ShipClient {
    /// `base_url`: the server, e.g. `https://trace.example.com` or `http://localhost:8080`.
    pub fn new(base_url: &str, token: &str) -> anyhow::Result<Self> {
        check_url(base_url)?;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(60))
            .user_agent(concat!("agent-trace/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let base = base_url.trim().trim_end_matches('/');
        Ok(Self {
            base: base.to_owned(),
            endpoint: format!("{base}/api/v1/"),
            token: token.trim().to_owned(),
            http,
        })
    }

    /// The server, for messages (no credentials, query or fragment).
    pub fn server(&self) -> String {
        display_url(&self.base)
    }

    /// The source of the token (fails with [`ShipError::Unauthorized`] for an unknown token).
    pub async fn whoami(&self) -> Result<SourceInfo, ShipError> {
        let request = self.http.get(format!("{}whoami", self.endpoint));
        self.call(request).await
    }

    /// Send one batch.
    pub async fn send(&self, batch: &IngestBatch) -> Result<IngestReply, ShipError> {
        let request = self
            .http
            .post(format!("{}ingest", self.endpoint))
            .json(batch);
        self.call(request).await
    }

    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T, ShipError> {
        let transport =
            |e: reqwest::Error| ShipError::Transport(Redactor::new().scrub(&e.to_string()));
        let mut response = request
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(transport)?;
        let status = response.status();
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(transport)? {
            if body.len() + chunk.len() > MAX_REPLY_BYTES {
                return Err(ShipError::Transport(format!(
                    "the server's answer exceeds {MAX_REPLY_BYTES} bytes"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        if status.is_success() {
            return serde_json::from_slice(&body).map_err(|e| {
                ShipError::Transport(format!("unexpected answer from the server: {e}"))
            });
        }
        let err: ErrorBody = serde_json::from_slice(&body).unwrap_or_default();
        let message = Redactor::new().scrub(
            &err.error
                .unwrap_or_else(|| status.canonical_reason().unwrap_or("error").to_owned()),
        );
        Err(match status.as_u16() {
            401 | 403 => ShipError::Unauthorized(message),
            409 => ShipError::Conflict {
                message,
                stored_seq: err.stored_seq,
            },
            code => ShipError::Rejected {
                status: code,
                message,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_or_loopback_and_no_token_in_debug() {
        assert!(ShipClient::new("http://localhost:8080", "ats_x").is_ok());
        assert!(ShipClient::new("https://trace.example.com/", "ats_x").is_ok());
        assert!(ShipClient::new("http://trace.example.com", "ats_x").is_err());
        let c = ShipClient::new("http://127.0.0.1:8080/", "ats_secret_value").unwrap();
        assert_eq!(c.endpoint, "http://127.0.0.1:8080/api/v1/");
        assert!(!format!("{c:?}").contains("ats_secret_value"));
    }
}
