//! HTTP client for the supported providers. API keys come from the environment only,
//! are never logged, and are never written to a trace.

use std::time::Duration;

use agent_trace_core::Redactor;
use serde_json::Value;

use crate::types::{ModelReply, ModelRequest};
use crate::{LlmError, anthropic, openai};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    Anthropic,
    OpenAi,
}

impl ProviderKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
        }
    }
}

/// Provider settings. `Debug` never prints the key.
#[derive(Clone)]
pub struct ProviderConfig {
    pub kind: ProviderKind,
    pub model: String,
    pub base_url: String,
    pub api_key: Option<String>,
    pub timeout: Duration,
}

impl std::fmt::Debug for ProviderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderConfig")
            .field("kind", &self.kind)
            .field("model", &self.model)
            .field("base_url", &self.base_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "[set]"))
            .finish()
    }
}

impl ProviderConfig {
    /// Build from CLI values and the environment:
    /// * Anthropic: `ANTHROPIC_API_KEY` (required), `ANTHROPIC_BASE_URL`, `ANTHROPIC_MODEL`
    /// * OpenAI-compatible: `OPENAI_API_KEY` (required for api.openai.com), `OPENAI_BASE_URL`,
    ///   `OPENAI_MODEL`
    pub fn from_env(
        kind: ProviderKind,
        model: Option<String>,
        base_url: Option<String>,
    ) -> Result<Self, LlmError> {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let (key_var, base_var, model_var, default_base) = match kind {
            ProviderKind::Anthropic => (
                "ANTHROPIC_API_KEY",
                "ANTHROPIC_BASE_URL",
                "ANTHROPIC_MODEL",
                anthropic::DEFAULT_BASE_URL,
            ),
            ProviderKind::OpenAi => (
                "OPENAI_API_KEY",
                "OPENAI_BASE_URL",
                "OPENAI_MODEL",
                openai::DEFAULT_BASE_URL,
            ),
        };
        let base_url = base_url
            .or_else(|| env(base_var))
            .unwrap_or_else(|| default_base.to_owned());
        let model = model.or_else(|| env(model_var)).or_else(|| match kind {
            ProviderKind::Anthropic => Some(anthropic::DEFAULT_MODEL.to_owned()),
            ProviderKind::OpenAi => None,
        });
        let model = model.ok_or_else(|| {
            LlmError::Config(format!(
                "no model selected for {}: pass --model or set {model_var}",
                kind.name()
            ))
        })?;
        let api_key = env(key_var);
        let official =
            base_url.contains("api.anthropic.com") || base_url.contains("api.openai.com");
        if api_key.is_none() && (kind == ProviderKind::Anthropic || official) {
            return Err(LlmError::Config(format!(
                "{key_var} is not set (the key is read from the environment only)"
            )));
        }
        Ok(Self {
            kind,
            model,
            base_url,
            api_key,
            timeout: Duration::from_secs(120),
        })
    }

    /// `provider/model @ host` for display and trace metadata.
    pub fn describe(&self) -> String {
        let host = agent_trace_core::policy::host_of(&self.base_url).unwrap_or_default();
        format!("{}/{} @ {host}", self.kind.name(), self.model)
    }
}

/// A configured provider client.
#[derive(Debug, Clone)]
pub struct LlmClient {
    config: ProviderConfig,
    http: reqwest::Client,
}

impl LlmClient {
    pub fn new(config: ProviderConfig) -> Result<Self, LlmError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent(concat!("agent-trace/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| LlmError::Http(e.to_string()))?;
        Ok(Self { config, http })
    }

    pub fn config(&self) -> &ProviderConfig {
        &self.config
    }

    pub async fn complete(&self, req: &ModelRequest<'_>) -> Result<ModelReply, LlmError> {
        let cfg = &self.config;
        let (url, body) = match cfg.kind {
            ProviderKind::Anthropic => (
                anthropic::endpoint(&cfg.base_url),
                anthropic::request_body(&cfg.model, req),
            ),
            ProviderKind::OpenAi => (
                openai::endpoint(&cfg.base_url),
                openai::request_body(&cfg.model, req),
            ),
        };
        let mut request = self.http.post(&url).json(&body);
        match cfg.kind {
            ProviderKind::Anthropic => {
                request = request
                    .header("anthropic-version", anthropic::API_VERSION)
                    .header("x-api-key", cfg.api_key.clone().unwrap_or_default());
            }
            ProviderKind::OpenAi => {
                if let Some(key) = &cfg.api_key {
                    request = request.bearer_auth(key);
                }
            }
        }
        let response = request
            .send()
            .await
            .map_err(|e| LlmError::Http(scrub(&e.to_string())))?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| LlmError::Http(scrub(&e.to_string())))?;
        let json: Value = serde_json::from_str(&text).map_err(|_| {
            LlmError::Parse(format!(
                "{} returned non-JSON (HTTP {status}): {}",
                cfg.kind.name(),
                scrub(&text.chars().take(200).collect::<String>())
            ))
        })?;
        if !status.is_success() {
            let message = match cfg.kind {
                ProviderKind::Anthropic => anthropic::error_message(&json),
                ProviderKind::OpenAi => openai::error_message(&json),
            }
            .unwrap_or_else(|| "unknown error".into());
            return Err(LlmError::Api {
                status: status.as_u16(),
                message: scrub(&message),
            });
        }
        match cfg.kind {
            ProviderKind::Anthropic => anthropic::parse_reply(&json),
            ProviderKind::OpenAi => openai::parse_reply(&json),
        }
    }
}

fn scrub(s: &str) -> String {
    Redactor::new().scrub(s)
}
