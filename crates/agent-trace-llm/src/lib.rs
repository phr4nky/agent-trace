//! `agent-trace-llm`: connect real language models to the agent-trace lab.
//!
//! * [`anthropic`]: Anthropic Messages API
//! * [`openai`]: OpenAI Chat Completions, also used by OpenAI-compatible servers
//!   (Ollama, vLLM, LM Studio, …)
//! * [`agent`]: an LLM-driven agent loop over the lab's MCP tools (policy-gated mocks)
//!
//! Opt-in only: nothing here runs unless a provider is selected explicitly.

pub mod agent;
pub mod anthropic;
pub mod client;
pub mod openai;
pub mod types;

use thiserror::Error;

pub use agent::{LlmRunOptions, run_llm_scenario};
pub use client::{LlmClient, ProviderConfig, ProviderKind};

#[derive(Debug, Error)]
pub enum LlmError {
    #[error("LLM configuration: {0}")]
    Config(String),
    #[error("LLM request failed: {0}")]
    Http(String),
    #[error("LLM API error (HTTP {status}): {message}")]
    Api { status: u16, message: String },
    #[error("unexpected LLM response: {0}")]
    Parse(String),
}
