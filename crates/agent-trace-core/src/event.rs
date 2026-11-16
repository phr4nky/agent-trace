//! Versioned event and trace model.
//!
//! Invariants (see `docs/event-schema.md`):
//! * `event_id` is unique within a trace.
//! * `sequence` starts at 1 and increases by exactly 1 per event.
//! * `parent_event_id` / `caused_by_event_id` refer to an event of the same
//!   trace with a *lower* sequence number. Causality is never inferred from
//!   timestamps; it is only what an adapter explicitly recorded.
//! * `payload` has already been redacted and size-limited before it is stored.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;
use uuid::Uuid;

/// Current event schema version written by this build.
pub const SCHEMA_VERSION: &str = "1.1";

/// Schema versions this build can read.
pub const SUPPORTED_SCHEMA_VERSIONS: &[&str] = &["1.0", "1.1"];

/// Agent id used for events that do not name an agent (all schema 1.0 traces).
pub const DEFAULT_AGENT: &str = "main";

/// Kind of a recorded event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    AgentStarted,
    AgentCompleted,
    UserPromptReceived,
    ModelRequest,
    ModelResponse,
    ToolCallRequested,
    ToolPolicyDecision,
    ToolCallExecuted,
    ToolCallCompleted,
    ToolCallFailed,
    ToolResultReceived,
    ExternalContentObserved,
    AgentDecision,
    /// An agent hands a task to another agent (schema 1.1).
    AgentDelegated,
    /// An agent sends a message (e.g. a report) to another agent (schema 1.1).
    AgentMessageSent,
    /// An agent receives a message from another agent (schema 1.1).
    AgentMessageReceived,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AgentStarted => "agent_started",
            Self::AgentCompleted => "agent_completed",
            Self::UserPromptReceived => "user_prompt_received",
            Self::ModelRequest => "model_request",
            Self::ModelResponse => "model_response",
            Self::ToolCallRequested => "tool_call_requested",
            Self::ToolPolicyDecision => "tool_policy_decision",
            Self::ToolCallExecuted => "tool_call_executed",
            Self::ToolCallCompleted => "tool_call_completed",
            Self::ToolCallFailed => "tool_call_failed",
            Self::ToolResultReceived => "tool_result_received",
            Self::ExternalContentObserved => "external_content_observed",
            Self::AgentDecision => "agent_decision",
            Self::AgentDelegated => "agent_delegated",
            Self::AgentMessageSent => "agent_message_sent",
            Self::AgentMessageReceived => "agent_message_received",
        }
    }

    /// Events that carry content which originated outside the trusted boundary.
    pub fn carries_content(self) -> bool {
        matches!(
            self,
            Self::ToolResultReceived
                | Self::ExternalContentObserved
                | Self::ModelResponse
                | Self::AgentMessageReceived
        )
    }
}

/// Where the content or action of an event originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    User,
    Agent,
    Model,
    McpTool,
    ExternalDocument,
    Policy,
    System,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Agent => "agent",
            Self::Model => "model",
            Self::McpTool => "mcp_tool",
            Self::ExternalDocument => "external_document",
            Self::Policy => "policy",
            Self::System => "system",
        }
    }
}

/// Trust label attached to an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    Trusted,
    LowerTrust,
    Unknown,
}

impl TrustLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::LowerTrust => "lower_trust",
            Self::Unknown => "unknown",
        }
    }
}

/// Whether the event was produced by a scripted simulation or a live system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    Simulated,
    Live,
}

impl ExecutionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Simulated => "simulated",
            Self::Live => "live",
        }
    }
}

/// Explicit tool-call lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolState {
    Requested,
    PolicyDecision,
    Blocked,
    Executed,
    Completed,
    Failed,
}

impl ToolState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::PolicyDecision => "policy_decision",
            Self::Blocked => "blocked",
            Self::Executed => "executed",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

/// One recorded event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub schema_version: String,
    pub event_id: Uuid,
    pub trace_id: Uuid,
    pub sequence: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub kind: EventKind,
    pub parent_event_id: Option<Uuid>,
    pub caused_by_event_id: Option<Uuid>,
    pub origin: Origin,
    pub trust_level: TrustLevel,
    pub name: String,
    pub payload: Value,
    pub execution_mode: ExecutionMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_state: Option<ToolState>,
    #[serde(default)]
    pub metadata: Map<String, Value>,
    /// Acting agent (schema 1.1). `None` means [`DEFAULT_AGENT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Additional explicit causes (schema 1.1): everything that was in the context of this
    /// event, e.g. all tool results a model request was based on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_event_ids: Vec<Uuid>,
}

impl Event {
    /// Number of values the redactor replaced in this event (recorded in metadata).
    /// Acting agent (defaults to [`DEFAULT_AGENT`]).
    pub fn agent(&self) -> &str {
        self.agent_id.as_deref().unwrap_or(DEFAULT_AGENT)
    }

    /// All explicit links of this event: parent, cause and context.
    pub fn links(&self) -> impl Iterator<Item = Uuid> + '_ {
        self.parent_event_id
            .into_iter()
            .chain(self.caused_by_event_id)
            .chain(self.context_event_ids.iter().copied())
    }

    /// Causal edges used for provenance: the cause (or the parent if no cause was recorded)
    /// plus all context links.
    pub fn cause_links(&self) -> impl Iterator<Item = Uuid> + '_ {
        self.caused_by_event_id
            .or(self.parent_event_id)
            .into_iter()
            .chain(self.context_event_ids.iter().copied())
    }

    pub fn redaction_count(&self) -> u64 {
        self.metadata
            .get("redactions")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    }

    /// Whether the event payload is labelled as containing sensitive data.
    pub fn is_sensitive(&self) -> bool {
        self.redaction_count() > 0
            || self.payload_text().contains(crate::redact::REDACTED_PREFIX)
            || self
                .metadata
                .get("data_labels")
                .and_then(Value::as_array)
                .is_some_and(|labels| labels.iter().any(|l| l == "sensitive"))
    }

    /// Concatenated textual payload content, used by content rules.
    pub fn payload_text(&self) -> String {
        let mut out = String::new();
        collect_strings(&self.payload, &mut out);
        out
    }
}

fn collect_strings(value: &Value, out: &mut String) {
    match value {
        Value::String(s) => {
            out.push_str(s);
            out.push('\n');
        }
        Value::Array(items) => items.iter().for_each(|v| collect_strings(v, out)),
        Value::Object(map) => map.values().for_each(|v| collect_strings(v, out)),
        _ => {}
    }
}

/// Lifecycle of a trace. Traces that never finish (crash, kill) stay `running`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TraceStatus {
    Running,
    #[default]
    Completed,
    Aborted,
}

impl TraceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Aborted => "aborted",
        }
    }
}

/// Trace header (one execution of one task, possibly with several agents).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Trace {
    pub schema_version: String,
    pub trace_id: Uuid,
    pub name: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub execution_mode: ExecutionMode,
    #[serde(default)]
    pub metadata: Map<String, Value>,
    /// Lifecycle status (schema 1.1; absent in 1.0 traces = completed).
    #[serde(default)]
    pub status: TraceStatus,
}

impl Trace {
    /// Distinct agents in a list of events, in order of first appearance.
    pub fn agents(events: &[Event]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for e in events {
            if !out.iter().any(|a| a == e.agent()) {
                out.push(e.agent().to_owned());
            }
        }
        out
    }
}

/// A trace together with all its events, ordered by sequence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceRecord {
    pub trace: Trace,
    pub events: Vec<Event>,
}

impl TraceRecord {
    pub fn event(&self, id: Uuid) -> Option<&Event> {
        self.events.iter().find(|e| e.event_id == id)
    }
}
