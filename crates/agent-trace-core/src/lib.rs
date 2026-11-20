//! `agent-trace-core`: event model, provenance, redaction, policy and rules.
//!
//! This crate is intentionally independent of AI vendors, MCP SDKs and UIs.

pub mod canary;
pub mod event;
pub mod finding;
pub mod policy;
pub mod provenance;
pub mod recorder;
pub mod redact;
pub mod rules;
pub mod taxonomy;

pub use event::{
    DEFAULT_AGENT, Event, EventKind, ExecutionMode, Origin, SCHEMA_VERSION, ToolState, Trace,
    TraceRecord, TraceStatus, TrustLevel,
};
pub use finding::{AttemptStatus, Confidence, Finding, Severity};
pub use policy::{
    Decision, DenialClass, PolicyConfig, PolicyOutcome, ProfileConfig, ToolPolicy, ToolProfile,
    glob_match,
};
pub use provenance::{TraceIndex, ValidationError, validate};
pub use recorder::{
    AccessError, EventSpec, MemoryTrace, RecorderEvent, TraceAccess, TraceRecorder,
};
pub use redact::{RedactionReport, Redactor};
pub use rules::{Analyzer, Rule};
