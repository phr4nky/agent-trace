//! Trace recorder: assigns IDs, sequence numbers and timestamps and applies
//! redaction *before* an event ever leaves the recorder.
//!
//! An optional sink receives every event as soon as it is recorded (live persistence).

use serde_json::{Map, Value};
use time::{Duration, OffsetDateTime, macros::datetime};
use uuid::Uuid;

use crate::event::{
    Event, EventKind, ExecutionMode, Origin, SCHEMA_VERSION, ToolState, Trace, TraceRecord,
    TraceStatus, TrustLevel,
};
use crate::redact::Redactor;

/// Namespace for deterministic (UUID v5) identifiers.
pub const DETERMINISTIC_NAMESPACE: Uuid =
    Uuid::from_u128(0x6167_656e_742d_7472_6163_652d_6964_7330);

/// Base timestamp used in deterministic mode.
pub const DETERMINISTIC_EPOCH: OffsetDateTime = datetime!(2026-01-01 00:00:00 UTC);

/// Description of an event to record. IDs, sequence and timestamps are assigned by the recorder.
#[derive(Debug, Clone)]
pub struct EventSpec {
    pub kind: EventKind,
    pub origin: Origin,
    pub trust_level: TrustLevel,
    pub name: String,
    pub payload: Value,
    pub parent_event_id: Option<Uuid>,
    pub caused_by_event_id: Option<Uuid>,
    pub context_event_ids: Vec<Uuid>,
    pub agent_id: Option<String>,
    pub tool_state: Option<ToolState>,
    pub metadata: Map<String, Value>,
}

impl EventSpec {
    pub fn new(
        kind: EventKind,
        origin: Origin,
        trust_level: TrustLevel,
        name: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            origin,
            trust_level,
            name: name.into(),
            payload: Value::Object(Map::new()),
            parent_event_id: None,
            caused_by_event_id: None,
            context_event_ids: Vec::new(),
            agent_id: None,
            tool_state: None,
            metadata: Map::new(),
        }
    }

    pub fn payload(mut self, payload: Value) -> Self {
        self.payload = payload;
        self
    }

    pub fn parent(mut self, id: impl Into<Option<Uuid>>) -> Self {
        self.parent_event_id = id.into();
        self
    }

    pub fn caused_by(mut self, id: impl Into<Option<Uuid>>) -> Self {
        self.caused_by_event_id = id.into();
        self
    }

    /// Additional causes: events whose content was in this event's context.
    pub fn context(mut self, ids: impl IntoIterator<Item = Uuid>) -> Self {
        for id in ids {
            if !self.context_event_ids.contains(&id) && Some(id) != self.caused_by_event_id {
                self.context_event_ids.push(id);
            }
        }
        self
    }

    /// Acting agent. `None` / not set means the default agent.
    pub fn agent(mut self, agent: impl Into<Option<String>>) -> Self {
        self.agent_id = agent.into();
        self
    }

    pub fn tool_state(mut self, state: ToolState) -> Self {
        self.tool_state = Some(state);
        self
    }

    pub fn meta(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.metadata.insert(key.to_owned(), value.into());
        self
    }
}

/// Notifications delivered to a recorder sink.
#[derive(Debug, Clone, Copy)]
pub enum RecorderEvent<'a> {
    /// Sent once, before the first event (with the trace header as known at that time).
    Started(&'a Trace),
    /// Sent for every recorded (already redacted) event.
    Recorded(&'a Trace, &'a Event),
    /// Sent when the trace is finished or aborted (with the final header).
    Finished(&'a Trace),
}

type Sink = Box<dyn FnMut(RecorderEvent<'_>) + Send>;

/// Records the events of exactly one trace.
pub struct TraceRecorder {
    trace: Trace,
    events: Vec<Event>,
    redactor: Redactor,
    deterministic: bool,
    sink: Option<Sink>,
    started: bool,
}

impl std::fmt::Debug for TraceRecorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraceRecorder")
            .field("trace", &self.trace)
            .field("events", &self.events.len())
            .field("live", &self.sink.is_some())
            .finish()
    }
}

impl TraceRecorder {
    /// Start a trace with random IDs and wall-clock timestamps.
    pub fn new(name: impl Into<String>, mode: ExecutionMode) -> Self {
        Self::build(name.into(), mode, Uuid::new_v4(), now_utc(), false)
    }

    /// Start a trace whose IDs and timestamps are derived from `seed` (for golden tests).
    pub fn deterministic(name: impl Into<String>, mode: ExecutionMode, seed: &str) -> Self {
        let trace_id = Uuid::new_v5(&DETERMINISTIC_NAMESPACE, seed.as_bytes());
        Self::build(name.into(), mode, trace_id, DETERMINISTIC_EPOCH, true)
    }

    fn build(
        name: String,
        mode: ExecutionMode,
        trace_id: Uuid,
        created_at: OffsetDateTime,
        deterministic: bool,
    ) -> Self {
        let mut metadata = Map::new();
        metadata.insert("deterministic".into(), Value::Bool(deterministic));
        Self {
            trace: Trace {
                schema_version: SCHEMA_VERSION.to_owned(),
                trace_id,
                name,
                created_at,
                execution_mode: mode,
                metadata,
                status: TraceStatus::Running,
            },
            events: Vec::new(),
            redactor: Redactor::new(),
            deterministic,
            sink: None,
            started: false,
        }
    }

    /// Deliver every event to `sink` as soon as it is recorded.
    pub fn with_sink(mut self, sink: impl FnMut(RecorderEvent<'_>) + Send + 'static) -> Self {
        self.sink = Some(Box::new(sink));
        self
    }

    pub fn trace_id(&self) -> Uuid {
        self.trace.trace_id
    }

    pub fn trace(&self) -> &Trace {
        &self.trace
    }

    pub fn set_trace_metadata(&mut self, key: &str, value: impl Into<Value>) {
        let (value, _) = self.redactor.redact_value(&value.into());
        self.trace.metadata.insert(key.to_owned(), value);
    }

    pub fn events(&self) -> &[Event] {
        &self.events
    }

    pub fn event(&self, id: Uuid) -> Option<&Event> {
        self.events.iter().find(|e| e.event_id == id)
    }

    /// Record an event and return its ID. Payload and metadata are redacted here.
    pub fn record(&mut self, spec: EventSpec) -> Uuid {
        let sequence = self.events.len() as u64 + 1;
        let event_id = if self.deterministic {
            Uuid::new_v5(&self.trace.trace_id, format!("event/{sequence}").as_bytes())
        } else {
            Uuid::new_v4()
        };
        let timestamp = if self.deterministic {
            DETERMINISTIC_EPOCH + Duration::seconds(sequence as i64)
        } else {
            now_utc()
        };
        let (payload, report) = self.redactor.redact_value(&spec.payload);
        let (metadata_value, meta_report) =
            self.redactor.redact_value(&Value::Object(spec.metadata));
        let mut metadata = match metadata_value {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        let redactions = report.redactions + meta_report.redactions;
        if redactions > 0 {
            metadata.insert("redactions".into(), Value::from(redactions));
        }
        if report.truncated || meta_report.truncated {
            metadata.insert("truncated".into(), Value::Bool(true));
        }
        // Only keep links to events that exist in this trace (never invent causality).
        let known = |id: &Uuid| self.events.iter().any(|e| e.event_id == *id);
        let context_event_ids: Vec<Uuid> =
            spec.context_event_ids.into_iter().filter(known).collect();
        let event = Event {
            schema_version: SCHEMA_VERSION.to_owned(),
            event_id,
            trace_id: self.trace.trace_id,
            sequence,
            timestamp,
            kind: spec.kind,
            parent_event_id: spec.parent_event_id,
            caused_by_event_id: spec.caused_by_event_id,
            origin: spec.origin,
            trust_level: spec.trust_level,
            name: self.redactor.scrub(&spec.name),
            payload,
            execution_mode: self.trace.execution_mode,
            tool_state: spec.tool_state,
            metadata,
            agent_id: spec
                .agent_id
                .map(|a| self.redactor.scrub(&a))
                .filter(|a| a != crate::event::DEFAULT_AGENT),
            context_event_ids,
        };
        if let Some(sink) = self.sink.as_mut() {
            if !self.started {
                sink(RecorderEvent::Started(&self.trace));
                self.started = true;
            }
            sink(RecorderEvent::Recorded(&self.trace, &event));
        }
        self.events.push(event);
        event_id
    }

    /// Finish successfully.
    pub fn finish(self) -> TraceRecord {
        self.finish_with(TraceStatus::Completed)
    }

    /// Finish with an explicit status (e.g. `Aborted` after an error).
    pub fn finish_with(mut self, status: TraceStatus) -> TraceRecord {
        self.trace.status = status;
        if let Some(sink) = self.sink.as_mut() {
            if !self.started {
                sink(RecorderEvent::Started(&self.trace));
            }
            sink(RecorderEvent::Finished(&self.trace));
        }
        TraceRecord {
            trace: self.trace,
            events: self.events,
        }
    }
}

fn now_utc() -> OffsetDateTime {
    let now = OffsetDateTime::now_utc();
    // Keep millisecond precision so RFC 3339 round trips are stable.
    now.replace_nanosecond(now.millisecond() as u32 * 1_000_000)
        .unwrap_or(now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    #[test]
    fn assigns_sequence_and_redacts() {
        let mut r = TraceRecorder::deterministic("t", ExecutionMode::Simulated, "seed");
        let a = r.record(
            EventSpec::new(
                EventKind::UserPromptReceived,
                Origin::User,
                TrustLevel::Trusted,
                "prompt",
            )
            .payload(json!({"text": "use token=FAKE_SECRET_XYZ please"})),
        );
        let b = r.record(
            EventSpec::new(
                EventKind::AgentDecision,
                Origin::Agent,
                TrustLevel::Unknown,
                "d",
            )
            .caused_by(a),
        );
        let rec = r.finish();
        assert_eq!(rec.events[0].sequence, 1);
        assert_eq!(rec.events[1].sequence, 2);
        assert_eq!(rec.events[1].caused_by_event_id, Some(a));
        assert_ne!(a, b);
        assert!(!rec.events[0].payload_text().contains("FAKE_SECRET_XYZ"));
        assert_eq!(rec.events[0].redaction_count(), 1);
        assert_eq!(rec.trace.status, TraceStatus::Completed);
    }

    #[test]
    fn deterministic_ids_are_stable() {
        let mk = || {
            let mut r = TraceRecorder::deterministic("t", ExecutionMode::Simulated, "seed");
            r.record(EventSpec::new(
                EventKind::AgentStarted,
                Origin::System,
                TrustLevel::Trusted,
                "a",
            ));
            r.finish()
        };
        assert_eq!(mk(), mk());
    }

    #[test]
    fn agent_and_context_links() {
        let mut r = TraceRecorder::new("t", ExecutionMode::Simulated);
        let a = r.record(EventSpec::new(
            EventKind::ToolResultReceived,
            Origin::McpTool,
            TrustLevel::LowerTrust,
            "x",
        ));
        let b = r.record(
            EventSpec::new(
                EventKind::ModelRequest,
                Origin::Agent,
                TrustLevel::Unknown,
                "m",
            )
            .agent("researcher".to_string())
            .context([a, a, Uuid::nil()]),
        );
        let main = r.record(
            EventSpec::new(
                EventKind::AgentDecision,
                Origin::Agent,
                TrustLevel::Unknown,
                "d",
            )
            .agent("main".to_string()),
        );
        let rec = r.finish();
        let eb = rec.event(b).unwrap();
        assert_eq!(eb.agent(), "researcher");
        assert_eq!(eb.context_event_ids, vec![a], "dedup + unknown ids dropped");
        assert_eq!(
            rec.event(main).unwrap().agent_id,
            None,
            "default agent is implicit"
        );
    }

    #[test]
    fn sink_sees_events_live() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let mut r = TraceRecorder::new("t", ExecutionMode::Simulated).with_sink(move |ev| {
            let label = match ev {
                RecorderEvent::Started(t) => format!("start:{}", t.status.as_str()),
                RecorderEvent::Recorded(_, e) => format!("event:{}", e.sequence),
                RecorderEvent::Finished(t) => format!("finish:{}", t.status.as_str()),
            };
            s.lock().unwrap().push(label);
        });
        r.record(EventSpec::new(
            EventKind::AgentStarted,
            Origin::System,
            TrustLevel::Trusted,
            "a",
        ));
        r.record(EventSpec::new(
            EventKind::AgentCompleted,
            Origin::System,
            TrustLevel::Trusted,
            "a",
        ));
        r.finish_with(TraceStatus::Aborted);
        assert_eq!(
            *seen.lock().unwrap(),
            ["start:running", "event:1", "event:2", "finish:aborted"]
        );
    }
}
