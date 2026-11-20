//! Traces that recorders send to `agent-trace-server` (`agent-trace ship`).
//!
//! A recorder sends one trace per request: the current trace header and the events after the
//! last one the server confirmed. The server appends them to the trace of that source after the
//! checks `import` makes: everything is redacted again, the whole trace must stay valid, and the
//! findings are computed on the server (a recorder never sends findings). Each trace belongs to
//! the source that sent it first; no other source can extend it.

use agent_trace_core::{Analyzer, Event, Trace, TraceRecord, validate};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::jsonl::{MAX_EVENTS, redact_record};
use crate::{StorageError, Store, TraceSource};

/// At most this many events per request.
pub const MAX_BATCH_EVENTS: usize = 2_000;

/// One request: the trace header as the recorder has it now, and events in sequence order,
/// starting after the last event the server confirmed (events the server already has are
/// accepted again if they are the same, so a request can be retried).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestBatch {
    pub trace: Trace,
    pub events: Vec<Event>,
}

/// The server's answer to a batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestReply {
    pub trace_id: Uuid,
    /// The sequence number of the last stored event: the next batch starts after it.
    pub stored_seq: u64,
    /// Findings of the whole trace after this batch.
    pub findings: usize,
    /// Values redacted again on the server (normally 0: the recorder redacts first).
    pub redactions: u64,
}

/// Why a batch was not stored.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    /// The batch does not continue the stored trace: the trace belongs to another source, a
    /// batch is missing, or an event differs from the stored one. `stored_seq` is where the
    /// recorder should continue, if the trace is its own.
    #[error("{message}")]
    Conflict {
        message: String,
        stored_seq: Option<u64>,
    },
    /// The batch is malformed, too large, or would make the trace invalid.
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Storage(#[from] StorageError),
}

fn conflict(message: impl Into<String>, stored_seq: Option<u64>) -> IngestError {
    IngestError::Conflict {
        message: message.into(),
        stored_seq,
    }
}

/// Append `batch` to the trace of `source_id` and recompute its findings with `analyzer`.
pub fn ingest(
    store: &mut Store,
    source_id: Uuid,
    batch: IngestBatch,
    analyzer: &Analyzer,
    now: OffsetDateTime,
) -> Result<IngestReply, IngestError> {
    let trace_id = batch.trace.trace_id;
    if batch.events.len() > MAX_BATCH_EVENTS {
        return Err(IngestError::Invalid(format!(
            "more than {MAX_BATCH_EVENTS} events in one batch"
        )));
    }
    if let Some(e) = batch.events.iter().find(|e| e.trace_id != trace_id) {
        return Err(IngestError::Invalid(format!(
            "event {} belongs to trace {}, not {trace_id}",
            e.event_id, e.trace_id
        )));
    }
    if !batch
        .events
        .windows(2)
        .all(|w| w[0].sequence < w[1].sequence)
    {
        return Err(IngestError::Invalid(
            "events must be in increasing sequence order".into(),
        ));
    }

    let existing = match store.trace_source(trace_id)? {
        None => None,
        Some(owner) if owner == Some(source_id) => Some(store.load_trace(trace_id)?),
        Some(_) => {
            return Err(conflict(
                format!("trace {trace_id} was not sent by this source"),
                None,
            ));
        }
    };
    let stored_seq = existing
        .as_ref()
        .and_then(|r| r.events.last())
        .map_or(0, |e| e.sequence);

    // Events the server already has: a retried request. They must be the same events.
    let mut new_events = Vec::with_capacity(batch.events.len());
    for event in batch.events {
        if event.sequence > stored_seq {
            new_events.push(event);
            continue;
        }
        let same = existing
            .as_ref()
            .and_then(|r| r.events.iter().find(|e| e.sequence == event.sequence))
            .is_some_and(|e| e.event_id == event.event_id);
        if !same {
            return Err(conflict(
                format!(
                    "event #{} differs from the stored event with that number",
                    event.sequence
                ),
                Some(stored_seq),
            ));
        }
    }
    if let Some(first) = new_events.first()
        && first.sequence != stored_seq + 1
    {
        return Err(conflict(
            format!(
                "expected event #{} next, got #{}",
                stored_seq + 1,
                first.sequence
            ),
            Some(stored_seq),
        ));
    }

    // The recorder redacted already; the server does not rely on it.
    let (incoming, redactions) = redact_record(&TraceRecord {
        trace: batch.trace,
        events: new_events,
    });
    let mut merged = existing.clone().unwrap_or_else(|| TraceRecord {
        trace: incoming.trace.clone(),
        events: Vec::new(),
    });
    merged.trace = incoming.trace.clone();
    merged.events.extend(incoming.events.iter().cloned());
    if merged.events.len() > MAX_EVENTS {
        return Err(IngestError::Invalid(format!(
            "trace has more than {MAX_EVENTS} events"
        )));
    }
    validate(&merged).map_err(|e| IngestError::Invalid(format!("invalid trace: {e}")))?;

    if existing.is_none() {
        store
            .begin_trace(&merged.trace, TraceSource::Received)
            .map_err(|e| match e {
                // Sent at the same time by another request, or a trace of the server itself.
                StorageError::DuplicateTrace(_) => {
                    conflict(format!("trace {trace_id} already exists"), None)
                }
                other => other.into(),
            })?;
        store.set_trace_source(trace_id, source_id)?;
    }
    for event in &incoming.events {
        store.append_event(event)?;
    }
    store.update_trace(&merged.trace)?;

    let findings = analyzer.analyze(&merged, now);
    let versions: Vec<(&str, u32)> = analyzer.rules().map(|r| (r.id(), r.version())).collect();
    store.save_findings(trace_id, &versions, &findings)?;
    Ok(IngestReply {
        trace_id,
        stored_seq: merged.events.last().map_or(0, |e| e.sequence),
        findings: findings.len(),
        redactions,
    })
}
