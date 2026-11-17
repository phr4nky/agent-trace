//! JSONL import/export and the JSON evidence report.
//!
//! JSONL layout: the first line is a `trace` record, followed by `event` records in sequence
//! order and optional `finding` records. Imports are treated as untrusted data: every value
//! is re-redacted, size limits are enforced and the trace invariants are validated.
//! Imported findings are ignored; findings are always recomputed locally.

use crate::integrity::{Chain, IntegrityRecord, SigningKey, Verified};
use std::io::{BufRead, Read, Write};

use agent_trace_core::rules::record_content_indicators;
use std::collections::HashMap;

use agent_trace_core::{
    Event, Finding, RedactionReport, Redactor, Trace, TraceRecord, ValidationError, validate,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::StorageError;

/// Maximum length of one JSONL line.
pub const MAX_LINE_BYTES: usize = 2 * 1024 * 1024;
/// Maximum number of events in one imported trace.
pub const MAX_EVENTS: usize = 100_000;
/// Maximum total size of one imported file (lines and events alone would allow ~200 GB).
pub const MAX_IMPORT_BYTES: u64 = 512 * 1024 * 1024;
/// Maximum number of JSON values (after redaction) kept for one import. Parsed values take
/// many times their text size in memory; this bounds the memory of a hostile import.
pub const MAX_IMPORT_VALUES: usize = 10_000_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "record_type", rename_all = "snake_case")]
pub enum JsonlRecord {
    Trace(Trace),
    Event(Event),
    Finding(Finding),
    /// Hash chain (and optional signature) over all previous lines; last line of an export.
    Integrity(IntegrityRecord),
}

/// Result of an import.
#[derive(Debug)]
pub struct Imported {
    pub record: TraceRecord,
    /// Number of finding lines that were present but ignored.
    pub ignored_findings: usize,
    /// Number of values redacted during import.
    pub redactions: u64,
    /// The file's integrity record, verified (`None`: the file has none).
    pub integrity: Option<Verified>,
}

/// Write a trace (and its findings) as JSONL. Values are redacted again defensively. The
/// last line is an integrity record (hash chain over all other lines, see [`crate::integrity`]).
pub fn write_jsonl(
    out: impl Write,
    record: &TraceRecord,
    findings: &[Finding],
) -> Result<(), StorageError> {
    write_jsonl_signed(out, record, findings, None)
}

/// [`write_jsonl`], with the integrity record signed by `key`.
pub fn write_jsonl_signed(
    mut out: impl Write,
    record: &TraceRecord,
    findings: &[Finding],
    key: Option<&SigningKey>,
) -> Result<(), StorageError> {
    let record = redact_record(record).0;
    let mut chain = Chain::default();
    let mut line = |rec: &JsonlRecord, chain: &mut Chain| -> Result<(), StorageError> {
        let text = serde_json::to_vec(rec)?;
        chain.push(&text);
        out.write_all(&text)?;
        out.write_all(b"\n")?;
        Ok(())
    };
    line(&JsonlRecord::Trace(record.trace.clone()), &mut chain)?;
    for event in &record.events {
        line(&JsonlRecord::Event(event.clone()), &mut chain)?;
    }
    for finding in findings {
        line(&JsonlRecord::Finding(finding.clone()), &mut chain)?;
    }
    let integrity = JsonlRecord::Integrity(chain.record(record.trace.trace_id, key));
    serde_json::to_writer(&mut out, &integrity)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

/// Parse, redact and validate a JSONL trace.
pub fn read_jsonl(input: impl Read) -> Result<Imported, StorageError> {
    read_jsonl_limited(input, MAX_IMPORT_BYTES, MAX_IMPORT_VALUES)
}

fn read_jsonl_limited(
    input: impl Read,
    max_total: u64,
    max_values: usize,
) -> Result<Imported, StorageError> {
    let mut reader = std::io::BufReader::new(input);
    let redactor = Redactor::new();
    let mut total: u64 = 0;
    let mut values = 0usize;
    let mut redactions = 0u64;
    let mut header_line = 0usize;
    let mut event_lines: HashMap<Uuid, usize> = HashMap::new();
    let mut trace: Option<Trace> = None;
    let mut events = Vec::new();
    let mut ignored_findings = 0;
    let mut line_no = 0usize;
    let mut buf = Vec::new();
    let mut chain = Chain::default();
    let mut integrity: Option<Verified> = None;
    loop {
        buf.clear();
        line_no += 1;
        let read = (&mut reader)
            .take(MAX_LINE_BYTES as u64 + 1)
            .read_until(b'\n', &mut buf)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > max_total {
            return Err(StorageError::Import {
                line: line_no,
                message: format!("file exceeds {max_total} bytes"),
            });
        }
        if buf.len() > MAX_LINE_BYTES {
            return Err(StorageError::Import {
                line: line_no,
                message: format!("line exceeds {MAX_LINE_BYTES} bytes"),
            });
        }
        let text = std::str::from_utf8(&buf).map_err(|_| StorageError::Import {
            line: line_no,
            message: "line is not valid UTF-8".into(),
        })?;
        if text.trim().is_empty() {
            continue;
        }
        if integrity.is_some() {
            return Err(StorageError::Import {
                line: line_no,
                message: "records after the integrity record (the file was extended after \
                          export)"
                    .into(),
            });
        }
        let rec: JsonlRecord = serde_json::from_str(text).map_err(|e| StorageError::Import {
            line: line_no,
            message: format!("malformed record: {e}"),
        })?;
        if !matches!(rec, JsonlRecord::Integrity(_)) {
            let raw = text.strip_suffix('\n').unwrap_or(text);
            chain.push(raw.strip_suffix('\r').unwrap_or(raw).as_bytes());
        }
        match rec {
            JsonlRecord::Trace(t) => {
                if trace.is_some() {
                    return Err(StorageError::Import {
                        line: line_no,
                        message: "more than one trace header; import one trace per file".into(),
                    });
                }
                if !events.is_empty() {
                    return Err(StorageError::Import {
                        line: line_no,
                        message: "trace header must be the first record".into(),
                    });
                }
                header_line = line_no;
                trace = Some(t);
            }
            JsonlRecord::Event(e) => {
                if trace.is_none() {
                    return Err(StorageError::Import {
                        line: line_no,
                        message: "event before trace header".into(),
                    });
                }
                if events.len() >= MAX_EVENTS {
                    return Err(StorageError::Import {
                        line: line_no,
                        message: format!("more than {MAX_EVENTS} events"),
                    });
                }
                // Redact (and cap) each event as it is read: only the bounded, redacted
                // copy is kept in memory.
                let (e, n) = redact_event(&redactor, e);
                redactions += n;
                values +=
                    count_values(&e.payload) + e.metadata.values().map(count_values).sum::<usize>();
                if values > max_values {
                    return Err(StorageError::Import {
                        line: line_no,
                        message: format!("trace has more than {max_values} JSON values"),
                    });
                }
                event_lines.insert(e.event_id, line_no);
                events.push(e);
            }
            JsonlRecord::Finding(_) => ignored_findings += 1,
            JsonlRecord::Integrity(record) => {
                let trace_id = trace
                    .as_ref()
                    .map(|t| t.trace_id)
                    .ok_or(StorageError::Import {
                        line: line_no,
                        message: "integrity record before the trace header".into(),
                    })?;
                integrity =
                    Some(
                        record
                            .verify(&chain, trace_id)
                            .map_err(|e| StorageError::Import {
                                line: line_no,
                                message: e.to_string(),
                            })?,
                    );
            }
        }
    }
    let trace = trace.ok_or(StorageError::Import {
        line: line_no,
        message: "no trace header found (empty file?)".into(),
    })?;
    let (trace, n) = redact_trace(&redactor, trace);
    redactions += n;
    let record = TraceRecord { trace, events };
    if let Err(e) = validate(&record) {
        let line = match &e {
            ValidationError::UnsupportedSchema { found, .. } => {
                if record.trace.schema_version == *found {
                    Some(header_line)
                } else {
                    record
                        .events
                        .iter()
                        .find(|ev| ev.schema_version == *found)
                        .and_then(|ev| event_lines.get(&ev.event_id).copied())
                }
            }
            other => validation_event(other).and_then(|id| event_lines.get(&id).copied()),
        };
        return Err(match line {
            Some(line) => StorageError::Import {
                line,
                message: format!("invalid trace: {e}"),
            },
            None => StorageError::Invalid(e),
        });
    }
    Ok(Imported {
        record,
        ignored_findings,
        redactions,
        integrity,
    })
}

/// JSON evidence report (`export --format json`).
#[derive(Debug, Serialize, Deserialize)]
pub struct EvidenceReport {
    pub report_version: String,
    pub generated_by: String,
    pub redacted: bool,
    pub disclaimer: String,
    pub trace: Trace,
    pub findings: Vec<Finding>,
    pub events: Vec<Event>,
}

pub fn evidence_report(record: &TraceRecord, findings: &[Finding]) -> EvidenceReport {
    let record = redact_record(record).0;
    EvidenceReport {
        report_version: "1.0".into(),
        generated_by: format!("agent-trace {}", env!("CARGO_PKG_VERSION")),
        redacted: true,
        disclaimer: "Findings are evidence-based indicators, not proof of compromise. \
                     Traces with execution_mode=simulated come from a scripted demo agent."
            .into(),
        trace: record.trace,
        findings: findings.to_vec(),
        events: record.events,
    }
}

pub fn write_json_report(
    mut out: impl Write,
    record: &TraceRecord,
    findings: &[Finding],
) -> Result<(), StorageError> {
    serde_json::to_writer_pretty(&mut out, &evidence_report(record, findings))?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

/// The event a validation error is about.
fn validation_event(e: &ValidationError) -> Option<Uuid> {
    match e {
        ValidationError::ForeignEvent { event_id, .. }
        | ValidationError::BadSequence { event_id, .. }
        | ValidationError::DanglingLink { event_id, .. }
        | ValidationError::SelfLink { event_id }
        | ValidationError::ForwardLink { event_id, .. }
        | ValidationError::PayloadTooLarge { event_id, .. } => Some(*event_id),
        ValidationError::DuplicateEventId(id) | ValidationError::Cycle(id) => Some(*id),
        ValidationError::UnsupportedSchema { .. } => None,
    }
}

/// Number of JSON values in `v` (itself included).
fn count_values(v: &Value) -> usize {
    1 + match v {
        Value::Array(items) => items.iter().map(count_values).sum(),
        Value::Object(map) => map.values().map(count_values).sum(),
        _ => 0,
    }
}

fn redact_map(redactor: &Redactor, m: Map<String, Value>) -> (Map<String, Value>, RedactionReport) {
    let (v, r) = redactor.redact_value(&Value::Object(m));
    match v {
        Value::Object(m) => (m, r),
        _ => (Map::new(), r),
    }
}

/// Redact one event like the recorder does: payload, metadata (both counted in
/// `metadata.redactions`), name and agent id. Returns the number of new redactions.
fn redact_event(redactor: &Redactor, mut e: Event) -> (Event, u64) {
    let (mut metadata, meta) = redact_map(redactor, std::mem::take(&mut e.metadata));
    let (payload, pay) = redactor.redact_value(&e.payload);
    let added = pay.redactions.saturating_add(meta.redactions);
    if added > 0 {
        let prev = metadata
            .get("redactions")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        metadata.insert("redactions".into(), Value::from(prev.saturating_add(added)));
    }
    if pay.truncated || meta.truncated {
        metadata.insert("truncated".into(), Value::Bool(true));
    }
    if pay.truncated {
        // Rules only see the stored (cut) payload; keep what the original contained.
        record_content_indicators(&mut metadata, &e.payload);
    }
    e.payload = payload;
    e.metadata = metadata;
    e.name = redactor.scrub(&e.name);
    e.agent_id = e.agent_id.as_deref().map(|a| redactor.scrub(a));
    (e, added)
}

fn redact_trace(redactor: &Redactor, mut trace: Trace) -> (Trace, u64) {
    let (metadata, r) = redact_map(redactor, std::mem::take(&mut trace.metadata));
    trace.metadata = metadata;
    trace.name = redactor.scrub(&trace.name);
    (trace, r.redactions)
}

/// Apply the shared redactor to every payload, metadata map and name of a trace.
pub fn redact_record(record: &TraceRecord) -> (TraceRecord, u64) {
    let redactor = Redactor::new();
    let (trace, mut total) = redact_trace(&redactor, record.trace.clone());
    let mut events = Vec::with_capacity(record.events.len());
    for event in &record.events {
        let (e, n) = redact_event(&redactor, event.clone());
        total += n;
        events.push(e);
    }
    (TraceRecord { trace, events }, total)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression: only per-line and event-count limits existed, no total size limit.
    #[test]
    fn total_import_size_is_limited() {
        let line = format!("{}\n", " ".repeat(1000));
        let input = line.repeat(20);
        let err = read_jsonl_limited(input.as_bytes(), 10_000, MAX_IMPORT_VALUES).unwrap_err();
        assert!(err.to_string().contains("exceeds 10000 bytes"), "{err}");
    }

    // Regression: parsed values take ~30x their text size, so a 512 MiB file could need
    // ~17 GB. The number of retained JSON values is capped.
    #[test]
    fn retained_json_values_are_capped() {
        let trace_id = "6f1c0d6e-0000-4000-8000-0000000000bb";
        let header = serde_json::json!({"record_type": "trace", "schema_version": "1.1",
            "trace_id": trace_id, "name": "n", "created_at": "2026-11-16T09:00:00Z",
            "execution_mode": "live"});
        let event = serde_json::json!({"record_type": "event", "schema_version": "1.1",
            "event_id": "6f1c0d6e-0000-4000-8000-000000000001", "trace_id": trace_id,
            "sequence": 1, "timestamp": "2026-11-16T09:00:01Z", "kind": "agent_decision",
            "parent_event_id": null, "caused_by_event_id": null, "origin": "agent",
            "trust_level": "unknown", "name": "d", "payload": {"xs": vec![0; 5000]},
            "execution_mode": "live", "tool_state": null, "metadata": {}});
        let input = format!("{header}\n{event}\n");
        let err = read_jsonl_limited(input.as_bytes(), MAX_IMPORT_BYTES, 1000).unwrap_err();
        assert!(
            err.to_string().contains("more than 1000 JSON values"),
            "{err}"
        );
        assert!(read_jsonl_limited(input.as_bytes(), MAX_IMPORT_BYTES, 10_000).is_ok());
    }
}
