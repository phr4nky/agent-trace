//! JSONL import/export and the JSON evidence report.
//!
//! JSONL layout: the first line is a `trace` record, followed by `event` records in sequence
//! order and optional `finding` records. Imports are treated as untrusted data: every value
//! is re-redacted, size limits are enforced and the trace invariants are validated.
//! Imported findings are ignored; findings are always recomputed locally.

use std::io::{BufRead, Read, Write};

use agent_trace_core::{Event, Finding, Redactor, Trace, TraceRecord, validate};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::StorageError;

/// Maximum length of one JSONL line.
pub const MAX_LINE_BYTES: usize = 2 * 1024 * 1024;
/// Maximum number of events in one imported trace.
pub const MAX_EVENTS: usize = 100_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "record_type", rename_all = "snake_case")]
pub enum JsonlRecord {
    Trace(Trace),
    Event(Event),
    Finding(Finding),
}

/// Result of an import.
#[derive(Debug)]
pub struct Imported {
    pub record: TraceRecord,
    /// Number of finding lines that were present but ignored.
    pub ignored_findings: usize,
    /// Number of values redacted during import.
    pub redactions: u64,
}

/// Write a trace (and its findings) as JSONL. Values are redacted again defensively.
pub fn write_jsonl(
    mut out: impl Write,
    record: &TraceRecord,
    findings: &[Finding],
) -> Result<(), StorageError> {
    let record = redact_record(record).0;
    let mut line = |rec: &JsonlRecord| -> Result<(), StorageError> {
        serde_json::to_writer(&mut out, rec)?;
        out.write_all(b"\n")?;
        Ok(())
    };
    line(&JsonlRecord::Trace(record.trace.clone()))?;
    for event in &record.events {
        line(&JsonlRecord::Event(event.clone()))?;
    }
    for finding in findings {
        line(&JsonlRecord::Finding(finding.clone()))?;
    }
    out.flush()?;
    Ok(())
}

/// Parse, redact and validate a JSONL trace.
pub fn read_jsonl(input: impl Read) -> Result<Imported, StorageError> {
    let mut reader = std::io::BufReader::new(input);
    let mut trace: Option<Trace> = None;
    let mut events = Vec::new();
    let mut ignored_findings = 0;
    let mut line_no = 0usize;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        line_no += 1;
        let read = (&mut reader)
            .take(MAX_LINE_BYTES as u64 + 1)
            .read_until(b'\n', &mut buf)?;
        if read == 0 {
            break;
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
        let rec: JsonlRecord = serde_json::from_str(text).map_err(|e| StorageError::Import {
            line: line_no,
            message: format!("malformed record: {e}"),
        })?;
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
                events.push(e);
            }
            JsonlRecord::Finding(_) => ignored_findings += 1,
        }
    }
    let trace = trace.ok_or(StorageError::Import {
        line: line_no,
        message: "no trace header found (empty file?)".into(),
    })?;
    let (record, redactions) = redact_record(&TraceRecord { trace, events });
    validate(&record)?;
    Ok(Imported {
        record,
        ignored_findings,
        redactions,
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

/// Apply the shared redactor to every payload, metadata map and name of a trace.
pub fn redact_record(record: &TraceRecord) -> (TraceRecord, u64) {
    let redactor = Redactor::new();
    let mut total = 0;
    let redact_map = |m: &Map<String, Value>, total: &mut u64| -> Map<String, Value> {
        let (v, r) = redactor.redact_value(&Value::Object(m.clone()));
        *total += r.redactions;
        match v {
            Value::Object(m) => m,
            _ => Map::new(),
        }
    };
    let mut trace = record.trace.clone();
    trace.metadata = redact_map(&trace.metadata, &mut total);
    let mut events = Vec::with_capacity(record.events.len());
    for event in &record.events {
        let mut e = event.clone();
        e.metadata = redact_map(&e.metadata, &mut total);
        let (payload, r) = redactor.redact_value(&e.payload);
        total += r.redactions;
        if r.redactions > 0 {
            let prev = e.redaction_count();
            e.metadata
                .insert("redactions".into(), Value::from(prev + r.redactions));
        }
        if r.truncated {
            e.metadata.insert("truncated".into(), Value::Bool(true));
        }
        e.payload = payload;
        e.name = redactor.scrub(&e.name);
        events.push(e);
    }
    trace.name = redactor.scrub(&trace.name);
    (TraceRecord { trace, events }, total)
}
