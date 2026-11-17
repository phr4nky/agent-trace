use std::fs::File;
use std::path::Path;

use agent_trace_storage::otlp::read_otlp;
use agent_trace_storage::{StorageError, TraceSource, read_jsonl};
use anyhow::Context as _;

use super::{Context, analyze_and_store, threshold_exit};
use crate::output::finding_line;
use crate::{ImportFormat, Threshold};

/// Import untrusted JSONL: validated, re-redacted, findings recomputed locally.
/// With `fail_on`, the exit code comes from the findings of this validated import.
pub fn run(
    ctx: &Context,
    format: ImportFormat,
    input: &Path,
    fail_on: Option<Threshold>,
) -> anyhow::Result<u8> {
    if let ImportFormat::Otlp = format {
        return otlp(ctx, input, fail_on);
    }
    let analyzer = ctx.analyzer()?;
    let file = File::open(input).with_context(|| format!("cannot open {}", input.display()))?;
    let imported = read_jsonl(file).with_context(|| format!("rejected {}", input.display()))?;
    let mut store = ctx.open_store()?;
    store.insert_trace(&imported.record, TraceSource::Imported)?;
    let findings = analyze_and_store(&analyzer, &mut store, &imported.record)?;
    outln!(
        "imported trace {} ({} events, {} value(s) redacted on import)",
        imported.record.trace.trace_id,
        imported.record.events.len(),
        imported.redactions
    );
    match &imported.integrity {
        Some(v) => outln!(
            "integrity: unchanged since export ({} records){}",
            v.lines,
            match &v.signed_by {
                Some((key_id, _)) =>
                    format!(", signed by key {key_id} (check it with `agent-trace verify`)"),
                None => ", unsigned".into(),
            }
        ),
        None => outln!("integrity: no integrity record (hand-written or older export)"),
    }
    if imported.ignored_findings > 0 {
        outln!(
            "ignored {} finding record(s) from the file; findings were recomputed locally",
            imported.ignored_findings
        );
    }
    for f in &findings {
        outln!("  {}", finding_line(&ctx.style, &imported.record, f));
    }
    Ok(threshold_exit(&findings, fail_on))
}

/// Import OTLP/JSON: every OTel trace in the file becomes a trace (mapped from the GenAI
/// semantic conventions, redacted, validated, analyzed). A trace imported before is skipped.
fn otlp(ctx: &Context, input: &Path, fail_on: Option<Threshold>) -> anyhow::Result<u8> {
    let analyzer = ctx.analyzer()?;
    let file = File::open(input).with_context(|| format!("cannot open {}", input.display()))?;
    let traces = read_otlp(file).with_context(|| format!("rejected {}", input.display()))?;
    let mut store = ctx.open_store()?;
    let mut all = Vec::new();
    let mut without_content = 0;
    for t in &traces {
        let record = &t.record;
        match store.insert_trace(record, TraceSource::Imported) {
            Ok(()) => {}
            Err(StorageError::DuplicateTrace(id)) => {
                outln!(
                    "skipped OTel trace {} (already imported as {id})",
                    record.trace.metadata["otel_trace_id"]
                        .as_str()
                        .unwrap_or("?")
                );
                continue;
            }
            Err(e) => return Err(e.into()),
        }
        let findings = analyze_and_store(&analyzer, &mut store, record)?;
        outln!(
            "imported trace {} ({}, {} events{})",
            record.trace.trace_id,
            crate::output::term_safe(&record.trace.name),
            record.events.len(),
            if t.ignored_spans > 0 {
                format!(", {} non-GenAI span(s) skipped", t.ignored_spans)
            } else {
                String::new()
            }
        );
        if !t.content_captured {
            without_content += 1;
        }
        for f in &findings {
            outln!("  {}", finding_line(&ctx.style, record, f));
        }
        all.extend(findings);
    }
    if without_content > 0 {
        eprintln!(
            "note: {without_content} trace(s) carry no message content, so tool calls cannot be linked to \
             what caused them and causal rules (AT-002, AT-003, AT-006) cannot fire. Enable content \
             capture in the instrumentation, e.g. OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=SPAN_ONLY."
        );
    }
    Ok(threshold_exit(&all, fail_on))
}
