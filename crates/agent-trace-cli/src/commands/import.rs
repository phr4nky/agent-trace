use std::fs::File;
use std::path::{Path, PathBuf};

use agent_trace_storage::otlp::{read_otlp_all, span_ids};
use agent_trace_storage::{StorageError, TraceSource, read_jsonl};
use anyhow::{Context as _, bail};

use super::{Context, analyze_and_store, threshold_exit};
use crate::output::{finding_line, term_safe};
use crate::{ImportFormat, Threshold};

/// Import untrusted files: validated, re-redacted, findings recomputed locally.
/// With `fail_on`, the exit code comes from the findings of this validated import.
pub fn run(
    ctx: &Context,
    format: ImportFormat,
    inputs: &[PathBuf],
    replace: bool,
    fail_on: Option<Threshold>,
) -> anyhow::Result<u8> {
    if let ImportFormat::Otlp = format {
        return otlp(ctx, inputs, replace, fail_on);
    }
    if replace {
        bail!("--replace applies to --format otlp only");
    }
    let mut code = crate::EXIT_OK;
    for input in inputs {
        code = code.max(jsonl(ctx, input, fail_on)?);
    }
    Ok(code)
}

/// Import one JSONL export.
fn jsonl(ctx: &Context, input: &Path, fail_on: Option<Threshold>) -> anyhow::Result<u8> {
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

/// Import OTLP/JSON: every OTel trace in the files becomes a trace (mapped from the GenAI
/// semantic conventions, redacted, validated, analyzed); spans are grouped by trace across
/// all files. A trace imported before is skipped when this import adds no span to it, and
/// replaced when this import holds all of its spans and more (the file grew, or all parts
/// are imported together). Otherwise its spans are split between imports and it is not
/// imported (exit 1) unless `replace` is set: a trace mapped from part of its spans would
/// silently miss the findings of the rest.
fn otlp(
    ctx: &Context,
    inputs: &[PathBuf],
    replace: bool,
    fail_on: Option<Threshold>,
) -> anyhow::Result<u8> {
    let analyzer = ctx.analyzer()?;
    let files = inputs
        .iter()
        .map(|p| File::open(p).with_context(|| format!("cannot open {}", p.display())))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let names = inputs
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let traces = read_otlp_all(files).with_context(|| format!("rejected {names}"))?;
    let mut store = ctx.open_store()?;
    let mut all = Vec::new();
    let mut without_content = 0;
    let mut split = Vec::new();
    for t in &traces {
        let record = &t.record;
        let otel_id = record.trace.metadata["otel_trace_id"]
            .as_str()
            .unwrap_or("?")
            .to_owned();
        let mut replaced = None;
        match store.insert_trace(record, TraceSource::Imported) {
            Ok(()) => {}
            Err(StorageError::DuplicateTrace(id)) => {
                let stored = span_ids(&store.load_trace(record.trace.trace_id)?);
                let new = span_ids(record);
                let added = new.difference(&stored).count();
                let missing = stored.difference(&new).count();
                if !replace && added == 0 {
                    outln!("skipped OTel trace {otel_id} (already imported as {id})");
                    continue;
                }
                if !replace && missing > 0 {
                    split.push((otel_id, added, missing));
                    continue;
                }
                store.delete_trace(record.trace.trace_id)?;
                store.insert_trace(record, TraceSource::Imported)?;
                replaced = Some(added);
            }
            Err(e) => return Err(e.into()),
        }
        let findings = analyze_and_store(&analyzer, &mut store, record)?;
        outln!(
            "{} trace {} ({}, {} events{}{})",
            if replaced.is_some() {
                "replaced"
            } else {
                "imported"
            },
            record.trace.trace_id,
            crate::output::term_safe(&record.trace.name),
            record.events.len(),
            if t.ignored_spans > 0 {
                format!(", {} non-GenAI span(s) skipped", t.ignored_spans)
            } else {
                String::new()
            },
            match replaced {
                Some(n) if n > 0 => format!(", {n} span(s) more than before"),
                _ => String::new(),
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
    if !split.is_empty() {
        for (otel_id, added, missing) in &split {
            eprintln!(
                "error: OTel trace {} was imported before from other spans: {added} span(s) of \
                 this import are not in it and {missing} of its span(s) are not in this import",
                term_safe(otel_id)
            );
        }
        bail!(
            "{} trace(s) not imported: their spans are split between files. Import all files \
             of these traces together and replace what was imported: agent-trace import \
             --format otlp --input FILE --input FILE ... --replace",
            split.len()
        );
    }
    Ok(threshold_exit(&all, fail_on))
}
