use std::fs::File;
use std::path::Path;

use agent_trace_storage::{TraceSource, read_jsonl};
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
    let ImportFormat::Jsonl = format;
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
