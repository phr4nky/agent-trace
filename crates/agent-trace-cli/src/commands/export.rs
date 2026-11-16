use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use agent_trace_storage::{restrict_file, write_json_report, write_jsonl};

use super::{Context, analyze_and_store, resolve_target};
use crate::{EXIT_OK, ExportFormat, TraceTarget};

/// Export is always redacted; there is intentionally no raw-output flag in v1.0.
pub fn run(
    ctx: &Context,
    target: &TraceTarget,
    format: ExportFormat,
    output: Option<&Path>,
) -> anyhow::Result<u8> {
    let mut store = ctx.open_store()?;
    let id = resolve_target(&mut store, target)?;
    let record = store.load_trace(id)?;
    let mut findings = store.load_findings(id)?;
    if findings.is_empty() {
        findings = analyze_and_store(&mut store, &record)?;
    }
    let writer: Box<dyn Write> = match output {
        Some(path) => Box::new(BufWriter::new(File::create(path)?)),
        None => Box::new(std::io::stdout().lock()),
    };
    match format {
        ExportFormat::Json => write_json_report(writer, &record, &findings)?,
        ExportFormat::Jsonl => write_jsonl(writer, &record, &findings)?,
    }
    if let Some(path) = output {
        restrict_file(path)?;
        eprintln!("exported trace {id} (redacted) to {}", path.display());
    }
    Ok(EXIT_OK)
}
