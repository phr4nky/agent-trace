use std::io::{BufWriter, Write};
use std::path::Path;

use agent_trace_storage::{
    SarifTrace, create_private_file, write_json_report, write_jsonl, write_sarif,
};

use super::{Context, analyze_and_store, resolve_target};
use crate::{EXIT_OK, ExportFormat, TraceTarget};

/// Export is always redacted; there is intentionally no raw-output flag.
pub fn run(
    ctx: &Context,
    target: &TraceTarget,
    format: ExportFormat,
    output: Option<&Path>,
    artifact_uri: Option<&str>,
) -> anyhow::Result<u8> {
    let mut store = ctx.open_store()?;
    let id = resolve_target(&mut store, target)?;
    let record = store.load_trace(id)?;
    let mut findings = store.load_findings(id)?;
    if findings.is_empty() {
        findings = analyze_and_store(&ctx.analyzer()?, &mut store, &record)?;
    }
    let writer: Box<dyn Write> = match output {
        Some(path) => Box::new(BufWriter::new(create_private_file(path)?)),
        None => Box::new(std::io::stdout().lock()),
    };
    match format {
        ExportFormat::Json => write_json_report(writer, &record, &findings)?,
        ExportFormat::Jsonl => write_jsonl(writer, &record, &findings)?,
        ExportFormat::Sarif => {
            let uri = artifact_uri
                .map(str::to_owned)
                .unwrap_or_else(|| format!("trace-{id}.jsonl"));
            write_sarif(
                writer,
                &[SarifTrace {
                    artifact_uri: &uri,
                    record: &record,
                    findings: &findings,
                    event_lines: None,
                }],
                &ctx.analyzer()?,
            )?
        }
    }
    if let Some(path) = output {
        eprintln!("exported trace {id} (redacted) to {}", path.display());
    }
    Ok(EXIT_OK)
}
