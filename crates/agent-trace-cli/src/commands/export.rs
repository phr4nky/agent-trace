use std::io::{BufWriter, Write};
use std::path::Path;

use agent_trace_storage::{
    SarifTrace, SiemFormat, create_private_file, write_json_report, write_jsonl_signed,
    write_sarif, write_siem,
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
    include_events: bool,
    // `Some(key path or default)` to sign.
    sign: Option<Option<&Path>>,
) -> anyhow::Result<u8> {
    let key = match (sign, format) {
        (None, _) => None,
        (Some(path), ExportFormat::Jsonl) => Some(super::keys::load_key(ctx, path)?),
        (Some(_), _) => anyhow::bail!("--sign is supported for --format jsonl"),
    };
    let siem = match format {
        ExportFormat::Ocsf => Some(SiemFormat::Ocsf),
        ExportFormat::SplunkHec => Some(SiemFormat::SplunkHec),
        ExportFormat::Elastic => Some(SiemFormat::Elastic),
        ExportFormat::Json | ExportFormat::Jsonl | ExportFormat::Sarif => None,
    };
    if include_events && siem.is_none() {
        anyhow::bail!("--include-events is supported for --format ocsf, splunk-hec and elastic");
    }
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
    match (format, siem) {
        (_, Some(siem)) => write_siem(writer, siem, &record, &findings, include_events)?,
        (ExportFormat::Json, _) => write_json_report(writer, &record, &findings)?,
        (ExportFormat::Jsonl, _) => write_jsonl_signed(writer, &record, &findings, key.as_ref())?,
        (ExportFormat::Sarif, _) => {
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
        (ExportFormat::Ocsf | ExportFormat::SplunkHec | ExportFormat::Elastic, None) => {
            unreachable!("SIEM formats map to a SiemFormat")
        }
    }
    if let Some(path) = output {
        eprintln!("exported trace {id} (redacted) to {}", path.display());
    }
    if let Some(key) = &key {
        eprintln!("signed with key {}", key.key_id());
    }
    Ok(EXIT_OK)
}
