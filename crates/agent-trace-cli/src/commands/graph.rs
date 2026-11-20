//! `agent-trace graph`: write a trace as a self-contained, interactive HTML causal graph.
//!
//! The page embeds the redacted evidence report (the same content as `export --format json`)
//! and a small viewer with no libraries. It makes no network requests: a Content-Security-
//! Policy allows only its own inline script and style (by hash) and no connections, and the
//! viewer inserts trace content as text only, so content from an attacker cannot run in it.

use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use agent_trace_storage::create_private_file;

use super::{Context, analyze_and_store, resolve_target};
use crate::{EXIT_OK, TraceTarget};

pub fn run(ctx: &Context, target: &TraceTarget, output: Option<&Path>) -> anyhow::Result<u8> {
    let mut store = ctx.open_store()?;
    let id = resolve_target(&mut store, target)?;
    let record = store.load_trace(id)?;
    let mut findings = store.load_findings(id)?;
    if findings.is_empty() {
        findings = analyze_and_store(&ctx.analyzer()?, &mut store, &record)?;
    }
    let path: PathBuf = match output {
        Some(p) => p.to_path_buf(),
        None => ctx.exports_dir()?.join(format!("graph-{id}.html")),
    };
    let html = agent_trace_storage::graph::render(&record, &findings)?;
    let mut out = BufWriter::new(create_private_file(&path)?);
    out.write_all(html.as_bytes())?;
    out.flush()?;
    outln!(
        "wrote the causal graph of trace {id} ({} events, {} findings, redacted) to",
        record.events.len(),
        findings.len()
    );
    outln!(
        "  {}",
        crate::output::term_safe(&path.display().to_string())
    );
    outln!("open it in a browser; it makes no network requests");
    Ok(EXIT_OK)
}
