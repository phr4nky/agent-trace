//! `agent-trace proxy -- <server command>`: record (and optionally enforce) the traffic
//! between an MCP client and an MCP server.
//!
//! Stdout belongs to the MCP protocol: this command writes nothing else there. Status lines
//! go to stderr, which MCP clients show in their server logs.

use std::io::BufWriter;
use std::path::PathBuf;
use std::time::Duration;

use agent_trace_core::{ExecutionMode, TraceRecorder};
use agent_trace_mcp::{McpSession, Proxy, ProxyConfig, ProxyMode, ServerCommand};
use agent_trace_storage::{LiveWriter, TraceSource, create_private_file, write_jsonl};
use anyhow::Context as _;

use super::Context;
use crate::EXIT_OK;
use crate::output::{finding_line, term_safe};

pub struct ProxyArgs {
    pub name: Option<String>,
    pub mode: Option<ProxyMode>,
    pub call_timeout_secs: Option<u64>,
    /// Upstream server command and its arguments.
    pub command: Vec<String>,
}

pub fn run(ctx: &Context, args: ProxyArgs) -> anyhow::Result<u8> {
    let s = &ctx.style;
    let loaded = ctx.config()?;
    loaded.announce();
    let section = &loaded.config.proxy;
    let (program, server_args) = args
        .command
        .split_first()
        .context("pass the upstream MCP server command after `--`")?;
    let name = args.name.clone().unwrap_or_else(|| {
        PathBuf::from(program)
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "mcp".into())
    });
    let config = ProxyConfig {
        name: name.clone(),
        mode: args.mode.or(section.mode).unwrap_or_default(),
        policy: loaded.policy(),
        taint_sources: section
            .taint_sources
            .clone()
            .unwrap_or_else(|| vec!["*".into()]),
    };
    let timeout = args
        .call_timeout_secs
        .or(section.call_timeout_secs)
        .map(Duration::from_secs);
    let mode = config.mode;
    let command = ServerCommand {
        program: PathBuf::from(program),
        args: server_args.to_vec(),
    };

    let store = ctx.open_store()?;
    let location = format!("{} ({})", store.location(), store.dialect().name());
    let writer = LiveWriter::spawn_with(store, TraceSource::Recorded, Some(loaded.analyzer()));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let served = runtime.block_on(async {
        let mut upstream = McpSession::connect_upstream(&command)
            .await
            .with_context(|| format!("cannot start upstream MCP server {program:?}"))?;
        if let Some(t) = timeout {
            upstream = upstream.with_call_timeout(t);
        }
        let rec = TraceRecorder::new(format!("proxy/{name}"), ExecutionMode::Live)
            .with_sink(writer.sink());
        let proxy = Proxy::new(upstream, rec, config);
        eprintln!(
            "agent-trace proxy: {} ({} mode), trace {}",
            term_safe(&name),
            mode.as_str(),
            proxy
                .trace_id()
                .map(|id| id.to_string())
                .unwrap_or_default()
        );
        eprintln!("agent-trace proxy: database {}", term_safe(&location));
        proxy.serve_stdio(shutdown_signal()).await
    });
    // Finished in every case above, so the writer can be drained.
    let (_, written) = writer.finish();
    let record = served?;
    if let Err(e) = written {
        if let Some(record) = &record {
            let path = ctx
                .exports_dir()?
                .join(format!("proxy-{}.jsonl", record.trace.trace_id));
            if create_private_file(&path)
                .map_err(agent_trace_storage::StorageError::from)
                .and_then(|f| write_jsonl(BufWriter::new(f), record, &[]))
                .is_ok()
            {
                eprintln!(
                    "storage failed; the trace was saved as {} (re-import it with `agent-trace import`)",
                    term_safe(&path.display().to_string())
                );
            }
        }
        return Err(e.into());
    }
    if let Some(record) = record {
        let findings = loaded
            .analyzer()
            .analyze(&record, time::OffsetDateTime::now_utc());
        eprintln!(
            "agent-trace proxy: trace {} finished ({} events, {} finding(s)); \
             inspect with `agent-trace explore {}`",
            record.trace.trace_id,
            record.events.len(),
            findings.len(),
            crate::output::short(record.trace.trace_id)
        );
        for f in &findings {
            eprintln!("  {}", finding_line(s, &record, f));
        }
    }
    Ok(EXIT_OK)
}

/// Ctrl-C, or SIGTERM on Unix (what MCP clients send when they stop a server).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
