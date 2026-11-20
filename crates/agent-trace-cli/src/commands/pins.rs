//! `agent-trace pins`: the tool definitions the MCP proxy pinned per server.
//!
//! * `pins list`: pinned servers.
//! * `pins show NAME`: the pinned tools of one server.
//! * `pins reset NAME [--tool TOOL]...`: forget pins, so the next `tools/list` pins the
//!   current definitions (accepts a change you reviewed).

use std::path::PathBuf;

use agent_trace_mcp::PinStore;
use anyhow::bail;

use super::Context;
use crate::EXIT_OK;
use crate::output::term_safe;

pub fn store(ctx: &Context) -> anyhow::Result<PinStore> {
    Ok(PinStore::new(pins_dir(ctx)?))
}

fn pins_dir(ctx: &Context) -> anyhow::Result<PathBuf> {
    Ok(ctx.data_dir()?.join("pins"))
}

pub fn list(ctx: &Context) -> anyhow::Result<u8> {
    let store = store(ctx)?;
    let files = store.list()?;
    if files.is_empty() {
        outln!(
            "no pinned MCP servers in {} (the proxy pins a server's tools on its first tools/list)",
            term_safe(&store.dir().display().to_string())
        );
        return Ok(EXIT_OK);
    }
    for f in &files {
        outln!(
            "{}  {} tool(s), pinned since {}",
            term_safe(&f.server),
            f.tools.len(),
            term_safe(&f.created_at)
        );
    }
    Ok(EXIT_OK)
}

pub fn show(ctx: &Context, server: &str) -> anyhow::Result<u8> {
    let store = store(ctx)?;
    let Some(file) = store.load(server)? else {
        bail!(
            "no pins for {:?} (see `agent-trace pins list`)",
            term_safe(server)
        );
    };
    outln!(
        "{}  ({})",
        term_safe(&file.server),
        term_safe(&store.path(server).display().to_string())
    );
    for (name, tool) in &file.tools {
        let hash = tool.hash.strip_prefix("sha256:").unwrap_or(&tool.hash);
        outln!(
            "  {}  {}  pinned {}{}",
            term_safe(name),
            &hash[..hash.len().min(12)],
            term_safe(&tool.pinned_at),
            tool.server_version
                .as_deref()
                .map(|v| format!(" (server {})", term_safe(v)))
                .unwrap_or_default()
        );
        if let Some(d) = &tool.description {
            let line: String = d.split_whitespace().collect::<Vec<_>>().join(" ");
            let short: String = line.chars().take(100).collect();
            let more = if line.chars().count() > 100 {
                "…"
            } else {
                ""
            };
            outln!("      {}{more}", term_safe(&short));
        }
    }
    Ok(EXIT_OK)
}

pub fn reset(ctx: &Context, server: &str, tools: &[String]) -> anyhow::Result<u8> {
    let store = store(ctx)?;
    if store.load(server)?.is_none() {
        bail!(
            "no pins for {:?} (see `agent-trace pins list`)",
            term_safe(server)
        );
    }
    let removed = store.reset(server, tools)?;
    if tools.is_empty() {
        outln!(
            "removed all {removed} pin(s) of {}; the next tools/list pins the current definitions",
            term_safe(server)
        );
    } else {
        outln!(
            "removed {removed} pin(s) of {}; the next tools/list pins the current definition{}",
            term_safe(server),
            if tools.len() == 1 { "" } else { "s" }
        );
        if removed < tools.len() {
            outln!(
                "note: {} of the named tool(s) had no pin",
                tools.len() - removed
            );
        }
    }
    Ok(EXIT_OK)
}
