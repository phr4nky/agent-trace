//! `agent-trace ship`: send recorded traces to `agent-trace-server`.
//!
//! The recorder decides, redacts and stores locally as always; `ship` sends what is new
//! afterwards (store and forward), so a slow or unreachable server never delays a tool call.
//! Per server, `<data dir>/ship/<server>.json` remembers how far each trace was sent (last
//! event and status). The server answers with the last event it stored and tells where to
//! continue when it has a different state, so nothing is lost or sent twice.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_trace_core::{TraceRecord, TraceStatus};
use agent_trace_net::ship::{ShipClient, ShipError};
use agent_trace_storage::ingest::{IngestBatch, MAX_BATCH_EVENTS};
use agent_trace_storage::{Store, create_private_dir, create_private_file};
use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::Context;
use crate::output::{short, term_safe};
use crate::{EXIT_ERROR, EXIT_OK};

/// Default environment variable holding the source token.
pub const DEFAULT_TOKEN_ENV: &str = "AGENT_TRACE_SHIP_TOKEN";

pub struct ShipArgs {
    pub to: Option<String>,
    pub follow: bool,
    pub interval: u64,
}

/// How far each trace was sent to one server.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Cursor {
    server: String,
    traces: BTreeMap<String, Sent>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Sent {
    seq: u64,
    status: String,
}

impl Cursor {
    fn path(data_dir: &Path, server: &str) -> PathBuf {
        let digest = Sha256::digest(server.as_bytes());
        let tag: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
        data_dir.join("ship").join(format!("{tag}.json"))
    }

    fn load(path: &Path, server: &str) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text)
                .with_context(|| format!("unreadable ship state {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                server: server.to_owned(),
                traces: BTreeMap::new(),
            }),
            Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
        }
    }

    /// Written to a temporary file and renamed, so a crash never leaves half a file.
    fn save(&self, path: &Path) -> anyhow::Result<()> {
        let dir = path.parent().context("ship state has no directory")?;
        create_private_dir(dir)?;
        let tmp = path.with_extension("json.tmp");
        let mut file = create_private_file(&tmp)?;
        use std::io::Write;
        file.write_all(serde_json::to_string_pretty(self)?.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

pub fn run(ctx: &Context, args: ShipArgs) -> anyhow::Result<u8> {
    let loaded = ctx.config()?;
    let section = &loaded.config.ship;
    let url = args
        .to
        .clone()
        .or_else(|| section.url.clone())
        .context("no server: pass --to URL or set `url` in the [ship] table")?;
    let token_env = section
        .token_env
        .clone()
        .unwrap_or_else(|| DEFAULT_TOKEN_ENV.to_owned());
    let token = std::env::var(&token_env)
        .ok()
        .filter(|t| !t.trim().is_empty())
        .with_context(|| {
            format!(
                "${token_env} is not set: export the token of this source \
                 (`agent-trace-server source add NAME` prints it)"
            )
        })?;
    let client = ShipClient::new(&url, &token)?;
    let server = client.server();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        // Check the token before anything else, also when there is nothing new to send.
        let source = match client.whoami().await {
            Ok(source) => source,
            Err(ShipError::Unauthorized(m)) => {
                anyhow::bail!("the server {server} did not accept the token: {m}")
            }
            Err(e) => anyhow::bail!("cannot reach {server}: {e}"),
        };
        eprintln!(
            "sending as source {} to {}",
            term_safe(&source.name),
            term_safe(&server)
        );
        let cursor_path = Cursor::path(&ctx.data_dir()?, &format!("{server} {}", source.source_id));
        let mut cursor = Cursor::load(&cursor_path, &server)?;
        let mut store = ctx.open_store()?;
        loop {
            let pass = ship_pass(&mut store, &client, &mut cursor, &cursor_path).await?;
            if !args.follow {
                outln!(
                    "{} trace(s) sent to {}, {} up to date{}",
                    pass.sent,
                    term_safe(&server),
                    pass.unchanged,
                    if pass.failed > 0 {
                        format!(", {} failed", pass.failed)
                    } else {
                        String::new()
                    }
                );
                return Ok(if pass.failed > 0 { EXIT_ERROR } else { EXIT_OK });
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(args.interval.max(1))) => {}
                _ = tokio::signal::ctrl_c() => return Ok(EXIT_OK),
            }
        }
    })
}

#[derive(Debug, Default)]
struct Pass {
    sent: usize,
    unchanged: usize,
    failed: usize,
}

async fn ship_pass(
    store: &mut Store,
    client: &ShipClient,
    cursor: &mut Cursor,
    cursor_path: &Path,
) -> anyhow::Result<Pass> {
    let mut pass = Pass::default();
    for summary in store.list_traces()? {
        let id = summary.trace.trace_id;
        let status = summary.trace.status.as_str().to_owned();
        let sent = cursor
            .traces
            .get(&id.to_string())
            .cloned()
            .unwrap_or_default();
        if sent.seq >= summary.event_count && sent.status == status {
            pass.unchanged += 1;
            continue;
        }
        let record = store.load_trace(id)?;
        match ship_trace(client, &record, sent.seq).await {
            Ok((seq, findings)) => {
                // A trace still being recorded is sent again when it grows or its status changes.
                let complete = seq >= record.events.last().map_or(0, |e| e.sequence);
                cursor.traces.insert(
                    id.to_string(),
                    Sent {
                        seq,
                        status: if complete { status } else { String::new() },
                    },
                );
                cursor.save(cursor_path)?;
                pass.sent += 1;
                outln!(
                    "sent {} {} up to event #{seq}{} ({findings} finding(s) on the server)",
                    short(id),
                    term_safe(&record.trace.name),
                    if record.trace.status == TraceStatus::Running {
                        ", still running"
                    } else {
                        ""
                    }
                );
            }
            Err(ShipError::Unauthorized(m)) => {
                anyhow::bail!(
                    "the server {} did not accept the token: {m}",
                    client.server()
                )
            }
            Err(e) => {
                pass.failed += 1;
                eprintln!(
                    "could not send {} {}: {}",
                    short(id),
                    term_safe(&record.trace.name),
                    term_safe(&e.to_string())
                );
            }
        }
    }
    Ok(pass)
}

/// Send the events of `record` after `from`, in batches. Returns the last event the server
/// stored and the number of findings it computed.
async fn ship_trace(
    client: &ShipClient,
    record: &TraceRecord,
    mut from: u64,
) -> Result<(u64, usize), ShipError> {
    let last = record.events.last().map_or(0, |e| e.sequence);
    let mut resynced = false;
    loop {
        let events = record
            .events
            .iter()
            .filter(|e| e.sequence > from)
            .take(MAX_BATCH_EVENTS)
            .cloned()
            .collect();
        let batch = IngestBatch {
            trace: record.trace.clone(),
            events,
        };
        match client.send(&batch).await {
            Ok(reply) => {
                if reply.stored_seq >= last || reply.stored_seq <= from {
                    return Ok((reply.stored_seq, reply.findings));
                }
                from = reply.stored_seq;
            }
            // The server has another state (e.g. its database was reset): continue from there.
            Err(ShipError::Conflict {
                stored_seq: Some(stored),
                ..
            }) if !resynced && stored != from => {
                from = stored;
                resynced = true;
            }
            Err(e) => return Err(e),
        }
    }
}
