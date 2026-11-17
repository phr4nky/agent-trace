//! `agent-trace proxy`: record (and optionally enforce) the traffic between an MCP client and
//! an MCP server, reached as a child process over stdio (`-- <command>`) or over streamable
//! HTTP (`--url`).
//!
//! The proxies an MCP client starts for its servers write into one trace per client session,
//! so content from one server and a call to another are linked. Stdout belongs to the MCP
//! protocol: this command writes nothing else there; status lines go to stderr.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use agent_trace_core::{ExecutionMode, TraceAccess, TraceRecorder};
use agent_trace_mcp::{McpSession, Proxy, ProxyConfig, ProxyMode, ServerCommand};
use agent_trace_net::{HttpUpstream, display_url};
use agent_trace_storage::SharedTrace;
use anyhow::{Context as _, bail};
use uuid::Uuid;

use super::Context;
use crate::EXIT_OK;
use crate::output::{finding_line, short, term_safe};

/// Namespace of trace IDs derived from proxy session keys.
const SESSION_NAMESPACE: Uuid = Uuid::from_u128(0x0b8e_51c4_7a2d_4f60_9e13_c5a7_d2f8_6e41);

pub struct ProxyArgs {
    pub name: Option<String>,
    pub mode: Option<ProxyMode>,
    pub call_timeout_secs: Option<u64>,
    /// Upstream server command and its arguments (stdio).
    pub command: Vec<String>,
    /// Upstream URL (streamable HTTP).
    pub url: Option<String>,
    /// Environment variable holding the bearer token for `url`.
    pub bearer_token_env: Option<String>,
    /// `NAME=ENV_VAR` pairs: headers for `url` whose values come from the environment.
    pub header_env: Vec<String>,
    /// Explicit session key (`--session`).
    pub session: Option<String>,
    /// One trace for this proxy alone (`--no-session`).
    pub no_session: bool,
}

/// How the proxies of one client session find their common trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionKey {
    /// `--session` or `$AGENT_TRACE_SESSION`.
    Explicit(String),
    /// The MCP client process: its PID plus its start time (PIDs are reused).
    Parent { pid: u32, started: String },
}

impl SessionKey {
    fn trace_id(&self) -> Uuid {
        let key = match self {
            Self::Explicit(k) => format!("explicit:{k}"),
            Self::Parent { pid, started } => format!("parent:{pid}:{started}"),
        };
        Uuid::new_v5(
            &SESSION_NAMESPACE,
            format!("proxy-session/{key}").as_bytes(),
        )
    }
}

/// The session key of this proxy, or `None` for a trace of its own.
fn session_key(args: &ProxyArgs) -> Option<SessionKey> {
    if args.no_session {
        return None;
    }
    let explicit = args.session.clone().or_else(|| {
        std::env::var("AGENT_TRACE_SESSION")
            .ok()
            .filter(|s| !s.trim().is_empty())
    });
    if let Some(k) = explicit {
        return Some(SessionKey::Explicit(k.trim().to_owned()));
    }
    parent_session()
}

#[cfg(unix)]
fn parent_session() -> Option<SessionKey> {
    let pid = std::os::unix::process::parent_id();
    if pid <= 1 {
        return None; // orphaned: no client to group by
    }
    // `ps -o lstart=` prints the start time on Linux and macOS alike.
    let out = std::process::Command::new("ps")
        .args(["-o", "lstart=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    let started = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    (out.status.success() && !started.is_empty()).then_some(SessionKey::Parent { pid, started })
}

#[cfg(not(unix))]
fn parent_session() -> Option<SessionKey> {
    // No portable parent PID on Windows without unsafe code: use --session there.
    None
}

fn header_pairs(specs: &[String]) -> anyhow::Result<Vec<(String, String)>> {
    specs
        .iter()
        .map(|spec| {
            let (name, var) = spec
                .split_once('=')
                .with_context(|| format!("--header-env expects NAME=ENV_VAR, got {spec:?}"))?;
            let value = std::env::var(var.trim()).with_context(|| {
                format!("environment variable {var} (for header {name}) is not set")
            })?;
            Ok((name.trim().to_owned(), value))
        })
        .collect()
}

pub fn run(ctx: &Context, args: ProxyArgs) -> anyhow::Result<u8> {
    let s = &ctx.style;
    let loaded = ctx.config()?;
    loaded.announce();
    let section = &loaded.config.proxy;

    // The upstream: a URL or a command, never both (clap enforces it).
    let http = match &args.url {
        Some(url) => {
            agent_trace_net::check_url(url)?;
            let bearer_token = match &args.bearer_token_env {
                Some(var) => Some(std::env::var(var).with_context(|| {
                    format!("environment variable {var} (bearer token) is not set")
                })?),
                None => None,
            };
            Some(HttpUpstream {
                url: url.clone(),
                bearer_token,
                headers: header_pairs(&args.header_env)?,
            })
        }
        None => None,
    };
    let command = match (&http, args.command.split_first()) {
        (Some(_), _) => None,
        (None, Some((program, rest))) => Some(ServerCommand {
            program: PathBuf::from(program),
            args: rest.to_vec(),
        }),
        (None, None) => bail!("pass the upstream MCP server as `--url URL` or after `--`"),
    };
    let endpoint = match (&http, &command) {
        (Some(h), _) => display_url(&h.url),
        (None, Some(c)) => c.program.display().to_string(),
        (None, None) => unreachable!(),
    };
    let name = args
        .name
        .clone()
        .unwrap_or_else(|| match (&http, &command) {
            (Some(h), _) => url::Url::parse(&h.url)
                .ok()
                .and_then(|u| u.host_str().map(str::to_owned))
                .unwrap_or_else(|| "mcp".into()),
            (None, Some(c)) => c
                .program
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "mcp".into()),
            (None, None) => unreachable!(),
        });
    let config = ProxyConfig {
        name: name.clone(),
        mode: args.mode.or(section.mode).unwrap_or_default(),
        policy: loaded.policy(),
        taint_sources: section
            .taint_sources
            .clone()
            .unwrap_or_else(|| vec!["*".into()]),
        endpoint: Some(endpoint),
    };
    let timeout = args
        .call_timeout_secs
        .or(section.call_timeout_secs)
        .map(Duration::from_secs);
    let mode = config.mode;

    // The trace: shared by the proxies of one client session, or this proxy's own.
    let session = session_key(&args);
    let trace_id = session
        .as_ref()
        .map(SessionKey::trace_id)
        .unwrap_or_else(Uuid::new_v4);
    let trace_name = match &session {
        Some(_) => format!("proxy-session/{}", short(trace_id)),
        None => format!("proxy/{name}"),
    };
    let session_meta = session.clone();
    let store = ctx.open_store()?;
    let location = format!("{} ({})", store.location(), store.dialect().name());
    let trace: Arc<SharedTrace> = Arc::new(SharedTrace::new(
        store,
        &ctx.data_dir()?.join("proxy-sessions"),
        trace_id,
        Some(loaded.analyzer()),
        move || {
            let mut rec =
                TraceRecorder::with_trace_id(trace_name.clone(), ExecutionMode::Live, trace_id);
            match &session_meta {
                Some(SessionKey::Explicit(k)) => {
                    rec.set_trace_metadata("proxy_session", format!("explicit:{k}"));
                }
                Some(SessionKey::Parent { pid, .. }) => {
                    rec.set_trace_metadata("proxy_session", "mcp-client-process");
                    rec.set_trace_metadata("mcp_client_pid", *pid);
                }
                None => {}
            }
            rec
        },
    )?);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let served = runtime.block_on(async {
        let mut upstream = match (&http, &command) {
            (Some(h), _) => agent_trace_net::connect(h).await?,
            (None, Some(c)) => McpSession::connect_upstream(c)
                .await
                .with_context(|| format!("cannot start upstream MCP server {:?}", c.program))?,
            (None, None) => unreachable!(),
        };
        if let Some(t) = timeout {
            upstream = upstream.with_call_timeout(t);
        }
        let proxy = Proxy::new(upstream, trace.clone() as Arc<dyn TraceAccess>, config)?;
        eprintln!(
            "agent-trace proxy: {} ({} mode), trace {}{}",
            term_safe(&name),
            mode.as_str(),
            trace_id,
            if session.is_some() {
                " (shared by this client's proxies)"
            } else {
                ""
            }
        );
        eprintln!("agent-trace proxy: database {}", term_safe(&location));
        proxy.serve_stdio(shutdown_signal()).await
    });
    served?;

    let record = trace.load()?;
    let findings = trace.findings()?;
    eprintln!(
        "agent-trace proxy: {} disconnected; trace {} has {} events and {} finding(s) \
         (status {}); inspect with `agent-trace explore {}`",
        term_safe(&name),
        record.trace.trace_id,
        record.events.len(),
        findings.len(),
        record.trace.status.as_str(),
        short(record.trace.trace_id)
    );
    for f in &findings {
        eprintln!("  {}", finding_line(s, &record, f));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_keys_map_to_stable_distinct_traces() {
        let a = SessionKey::Explicit("a".into());
        assert_eq!(a.trace_id(), SessionKey::Explicit("a".into()).trace_id());
        assert_ne!(a.trace_id(), SessionKey::Explicit("b".into()).trace_id());
        let p1 = SessionKey::Parent {
            pid: 42,
            started: "Mon Nov 17 10:00:00 2026".into(),
        };
        let p2 = SessionKey::Parent {
            pid: 42,
            started: "Tue Nov 18 09:00:00 2026".into(),
        };
        assert_ne!(
            p1.trace_id(),
            p2.trace_id(),
            "a reused PID is another session"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_parent_process_is_found() {
        let key = parent_session().expect("tests run under cargo, a parent exists");
        let SessionKey::Parent { pid, started } = key else {
            panic!()
        };
        assert_eq!(pid, std::os::unix::process::parent_id());
        assert!(!started.is_empty());
    }

    #[test]
    fn header_specs_need_name_and_variable() {
        assert!(header_pairs(&["no-equals".into()]).is_err());
        assert!(header_pairs(&["X-Key=AGENT_TRACE_SURELY_UNSET_VAR".into()]).is_err());
    }
}
