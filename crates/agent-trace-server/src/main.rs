//! `agent-trace-server`: the team server. See the crate documentation and docs/server.md.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use agent_trace_core::Analyzer;
use agent_trace_server::config::ServerConfig;
use agent_trace_server::{AppState, Settings, serve, token};
use agent_trace_storage::{DatabaseConfig, Store};
use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand};

/// Receives traces from recorders (`agent-trace ship`), stores them, and serves a read API and
/// the web UI.
#[derive(Parser)]
#[command(name = "agent-trace-server", version)]
struct Cli {
    /// Database URL (default: $AGENT_TRACE_DATABASE_URL, else SQLite in --data-dir), e.g.
    /// postgres://user@host/db. Prefer the environment variable: it keeps a password out of
    /// the process list.
    #[arg(long, global = true, value_name = "URL")]
    database_url: Option<String>,
    /// Directory of the SQLite database when no database URL is given.
    #[arg(long, global = true, value_name = "PATH")]
    data_dir: Option<PathBuf>,
    /// agent-trace.toml with [policy], [[rules]] and [redaction] additions (other tables are
    /// ignored), so findings on the server match those of the recorders.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server.
    Serve {
        /// Address to listen on.
        #[arg(long, default_value = "127.0.0.1:8080", value_name = "ADDR")]
        listen: SocketAddr,
        /// Directory with the built web UI (ui/dist/agent-trace-ui/browser).
        #[arg(long, value_name = "PATH")]
        ui_dir: Option<PathBuf>,
        /// Serve the read API and UI on a non-loopback address. They have no login yet: use
        /// this only behind your own access control (or in a container whose port is
        /// published on loopback only).
        #[arg(long)]
        allow_unauthenticated_reads: bool,
        /// Take the client address from X-Forwarded-For (only behind a trusted reverse proxy).
        #[arg(long)]
        trust_forwarded_for: bool,
    },
    /// Manage sources: the recorders that may send traces.
    Source {
        #[command(subcommand)]
        command: SourceCommand,
    },
}

#[derive(Subcommand)]
enum SourceCommand {
    /// Add a source and print its token (shown only once).
    Add { name: String },
    /// List the sources.
    List,
    /// Remove a source: its token stops working, its traces stay.
    Remove { name: String },
}

fn open_store(cli: &Cli) -> anyhow::Result<Store> {
    let url = cli.database_url.clone().or_else(|| {
        std::env::var("AGENT_TRACE_DATABASE_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
    });
    if let Some(url) = url {
        let config = DatabaseConfig::parse(&url)?;
        return Store::connect(&config).context("cannot open the database");
    }
    let dir = match &cli.data_dir {
        Some(d) => d.clone(),
        None => dirs::data_local_dir()
            .context("no local data directory; pass --data-dir")?
            .join("agent-trace-server"),
    };
    Store::open(dir.join("server.sqlite3")).context("cannot open the database")
}

fn analyzer(cli: &Cli) -> anyhow::Result<Analyzer> {
    let config = match &cli.config {
        Some(path) => ServerConfig::load(path)?,
        None => ServerConfig::default(),
    };
    config.install_redaction()?;
    config.analyzer()
}

fn run(cli: Cli) -> anyhow::Result<()> {
    match &cli.command {
        Command::Source { command } => {
            let mut store = open_store(&cli)?;
            match command {
                SourceCommand::Add { name } => {
                    if !token::valid_source_name(name) {
                        bail!(
                            "source name {name:?}: use 1 to 64 lowercase letters, digits, `-`, `_` or `.`"
                        );
                    }
                    let token = token::generate()?;
                    store.add_source(name, &token::hash(&token))?;
                    println!("added source {name}; its token (shown only once):");
                    println!("{token}");
                    eprintln!(
                        "give it to the recorder as AGENT_TRACE_SHIP_TOKEN (never in a command line or a file in a repository)"
                    );
                }
                SourceCommand::List => {
                    let sources = store.sources()?;
                    if sources.is_empty() {
                        println!("no sources; add one with `agent-trace-server source add NAME`");
                    }
                    for s in sources {
                        println!(
                            "{:<24} {:>5} trace(s)  last seen {}{}",
                            s.source.name,
                            s.traces,
                            s.source.last_seen_at.as_deref().unwrap_or("never"),
                            s.source
                                .last_ip
                                .map(|ip| format!(" from {ip}"))
                                .unwrap_or_default()
                        );
                    }
                }
                SourceCommand::Remove { name } => {
                    if store.remove_source(name)? {
                        println!("removed source {name}; its traces stay");
                    } else {
                        bail!("no source {name:?}");
                    }
                }
            }
            Ok(())
        }
        Command::Serve {
            listen,
            ui_dir,
            allow_unauthenticated_reads,
            trust_forwarded_for,
        } => {
            if !listen.ip().is_loopback() && !allow_unauthenticated_reads {
                bail!(
                    "refusing to serve the read API on {listen}: it has no login yet. Listen on \
                     127.0.0.1, or pass --allow-unauthenticated-reads behind your own access control"
                );
            }
            if let Some(dir) = ui_dir
                && !dir.join("index.html").is_file()
            {
                bail!("{} has no index.html (build ui/ first)", dir.display());
            }
            let analyzer = analyzer(&cli)?;
            let store = open_store(&cli)?;
            let state = AppState::new(
                store,
                analyzer,
                Settings {
                    ui_dir: ui_dir.clone(),
                    trust_forwarded_for: *trust_forwarded_for,
                },
            );
            let listen = *listen;
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(async move {
                    let listener = tokio::net::TcpListener::bind(listen)
                        .await
                        .with_context(|| format!("cannot listen on {listen}"))?;
                    tracing::info!("agent-trace-server listening on http://{listen}");
                    eprintln!("agent-trace-server listening on http://{listen}");
                    serve(listener, state, shutdown())
                        .await
                        .context("server failed")
                })
        }
    }
}

/// Ctrl-C, or SIGTERM on Unix (what container runtimes send).
async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            return ExitCode::from(if e.use_stderr() { 1 } else { 0 });
        }
    };
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(1)
        }
    }
}
