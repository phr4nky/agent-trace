//! `agent-trace` — see what your AI agent really did.

mod commands;
mod logging;
mod output;
mod tui;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Exit code: completed, nothing at/above the selected threshold.
pub const EXIT_OK: u8 = 0;
/// Exit code: program or input error.
pub const EXIT_ERROR: u8 = 1;
/// Exit code: findings at/above the `--fail-on` threshold.
pub const EXIT_FINDINGS: u8 = 2;

#[derive(Debug, Parser)]
#[command(
    name = "agent-trace",
    version,
    about = "See what your AI agent really did.",
    long_about = "agent-trace records and correlates AI agent requests, decisions, MCP tool calls and \
                  trust boundaries, and highlights suspicious sequences such as prompt injection \
                  followed by privileged tool requests.\n\n\
                  Everything is local: no API keys, no telemetry, no network.\n\n\
                  Exit codes: 0 = ok / no findings at or above --fail-on, 1 = error, \
                  2 = findings at or above --fail-on."
)]
pub struct Cli {
    /// Data directory (default: per-user local data dir, or $AGENT_TRACE_DATA_DIR).
    #[arg(long, global = true, value_name = "PATH")]
    data_dir: Option<PathBuf>,

    /// Database URL (default: SQLite file in the data dir; or $AGENT_TRACE_DATABASE_URL).
    /// Examples: sqlite:///path/traces.sqlite3, postgres://user@host/db, mariadb://user@host/db
    #[arg(long, global = true, value_name = "URL")]
    database_url: Option<String>,

    /// Disable ANSI colors (also honored: NO_COLOR environment variable).
    #[arg(long, global = true)]
    no_color: bool,

    /// Diagnostic log verbosity on stderr (-v info, -vv debug). Logs are redacted.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the bundled local lab (real local MCP server, scripted SIMULATED agent).
    Demo {
        #[command(subcommand)]
        command: DemoCommand,
    },
    /// List and inspect stored traces.
    Trace {
        #[command(subcommand)]
        command: TraceCommand,
    },
    /// Run the security rules on a trace and store the findings.
    Analyze {
        #[command(flatten)]
        target: TraceTarget,
        /// Exit with code 2 if a finding has at least this severity.
        #[arg(long, value_enum)]
        fail_on: Option<Threshold>,
    },
    /// Open the interactive terminal trace explorer.
    Explore {
        #[command(flatten)]
        target: TraceTarget,
        /// Render one frame as plain text instead of starting the interactive UI
        /// (works without a TTY, e.g. in CI or for screenshots).
        #[arg(long)]
        snapshot: bool,
        /// Keys to replay before the snapshot, e.g. "jjjf" (j/k/f/q, "\n" for Enter).
        #[arg(long, requires = "snapshot", default_value = "")]
        keys: String,
        /// Snapshot size as COLSxROWS.
        #[arg(long, requires = "snapshot", default_value = "150x40")]
        size: String,
        /// Live view: keep reading new events while the trace is recorded. With --latest,
        /// switch to newer traces as they start.
        #[arg(long, conflicts_with = "snapshot")]
        follow: bool,
    },
    /// Export a trace and its findings (always redacted).
    Export {
        #[command(flatten)]
        target: TraceTarget,
        #[arg(long, value_enum, default_value = "json")]
        format: ExportFormat,
        /// Output file (default: stdout).
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Import a trace from JSONL (validated and re-redacted; findings are recomputed).
    Import {
        #[arg(long, value_enum, default_value = "jsonl")]
        format: ImportFormat,
        #[arg(long, value_name = "PATH")]
        input: PathBuf,
    },
    /// Internal: run the local lab MCP server on stdio.
    #[command(hide = true)]
    LabServer {
        #[arg(long)]
        documents: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum DemoCommand {
    /// Run one or all lab scenarios, analyze them and export evidence.
    Run {
        #[arg(long, value_enum, default_value = "all")]
        scenario: ScenarioArg,
        /// Path to examples/local-lab (auto-detected by default).
        #[arg(long, value_name = "PATH")]
        lab_dir: Option<PathBuf>,
        /// Deterministic IDs and timestamps (for golden snapshots; needs a fresh data dir).
        #[arg(long, conflicts_with = "provider")]
        deterministic: bool,
        /// Let a real LLM drive the agent instead of the script (opt-in; sends the lab's
        /// prompts and fixture documents to the provider). Keys come from the environment:
        /// ANTHROPIC_API_KEY / OPENAI_API_KEY.
        #[arg(long, value_enum)]
        provider: Option<ProviderArg>,
        /// Model name (default for anthropic: claude-sonnet-5-5; required for openai,
        /// or set ANTHROPIC_MODEL / OPENAI_MODEL).
        #[arg(long, requires = "provider")]
        model: Option<String>,
        /// API base URL, e.g. http://localhost:11434/v1 for Ollama
        /// (or ANTHROPIC_BASE_URL / OPENAI_BASE_URL).
        #[arg(long, requires = "provider", value_name = "URL")]
        base_url: Option<String>,
        /// Maximum model turns per agent.
        #[arg(long, default_value_t = 8, requires = "provider")]
        max_turns: usize,
        /// Slow down so the run can be watched live (`agent-trace explore --latest --follow`).
        #[arg(long)]
        live: bool,
        /// Pause between agent steps in milliseconds (default with --live: 800).
        #[arg(long, value_name = "MS")]
        step_delay_ms: Option<u64>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ProviderArg {
    Anthropic,
    Openai,
}

#[derive(Debug, Subcommand)]
enum TraceCommand {
    /// List stored traces in creation order.
    List,
    /// Show the event timeline of a trace.
    Show {
        #[command(flatten)]
        target: TraceTarget,
        /// Also print the (redacted) payload of each event.
        #[arg(long)]
        payload: bool,
    },
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct TraceTarget {
    /// Trace id or unique prefix.
    trace_id: Option<String>,
    /// Use the most recently stored trace.
    #[arg(long)]
    latest: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ScenarioArg {
    Benign,
    PromptInjection,
    ExfilAttempt,
    MultiAgentHandoff,
    All,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Threshold {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ExportFormat {
    Json,
    Jsonl,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ImportFormat {
    Jsonl,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    logging::init(cli.verbose);
    let color = !cli.no_color && std::env::var_os("NO_COLOR").is_none();
    let ctx = commands::Context {
        data_dir: cli.data_dir.clone(),
        database_url: cli.database_url.clone(),
        style: output::Style::new(color),
    };
    let result =
        match cli.command {
            Command::LabServer { documents } => commands::lab_server(&documents).map(|_| EXIT_OK),
            Command::Demo {
                command:
                    DemoCommand::Run {
                        scenario,
                        lab_dir,
                        deterministic,
                        provider,
                        model,
                        base_url,
                        max_turns,
                        live,
                        step_delay_ms,
                    },
            } => commands::demo::run(
                &ctx,
                commands::demo::DemoArgs {
                    scenario,
                    lab_dir,
                    deterministic,
                    provider,
                    model,
                    base_url,
                    max_turns,
                    step_delay: std::time::Duration::from_millis(
                        step_delay_ms.unwrap_or(if live { 800 } else { 0 }),
                    ),
                },
            ),
            Command::Trace {
                command: TraceCommand::List,
            } => commands::trace::list(&ctx),
            Command::Trace {
                command: TraceCommand::Show { target, payload },
            } => commands::trace::show(&ctx, &target, payload),
            Command::Analyze { target, fail_on } => commands::analyze::run(&ctx, &target, fail_on),
            Command::Explore {
                target,
                snapshot,
                keys,
                size,
                follow,
            } => commands::explore(
                &ctx,
                &target,
                snapshot.then_some((keys.as_str(), size.as_str())),
                follow,
            ),
            Command::Export {
                target,
                format,
                output,
            } => commands::export::run(&ctx, &target, format, output.as_deref()),
            Command::Import { format, input } => commands::import::run(&ctx, format, &input),
        };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            let redactor = agent_trace_core::Redactor::new();
            eprintln!("error: {}", redactor.scrub(&format!("{err:#}")));
            ExitCode::from(EXIT_ERROR)
        }
    }
}
