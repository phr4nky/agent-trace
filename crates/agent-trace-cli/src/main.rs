//! `agent-trace` — see what your AI agent really did.

#[macro_use]
mod output;
mod commands;
mod config;
mod hooks;
mod logging;
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

    /// Config file (default: $AGENT_TRACE_CONFIG, ./agent-trace.toml, or agent-trace.toml
    /// in the data dir). It adds tools and destinations to the default policy.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

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
    /// Replay recorded sessions with a model (or system prompt) and compare the findings:
    /// prompts and tool results come from the recording, nothing is executed.
    Replay {
        #[command(subcommand)]
        command: ReplayCommand,
    },
    /// Write an interactive causal graph of a trace as a self-contained HTML file
    /// (redacted, no network requests). Open it in a browser.
    Graph {
        #[command(flatten)]
        target: TraceTarget,
        /// Output file (default: graph-<trace id>.html in the exports directory).
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
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
        /// SARIF only: the trace's JSONL file in the repository, which alerts point to
        /// (default: trace-<id>.jsonl, the layout `--format jsonl` writes).
        #[arg(long, value_name = "URI")]
        artifact_uri: Option<String>,
        /// JSONL only: sign the export with your signing key (see `agent-trace keys`).
        #[arg(long)]
        sign: bool,
        /// Signing key file (default: $AGENT_TRACE_SIGNING_KEY or the data directory).
        #[arg(long, value_name = "PATH", requires = "sign")]
        key: Option<PathBuf>,
    },
    /// Check that a JSONL export is unchanged (hash chain) and who signed it.
    Verify {
        /// The JSONL file.
        file: PathBuf,
        /// A trusted signer: hex public key or a .pub file. Repeatable. Your own signing key
        /// is always trusted.
        #[arg(long, value_name = "KEY")]
        public_key: Vec<String>,
        /// Fail if the file is not signed.
        #[arg(long)]
        require_signature: bool,
    },
    /// Canary tokens: decoy secrets whose use in a tool call is reported (AT-007) and, in
    /// enforce mode, denied. Configure them with [[canaries]] in agent-trace.toml.
    Canary {
        #[command(subcommand)]
        command: CanaryCommand,
    },
    /// Tool definitions the MCP proxy pinned per server (rug-pull protection, AT-008).
    Pins {
        #[command(subcommand)]
        command: PinsCommand,
    },
    /// Manage the key that signs exports.
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
    /// Convert JSONL trace files into one SARIF file for GitHub Code Scanning (validated,
    /// redacted, findings recomputed; nothing is stored).
    Sarif {
        /// JSONL trace files, e.g. traces/*.jsonl. Alerts point to lines in these files.
        #[arg(required = true, value_name = "FILE")]
        inputs: Vec<PathBuf>,
        /// Output file (default: stdout).
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Exit with code 2 if a finding has at least this severity.
        #[arg(long, value_enum)]
        fail_on: Option<Threshold>,
    },
    /// Delete old traces (retention). Defaults come from [retention] in agent-trace.toml;
    /// traces still being recorded are kept.
    Prune {
        /// Delete traces older than this: 30d, 12h, 90m (a plain number means days).
        #[arg(long, value_name = "AGE")]
        older_than: Option<String>,
        /// Keep only the newest N traces.
        #[arg(long, value_name = "N")]
        keep: Option<usize>,
        /// Only list what would be deleted.
        #[arg(long)]
        dry_run: bool,
    },
    /// Import a trace from JSONL (validated and re-redacted; findings are recomputed).
    Import {
        #[arg(long, value_enum, default_value = "jsonl")]
        format: ImportFormat,
        #[arg(long, value_name = "PATH")]
        input: PathBuf,
        /// Exit with code 2 if a finding of this import has at least this severity
        /// (decided on the validated file, not on a later read of the database).
        #[arg(long, value_enum)]
        fail_on: Option<Threshold>,
    },
    /// Run between an MCP client and an MCP server, record every tool call and check it
    /// against the policy. Put it in the client's MCP config in place of the server:
    /// `agent-trace proxy --name github -- <server command> [args...]`.
    Proxy {
        /// Name of the proxied server (default: the server program's file name, or the
        /// URL's host).
        #[arg(long)]
        name: Option<String>,
        /// observe: record only (default). enforce: answer denied calls with a tool error
        /// instead of forwarding them. Overrides `mode` in agent-trace.toml.
        #[arg(long, value_enum)]
        mode: Option<ProxyModeArg>,
        /// Seconds to wait for the upstream server's answer to a tool call (default 300).
        #[arg(long, value_name = "SECONDS")]
        call_timeout: Option<u64>,
        /// Upstream MCP server over streamable HTTP (https, or http to localhost) instead of
        /// a command.
        #[arg(long, value_name = "URL", conflicts_with = "command")]
        url: Option<String>,
        /// Environment variable holding a bearer token for --url (never pass the token
        /// itself on the command line).
        #[arg(long, value_name = "VAR", requires = "url")]
        bearer_token_env: Option<String>,
        /// Request header for --url whose value comes from an environment variable,
        /// as NAME=VAR, e.g. X-Api-Key=MY_API_KEY. Repeatable.
        #[arg(long, value_name = "NAME=VAR", requires = "url")]
        header_env: Vec<String>,
        /// Session key: proxies with the same key write one trace. Default: the MCP client
        /// process that started the proxy ($AGENT_TRACE_SESSION also sets a key).
        #[arg(long, value_name = "KEY", conflicts_with = "no_session")]
        session: Option<String>,
        /// Record this proxy in a trace of its own.
        #[arg(long)]
        no_session: bool,
        /// The upstream MCP server command, after `--`.
        #[arg(last = true, required_unless_present = "url", value_name = "COMMAND")]
        command: Vec<String>,
    },
    /// Claude Code hook: record the hook event on stdin in the session's trace and, in
    /// enforce mode, deny tool calls the policy denies. Register it with the settings that
    /// `agent-trace hook --print-settings` prints.
    Hook {
        /// observe: record only (default). enforce: deny tool calls the policy denies.
        /// Overrides `mode` in the [hooks] table of agent-trace.toml.
        #[arg(long, value_enum)]
        mode: Option<ProxyModeArg>,
        /// Print the `hooks` block for Claude Code's settings.json and exit.
        #[arg(long)]
        print_settings: bool,
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
        /// Exit with code 2 if a finding of this run has at least this severity.
        #[arg(long, value_enum)]
        fail_on: Option<Threshold>,
    },
}

#[derive(Debug, Subcommand)]
enum ReplayCommand {
    /// Replay one recording.
    Trace {
        #[command(flatten)]
        source: ReplaySource,
        #[command(flatten)]
        model: ModelFlags,
        /// The task, if the recording has none (MCP proxy traces) or it should change.
        #[arg(long)]
        prompt: Option<String>,
        /// Number of replays (models are not deterministic).
        #[arg(long, default_value_t = 1)]
        runs: usize,
        /// Exit with code 2 if a replay has a model action at or above this severity.
        #[arg(long, value_enum)]
        fail_on: Option<Threshold>,
        /// Also write a JSON report to this file.
        #[arg(long, value_name = "PATH")]
        report: Option<PathBuf>,
    },
    /// Run a regression suite (TOML) of recordings; exits with code 2 if a case fails.
    Suite {
        /// The suite file.
        file: PathBuf,
        #[command(flatten)]
        model: ModelFlags,
        /// Also write a JSON report to this file.
        #[arg(long, value_name = "PATH")]
        report: Option<PathBuf>,
    },
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct ReplaySource {
    /// Stored trace id or unique prefix.
    trace_id: Option<String>,
    /// The most recently stored trace.
    #[arg(long)]
    latest: bool,
    /// A JSONL trace file (as written by `export --format jsonl`).
    #[arg(long, value_name = "PATH")]
    input: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ModelFlags {
    /// Model provider. Keys come from the environment: ANTHROPIC_API_KEY / OPENAI_API_KEY.
    #[arg(long, value_enum)]
    provider: ProviderArg,
    /// Model name (or ANTHROPIC_MODEL / OPENAI_MODEL).
    #[arg(long)]
    model: Option<String>,
    /// API base URL (or ANTHROPIC_BASE_URL / OPENAI_BASE_URL).
    #[arg(long, value_name = "URL")]
    base_url: Option<String>,
    /// Maximum model turns per agent.
    #[arg(long, default_value_t = 8)]
    max_turns: usize,
    /// Use this system prompt instead of the built-in one (to test a prompt change).
    #[arg(long, value_name = "PATH")]
    system_prompt: Option<PathBuf>,
}

impl ModelFlags {
    fn into_args(self) -> commands::replay::ModelArgs {
        commands::replay::ModelArgs {
            provider: self.provider,
            model: self.model,
            base_url: self.base_url,
            max_turns: self.max_turns,
            system_prompt: self.system_prompt,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ProxyModeArg {
    Observe,
    Enforce,
}

impl ProxyModeArg {
    fn into_mode(self) -> agent_trace_mcp::ProxyMode {
        match self {
            Self::Observe => agent_trace_mcp::ProxyMode::Observe,
            Self::Enforce => agent_trace_mcp::ProxyMode::Enforce,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ProviderArg {
    Anthropic,
    Openai,
}

#[derive(Debug, Subcommand)]
enum CanaryCommand {
    /// Print a fresh decoy value and its [[canaries]] entry (nothing is written).
    New {
        /// Name shown in findings: lowercase letters, digits, `-`, `_`, `.`.
        name: String,
        /// Shape of the decoy.
        #[arg(long, value_enum, default_value_t = commands::canary::CanaryKind::Aws)]
        kind: commands::canary::CanaryKind,
    },
    /// List the configured canaries (names only).
    List,
}

#[derive(Debug, Subcommand)]
enum PinsCommand {
    /// List the pinned servers.
    List,
    /// Show the pinned tools of a server (the proxy's --name).
    Show { server: String },
    /// Forget pins so the next tools/list pins the current definitions (accept a reviewed
    /// change). Without --tool, all pins of the server.
    Reset {
        server: String,
        /// Only this tool; repeatable.
        #[arg(long = "tool", value_name = "TOOL")]
        tools: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
enum KeysCommand {
    /// Create an Ed25519 signing key (never overwrites an existing key).
    Generate {
        /// Key file (default: $AGENT_TRACE_SIGNING_KEY or <data dir>/keys/signing-key.pk8).
        #[arg(long, value_name = "PATH")]
        key: Option<PathBuf>,
    },
    /// Print the key id and public key.
    Show {
        #[arg(long, value_name = "PATH")]
        key: Option<PathBuf>,
    },
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
    /// SARIF 2.1.0 (GitHub Code Scanning)
    Sarif,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ImportFormat {
    Jsonl,
    /// OpenTelemetry traces as OTLP/JSON (GenAI semantic conventions), one request per file
    /// or per line (the Collector's file exporter). Each OTel trace becomes a trace.
    Otlp,
}

fn main() -> ExitCode {
    // Usage errors exit with 1 (error), not clap's default 2, which the documented exit-code
    // contract reserves for findings; --help and --version exit with 0.
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            return ExitCode::from(if e.use_stderr() { EXIT_ERROR } else { EXIT_OK });
        }
    };
    logging::init(cli.verbose);
    let color = !cli.no_color && std::env::var_os("NO_COLOR").is_none();
    let ctx = commands::Context {
        data_dir: cli.data_dir.clone(),
        database_url: cli.database_url.clone(),
        config: cli.config.clone(),
        style: output::Style::new(color),
    };
    // Configured redaction applies to everything this process stores, exports and prints,
    // so a configuration that cannot be loaded stops every command instead of being skipped.
    // Canaries likewise: they are matched before redaction and checked by the policy gate.
    let installed = ctx.config().and_then(|loaded| {
        agent_trace_core::redact::configure(&loaded.config.redaction)
            .map_err(anyhow::Error::msg)?;
        let canaries = agent_trace_core::canary::resolve(&loaded.config.canaries)
            .map_err(anyhow::Error::msg)?;
        agent_trace_core::canary::configure(canaries).map_err(anyhow::Error::msg)
    });
    if let Err(e) = installed {
        eprintln!(
            "error: {}",
            output::term_safe(&agent_trace_core::Redactor::new().scrub(&format!("{e:#}")))
        );
        return ExitCode::from(EXIT_ERROR);
    }
    let result = match cli.command {
        Command::Prune {
            older_than,
            keep,
            dry_run,
        } => commands::prune::run(&ctx, older_than.as_deref(), keep, dry_run),
        Command::LabServer { documents } => commands::lab_server(&documents).map(|_| EXIT_OK),
        Command::Hook {
            mode,
            print_settings,
        } => commands::hook::run(
            &ctx,
            commands::hook::HookArgs {
                mode: mode.map(ProxyModeArg::into_mode),
                print_settings,
            },
        ),
        Command::Proxy {
            name,
            mode,
            call_timeout,
            url,
            bearer_token_env,
            header_env,
            session,
            no_session,
            command,
        } => commands::proxy::run(
            &ctx,
            commands::proxy::ProxyArgs {
                name,
                mode: mode.map(ProxyModeArg::into_mode),
                call_timeout_secs: call_timeout,
                command,
                url,
                bearer_token_env,
                header_env,
                session,
                no_session,
            },
        ),
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
                    fail_on,
                },
        } => {
            commands::demo::run(
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
                    fail_on,
                },
            )
        }
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
        Command::Replay {
            command:
                ReplayCommand::Trace {
                    source,
                    model,
                    prompt,
                    runs,
                    fail_on,
                    report,
                },
        } => commands::replay::trace(
            &ctx,
            model.into_args(),
            commands::replay::TraceArgs {
                target: source.input.is_none().then_some(TraceTarget {
                    trace_id: source.trace_id,
                    latest: source.latest,
                }),
                input: source.input,
                prompt,
                runs,
                fail_on,
                report,
            },
        ),
        Command::Replay {
            command:
                ReplayCommand::Suite {
                    file,
                    model,
                    report,
                },
        } => commands::replay::suite(&ctx, model.into_args(), &file, report.as_deref()),
        Command::Graph { target, output } => commands::graph::run(&ctx, &target, output.as_deref()),
        Command::Export {
            target,
            format,
            output,
            artifact_uri,
            sign,
            key,
        } => commands::export::run(
            &ctx,
            &target,
            format,
            output.as_deref(),
            artifact_uri.as_deref(),
            sign.then_some(key.as_deref()),
        ),
        Command::Sarif {
            inputs,
            output,
            fail_on,
        } => commands::sarif::run(&ctx, &inputs, output.as_deref(), fail_on),
        Command::Verify {
            file,
            public_key,
            require_signature,
        } => commands::keys::verify(&ctx, &file, &public_key, require_signature),
        Command::Canary {
            command: CanaryCommand::New { name, kind },
        } => commands::canary::new(&name, kind),
        Command::Canary {
            command: CanaryCommand::List,
        } => commands::canary::list(&ctx),
        Command::Pins {
            command: PinsCommand::List,
        } => commands::pins::list(&ctx),
        Command::Pins {
            command: PinsCommand::Show { server },
        } => commands::pins::show(&ctx, &server),
        Command::Pins {
            command: PinsCommand::Reset { server, tools },
        } => commands::pins::reset(&ctx, &server, &tools),
        Command::Keys {
            command: KeysCommand::Generate { key },
        } => commands::keys::generate(&ctx, key.as_deref()),
        Command::Keys {
            command: KeysCommand::Show { key },
        } => commands::keys::show(&ctx, key.as_deref()),
        Command::Import {
            format,
            input,
            fail_on,
        } => commands::import::run(&ctx, format, &input, fail_on),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            let redactor = agent_trace_core::Redactor::new();
            eprintln!(
                "error: {}",
                output::term_safe(&redactor.scrub(&format!("{err:#}")))
            );
            ExitCode::from(EXIT_ERROR)
        }
    }
}
