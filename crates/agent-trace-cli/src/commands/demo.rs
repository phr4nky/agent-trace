use std::io::BufWriter;
use std::path::PathBuf;
use std::time::Duration;

use agent_trace_core::{ExecutionMode, TraceRecord};
use agent_trace_llm::{LlmClient, LlmRunOptions, ProviderConfig, ProviderKind, run_llm_scenario};
use agent_trace_mcp::{
    LabPaths, McpSession, RunOptions, SCENARIO_NAMES, ServerCommand, lab_recorder, locate_lab_dir,
    run_scenario_with,
};
use agent_trace_storage::{
    LiveWriter, StorageError, TraceSource, create_private_file, write_json_report, write_jsonl,
};
use anyhow::Context as _;

use super::{Context, analyze_and_store, threshold_exit};
use crate::output::{finding_line, short};
use crate::{ProviderArg, ScenarioArg, Threshold};

pub struct DemoArgs {
    pub scenario: ScenarioArg,
    pub lab_dir: Option<PathBuf>,
    pub deterministic: bool,
    pub provider: Option<ProviderArg>,
    pub model: Option<String>,
    pub base_url: Option<String>,
    pub max_turns: usize,
    pub step_delay: Duration,
    pub fail_on: Option<Threshold>,
}

pub fn run(ctx: &Context, args: DemoArgs) -> anyhow::Result<u8> {
    let s = &ctx.style;
    let config = ctx.config()?;
    config.announce();
    let policy = config.policy();
    let lab = LabPaths::new(locate_lab_dir(args.lab_dir.as_deref())?);
    let names: Vec<&str> = match args.scenario {
        ScenarioArg::All => SCENARIO_NAMES.to_vec(),
        ScenarioArg::Benign => vec!["benign"],
        ScenarioArg::PromptInjection => vec!["prompt-injection"],
        ScenarioArg::ExfilAttempt => vec!["exfil-attempt"],
        ScenarioArg::MultiAgentHandoff => vec!["multi-agent-handoff"],
    };
    let server = ServerCommand {
        program: std::env::current_exe().context("cannot locate own executable")?,
        args: vec![
            "lab-server".into(),
            "--documents".into(),
            lab.documents().display().to_string(),
        ],
    };
    let llm = match args.provider {
        None => None,
        Some(p) => {
            let kind = match p {
                ProviderArg::Anthropic => ProviderKind::Anthropic,
                ProviderArg::Openai => ProviderKind::OpenAi,
            };
            let config = ProviderConfig::from_env(kind, args.model.clone(), args.base_url.clone())?;
            Some(LlmClient::new(config)?)
        }
    };
    let options = RunOptions {
        deterministic: args.deterministic,
        policy: policy.clone(),
        step_delay: args.step_delay,
    };
    let llm_options = LlmRunOptions {
        max_turns: args.max_turns,
        policy,
        step_delay: args.step_delay,
        ..LlmRunOptions::default()
    };

    let store = ctx.open_store()?;
    let location = format!("{} ({})", store.location(), store.dialect().name());
    let exports = ctx.exports_dir()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    match &llm {
        None => outln!(
            "{}",
            s.bold(
                "agent-trace local lab — SIMULATED scenarios (scripted agent, mock tools, no shell, no network)"
            )
        ),
        Some(client) => {
            outln!(
                "{}",
                s.bold(&format!(
                    "agent-trace local lab — LIVE MODEL {} (mock tools, policy-gated, no shell)",
                    client.config().describe()
                ))
            );
            outln!(
                "{}",
                s.yellow(
                    "note: the lab's prompts and fixture documents (incl. their fake secrets) are sent to this provider."
                )
            );
        }
    }
    outln!("lab: {}", lab.root.display());
    if !args.step_delay.is_zero() {
        outln!(
            "live mode: {} ms per step — watch with: agent-trace explore --latest --follow",
            args.step_delay.as_millis()
        );
    }
    outln!();

    // Load every scenario first: an error later would leave the live writer unfinished and
    // the traces of scenarios that already ran lost or stuck at `running`.
    let scenarios = names
        .iter()
        .map(|name| lab.load_scenario(name).map(|s| (*name, s)))
        .collect::<Result<Vec<_>, _>>()?;

    // Every event is persisted as soon as it is recorded (live), by a writer thread.
    let writer = LiveWriter::spawn_with(store, TraceSource::Recorded, Some(config.analyzer()));
    let mut produced: Vec<(String, String, Result<TraceRecord, String>)> = Vec::new();
    for (name, scenario) in scenarios {
        let result = match &llm {
            None => {
                let rec = lab_recorder(&scenario, ExecutionMode::Simulated, args.deterministic)
                    .with_sink(writer.sink());
                runtime.block_on(run_scenario_with(rec, &scenario, &server, &options))
            }
            Some(client) => {
                let rec =
                    lab_recorder(&scenario, ExecutionMode::Live, false).with_sink(writer.sink());
                runtime.block_on(async {
                    let session = McpSession::connect(&server).await?;
                    let out =
                        run_llm_scenario(rec, &scenario, &session, client, &llm_options).await;
                    let _ = session.close().await;
                    out
                })
            }
        };
        produced.push((
            name.to_string(),
            scenario.title,
            result.map_err(|e| format!("{e:#}")),
        ));
    }
    let (mut store, written) = writer.finish();
    if let Err(e) = written {
        if matches!(e, StorageError::DuplicateTrace(_)) && args.deterministic {
            anyhow::bail!("{e}: deterministic traces have fixed ids; use a fresh --data-dir");
        }
        // The store failed mid-run; keep the complete in-memory traces as files so nothing
        // that was recorded is lost (they can be imported later).
        let mut saved = Vec::new();
        for (name, _, result) in &produced {
            if let Ok(record) = result {
                let path = exports.join(format!("{name}-{}.jsonl", record.trace.trace_id));
                if create_private_file(&path)
                    .map_err(StorageError::from)
                    .and_then(|f| write_jsonl(BufWriter::new(f), record, &[]))
                    .is_ok()
                {
                    saved.push(path.display().to_string());
                }
            }
        }
        if saved.is_empty() {
            return Err(e.into());
        }
        eprintln!(
            "storage failed; the recorded traces were saved as JSONL \
             (re-import them with `agent-trace import`):"
        );
        for path in &saved {
            eprintln!("  {}", crate::output::term_safe(path));
        }
        return Err(e.into());
    }

    let mut failures = 0;
    let mut last_id = None;
    let mut all_findings = Vec::new();
    for (name, title, result) in produced {
        let record = match result {
            Ok(r) => r,
            Err(e) => {
                failures += 1;
                outln!(
                    "{} {}  [{}]",
                    s.bold(&format!("▶ {name}")),
                    s.dim(&title),
                    s.red("ABORTED")
                );
                outln!(
                    "  error    : {}\n",
                    crate::output::term_safe(&agent_trace_core::Redactor::new().scrub(&e))
                );
                continue;
            }
        };
        let findings = analyze_and_store(&config.analyzer(), &mut store, &record)?;
        all_findings.extend(findings.iter().cloned());
        let base = format!("{name}-{}", record.trace.trace_id);
        let jsonl_path = exports.join(format!("{base}.jsonl"));
        let report_path = exports.join(format!("{base}.findings.json"));
        write_jsonl(
            BufWriter::new(create_private_file(&jsonl_path)?),
            &record,
            &findings,
        )?;
        write_json_report(
            BufWriter::new(create_private_file(&report_path)?),
            &record,
            &findings,
        )?;

        let agents = agent_trace_core::Trace::agents(&record.events);
        outln!(
            "{} {}  [{}]",
            s.bold(&format!("▶ {name}")),
            s.dim(&title),
            s.mode(record.trace.execution_mode)
        );
        outln!("  trace id : {}", record.trace.trace_id);
        outln!(
            "  events   : {}   agents: {}   mcp server: {} {} via {} (MCP {})",
            record.events.len(),
            agents.join(", "),
            meta(&record, "mcp_server"),
            meta(&record, "mcp_server_version"),
            meta(&record, "transport"),
            meta(&record, "mcp_protocol_version"),
        );
        if let Some(model) = record
            .trace
            .metadata
            .get("llm_endpoint")
            .and_then(|v| v.as_str())
        {
            outln!("  model    : {model}");
        }
        if findings.is_empty() {
            outln!("  findings : {}", s.green("none"));
        } else {
            outln!("  findings :");
            for f in &findings {
                outln!("    {}", finding_line(s, &record, f));
            }
        }
        outln!("  trace    : {}", jsonl_path.display());
        outln!("  report   : {}\n", report_path.display());
        last_id = Some(record.trace.trace_id);
    }

    outln!("database: {location}");
    if let Some(id) = last_id {
        outln!(
            "next: agent-trace trace show {}   |   agent-trace explore --latest",
            short(id)
        );
    }
    if llm.is_none() {
        outln!(
            "{}",
            s.dim(
                "All scenario behavior is SIMULATED. Findings are indicators, not proof of compromise."
            )
        );
    } else {
        outln!(
            "{}",
            s.dim(
                "Model decisions are LIVE; tools are mocks. Findings are indicators, not proof of compromise."
            )
        );
    }
    if failures > 0 {
        anyhow::bail!(
            "{failures} scenario(s) aborted; their partial traces are stored with status `aborted`"
        );
    }
    Ok(threshold_exit(&all_findings, args.fail_on))
}

fn meta(record: &TraceRecord, key: &str) -> String {
    record
        .trace
        .metadata
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_owned()
}
