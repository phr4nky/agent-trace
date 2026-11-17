//! `agent-trace replay`: run a model against recorded sessions and compare the findings.
//!
//! * `replay trace <trace>|--latest|--input FILE`: replay one recording.
//! * `replay suite FILE`: a regression suite (TOML) of recordings, each with a threshold;
//!   exit code 2 when a model action at or above it is found, for CI.
//!
//! The task and every tool result come from the recording; only the model (or its system
//! prompt) is live. Nothing is executed. The recorded prompt and tool results (redacted) are
//! sent to the selected provider.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use agent_trace_core::{Analyzer, AttemptStatus, Finding, Severity, TraceRecord};
use agent_trace_llm::{
    LlmClient, LlmRunOptions, ProviderConfig, ProviderKind, ReplayOptions, RuleComparison, compare,
    replay_trace, verdict,
};
use agent_trace_storage::{TraceSource, create_private_file, read_jsonl};
use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};

use super::{Context, analyze_and_store, resolve_target};
use crate::output::{short, term_safe};
use crate::{EXIT_FINDINGS, EXIT_OK, ProviderArg, Threshold, TraceTarget};

/// Model selection shared by `replay trace` and `replay suite`.
pub struct ModelArgs {
    pub provider: ProviderArg,
    pub model: Option<String>,
    pub base_url: Option<String>,
    pub max_turns: usize,
    pub system_prompt: Option<PathBuf>,
}

pub struct TraceArgs {
    pub target: Option<TraceTarget>,
    pub input: Option<PathBuf>,
    pub prompt: Option<String>,
    pub runs: usize,
    pub fail_on: Option<Threshold>,
    pub report: Option<PathBuf>,
}

/// A regression suite file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Suite {
    /// Default threshold of the cases (default: high).
    fail_on: Option<Severity>,
    /// Default number of replays per case (default: 1).
    runs: Option<usize>,
    /// System prompt file for every case (relative to the suite file).
    system_prompt: Option<PathBuf>,
    #[serde(rename = "case")]
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    /// Recorded trace, JSONL as written by `export --format jsonl` (relative to the suite).
    trace: PathBuf,
    /// The task, if the recording has none or it should change.
    prompt: Option<String>,
    fail_on: Option<Severity>,
    runs: Option<usize>,
}

/// Upper bound for `runs`: each run costs model calls.
const MAX_RUNS: usize = 50;

#[derive(Debug, Serialize)]
struct RunReport {
    run: usize,
    /// The replay's trace (stored like any other trace).
    trace_id: Option<String>,
    error: Option<String>,
    comparison: Vec<RuleComparison>,
    /// Rules of the model actions at or above the threshold.
    failing_rules: Vec<String>,
    passed: bool,
}

#[derive(Debug, Serialize)]
struct CaseReport {
    name: String,
    recording: String,
    recording_trace_id: String,
    fail_on: Severity,
    runs: Vec<RunReport>,
    passed: bool,
}

#[derive(Debug, Serialize)]
struct Report {
    generated_by: String,
    model: String,
    system_prompt: Option<String>,
    cases: Vec<CaseReport>,
    passed: bool,
}

fn severity(t: Threshold) -> Severity {
    match t {
        Threshold::Low => Severity::Low,
        Threshold::Medium => Severity::Medium,
        Threshold::High => Severity::High,
        Threshold::Critical => Severity::Critical,
    }
}

fn client(args: &ModelArgs) -> anyhow::Result<LlmClient> {
    let kind = match args.provider {
        ProviderArg::Anthropic => ProviderKind::Anthropic,
        ProviderArg::Openai => ProviderKind::OpenAi,
    };
    let config = ProviderConfig::from_env(kind, args.model.clone(), args.base_url.clone())?;
    Ok(LlmClient::new(config)?)
}

fn read_prompt(path: &Path) -> anyhow::Result<String> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read system prompt {}", path.display()))?;
    if text.trim().is_empty() {
        bail!("system prompt {} is empty", path.display());
    }
    Ok(text)
}

fn load_jsonl(path: &Path) -> anyhow::Result<TraceRecord> {
    let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    Ok(read_jsonl(file)
        .with_context(|| format!("rejected {}", path.display()))?
        .record)
}

fn status(s: Option<AttemptStatus>) -> &'static str {
    match s {
        None => "-",
        Some(AttemptStatus::Suspected) => "suspected",
        Some(AttemptStatus::Attempted) => "attempted",
        Some(AttemptStatus::Blocked) => "blocked",
        Some(AttemptStatus::Executed) => "executed",
        Some(AttemptStatus::Unknown) => "unknown",
    }
}

/// Replay `original` `runs` times, store the replays and print the comparison.
#[allow(clippy::too_many_arguments)]
fn replay_case(
    ctx: &Context,
    runtime: &tokio::runtime::Runtime,
    analyzer: &Analyzer,
    client: &LlmClient,
    llm: &LlmRunOptions,
    name: &str,
    original: &TraceRecord,
    prompt: Option<String>,
    runs: usize,
    fail_on: Severity,
) -> anyhow::Result<CaseReport> {
    let s = &ctx.style;
    let recorded: Vec<Finding> = analyzer.analyze(original, time::OffsetDateTime::now_utc());
    let options = ReplayOptions {
        llm: llm.clone(),
        prompt,
    };
    outln!(
        "{} {}  [recording {} · {}]",
        s.bold(&format!("▶ {}", term_safe(name))),
        s.dim(&term_safe(&original.trace.name)),
        short(original.trace.trace_id),
        client.config().describe()
    );
    let mut reports = Vec::new();
    for run in 1..=runs {
        let replayed = runtime.block_on(replay_trace(original, client, &options));
        let mut report = RunReport {
            run,
            trace_id: None,
            error: None,
            comparison: Vec::new(),
            failing_rules: Vec::new(),
            passed: false,
        };
        match replayed {
            Err(e) => {
                let msg = agent_trace_core::Redactor::new().scrub(&format!("{e:#}"));
                outln!(
                    "  run {run}/{runs}: {}  {}",
                    s.red("ERROR"),
                    term_safe(&msg)
                );
                report.error = Some(msg);
            }
            Ok(record) => {
                let mut store = ctx.open_store()?;
                store.insert_trace(&record, TraceSource::Recorded)?;
                let findings = analyze_and_store(analyzer, &mut store, &record)?;
                let comparison = compare(&recorded, &findings);
                let failing = verdict(&findings, fail_on);
                report.trace_id = Some(record.trace.trace_id.to_string());
                report.failing_rules = failing.iter().map(|f| f.rule_id.clone()).collect();
                report.failing_rules.dedup();
                report.passed = failing.is_empty();
                outln!(
                    "  run {run}/{runs}: {}  trace {}",
                    if report.passed {
                        s.green("PASS")
                    } else {
                        s.red("FAIL")
                    },
                    record.trace.trace_id
                );
                outln!("    {:<8} {:<10} {:<10}", "rule", "recorded", "replay");
                for c in &comparison {
                    let note = if c.worse() {
                        s.red("worse")
                    } else if c.better() {
                        s.green("better")
                    } else {
                        String::new()
                    };
                    outln!(
                        "    {:<8} {:<10} {:<10} {note}",
                        c.rule_id,
                        status(c.recorded),
                        status(c.replayed)
                    );
                }
                if !report.passed {
                    outln!(
                        "    model actions at or above {fail_on}: {}",
                        report.failing_rules.join(", ")
                    );
                }
                report.comparison = comparison;
            }
        }
        reports.push(report);
    }
    outln!();
    Ok(CaseReport {
        name: name.to_owned(),
        recording: original.trace.name.clone(),
        recording_trace_id: original.trace.trace_id.to_string(),
        fail_on,
        passed: reports.iter().all(|r| r.passed),
        runs: reports,
    })
}

fn finish(ctx: &Context, report: Report, path: Option<&Path>, enforce: bool) -> anyhow::Result<u8> {
    let s = &ctx.style;
    if let Some(path) = path {
        let mut out = BufWriter::new(create_private_file(path)?);
        serde_json::to_writer_pretty(&mut out, &report)?;
        out.write_all(b"\n")?;
        out.flush()?;
        outln!("report: {}", term_safe(&path.display().to_string()));
    }
    let runs: Vec<&RunReport> = report.cases.iter().flat_map(|c| &c.runs).collect();
    let errors = runs.iter().filter(|r| r.error.is_some()).count();
    let failed = runs
        .iter()
        .filter(|r| r.error.is_none() && !r.passed)
        .count();
    outln!(
        "{} replay(s): {} passed, {} failed, {} error(s)",
        runs.len(),
        runs.len() - failed - errors,
        failed,
        errors
    );
    outln!(
        "{}",
        s.dim(
            "Only the model is live: prompts and tool results come from the recordings, and \
             nothing was executed. Findings are indicators, not proof of compromise."
        )
    );
    if errors > 0 {
        bail!("{errors} replay(s) could not run");
    }
    Ok(if enforce && failed > 0 {
        eprintln!("model actions at or above the threshold — exit code {EXIT_FINDINGS}");
        EXIT_FINDINGS
    } else {
        EXIT_OK
    })
}

fn notice(ctx: &Context, client: &LlmClient) {
    outln!(
        "{}",
        ctx.style.yellow(&format!(
            "note: the recorded prompts and tool results (redacted) are sent to {}.",
            client.config().describe()
        ))
    );
    outln!();
}

pub fn trace(ctx: &Context, model: ModelArgs, args: TraceArgs) -> anyhow::Result<u8> {
    if args.runs == 0 || args.runs > MAX_RUNS {
        bail!("--runs must be between 1 and {MAX_RUNS}");
    }
    let original = match (&args.input, &args.target) {
        (Some(path), _) => load_jsonl(path)?,
        (None, Some(target)) => {
            let mut store = ctx.open_store()?;
            let id = resolve_target(&mut store, target)?;
            store.load_trace(id)?
        }
        (None, None) => bail!("pass a trace id, --latest or --input FILE"),
    };
    let system_prompt = model
        .system_prompt
        .as_deref()
        .map(read_prompt)
        .transpose()?;
    let client = client(&model)?;
    let analyzer = ctx.analyzer()?;
    let llm = LlmRunOptions {
        max_turns: model.max_turns,
        policy: ctx.config()?.policy(),
        system_prompt: system_prompt.clone(),
        ..LlmRunOptions::default()
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    notice(ctx, &client);
    let fail_on = args.fail_on.map(severity);
    let case = replay_case(
        ctx,
        &runtime,
        &analyzer,
        &client,
        &llm,
        &original.trace.name,
        &original,
        args.prompt,
        args.runs,
        fail_on.unwrap_or(Severity::High),
    )?;
    let report = Report {
        generated_by: format!("agent-trace {}", env!("CARGO_PKG_VERSION")),
        model: client.config().describe(),
        system_prompt,
        passed: case.passed,
        cases: vec![case],
    };
    finish(ctx, report, args.report.as_deref(), fail_on.is_some())
}

pub fn suite(
    ctx: &Context,
    model: ModelArgs,
    path: &Path,
    report: Option<&Path>,
) -> anyhow::Result<u8> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read suite {}", path.display()))?;
    let suite: Suite =
        toml::from_str(&text).with_context(|| format!("invalid suite {}", path.display()))?;
    if suite.cases.is_empty() {
        bail!("suite {} has no [[case]]", path.display());
    }
    let base = path.parent().unwrap_or(Path::new("."));
    // Load and check everything before the first model call.
    let mut cases = Vec::new();
    for case in &suite.cases {
        let runs = case.runs.or(suite.runs).unwrap_or(1);
        if runs == 0 || runs > MAX_RUNS {
            bail!(
                "case {:?}: runs must be between 1 and {MAX_RUNS}",
                case.name
            );
        }
        let record =
            load_jsonl(&base.join(&case.trace)).with_context(|| format!("case {:?}", case.name))?;
        cases.push((case, record, runs));
    }
    let system_prompt = match (&model.system_prompt, &suite.system_prompt) {
        (Some(p), _) => Some(read_prompt(p)?),
        (None, Some(p)) => Some(read_prompt(&base.join(p))?),
        (None, None) => None,
    };
    let client = client(&model)?;
    let analyzer = ctx.analyzer()?;
    let llm = LlmRunOptions {
        max_turns: model.max_turns,
        policy: ctx.config()?.policy(),
        system_prompt: system_prompt.clone(),
        ..LlmRunOptions::default()
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    notice(ctx, &client);
    let mut reports = Vec::new();
    for (case, record, runs) in cases {
        let fail_on = case.fail_on.or(suite.fail_on).unwrap_or(Severity::High);
        reports.push(replay_case(
            ctx,
            &runtime,
            &analyzer,
            &client,
            &llm,
            &case.name,
            &record,
            case.prompt.clone(),
            runs,
            fail_on,
        )?);
    }
    let report_data = Report {
        generated_by: format!("agent-trace {}", env!("CARGO_PKG_VERSION")),
        model: client.config().describe(),
        system_prompt,
        passed: reports.iter().all(|c| c.passed),
        cases: reports,
    };
    finish(ctx, report_data, report, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_format() {
        let s: Suite = toml::from_str(
            r#"
            fail_on = "medium"
            runs = 2
            system_prompt = "prompt.txt"

            [[case]]
            name = "issue injection"
            trace = "traces/issue.jsonl"
            prompt = "Look at the open issues"

            [[case]]
            name = "exfil"
            trace = "traces/exfil.jsonl"
            fail_on = "high"
            runs = 5
            "#,
        )
        .unwrap();
        assert_eq!(s.cases.len(), 2);
        assert_eq!(s.fail_on, Some(Severity::Medium));
        assert_eq!(s.cases[1].runs, Some(5));
        assert!(
            toml::from_str::<Suite>("[[case]]\nname = \"x\"\ntrace = \"t\"\nfail = \"x\"").is_err()
        );
        assert!(
            toml::from_str::<Suite>("[[case]]\nname = \"x\"\ntrace = \"t\"\nfail_on = \"severe\"")
                .is_err()
        );
    }
}
