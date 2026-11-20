//! `agent-trace evidence`: a record-keeping evidence report.
//!
//! The report answers four questions about recorded traces: what was recorded, under which
//! configuration, how long traces are kept, and whether exported files are unchanged. It is
//! meant as material for record-keeping duties (such as Articles 12 and 26(6) of the EU AI
//! Act) and deliberately makes no compliance claim.
//!
//! Inputs are JSONL exports (verified with the same code as `agent-trace verify`) and/or
//! traces in the store. Only signed exports are tamper-evident; the store is not.
//!
//! Privacy: the report holds metadata and counts only, never payloads. Every text taken from
//! a trace or the configuration passes through the redactor; canary values and redaction
//! patterns are never included (only canary names and pattern labels).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use agent_trace_core::{EventKind, Finding, Redactor, Severity, TraceRecord};
use agent_trace_storage::{Store, create_private_file, read_jsonl};
use anyhow::{Context as _, bail};
use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use super::Context;
use crate::{EXIT_ERROR, EXIT_OK};

/// Version of the JSON layout. Field names are stable within a version.
pub const REPORT_VERSION: &str = "1";
/// Six months in days, rounded up: Article 26(6) EU AI Act names "at least six months".
pub const SIX_MONTHS_DAYS: u64 = 183;

const DISCLAIMER: &str = "This report is not a statement of compliance with the EU AI Act or \
     any other law. It collects evidence about recorded agent traces: what was recorded, under \
     which configuration, how long traces are kept, and whether exported files are unchanged. \
     Whether an obligation applies to a system and whether it is met is for the operator and \
     their legal advisers to assess.";

const NOT_PROVEN: &[&str] = &[
    "Compliance: the report is not a statement of compliance with the EU AI Act or any other \
     law, and says nothing about whether a system is high-risk.",
    "Integrity of stored traces: traces read from the database are not tamper-evident; whoever \
     can write to the database can change them. Only signed JSONL exports, verified against a \
     trusted key, show that a trace is unchanged since it was exported.",
    "Completeness: only what passed through agent-trace (MCP proxy, Claude Code hooks, the lab, \
     imports) is recorded. Actions outside it, or before recording started, are not in a trace, \
     and a signature does not show that a recording is complete.",
    "Configuration at recording time: the configuration hash and summary describe the \
     configuration when the report was generated, not necessarily the one in effect when each \
     trace was recorded.",
    "Retention in practice: retention settings take effect only when `agent-trace prune` runs. \
     The report shows the configured limits and the oldest and newest trace in the store now, \
     not that traces were kept for any period.",
    "Time: timestamps come from the recording machine's clock and are not independently \
     attested.",
    "Absence of attacks: findings are indicators produced by rules, not proof of an attack, and \
     no findings is not proof that none happened.",
    "Absence of sensitive data: redaction counts show that values were replaced, not that no \
     sensitive data remains in a trace.",
];

/// Output format of the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Markdown,
    Json,
}

pub struct Args<'a> {
    pub files: &'a [PathBuf],
    pub trace_ids: &'a [String],
    pub since: Option<&'a str>,
    pub all: bool,
    pub public_keys: &'a [String],
    pub require_signature: bool,
    pub format: Format,
    pub output: Option<&'a Path>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub report_version: &'static str,
    pub report_type: &'static str,
    pub generated_at: String,
    pub generated_by: String,
    pub disclaimer: &'static str,
    /// `ok`, or `failed` if an input file failed verification.
    pub result: &'static str,
    pub summary: Summary,
    pub configuration: ConfigSummary,
    pub retention: Retention,
    pub traces: Vec<TraceEvidence>,
    pub not_proven: Vec<&'static str>,
    pub references: Vec<Reference>,
}

#[derive(Debug, Default, Serialize)]
pub struct Summary {
    pub traces: usize,
    pub from_files: usize,
    pub from_store: usize,
    pub verified: usize,
    pub unsigned: usize,
    pub failed: usize,
    pub not_tamper_evident: usize,
    pub events: u64,
    pub findings: u64,
}

#[derive(Debug, Serialize)]
pub struct ConfigSummary {
    /// The configuration file, or `null` for the built-in defaults.
    pub source: Option<String>,
    /// SHA-256 of the canonical configuration (canary values excluded).
    pub sha256: String,
    pub policy: PolicySummary,
    pub redaction: RedactionSummary,
    pub retention: RetentionConfig,
    pub custom_rules: Vec<String>,
    pub canaries: Vec<String>,
    /// Task profiles (`[profiles.<name>]`): name -> allowed tools.
    pub profiles: std::collections::BTreeMap<String, Vec<String>>,
    pub proxy_mode: String,
    pub hooks_mode: String,
    pub hooks_on_error: String,
}

#[derive(Debug, Serialize)]
pub struct PolicySummary {
    pub privileged: Vec<String>,
    pub outbound: Vec<String>,
    pub allow_destinations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RedactionSummary {
    /// Labels of the added secret patterns (the patterns themselves are never shown).
    pub pattern_labels: Vec<String>,
    /// Added field names whose values are always replaced.
    pub keys: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RetentionConfig {
    pub max_age_days: Option<u64>,
    pub max_traces: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct Retention {
    pub max_age_days: Option<u64>,
    pub max_traces: Option<usize>,
    /// The command that applies the limits; it does not run by itself.
    pub applied_by: &'static str,
    pub store: StoreSummary,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct StoreSummary {
    pub location: String,
    pub traces: usize,
    pub oldest: Option<TraceRef>,
    pub newest: Option<TraceRef>,
}

#[derive(Debug, Serialize)]
pub struct TraceRef {
    pub trace_id: Uuid,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct TraceEvidence {
    /// `file` or `store`.
    pub source: &'static str,
    pub file: Option<String>,
    pub integrity: Integrity,
    /// `null` if the file failed verification (its content cannot be relied on).
    pub trace: Option<TraceFacts>,
}

#[derive(Debug, Serialize)]
pub struct Integrity {
    /// `verified`, `unsigned`, `untrusted_signer`, `failed` or `not_tamper_evident`.
    pub status: &'static str,
    pub chained_records: Option<u64>,
    pub signed: bool,
    pub signer_key_id: Option<String>,
    pub signer_public_key: Option<String>,
    pub signer_trusted: Option<bool>,
    pub trusted_by: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TraceFacts {
    pub trace_id: Uuid,
    pub name: String,
    pub execution_mode: &'static str,
    pub status: &'static str,
    pub started_at: String,
    pub ended_at: String,
    pub event_count: usize,
    pub agents: Vec<String>,
    pub mcp_servers: Vec<String>,
    pub tools: Vec<String>,
    pub findings: FindingCounts,
    pub redaction: RedactionCounts,
}

#[derive(Debug, Serialize)]
pub struct FindingCounts {
    pub total: usize,
    pub by_severity: BTreeMap<&'static str, usize>,
    pub by_rule: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize)]
pub struct RedactionCounts {
    /// Values replaced by the redactor (sum of `metadata.redactions` over all events).
    pub redacted_values: u64,
    pub events_with_redactions: usize,
    /// Events whose payload was cut to the size limit.
    pub truncated_events: usize,
}

#[derive(Debug, Serialize)]
pub struct Reference {
    pub title: &'static str,
    pub url: &'static str,
}

const REFERENCES: &[Reference] = &[
    Reference {
        title: "EU AI Act, Article 12: Record-keeping",
        url: "https://artificialintelligenceact.eu/article/12/",
    },
    Reference {
        title: "EU AI Act, Article 26: Obligations of deployers of high-risk AI systems",
        url: "https://artificialintelligenceact.eu/article/26/",
    },
];

fn rfc3339(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_else(|_| t.to_string())
}

/// `YYYY-MM-DD` (midnight UTC) or an RFC 3339 timestamp.
pub fn parse_since(text: &str) -> anyhow::Result<OffsetDateTime> {
    let t = text.trim();
    if let Ok(ts) = OffsetDateTime::parse(t, &Rfc3339) {
        return Ok(ts);
    }
    let format = time::macros::format_description!("[year]-[month]-[day]");
    let date = time::Date::parse(t, &format).map_err(|_| {
        anyhow::anyhow!("invalid --since {text:?}: use YYYY-MM-DD or an RFC 3339 timestamp")
    })?;
    Ok(date.midnight().assume_utc())
}

fn facts(redactor: &Redactor, record: &TraceRecord, findings: &[Finding]) -> TraceFacts {
    let scrub = |s: &str| redactor.scrub(s);
    let trace = &record.trace;
    let mut servers = BTreeSet::new();
    let mut add_server = |m: &serde_json::Map<String, Value>| {
        if let Some(s) = m.get("mcp_server").and_then(Value::as_str) {
            servers.insert(scrub(s));
        }
    };
    add_server(&trace.metadata);
    let mut tools = BTreeSet::new();
    let mut redacted_values = 0u64;
    let mut events_with_redactions = 0;
    let mut truncated_events = 0;
    for e in &record.events {
        add_server(&e.metadata);
        if e.kind == EventKind::ToolCallRequested {
            tools.insert(scrub(&e.name));
        }
        let n = e
            .metadata
            .get("redactions")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if n > 0 {
            redacted_values = redacted_values.saturating_add(n);
            events_with_redactions += 1;
        }
        if e.metadata.get("truncated").and_then(Value::as_bool) == Some(true) {
            truncated_events += 1;
        }
    }
    let mut by_severity: BTreeMap<&'static str, usize> = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ]
    .into_iter()
    .map(|s| (s.as_str(), 0))
    .collect();
    let mut by_rule = BTreeMap::new();
    for f in findings {
        *by_severity.entry(f.severity.as_str()).or_default() += 1;
        *by_rule.entry(scrub(&f.rule_id)).or_default() += 1;
    }
    let first = record
        .events
        .first()
        .map_or(trace.created_at, |e| e.timestamp);
    let last = record.events.last().map_or(first, |e| e.timestamp);
    TraceFacts {
        trace_id: trace.trace_id,
        name: scrub(&trace.name),
        execution_mode: trace.execution_mode.as_str(),
        status: trace.status.as_str(),
        started_at: rfc3339(first.min(trace.created_at)),
        ended_at: rfc3339(last),
        event_count: record.events.len(),
        agents: agent_trace_core::Trace::agents(&record.events)
            .iter()
            .map(|a| scrub(a))
            .collect(),
        mcp_servers: servers.into_iter().collect(),
        tools: tools.into_iter().collect(),
        findings: FindingCounts {
            total: findings.len(),
            by_severity,
            by_rule,
        },
        redaction: RedactionCounts {
            redacted_values,
            events_with_redactions,
            truncated_events,
        },
    }
}

fn file_evidence(
    redactor: &Redactor,
    analyzer: &agent_trace_core::Analyzer,
    path: &Path,
    trusted: &[(String, String)],
    require_signature: bool,
) -> TraceEvidence {
    let failed = |error: String| TraceEvidence {
        source: "file",
        file: Some(redactor.scrub(&path.display().to_string())),
        integrity: Integrity {
            status: "failed",
            chained_records: None,
            signed: false,
            signer_key_id: None,
            signer_public_key: None,
            signer_trusted: None,
            trusted_by: None,
            error: Some(redactor.scrub(&error)),
        },
        trace: None,
    };
    let imported = match File::open(path)
        .with_context(|| format!("cannot open {}", path.display()))
        .and_then(|f| {
            read_jsonl(f).with_context(|| format!("{} failed verification", path.display()))
        }) {
        Ok(imported) => imported,
        Err(e) => return failed(format!("{e:#}")),
    };
    let Some(verified) = imported.integrity else {
        return failed(format!(
            "{} has no integrity record: it was written by hand, by an agent-trace version \
             without tamper evidence, or the record was removed",
            path.display()
        ));
    };
    let mut integrity = Integrity {
        status: "unsigned",
        chained_records: Some(verified.lines),
        signed: false,
        signer_key_id: None,
        signer_public_key: None,
        signer_trusted: None,
        trusted_by: None,
        error: None,
    };
    match verified.signed_by {
        None if require_signature => {
            integrity.status = "failed";
            integrity.error = Some("--require-signature: the file is not signed".into());
        }
        None => {}
        Some((key_id, public)) => {
            integrity.signed = true;
            let source = trusted.iter().find(|(k, _)| *k == public).map(|(_, s)| s);
            integrity.signer_trusted = Some(source.is_some());
            integrity.trusted_by = source.map(|s| redactor.scrub(s));
            match source {
                Some(_) => integrity.status = "verified",
                None => {
                    integrity.status = "untrusted_signer";
                    integrity.error = Some(
                        "the signature is valid, but the key is not trusted: pass the \
                         expected key with --public-key"
                            .into(),
                    );
                }
            }
            integrity.signer_key_id = Some(key_id);
            integrity.signer_public_key = Some(public);
        }
    }
    // Findings in a file are ignored on import; they are recomputed like `import` does.
    let findings = analyzer.analyze(&imported.record, OffsetDateTime::now_utc());
    TraceEvidence {
        source: "file",
        file: Some(redactor.scrub(&path.display().to_string())),
        integrity,
        trace: Some(facts(redactor, &imported.record, &findings)),
    }
}

fn store_evidence(
    redactor: &Redactor,
    analyzer: &agent_trace_core::Analyzer,
    store: &mut Store,
    id: Uuid,
) -> anyhow::Result<TraceEvidence> {
    let record = store.load_trace(id)?;
    let mut findings = store.load_findings(id)?;
    if findings.is_empty() {
        // Not analyzed yet (or nothing found): compute, without writing to the store.
        findings = analyzer.analyze(&record, OffsetDateTime::now_utc());
    }
    Ok(TraceEvidence {
        source: "store",
        file: None,
        integrity: Integrity {
            status: "not_tamper_evident",
            chained_records: None,
            signed: false,
            signer_key_id: None,
            signer_public_key: None,
            signer_trusted: None,
            trusted_by: None,
            error: None,
        },
        trace: Some(facts(redactor, &record, &findings)),
    })
}

fn config_summary(
    redactor: &Redactor,
    loaded: &crate::config::Loaded,
) -> anyhow::Result<ConfigSummary> {
    let c = &loaded.config;
    let scrub_all = |v: &[String]| v.iter().map(|s| redactor.scrub(s)).collect::<Vec<_>>();
    Ok(ConfigSummary {
        source: loaded
            .path
            .as_ref()
            .map(|p| redactor.scrub(&p.display().to_string())),
        sha256: c.sha256()?,
        policy: PolicySummary {
            privileged: scrub_all(&c.policy.privileged),
            outbound: scrub_all(&c.policy.outbound),
            allow_destinations: scrub_all(&c.policy.allow_destinations),
        },
        redaction: RedactionSummary {
            pattern_labels: c
                .redaction
                .patterns
                .iter()
                .map(|p| redactor.scrub(&p.label))
                .collect(),
            keys: scrub_all(&c.redaction.keys),
        },
        retention: RetentionConfig {
            max_age_days: c.retention.max_age_days,
            max_traces: c.retention.max_traces,
        },
        custom_rules: c.rules.iter().map(|r| redactor.scrub(&r.id)).collect(),
        canaries: c.canaries.iter().map(|k| redactor.scrub(&k.name)).collect(),
        profiles: c
            .profiles
            .iter()
            .map(|(name, p)| (redactor.scrub(name), scrub_all(&p.tools)))
            .collect(),
        proxy_mode: c.proxy.mode.unwrap_or_default().as_str().into(),
        hooks_mode: c.hooks.mode.unwrap_or_default().as_str().into(),
        hooks_on_error: match c.hooks.on_error {
            crate::config::OnError::Allow => "allow".into(),
            crate::config::OnError::Deny => "deny".into(),
        },
    })
}

/// Neutral notes on the retention settings.
pub fn retention_warnings(max_age_days: Option<u64>, max_traces: Option<usize>) -> Vec<String> {
    let mut out = Vec::new();
    if max_age_days.is_none() && max_traces.is_none() {
        out.push(
            "No retention is configured ([retention] in agent-trace.toml): agent-trace does \
             not define how long traces are kept. Article 26(6) of the EU AI Act names at \
             least six months for deployers of high-risk AI systems."
                .into(),
        );
    }
    if let Some(days) = max_age_days
        && days < SIX_MONTHS_DAYS
    {
        out.push(format!(
            "max_age_days = {days} is shorter than six months ({SIX_MONTHS_DAYS} days): \
             `agent-trace prune` deletes older traces. Article 26(6) of the EU AI Act names \
             at least six months for deployers of high-risk AI systems."
        ));
    }
    if let Some(n) = max_traces {
        out.push(format!(
            "max_traces = {n} limits retention by count, not by time: the period covered \
             depends on how many traces are recorded."
        ));
    }
    out
}

pub fn run(ctx: &Context, args: &Args<'_>) -> anyhow::Result<u8> {
    if args.files.is_empty() && args.trace_ids.is_empty() && args.since.is_none() && !args.all {
        bail!("pass JSONL files, --trace ID, --since DATE or --all");
    }
    let since = args.since.map(parse_since).transpose()?;
    let redactor = Redactor::new();
    let loaded = ctx.config()?;
    loaded.announce();
    let analyzer = loaded.analyzer();
    let trusted = super::keys::trusted_keys(ctx, args.public_keys)?;

    let mut traces = Vec::new();
    for path in args.files {
        traces.push(file_evidence(
            &redactor,
            &analyzer,
            path,
            &trusted,
            args.require_signature,
        ));
    }

    let mut store = ctx.open_store()?;
    let listed = store.list_traces()?; // oldest first
    let mut selected: Vec<Uuid> = Vec::new();
    for id in args.trace_ids {
        let id = store.resolve_trace_id(id)?;
        if !selected.contains(&id) {
            selected.push(id);
        }
    }
    for t in &listed {
        let wanted = args.all || since.is_some_and(|s| t.trace.created_at >= s);
        if wanted && !selected.contains(&t.trace.trace_id) {
            selected.push(t.trace.trace_id);
        }
    }
    for id in selected {
        traces.push(store_evidence(&redactor, &analyzer, &mut store, id)?);
    }

    let retention_cfg = &loaded.config.retention;
    let as_ref = |t: &agent_trace_storage::TraceSummary| TraceRef {
        trace_id: t.trace.trace_id,
        created_at: rfc3339(t.trace.created_at),
    };
    let retention = Retention {
        max_age_days: retention_cfg.max_age_days,
        max_traces: retention_cfg.max_traces,
        applied_by: "agent-trace prune",
        store: StoreSummary {
            location: redactor.scrub(store.location()),
            traces: listed.len(),
            oldest: listed.iter().min_by_key(|t| t.trace.created_at).map(as_ref),
            newest: listed.iter().max_by_key(|t| t.trace.created_at).map(as_ref),
        },
        warnings: retention_warnings(retention_cfg.max_age_days, retention_cfg.max_traces),
    };

    let mut summary = Summary {
        traces: traces.len(),
        ..Summary::default()
    };
    for t in &traces {
        match t.source {
            "file" => summary.from_files += 1,
            _ => summary.from_store += 1,
        }
        match t.integrity.status {
            "verified" => summary.verified += 1,
            "unsigned" => summary.unsigned += 1,
            "not_tamper_evident" => summary.not_tamper_evident += 1,
            _ => summary.failed += 1,
        }
        if let Some(f) = &t.trace {
            summary.events += f.event_count as u64;
            summary.findings += f.findings.total as u64;
        }
    }

    let report = Report {
        report_version: REPORT_VERSION,
        report_type: "agent-trace-evidence",
        generated_at: rfc3339(OffsetDateTime::now_utc()),
        generated_by: format!("agent-trace {}", env!("CARGO_PKG_VERSION")),
        disclaimer: DISCLAIMER,
        result: if summary.failed > 0 { "failed" } else { "ok" },
        summary,
        configuration: config_summary(&redactor, &loaded)?,
        retention,
        traces,
        not_proven: NOT_PROVEN.to_vec(),
        references: REFERENCES
            .iter()
            .map(|r| Reference {
                title: r.title,
                url: r.url,
            })
            .collect(),
    };

    let text = match args.format {
        Format::Json => serde_json::to_string_pretty(&report)? + "\n",
        Format::Markdown => markdown(&report),
    };
    match args.output {
        Some(path) => {
            let mut file = create_private_file(path)
                .with_context(|| format!("cannot create {}", path.display()))?;
            file.write_all(text.as_bytes())?;
            file.flush()?;
            eprintln!(
                "wrote evidence report ({} trace(s)) to {}",
                report.summary.traces,
                crate::output::term_safe(&path.display().to_string())
            );
        }
        // Markdown/JSON for a file or pipe: every untrusted text is escaped already.
        None => out!("{text}"),
    }
    if report.summary.failed > 0 {
        eprintln!(
            "error: {} input(s) FAILED verification (see the report); exit code {EXIT_ERROR}",
            report.summary.failed
        );
        return Ok(EXIT_ERROR);
    }
    Ok(EXIT_OK)
}

/// Escape text for Markdown (and a terminal): no control characters, no markup.
fn md(text: &str) -> String {
    let safe = crate::output::term_safe(text);
    let mut out = String::with_capacity(safe.len());
    for c in safe.chars() {
        if "\\`*_[]<>|#!{}~".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn md_list(items: &[String]) -> String {
    if items.is_empty() {
        "none".into()
    } else {
        items.iter().map(|s| md(s)).collect::<Vec<_>>().join(", ")
    }
}

fn opt<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map_or_else(|| "not set".into(), |v| v.to_string())
}

fn integrity_line(i: &Integrity) -> String {
    let records = i
        .chained_records
        .map(|n| format!("hash chain OK ({n} records)"))
        .unwrap_or_default();
    match i.status {
        "verified" => format!(
            "**VERIFIED**: {records}, signed by key `{}` (trusted: {})",
            md(i.signer_key_id.as_deref().unwrap_or("")),
            md(i.trusted_by.as_deref().unwrap_or(""))
        ),
        "unsigned" => format!(
            "**UNSIGNED**: {records}; no signature, so this shows the file is consistent, not \
             who exported it"
        ),
        "untrusted_signer" => format!(
            "**FAILED (untrusted signer)**: {records}, valid signature by key `{}`, which is \
             not trusted",
            md(i.signer_key_id.as_deref().unwrap_or(""))
        ),
        "not_tamper_evident" => {
            "**NOT TAMPER-EVIDENT**: read from the store; export it with `export --format \
             jsonl --sign` for tamper evidence"
                .into()
        }
        _ => format!(
            "**FAILED**: {}",
            md(i.error.as_deref().unwrap_or("verification failed"))
        ),
    }
}

/// The human-readable report.
pub fn markdown(r: &Report) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    let s = &r.summary;
    let _ = writeln!(o, "# agent-trace evidence report\n");
    let _ = writeln!(o, "> **Not a compliance statement.** {}\n", r.disclaimer);
    let _ = writeln!(o, "- Generated at: {}", md(&r.generated_at));
    let _ = writeln!(o, "- Generated by: {}", md(&r.generated_by));
    let _ = writeln!(o, "- Report version: {}", r.report_version);
    let result = if r.result == "ok" {
        "**OK**: no input failed verification".to_string()
    } else {
        format!("**FAILED**: {} input(s) failed verification", s.failed)
    };
    let _ = writeln!(o, "- Result: {result}\n");

    let _ = writeln!(o, "## Summary\n");
    let _ = writeln!(o, "| Item | Count |\n| --- | ---: |");
    for (k, v) in [
        ("Traces", s.traces),
        ("From signed or unsigned files", s.from_files),
        ("From the store", s.from_store),
        ("Verified (chain OK, trusted signature)", s.verified),
        ("Unsigned (chain OK, no signature)", s.unsigned),
        ("Failed verification", s.failed),
        ("Not tamper-evident (store)", s.not_tamper_evident),
    ] {
        let _ = writeln!(o, "| {k} | {v} |");
    }
    let _ = writeln!(o, "| Events | {} |", s.events);
    let _ = writeln!(o, "| Findings | {} |\n", s.findings);

    let c = &r.configuration;
    let _ = writeln!(o, "## Configuration\n");
    let _ = writeln!(
        o,
        "- Source: {}",
        c.source
            .as_deref()
            .map_or_else(|| "built-in defaults (no agent-trace.toml)".into(), md)
    );
    let _ = writeln!(
        o,
        "- SHA-256 (canonical form, canary values excluded): `{}`",
        c.sha256
    );
    let _ = writeln!(
        o,
        "- Policy additions: privileged: {}; outbound: {}; allowed destinations: {}",
        md_list(&c.policy.privileged),
        md_list(&c.policy.outbound),
        md_list(&c.policy.allow_destinations)
    );
    let _ = writeln!(
        o,
        "- Redaction additions: pattern labels: {}; field names: {}",
        md_list(&c.redaction.pattern_labels),
        md_list(&c.redaction.keys)
    );
    let _ = writeln!(o, "- Custom rules: {}", md_list(&c.custom_rules));
    let _ = writeln!(o, "- Canaries (names only): {}", md_list(&c.canaries));
    let profiles: Vec<String> = c
        .profiles
        .iter()
        .map(|(name, tools)| format!("{name} ({})", tools.join(", ")))
        .collect();
    let _ = writeln!(o, "- Task profiles: {}", md_list(&profiles));
    let _ = writeln!(
        o,
        "- Proxy mode: {}; hooks mode: {} (on error: {})\n",
        c.proxy_mode, c.hooks_mode, c.hooks_on_error
    );

    let ret = &r.retention;
    let _ = writeln!(o, "## Retention\n");
    let _ = writeln!(o, "- max_age_days: {}", opt(ret.max_age_days));
    let _ = writeln!(o, "- max_traces: {}", opt(ret.max_traces));
    let _ = writeln!(
        o,
        "- Applied by: `{}` (not automatic; run it on a schedule)",
        ret.applied_by
    );
    let _ = writeln!(
        o,
        "- Store: {} ({} trace(s))",
        md(&ret.store.location),
        ret.store.traces
    );
    let tref = |t: &Option<TraceRef>| {
        t.as_ref().map_or_else(
            || "none".into(),
            |t| format!("{} (`{}`)", md(&t.created_at), t.trace_id),
        )
    };
    let _ = writeln!(
        o,
        "- Oldest trace in the store: {}",
        tref(&ret.store.oldest)
    );
    let _ = writeln!(
        o,
        "- Newest trace in the store: {}",
        tref(&ret.store.newest)
    );
    if !ret.warnings.is_empty() {
        let _ = writeln!(o, "\nNotes:\n");
        for w in &ret.warnings {
            // Built from numbers only; the text is ours.
            let _ = writeln!(o, "- **Note:** {w}");
        }
    }
    let _ = writeln!(o);

    let _ = writeln!(o, "## Traces\n");
    if r.traces.is_empty() {
        let _ = writeln!(o, "No traces selected.\n");
    }
    for (i, t) in r.traces.iter().enumerate() {
        match &t.trace {
            Some(f) => {
                let _ = writeln!(o, "### {}. {} (`{}`)\n", i + 1, md(&f.name), f.trace_id);
            }
            None => {
                let _ = writeln!(o, "### {}. FAILED input\n", i + 1);
            }
        }
        let _ = writeln!(o, "| Field | Value |\n| --- | --- |");
        let source = match &t.file {
            Some(file) => format!("file {}", md(file)),
            None => "store".into(),
        };
        let _ = writeln!(o, "| Source | {source} |");
        let _ = writeln!(o, "| Integrity | {} |", integrity_line(&t.integrity));
        if let Some(f) = &t.trace {
            let sev: Vec<String> = f
                .findings
                .by_severity
                .iter()
                .filter(|(_, n)| **n > 0)
                .map(|(k, n)| format!("{k} {n}"))
                .collect();
            let rules: Vec<String> = f
                .findings
                .by_rule
                .iter()
                .map(|(k, n)| format!("{} ×{n}", md(k)))
                .collect();
            for (k, v) in [
                ("Mode", f.execution_mode.to_string()),
                ("Status", f.status.to_string()),
                (
                    "Time span",
                    format!("{} to {}", md(&f.started_at), md(&f.ended_at)),
                ),
                ("Events", f.event_count.to_string()),
                ("Agents", md_list(&f.agents)),
                ("MCP servers", md_list(&f.mcp_servers)),
                ("Tools requested", md_list(&f.tools)),
                (
                    "Findings",
                    if sev.is_empty() {
                        "0".into()
                    } else {
                        format!("{} ({})", f.findings.total, sev.join(", "))
                    },
                ),
                (
                    "Findings by rule",
                    if rules.is_empty() {
                        "none".into()
                    } else {
                        rules.join(", ")
                    },
                ),
                (
                    "Redaction",
                    format!(
                        "{} value(s) redacted in {} event(s); {} event(s) truncated",
                        f.redaction.redacted_values,
                        f.redaction.events_with_redactions,
                        f.redaction.truncated_events
                    ),
                ),
            ] {
                let _ = writeln!(o, "| {k} | {v} |");
            }
        }
        let _ = writeln!(o);
    }

    let _ = writeln!(o, "## What this report does not prove\n");
    for n in &r.not_proven {
        let _ = writeln!(o, "- {n}");
    }
    let _ = writeln!(o, "\n## Legal context\n");
    let _ = writeln!(
        o,
        "Article 12 of the EU AI Act requires that high-risk AI systems technically allow for \
         the automatic recording of events (logs) over the lifetime of the system. \
         Article 26(6) requires deployers of high-risk AI systems to keep the logs \
         automatically generated by the system, to the extent they are under their control, \
         for a period appropriate to the intended purpose, of at least six months, unless \
         Union or national law provides otherwise. Both apply only to high-risk AI systems, \
         and their application dates have changed before and may change again: check the \
         current text.\n"
    );
    for refr in &r.references {
        let _ = writeln!(o, "- [{}]({})", refr.title, refr.url);
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_accepts_dates_and_timestamps() {
        assert_eq!(
            rfc3339(parse_since("2026-05-01").unwrap()),
            "2026-05-01T00:00:00Z"
        );
        assert_eq!(
            rfc3339(parse_since("2026-05-01T12:30:00+02:00").unwrap()),
            "2026-05-01T12:30:00+02:00"
        );
        for bad in ["", "yesterday", "2026-13-01", "2026/05/01"] {
            assert!(parse_since(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn retention_notes() {
        assert_eq!(retention_warnings(None, None).len(), 1);
        assert!(retention_warnings(Some(30), None)[0].contains("shorter than six months"));
        assert!(retention_warnings(Some(183), None).is_empty());
        assert!(retention_warnings(Some(365), Some(10))[0].contains("by count"));
    }

    #[test]
    fn markdown_escapes_untrusted_text() {
        assert_eq!(md("a|b"), "a\\|b");
        assert_eq!(md("<script>"), "\\<script\\>");
        assert!(!md("x\ny").contains('\n'));
    }
}
