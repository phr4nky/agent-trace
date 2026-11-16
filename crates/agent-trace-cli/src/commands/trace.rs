use agent_trace_core::Event;

use super::{Context, resolve_target};
use crate::output::{finding_line, seq_of, term_safe};
use crate::{EXIT_OK, TraceTarget};

pub fn list(ctx: &Context) -> anyhow::Result<u8> {
    let s = &ctx.style;
    let mut store = ctx.open_store()?;
    let traces = store.list_traces()?;
    if traces.is_empty() {
        outln!("no traces stored in {}", store.location());
        outln!("run: agent-trace demo run --scenario all");
        return Ok(EXIT_OK);
    }
    outln!(
        "{}",
        s.bold(&format!(
            "{:>4}  {:<36}  {:<32}  {:<9}  {:<9}  {:>6}  {:>8}  {:<8}  {}",
            "#", "TRACE ID", "NAME", "MODE", "STATUS", "EVENTS", "FINDINGS", "MAX SEV", "CREATED"
        ))
    );
    for t in traces {
        outln!(
            "{:>4}  {:<36}  {:<32}  {:<9}  {:<9}  {:>6}  {:>8}  {:<8}  {}",
            t.created_order,
            t.trace.trace_id,
            truncate(&term_safe(&t.trace.name), 32),
            t.trace.execution_mode.as_str(),
            t.trace.status.as_str(),
            t.event_count,
            t.finding_count,
            t.max_severity.map(|s| s.as_str()).unwrap_or("-"),
            t.trace
                .created_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        );
    }
    Ok(EXIT_OK)
}

pub fn show(ctx: &Context, target: &TraceTarget, payload: bool) -> anyhow::Result<u8> {
    let s = &ctx.style;
    let mut store = ctx.open_store()?;
    let id = resolve_target(&mut store, target)?;
    let record = store.load_trace(id)?;
    let findings = store.load_findings(id)?;
    let t = &record.trace;
    let agents = agent_trace_core::Trace::agents(&record.events);
    let multi = agents.len() > 1;
    outln!(
        "{} {}  [{}]  status: {}  events: {}  agents: {}",
        s.bold("trace"),
        t.trace_id,
        s.mode(t.execution_mode),
        t.status.as_str(),
        record.events.len(),
        term_safe(&agents.join(", "))
    );
    outln!("name: {}   created: {}", term_safe(&t.name), t.created_at);
    if !t.metadata.is_empty() {
        outln!(
            "metadata: {}",
            term_safe(&serde_json::Value::Object(t.metadata.clone()).to_string())
        );
    }
    outln!();
    let agent_col = |name: &str| {
        if multi {
            format!("{:<13} ", truncate(&term_safe(name), 13))
        } else {
            String::new()
        }
    };
    outln!(
        "{}",
        s.bold(&format!(
            "{:>4}  {}{:<26}  {:<10}  {:<11}  {:<22}  {:<15}  {}",
            "SEQ",
            agent_col("AGENT"),
            "KIND",
            "ORIGIN",
            "TRUST",
            "NAME",
            "TOOL STATE",
            "LINKS"
        ))
    );
    for e in &record.events {
        outln!(
            "{:>4}  {}{:<26}  {:<10}  {:<11}  {:<22}  {:<15}  {}  {}",
            e.sequence,
            agent_col(e.agent()),
            e.kind.as_str(),
            e.origin.as_str(),
            e.trust_level.as_str(),
            truncate(&term_safe(&e.name), 22),
            e.tool_state.map(|t| t.as_str()).unwrap_or("-"),
            links(&record, e),
            s.event_marker(e),
        );
        if payload {
            outln!("        {}", s.dim(&term_safe(&e.payload.to_string())));
        }
    }
    outln!();
    if findings.is_empty() {
        outln!(
            "findings: none stored (run `agent-trace analyze {}`)",
            short_id(t)
        );
    } else {
        outln!("{}", s.bold("findings:"));
        for f in &findings {
            outln!("  {}", finding_line(s, &record, f));
        }
    }
    Ok(EXIT_OK)
}

fn short_id(t: &agent_trace_core::Trace) -> String {
    t.trace_id.to_string()[..8].to_owned()
}

fn links(record: &agent_trace_core::TraceRecord, e: &Event) -> String {
    let mut parts = Vec::new();
    if let Some(c) = e.caused_by_event_id {
        parts.push(format!("cause {}", seq_of(record, c)));
    }
    if let Some(p) = e.parent_event_id {
        parts.push(format!("parent {}", seq_of(record, p)));
    }
    if !e.context_event_ids.is_empty() {
        let ctx: Vec<String> = e
            .context_event_ids
            .iter()
            .map(|c| seq_of(record, *c))
            .collect();
        parts.push(format!("context {}", ctx.join(" ")));
    }
    if parts.is_empty() {
        "-".into()
    } else {
        parts.join(", ")
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let mut out: String = s.chars().take(max - 1).collect();
        out.push('…');
        out
    }
}
