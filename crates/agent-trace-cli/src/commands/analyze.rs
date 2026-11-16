use agent_trace_core::Severity;

use super::{Context, analyze_and_store, resolve_target};
use crate::output::{finding_line, max_severity};
use crate::{EXIT_FINDINGS, EXIT_OK, Threshold, TraceTarget};

pub fn run(ctx: &Context, target: &TraceTarget, fail_on: Option<Threshold>) -> anyhow::Result<u8> {
    let s = &ctx.style;
    let mut store = ctx.open_store()?;
    let id = resolve_target(&mut store, target)?;
    let record = store.load_trace(id)?;
    let findings = analyze_and_store(&mut store, &record)?;
    println!(
        "analyzed trace {} ({})  [{}]  {} finding(s)",
        record.trace.trace_id,
        record.trace.name,
        s.mode(record.trace.execution_mode),
        findings.len()
    );
    for f in &findings {
        println!("  {}", finding_line(s, &record, f));
        println!("      {}", s.dim(&f.description));
    }
    let threshold = fail_on.map(|t| match t {
        Threshold::Low => Severity::Low,
        Threshold::Medium => Severity::Medium,
        Threshold::High => Severity::High,
        Threshold::Critical => Severity::Critical,
    });
    match (threshold, max_severity(&findings)) {
        (Some(t), Some(max)) if max >= t => {
            eprintln!("findings at or above {t} — exit code {EXIT_FINDINGS}");
            Ok(EXIT_FINDINGS)
        }
        _ => Ok(EXIT_OK),
    }
}
