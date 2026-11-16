use super::{Context, analyze_and_store, resolve_target, threshold_exit};
use crate::output::{finding_line, term_safe};
use crate::{Threshold, TraceTarget};

pub fn run(ctx: &Context, target: &TraceTarget, fail_on: Option<Threshold>) -> anyhow::Result<u8> {
    let s = &ctx.style;
    let mut store = ctx.open_store()?;
    let id = resolve_target(&mut store, target)?;
    let record = store.load_trace(id)?;
    let findings = analyze_and_store(&mut store, &record)?;
    println!(
        "analyzed trace {} ({})  [{}]  {} finding(s)",
        record.trace.trace_id,
        term_safe(&record.trace.name),
        s.mode(record.trace.execution_mode),
        findings.len()
    );
    for f in &findings {
        println!("  {}", finding_line(s, &record, f));
        println!("      {}", s.dim(&term_safe(&f.description)));
    }
    Ok(threshold_exit(&findings, fail_on))
}
