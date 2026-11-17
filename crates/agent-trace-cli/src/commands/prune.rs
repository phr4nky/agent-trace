//! `agent-trace prune`: delete old traces (retention).
//!
//! Criteria come from `--older-than` / `--keep` or the `[retention]` table. Traces that are
//! still being recorded (`running`) are never deleted. On SQLite, deleted content is
//! overwritten and the write-ahead log is truncated.

use agent_trace_core::TraceStatus;
use anyhow::bail;
use time::{Duration, OffsetDateTime};

use super::Context;
use crate::EXIT_OK;
use crate::output::{short, term_safe};

/// `30d`, `12h`, `90m`, or a plain number of days.
pub fn parse_age(text: &str) -> anyhow::Result<Duration> {
    let t = text.trim();
    let (number, unit) = match t.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => (&t[..i], c.to_ascii_lowercase()),
        _ => (t, 'd'),
    };
    let n: i64 = number
        .parse()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| anyhow::anyhow!("invalid age {text:?}: use e.g. 30d, 12h or 90m"))?;
    Ok(match unit {
        'd' => Duration::days(n),
        'h' => Duration::hours(n),
        'm' => Duration::minutes(n),
        _ => bail!("invalid age {text:?}: use e.g. 30d, 12h or 90m"),
    })
}

pub fn run(
    ctx: &Context,
    older_than: Option<&str>,
    keep: Option<usize>,
    dry_run: bool,
) -> anyhow::Result<u8> {
    let s = &ctx.style;
    let loaded = ctx.config()?;
    loaded.announce();
    let retention = &loaded.config.retention;
    let max_age = match older_than {
        Some(text) => Some(parse_age(text)?),
        None => retention
            .max_age_days
            .map(|d| Duration::days(d.min(i64::MAX as u64 / 86_400) as i64)),
    };
    let keep = keep.or(retention.max_traces);
    if max_age.is_none() && keep.is_none() {
        bail!(
            "nothing to prune by: pass --older-than or --keep, or set [retention] in agent-trace.toml"
        );
    }
    let mut store = ctx.open_store()?;
    let traces = store.list_traces()?; // oldest first
    let now = OffsetDateTime::now_utc();
    let excess = keep.map_or(0, |k| traces.len().saturating_sub(k));
    let selected: Vec<_> = traces
        .iter()
        .enumerate()
        .filter(|(i, t)| {
            let too_old = max_age.is_some_and(|age| t.trace.created_at < now - age);
            let too_many = *i < excess;
            (too_old || too_many) && t.trace.status != TraceStatus::Running
        })
        .map(|(_, t)| t)
        .collect();
    let events: u64 = selected.iter().map(|t| t.event_count).sum();
    for t in &selected {
        outln!(
            "  {} {}  {}  {} events",
            if dry_run { "would delete" } else { "delete" },
            short(t.trace.trace_id),
            term_safe(&t.trace.name),
            t.event_count
        );
    }
    if dry_run {
        outln!(
            "{} trace(s) with {events} events would be deleted (dry run)",
            selected.len()
        );
        return Ok(EXIT_OK);
    }
    for t in &selected {
        store.delete_trace(t.trace.trace_id)?;
    }
    store.compact()?;
    outln!(
        "{} {} trace(s) with {events} events; {} kept",
        s.bold("deleted"),
        selected.len(),
        traces.len() - selected.len()
    );
    Ok(EXIT_OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ages() {
        assert_eq!(parse_age("30d").unwrap(), Duration::days(30));
        assert_eq!(parse_age("12h").unwrap(), Duration::hours(12));
        assert_eq!(parse_age("90M").unwrap(), Duration::minutes(90));
        assert_eq!(parse_age("7").unwrap(), Duration::days(7));
        for bad in ["", "0d", "-3d", "3w", "d", "1.5d"] {
            assert!(parse_age(bad).is_err(), "{bad}");
        }
    }
}
