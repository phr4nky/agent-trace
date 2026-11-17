pub mod analyze;
pub mod demo;
pub mod export;
pub mod graph;
pub mod hook;
pub mod import;
pub mod keys;
pub mod proxy;
pub mod prune;
pub mod replay;
pub mod sarif;
pub mod trace;

use std::path::{Path, PathBuf};

use agent_trace_core::{Analyzer, Finding, TraceRecord};
use agent_trace_storage::{DatabaseConfig, Store};
use anyhow::{Context as _, bail};
use uuid::Uuid;

use crate::output::Style;
use crate::{EXIT_OK, TraceTarget};

pub struct Context {
    pub data_dir: Option<PathBuf>,
    pub database_url: Option<String>,
    /// `--config`; see [`crate::config::load`] for the lookup without it.
    pub config: Option<PathBuf>,
    pub style: Style,
}

impl Context {
    pub fn data_dir(&self) -> anyhow::Result<PathBuf> {
        if let Some(dir) = &self.data_dir {
            return Ok(dir.clone());
        }
        if let Some(dir) = std::env::var_os("AGENT_TRACE_DATA_DIR") {
            return Ok(PathBuf::from(dir));
        }
        dirs::data_local_dir()
            .map(|d| d.join("agent-trace"))
            .context("cannot determine a local data directory; pass --data-dir")
    }

    pub fn exports_dir(&self) -> anyhow::Result<PathBuf> {
        let dir = self.data_dir()?.join("exports");
        agent_trace_storage::create_private_dir(&dir)?;
        Ok(dir)
    }

    /// Database selection: `--database-url`, then `$AGENT_TRACE_DATABASE_URL`,
    /// then a SQLite file in the data directory.
    pub fn database(&self) -> anyhow::Result<DatabaseConfig> {
        let url = self
            .database_url
            .clone()
            .or_else(|| std::env::var("AGENT_TRACE_DATABASE_URL").ok())
            .filter(|u| !u.trim().is_empty());
        Ok(match url {
            Some(url) => DatabaseConfig::parse(&url)?,
            None => DatabaseConfig::Sqlite(self.data_dir()?.join("agent-trace.sqlite3")),
        })
    }

    /// The configuration (`agent-trace.toml`), or the built-in defaults.
    pub fn config(&self) -> anyhow::Result<crate::config::Loaded> {
        let data_dir = self.data_dir().ok();
        crate::config::load(self.config.as_deref(), data_dir.as_deref())
    }

    /// The analyzer with the configured policy; names the config file on stderr.
    pub fn analyzer(&self) -> anyhow::Result<Analyzer> {
        let loaded = self.config()?;
        loaded.announce();
        Ok(loaded.analyzer())
    }

    pub fn open_store(&self) -> anyhow::Result<Store> {
        let config = self.database()?;
        Ok(Store::connect(&config)?)
    }
}

pub fn resolve_target(store: &mut Store, target: &TraceTarget) -> anyhow::Result<Uuid> {
    if target.latest {
        return store
            .latest_trace_id()?
            .context("no traces stored yet; run `agent-trace demo run --scenario all` first");
    }
    match &target.trace_id {
        Some(id) => Ok(store.resolve_trace_id(id)?),
        None => bail!("pass a trace id or --latest"),
    }
}

/// Run all rules and persist the findings (idempotent).
pub fn analyze_and_store(
    analyzer: &Analyzer,
    store: &mut Store,
    record: &TraceRecord,
) -> anyhow::Result<Vec<Finding>> {
    let findings = analyzer.analyze(record, time::OffsetDateTime::now_utc());
    let versions: Vec<(&str, u32)> = analyzer.rules().map(|r| (r.id(), r.version())).collect();
    Ok(store.save_findings(record.trace.trace_id, &versions, &findings)?)
}

pub fn lab_server(documents: &Path) -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(agent_trace_mcp::serve_stdio(documents))
}

pub fn explore(
    ctx: &Context,
    target: &TraceTarget,
    snapshot: Option<(&str, &str)>,
    follow: bool,
) -> anyhow::Result<u8> {
    let mut store = ctx.open_store()?;
    let id = resolve_target(&mut store, target)?;
    let record = store.load_trace(id)?;
    let mut findings = store.load_findings(id)?;
    if findings.is_empty() && record.trace.status != agent_trace_core::TraceStatus::Running {
        findings = analyze_and_store(&ctx.analyzer()?, &mut store, &record)?;
    }
    match snapshot {
        Some((keys, size)) => out!(
            "{}",
            crate::output::term_safe_lines(&crate::tui::snapshot(record, findings, keys, size)?)
        ),
        None => {
            let follow = follow.then_some(crate::tui::Follow {
                store: &mut store,
                latest: target.latest,
            });
            crate::tui::run(record, findings, follow)?
        }
    }
    Ok(EXIT_OK)
}

/// Exit code for `--fail-on`: [`crate::EXIT_FINDINGS`] if any finding reaches the threshold.
pub fn threshold_exit(
    findings: &[agent_trace_core::Finding],
    fail_on: Option<crate::Threshold>,
) -> u8 {
    use agent_trace_core::Severity;
    let threshold = fail_on.map(|t| match t {
        crate::Threshold::Low => Severity::Low,
        crate::Threshold::Medium => Severity::Medium,
        crate::Threshold::High => Severity::High,
        crate::Threshold::Critical => Severity::Critical,
    });
    match (threshold, crate::output::max_severity(findings)) {
        (Some(t), Some(max)) if max >= t => {
            eprintln!(
                "findings at or above {t} — exit code {}",
                crate::EXIT_FINDINGS
            );
            crate::EXIT_FINDINGS
        }
        _ => crate::EXIT_OK,
    }
}
