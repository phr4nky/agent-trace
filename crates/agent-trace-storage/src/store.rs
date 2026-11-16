//! Trace store on top of any [`Backend`]. Events are stored immutably as redacted JSON
//! plus indexed columns. The same logic runs on SQLite, PostgreSQL and MySQL/MariaDB.

use std::collections::HashMap;
use std::path::Path;

use agent_trace_core::{Event, Finding, Severity, Trace, TraceRecord};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::StorageError;
use crate::backend::{Backend, Dialect, SqlValue};
use crate::config::DatabaseConfig;

/// Where a trace came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceSource {
    Recorded,
    Imported,
}

impl TraceSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Imported => "imported",
        }
    }
}

/// One row of `trace list`.
#[derive(Debug, Clone)]
pub struct TraceSummary {
    pub created_order: i64,
    pub trace: Trace,
    pub source: String,
    pub event_count: u64,
    pub finding_count: u64,
    pub max_severity: Option<Severity>,
}

/// Width of indexed name columns; the full value is always kept in the JSON body.
const NAME_COLUMN_CHARS: usize = 255;

fn migrations(d: Dialect) -> Vec<(i64, Vec<String>)> {
    let big = d.big_text();
    let sfx = d.table_suffix();
    let v1 = vec![
        format!(
            "CREATE TABLE traces (
                created_order   {pk},
                trace_id        VARCHAR(36) NOT NULL UNIQUE,
                name            VARCHAR(255) NOT NULL,
                schema_version  VARCHAR(16) NOT NULL,
                created_at      VARCHAR(40) NOT NULL,
                execution_mode  VARCHAR(16) NOT NULL,
                source          VARCHAR(16) NOT NULL,
                metadata        {big} NOT NULL,
                body            {big} NOT NULL
            ){sfx}",
            pk = d.autoincrement_pk()
        ),
        format!(
            "CREATE TABLE events (
                trace_id            VARCHAR(36) NOT NULL,
                event_id            VARCHAR(36) NOT NULL,
                seq                 BIGINT NOT NULL,
                ts                  VARCHAR(40) NOT NULL,
                kind                VARCHAR(64) NOT NULL,
                origin              VARCHAR(32) NOT NULL,
                trust_level         VARCHAR(32) NOT NULL,
                name                VARCHAR(255) NOT NULL,
                tool_state          VARCHAR(32),
                parent_event_id     VARCHAR(36),
                caused_by_event_id  VARCHAR(36),
                execution_mode      VARCHAR(16) NOT NULL,
                body                {big} NOT NULL,
                PRIMARY KEY (trace_id, event_id),
                UNIQUE (trace_id, seq),
                FOREIGN KEY (trace_id) REFERENCES traces(trace_id) ON DELETE CASCADE
            ){sfx}"
        ),
        "CREATE INDEX idx_events_trace_id ON events(trace_id)".into(),
        "CREATE INDEX idx_events_ts ON events(ts)".into(),
        format!(
            "CREATE TABLE findings (
                finding_id      VARCHAR(36) NOT NULL PRIMARY KEY,
                trace_id        VARCHAR(36) NOT NULL,
                rule_id         VARCHAR(32) NOT NULL,
                rule_version    BIGINT NOT NULL,
                severity        VARCHAR(16) NOT NULL,
                severity_rank   BIGINT NOT NULL,
                confidence      VARCHAR(16) NOT NULL,
                attempt_status  VARCHAR(16) NOT NULL,
                created_at      VARCHAR(40) NOT NULL,
                body            {big} NOT NULL,
                FOREIGN KEY (trace_id) REFERENCES traces(trace_id) ON DELETE CASCADE
            ){sfx}"
        ),
        "CREATE INDEX idx_findings_trace_id ON findings(trace_id)".into(),
        "CREATE INDEX idx_findings_rule_id ON findings(rule_id)".into(),
        format!(
            "CREATE TABLE evidence_links (
                finding_id  VARCHAR(36) NOT NULL,
                pos         BIGINT NOT NULL,
                event_id    VARCHAR(36) NOT NULL,
                PRIMARY KEY (finding_id, pos),
                FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
            ){sfx}"
        ),
        "CREATE INDEX idx_evidence_event ON evidence_links(event_id)".into(),
    ];
    let v2 = vec![
        "ALTER TABLE traces ADD COLUMN status VARCHAR(16) NOT NULL DEFAULT 'completed'".to_owned(),
        "ALTER TABLE events ADD COLUMN agent_id VARCHAR(64)".to_owned(),
        "CREATE INDEX idx_events_agent ON events(trace_id, agent_id)".to_owned(),
    ];
    vec![(1, v1), (2, v2)]
}

pub struct Store {
    backend: Box<dyn Backend>,
    location: String,
}

impl Store {
    /// Open (and migrate) a SQLite database file, creating private parent directories.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        Self::connect(&DatabaseConfig::Sqlite(path.as_ref().to_path_buf()))
    }

    /// In-memory SQLite store for tests.
    pub fn open_in_memory() -> Result<Self, StorageError> {
        Self::with_backend(
            Box::new(crate::sqlite::SqliteBackend::in_memory()?),
            ":memory:".into(),
        )
    }

    /// Connect to the configured database and apply pending migrations.
    pub fn connect(config: &DatabaseConfig) -> Result<Self, StorageError> {
        let backend: Box<dyn Backend> = match config {
            DatabaseConfig::Sqlite(path) => Box::new(crate::sqlite::SqliteBackend::open(path)?),
            #[cfg(feature = "postgres")]
            DatabaseConfig::Postgres(url) => {
                Box::new(crate::postgres::PostgresBackend::connect(url)?)
            }
            #[cfg(not(feature = "postgres"))]
            DatabaseConfig::Postgres(_) => {
                return Err(StorageError::Config(
                    "this build has no PostgreSQL support (enable feature `postgres`)".into(),
                ));
            }
            #[cfg(feature = "mysql")]
            DatabaseConfig::MySql(url) => Box::new(crate::mysql::MySqlBackend::connect(url)?),
            #[cfg(not(feature = "mysql"))]
            DatabaseConfig::MySql(_) => {
                return Err(StorageError::Config(
                    "this build has no MySQL/MariaDB support (enable feature `mysql`)".into(),
                ));
            }
        };
        Self::with_backend(backend, config.display_redacted())
    }

    /// Wrap a custom backend (used by tests and alternative drivers).
    pub fn with_backend(backend: Box<dyn Backend>, location: String) -> Result<Self, StorageError> {
        let mut store = Self { backend, location };
        store.migrate()?;
        store.verify_schema()?;
        Ok(store)
    }

    /// Database location for display; never contains credentials.
    pub fn location(&self) -> &str {
        &self.location
    }

    pub fn dialect(&self) -> Dialect {
        self.backend.dialect()
    }

    fn exec(&mut self, sql: &str, params: &[SqlValue]) -> Result<u64, StorageError> {
        self.backend.execute(sql, params)
    }

    fn rows(&mut self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, StorageError> {
        self.backend.query(sql, params)
    }

    /// Run `f` inside a transaction; rolls back on error.
    fn transaction<T>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        let begin = self.dialect().begin();
        self.exec(begin, &[])?;
        match f(self) {
            Ok(v) => {
                self.exec("COMMIT", &[])?;
                Ok(v)
            }
            Err(e) => {
                let _ = self.exec("ROLLBACK", &[]);
                Err(e)
            }
        }
    }

    fn migrate(&mut self) -> Result<(), StorageError> {
        self.exec(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version BIGINT NOT NULL PRIMARY KEY,
                applied_at VARCHAR(40) NOT NULL
            )",
            &[],
        )?;
        let current = self.rows(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            &[],
        )?;
        let current = current
            .first()
            .and_then(|r| r.first())
            .map(SqlValue::as_i64)
            .transpose()?
            .unwrap_or(0);
        for (version, statements) in migrations(self.dialect()) {
            if version <= current {
                continue;
            }
            // Note: MySQL/MariaDB commit DDL implicitly; there a failed migration may be partial.
            self.transaction(|s| {
                for stmt in &statements {
                    s.exec(stmt, &[])?;
                }
                s.exec(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    &[version.into(), now().into()],
                )?;
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Check that all columns this build needs exist. Catches databases created by
    /// incompatible (e.g. pre-release) builds with a clear message instead of SQL errors.
    fn verify_schema(&mut self) -> Result<(), StorageError> {
        const CHECKS: &[&str] = &[
            "SELECT created_order, trace_id, name, schema_version, created_at, execution_mode, source, metadata, body, status FROM traces LIMIT 0",
            "SELECT trace_id, event_id, seq, ts, kind, origin, trust_level, name, tool_state, parent_event_id, caused_by_event_id, execution_mode, body, agent_id FROM events LIMIT 0",
            "SELECT finding_id, trace_id, rule_id, rule_version, severity, severity_rank, confidence, attempt_status, created_at, body FROM findings LIMIT 0",
            "SELECT finding_id, pos, event_id FROM evidence_links LIMIT 0",
        ];
        for sql in CHECKS {
            if let Err(e) = self.rows(sql, &[]) {
                return Err(StorageError::Config(format!(
                    "database {} has an incompatible schema (created by a different agent-trace build?). \
                     Use a new database or --data-dir. Details: {e}",
                    self.location
                )));
            }
        }
        Ok(())
    }

    /// Insert a complete trace. Fails if the trace id already exists (traces are immutable).
    pub fn insert_trace(
        &mut self,
        record: &TraceRecord,
        source: TraceSource,
    ) -> Result<(), StorageError> {
        let trace = &record.trace;
        self.ensure_new(trace.trace_id)?;
        self.transaction(|s| {
            s.insert_trace_row(trace, source)?;
            for e in &record.events {
                s.insert_event_row(e)?;
            }
            Ok(())
        })
        .map_err(|e| duplicate_or(e, trace.trace_id))
    }

    /// Live recording: create the trace header (usually with status `running`).
    pub fn begin_trace(&mut self, trace: &Trace, source: TraceSource) -> Result<(), StorageError> {
        self.ensure_new(trace.trace_id)?;
        self.insert_trace_row(trace, source)
            .map_err(|e| duplicate_or(e, trace.trace_id))
    }

    /// Live recording: append one event to an existing trace.
    pub fn append_event(&mut self, event: &Event) -> Result<(), StorageError> {
        self.insert_event_row(event)
    }

    /// Live recording: update the trace header (status, metadata) after the run.
    pub fn update_trace(&mut self, trace: &Trace) -> Result<(), StorageError> {
        let n = self.exec(
            "UPDATE traces SET name = ?, status = ?, metadata = ?, body = ? WHERE trace_id = ?",
            &[
                column_text(&trace.name).into(),
                trace.status.as_str().into(),
                serde_json::to_string(&trace.metadata)?.into(),
                serde_json::to_string(trace)?.into(),
                trace.trace_id.to_string().into(),
            ],
        )?;
        // MySQL reports 0 affected rows when nothing changed, so only check existence then.
        if n == 0 && !self.trace_exists(trace.trace_id)? {
            return Err(StorageError::TraceNotFound(trace.trace_id.to_string()));
        }
        Ok(())
    }

    /// Number of stored events of a trace (cheap check for live viewers).
    pub fn event_count(&mut self, trace_id: Uuid) -> Result<u64, StorageError> {
        let rows = self.rows(
            "SELECT COUNT(*) FROM events WHERE trace_id = ?",
            &[trace_id.to_string().into()],
        )?;
        Ok(rows
            .first()
            .and_then(|r| r.first())
            .map(SqlValue::as_i64)
            .transpose()?
            .unwrap_or(0) as u64)
    }

    fn trace_exists(&mut self, trace_id: Uuid) -> Result<bool, StorageError> {
        Ok(!self
            .rows(
                "SELECT created_order FROM traces WHERE trace_id = ?",
                &[trace_id.to_string().into()],
            )?
            .is_empty())
    }

    fn ensure_new(&mut self, trace_id: Uuid) -> Result<(), StorageError> {
        if self.trace_exists(trace_id)? {
            return Err(StorageError::DuplicateTrace(trace_id));
        }
        Ok(())
    }

    fn insert_trace_row(&mut self, trace: &Trace, source: TraceSource) -> Result<(), StorageError> {
        self.exec(
            "INSERT INTO traces (trace_id, name, schema_version, created_at, execution_mode, source,
                metadata, body, status)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            &[
                trace.trace_id.to_string().into(),
                column_text(&trace.name).into(),
                trace.schema_version.as_str().into(),
                fmt_time(trace.created_at)?.into(),
                trace.execution_mode.as_str().into(),
                source.as_str().into(),
                serde_json::to_string(&trace.metadata)?.into(),
                serde_json::to_string(trace)?.into(),
                trace.status.as_str().into(),
            ],
        )?;
        Ok(())
    }

    fn insert_event_row(&mut self, e: &Event) -> Result<(), StorageError> {
        self.exec(
            "INSERT INTO events (trace_id, event_id, seq, ts, kind, origin, trust_level,
                name, tool_state, parent_event_id, caused_by_event_id, execution_mode, body, agent_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            &[
                e.trace_id.to_string().into(),
                e.event_id.to_string().into(),
                (e.sequence as i64).into(),
                fmt_time(e.timestamp)?.into(),
                e.kind.as_str().into(),
                e.origin.as_str().into(),
                e.trust_level.as_str().into(),
                column_text(&e.name).into(),
                e.tool_state.map(|t| t.as_str()).into(),
                e.parent_event_id.map(|u| u.to_string()).into(),
                e.caused_by_event_id.map(|u| u.to_string()).into(),
                e.execution_mode.as_str().into(),
                serde_json::to_string(e)?.into(),
                column_text(e.agent()).chars().take(64).collect::<String>().into(),
            ],
        )?;
        Ok(())
    }

    /// All traces in persisted creation order (oldest first).
    pub fn list_traces(&mut self) -> Result<Vec<TraceSummary>, StorageError> {
        let rows = self.rows(
            "SELECT t.created_order, t.body, t.source,
                    (SELECT COUNT(*) FROM events e WHERE e.trace_id = t.trace_id),
                    (SELECT COUNT(*) FROM findings f WHERE f.trace_id = t.trace_id),
                    (SELECT MAX(f.severity_rank) FROM findings f WHERE f.trace_id = t.trace_id)
             FROM traces t ORDER BY t.created_order ASC",
            &[],
        )?;
        rows.into_iter().map(summary_from_row).collect()
    }

    /// Most recently stored trace, by explicit creation order.
    pub fn latest_trace_id(&mut self) -> Result<Option<Uuid>, StorageError> {
        let rows = self.rows(
            "SELECT trace_id FROM traces ORDER BY created_order DESC LIMIT 1",
            &[],
        )?;
        rows.into_iter()
            .next()
            .and_then(|r| r.into_iter().next())
            .map(|v| parse_uuid(&v.into_string()?))
            .transpose()
    }

    /// Resolve a full trace id or a unique prefix of one.
    pub fn resolve_trace_id(&mut self, input: &str) -> Result<Uuid, StorageError> {
        let needle = input.trim().to_ascii_lowercase();
        if needle.is_empty() || !needle.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
            return Err(StorageError::TraceNotFound(input.to_owned()));
        }
        let rows = self.rows(
            "SELECT trace_id FROM traces WHERE trace_id LIKE ? ORDER BY created_order LIMIT 2",
            &[format!("{needle}%").into()],
        )?;
        let ids: Vec<String> = rows
            .into_iter()
            .filter_map(|r| r.into_iter().next())
            .map(SqlValue::into_string)
            .collect::<Result<_, _>>()?;
        match ids.as_slice() {
            [one] => parse_uuid(one),
            [] => Err(StorageError::TraceNotFound(input.to_owned())),
            _ => Err(StorageError::AmbiguousTraceId(input.to_owned())),
        }
    }

    pub fn load_trace(&mut self, trace_id: Uuid) -> Result<TraceRecord, StorageError> {
        let id = trace_id.to_string();
        let rows = self.rows(
            "SELECT t.created_order, t.body, t.source, 0, 0, NULL
             FROM traces t WHERE t.trace_id = ?",
            &[id.clone().into()],
        )?;
        let summary = rows
            .into_iter()
            .next()
            .map(summary_from_row)
            .transpose()?
            .ok_or_else(|| StorageError::TraceNotFound(id.clone()))?;
        let events = self
            .rows(
                "SELECT body FROM events WHERE trace_id = ? ORDER BY seq ASC",
                &[id.into()],
            )?
            .into_iter()
            .map(|r| {
                let body = r
                    .into_iter()
                    .next()
                    .ok_or_else(|| StorageError::Corrupt("missing event body".into()))?
                    .into_string()?;
                Ok(serde_json::from_str(&body)?)
            })
            .collect::<Result<Vec<_>, StorageError>>()?;
        Ok(TraceRecord {
            trace: summary.trace,
            events,
        })
    }

    /// Store analysis results. Findings of the given rule versions are replaced; the original
    /// `created_at` of a finding that already existed is preserved, so re-analysis is idempotent.
    /// Findings produced by other rule versions are kept untouched.
    pub fn save_findings(
        &mut self,
        trace_id: Uuid,
        rule_versions: &[(&str, u32)],
        findings: &[Finding],
    ) -> Result<Vec<Finding>, StorageError> {
        let existing: HashMap<Uuid, OffsetDateTime> = self
            .load_findings(trace_id)?
            .into_iter()
            .map(|f| (f.finding_id, f.created_at))
            .collect();
        self.transaction(|s| {
            for (rule, version) in rule_versions {
                // evidence_links rows go with their finding (ON DELETE CASCADE).
                s.exec(
                    "DELETE FROM findings WHERE trace_id = ? AND rule_id = ? AND rule_version = ?",
                    &[
                        trace_id.to_string().into(),
                        (*rule).into(),
                        (*version).into(),
                    ],
                )?;
            }
            let mut stored = Vec::new();
            for f in findings {
                let mut f = f.clone();
                if let Some(created) = existing.get(&f.finding_id) {
                    f.created_at = *created;
                }
                s.exec(
                    "INSERT INTO findings (finding_id, trace_id, rule_id, rule_version, severity,
                        severity_rank, confidence, attempt_status, created_at, body)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    &[
                        f.finding_id.to_string().into(),
                        f.trace_id.to_string().into(),
                        f.rule_id.as_str().into(),
                        f.rule_version.into(),
                        f.severity.as_str().into(),
                        (f.severity as i64).into(),
                        f.confidence.as_str().into(),
                        f.attempt_status.as_str().into(),
                        fmt_time(f.created_at)?.into(),
                        serde_json::to_string(&f)?.into(),
                    ],
                )?;
                for (pos, event_id) in f.evidence_event_ids.iter().enumerate() {
                    s.exec(
                        "INSERT INTO evidence_links (finding_id, pos, event_id) VALUES (?, ?, ?)",
                        &[
                            f.finding_id.to_string().into(),
                            (pos as i64).into(),
                            event_id.to_string().into(),
                        ],
                    )?;
                }
                stored.push(f);
            }
            Ok(stored)
        })
    }

    pub fn load_findings(&mut self, trace_id: Uuid) -> Result<Vec<Finding>, StorageError> {
        let rows = self.rows(
            "SELECT f.body FROM findings f
             WHERE f.trace_id = ?
             ORDER BY (SELECT MAX(e.seq) FROM evidence_links l
                       JOIN events e ON e.event_id = l.event_id AND e.trace_id = f.trace_id
                       WHERE l.finding_id = f.finding_id), f.rule_id",
            &[trace_id.to_string().into()],
        )?;
        rows.into_iter()
            .map(|r| {
                let body = r
                    .into_iter()
                    .next()
                    .ok_or_else(|| StorageError::Corrupt("missing finding body".into()))?
                    .into_string()?;
                Ok(serde_json::from_str(&body)?)
            })
            .collect()
    }
}

fn summary_from_row(row: Vec<SqlValue>) -> Result<TraceSummary, StorageError> {
    let mut it = row.into_iter();
    let mut next = || {
        it.next()
            .ok_or_else(|| StorageError::Corrupt("short trace row".into()))
    };
    let created_order = next()?.as_i64()?;
    let trace: Trace = serde_json::from_str(&next()?.into_string()?)?;
    let source = next()?.into_string()?;
    let event_count = next()?.as_i64()? as u64;
    let finding_count = next()?.as_i64()? as u64;
    let max_severity = next()?.as_opt_i64()?.and_then(severity_from_rank);
    Ok(TraceSummary {
        created_order,
        trace,
        source,
        event_count,
        finding_count,
        max_severity,
    })
}

/// Map a unique-constraint violation from a concurrent writer to `DuplicateTrace`.
fn duplicate_or(e: StorageError, trace_id: Uuid) -> StorageError {
    match e {
        StorageError::Backend(msg)
            if msg.to_lowercase().contains("duplicate")
                || msg.to_lowercase().contains("unique") =>
        {
            StorageError::DuplicateTrace(trace_id)
        }
        StorageError::Sqlite(err) if err.to_string().to_lowercase().contains("unique") => {
            StorageError::DuplicateTrace(trace_id)
        }
        other => other,
    }
}

fn column_text(s: &str) -> String {
    s.chars().take(NAME_COLUMN_CHARS).collect()
}

fn severity_from_rank(rank: i64) -> Option<Severity> {
    [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ]
    .into_iter()
    .find(|s| *s as i64 == rank)
}

fn parse_uuid(s: &str) -> Result<Uuid, StorageError> {
    Uuid::parse_str(s).map_err(|_| StorageError::Corrupt(format!("invalid uuid {s:?} in database")))
}

fn fmt_time(t: OffsetDateTime) -> Result<String, StorageError> {
    Ok(t.format(&Rfc3339)?)
}

fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Backend;
    use crate::sqlite::SqliteBackend;

    /// A database created by v1 (migration 1 only) is upgraded in place.
    #[test]
    fn upgrades_schema_v1_to_current() {
        let mut backend = SqliteBackend::in_memory().unwrap();
        backend
            .execute(
                "CREATE TABLE schema_migrations (version BIGINT NOT NULL PRIMARY KEY, applied_at VARCHAR(40) NOT NULL)",
                &[],
            )
            .unwrap();
        for stmt in &migrations(Dialect::Sqlite)[0].1 {
            backend.execute(stmt, &[]).unwrap();
        }
        backend
            .execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (1, 'x')",
                &[],
            )
            .unwrap();
        // A v1 row without status / agent_id columns.
        backend
            .execute(
                "INSERT INTO traces (trace_id, name, schema_version, created_at, execution_mode, source, metadata, body)
                 VALUES ('00000000-0000-4000-8000-000000000001', 'old', '1.0', '2026-01-01T00:00:00Z', 'simulated', 'recorded', '{}',
                 '{\"schema_version\":\"1.0\",\"trace_id\":\"00000000-0000-4000-8000-000000000001\",\"name\":\"old\",\"created_at\":\"2026-01-01T00:00:00Z\",\"execution_mode\":\"simulated\",\"metadata\":{}}')",
                &[],
            )
            .unwrap();
        let mut store = Store::with_backend(Box::new(backend), "mem".into()).unwrap();
        let list = store.list_traces().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(
            list[0].trace.status,
            agent_trace_core::TraceStatus::Completed
        );
        let versions = store
            .rows(
                "SELECT version FROM schema_migrations ORDER BY version",
                &[],
            )
            .unwrap();
        assert_eq!(versions.len(), 2);
    }
}
