//! Recorders that send their traces to `agent-trace-server` (sources), and the source of each
//! trace they sent. A source authenticates with a token; only its SHA-256 hash is stored.

use serde::Serialize;
use uuid::Uuid;

use super::{Store, TraceSummary, column_text, now, parse_uuid, summary_from_row};
use crate::StorageError;
use crate::backend::SqlValue;

/// A recorder registered on the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Source {
    pub source_id: Uuid,
    pub name: String,
    pub created_at: String,
    /// When the source last sent a batch.
    pub last_seen_at: Option<String>,
    /// The address the last batch came from, as the server saw it.
    pub last_ip: Option<String>,
}

/// A source and the number of traces it sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceSummary {
    #[serde(flatten)]
    pub source: Source,
    pub traces: u64,
}

fn opt_string(v: SqlValue) -> Result<Option<String>, StorageError> {
    match v {
        SqlValue::Null => Ok(None),
        other => other.into_string().map(Some),
    }
}

fn source_from_row(row: Vec<SqlValue>) -> Result<Source, StorageError> {
    let mut it = row.into_iter();
    let mut next = || {
        it.next()
            .ok_or_else(|| StorageError::Corrupt("short source row".into()))
    };
    Ok(Source {
        source_id: parse_uuid(&next()?.into_string()?)?,
        name: next()?.into_string()?,
        created_at: next()?.into_string()?,
        last_seen_at: opt_string(next()?)?,
        last_ip: opt_string(next()?)?,
    })
}

const SOURCE_COLUMNS: &str = "s.source_id, s.name, s.created_at, s.last_seen_at, s.last_ip";

impl Store {
    /// Register a source. `token_hash` is the hex SHA-256 of its token.
    pub fn add_source(&mut self, name: &str, token_hash: &str) -> Result<Source, StorageError> {
        if self.source_by_name(name)?.is_some() {
            return Err(StorageError::DuplicateSource(name.to_owned()));
        }
        let source = Source {
            source_id: Uuid::new_v4(),
            name: name.to_owned(),
            created_at: now(),
            last_seen_at: None,
            last_ip: None,
        };
        self.exec(
            "INSERT INTO sources (source_id, name, token_hash, created_at) VALUES (?, ?, ?, ?)",
            &[
                source.source_id.to_string().into(),
                source.name.as_str().into(),
                token_hash.into(),
                source.created_at.as_str().into(),
            ],
        )
        .map_err(|e| match e {
            StorageError::Backend(m) if m.to_lowercase().contains("unique") => {
                StorageError::DuplicateSource(name.to_owned())
            }
            StorageError::Sqlite(e) if e.to_string().to_lowercase().contains("unique") => {
                StorageError::DuplicateSource(name.to_owned())
            }
            other => other,
        })?;
        Ok(source)
    }

    /// All sources by name, with their trace counts.
    pub fn sources(&mut self) -> Result<Vec<SourceSummary>, StorageError> {
        let rows = self.rows(
            &format!(
                "SELECT {SOURCE_COLUMNS},
                        (SELECT COUNT(*) FROM traces t WHERE t.source_id = s.source_id)
                 FROM sources s ORDER BY s.name"
            ),
            &[],
        )?;
        rows.into_iter()
            .map(|mut row| {
                let traces = row
                    .pop()
                    .ok_or_else(|| StorageError::Corrupt("short source row".into()))?
                    .as_i64()? as u64;
                Ok(SourceSummary {
                    source: source_from_row(row)?,
                    traces,
                })
            })
            .collect()
    }

    pub fn source_by_name(&mut self, name: &str) -> Result<Option<Source>, StorageError> {
        let rows = self.rows(
            &format!("SELECT {SOURCE_COLUMNS} FROM sources s WHERE s.name = ?"),
            &[name.into()],
        )?;
        rows.into_iter().next().map(source_from_row).transpose()
    }

    /// The source a token belongs to (`token_hash`: hex SHA-256 of the token).
    pub fn source_by_token_hash(
        &mut self,
        token_hash: &str,
    ) -> Result<Option<Source>, StorageError> {
        let rows = self.rows(
            &format!("SELECT {SOURCE_COLUMNS} FROM sources s WHERE s.token_hash = ?"),
            &[token_hash.into()],
        )?;
        rows.into_iter().next().map(source_from_row).transpose()
    }

    /// Remove a source; its token stops working. Its traces stay, without a source.
    pub fn remove_source(&mut self, name: &str) -> Result<bool, StorageError> {
        let Some(source) = self.source_by_name(name)? else {
            return Ok(false);
        };
        let id = source.source_id.to_string();
        self.transaction(|s| {
            s.exec(
                "UPDATE traces SET source_id = NULL WHERE source_id = ?",
                &[id.clone().into()],
            )?;
            s.exec("DELETE FROM sources WHERE source_id = ?", &[id.into()])?;
            Ok(())
        })?;
        Ok(true)
    }

    /// Note that a source just sent a batch, from `ip` if known.
    pub fn touch_source(&mut self, source_id: Uuid, ip: Option<&str>) -> Result<(), StorageError> {
        self.exec(
            "UPDATE sources SET last_seen_at = ?, last_ip = ? WHERE source_id = ?",
            &[
                now().into(),
                ip.map_or(SqlValue::Null, |ip| column_text(ip).into()),
                source_id.to_string().into(),
            ],
        )?;
        Ok(())
    }

    /// The source of a stored trace: `None` if there is no such trace, `Some(None)` for a
    /// trace that no source sent (recorded or imported on the server's database).
    pub fn trace_source(&mut self, trace_id: Uuid) -> Result<Option<Option<Uuid>>, StorageError> {
        let rows = self.rows(
            "SELECT source_id FROM traces WHERE trace_id = ?",
            &[trace_id.to_string().into()],
        )?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        match row.into_iter().next() {
            None | Some(SqlValue::Null) => Ok(Some(None)),
            Some(v) => Ok(Some(Some(parse_uuid(&v.into_string()?)?))),
        }
    }

    pub(crate) fn set_trace_source(
        &mut self,
        trace_id: Uuid,
        source_id: Uuid,
    ) -> Result<(), StorageError> {
        self.exec(
            "UPDATE traces SET source_id = ? WHERE trace_id = ?",
            &[source_id.to_string().into(), trace_id.to_string().into()],
        )?;
        Ok(())
    }

    /// The traces a source sent, newest first.
    pub fn list_traces_of_source(
        &mut self,
        source_id: Uuid,
    ) -> Result<Vec<TraceSummary>, StorageError> {
        let rows = self.rows(
            "SELECT t.created_order, t.body, t.source,
                    (SELECT COUNT(*) FROM events e WHERE e.trace_id = t.trace_id),
                    (SELECT COUNT(*) FROM findings f WHERE f.trace_id = t.trace_id),
                    (SELECT MAX(f.severity_rank) FROM findings f WHERE f.trace_id = t.trace_id)
             FROM traces t WHERE t.source_id = ? ORDER BY t.created_order DESC",
            &[source_id.to_string().into()],
        )?;
        rows.into_iter().map(summary_from_row).collect()
    }
}
