//! Minimal SQL backend abstraction. The store logic is written once against this
//! trait; each database only supplies its driver glue and dialect differences.
//!
//! SQL passed to a backend always uses `?` placeholders; backends translate them
//! if their driver needs another syntax (PostgreSQL: `$1`, `$2`, …).

use crate::StorageError;

/// A SQL parameter or result value. The schema only uses integers and text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqlValue {
    Null,
    Int(i64),
    Text(String),
}

impl SqlValue {
    pub fn as_i64(&self) -> Result<i64, StorageError> {
        match self {
            Self::Int(i) => Ok(*i),
            Self::Text(s) => s
                .parse()
                .map_err(|_| StorageError::Corrupt(format!("expected integer, got {s:?}"))),
            Self::Null => Err(StorageError::Corrupt("unexpected NULL integer".into())),
        }
    }

    pub fn as_opt_i64(&self) -> Result<Option<i64>, StorageError> {
        match self {
            Self::Null => Ok(None),
            other => other.as_i64().map(Some),
        }
    }

    pub fn into_string(self) -> Result<String, StorageError> {
        match self {
            Self::Text(s) => Ok(s),
            Self::Int(i) => Ok(i.to_string()),
            Self::Null => Err(StorageError::Corrupt("unexpected NULL text".into())),
        }
    }
}

impl From<i64> for SqlValue {
    fn from(v: i64) -> Self {
        Self::Int(v)
    }
}

impl From<u32> for SqlValue {
    fn from(v: u32) -> Self {
        Self::Int(i64::from(v))
    }
}

impl From<&str> for SqlValue {
    fn from(v: &str) -> Self {
        Self::Text(v.to_owned())
    }
}

impl From<String> for SqlValue {
    fn from(v: String) -> Self {
        Self::Text(v)
    }
}

impl<T: Into<SqlValue>> From<Option<T>> for SqlValue {
    fn from(v: Option<T>) -> Self {
        v.map(Into::into).unwrap_or(Self::Null)
    }
}

/// SQL dialect of a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Sqlite,
    Postgres,
    MySql,
}

impl Dialect {
    pub fn name(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgresql",
            Self::MySql => "mysql/mariadb",
        }
    }

    /// Start a write transaction. On SQLite the write lock is taken up front (IMMEDIATE),
    /// so concurrent writers wait on the busy timeout instead of failing on a lock upgrade.
    pub(crate) fn begin(self) -> &'static str {
        match self {
            Self::MySql => "START TRANSACTION",
            Self::Sqlite => "BEGIN IMMEDIATE",
            Self::Postgres => "BEGIN",
        }
    }

    /// Statement that serializes concurrent schema migrations inside a transaction, where
    /// the backend needs one (SQLite: BEGIN IMMEDIATE already does; MySQL: see `migrate`).
    pub(crate) fn migration_xact_lock(self) -> Option<&'static str> {
        match self {
            Self::Postgres => Some("SELECT pg_advisory_xact_lock(4206921001)"),
            _ => None,
        }
    }

    /// Row lock on a trace inside a transaction, so concurrent writers of the same trace's
    /// findings run one after the other (SQLite: BEGIN IMMEDIATE already serializes).
    pub(crate) fn lock_trace_row(self) -> Option<&'static str> {
        match self {
            Self::Sqlite => None,
            _ => Some("SELECT trace_id FROM traces WHERE trace_id = ? FOR UPDATE"),
        }
    }

    /// Auto-incrementing 64-bit primary key column definition.
    pub(crate) fn autoincrement_pk(self) -> &'static str {
        match self {
            Self::Sqlite => "INTEGER PRIMARY KEY AUTOINCREMENT",
            Self::Postgres => "BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY",
            Self::MySql => "BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
        }
    }

    /// Unbounded text (event / finding JSON bodies, up to a few MiB).
    pub(crate) fn big_text(self) -> &'static str {
        match self {
            Self::MySql => "LONGTEXT",
            _ => "TEXT",
        }
    }

    pub(crate) fn table_suffix(self) -> &'static str {
        match self {
            Self::MySql => " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin",
            _ => "",
        }
    }
}

/// Driver glue for one database connection.
pub trait Backend: Send {
    fn dialect(&self) -> Dialect;
    /// Execute a statement, returning the number of affected rows.
    fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<u64, StorageError>;
    /// Run a query and return all rows as positional values.
    fn query(&mut self, sql: &str, params: &[SqlValue])
    -> Result<Vec<Vec<SqlValue>>, StorageError>;
}

/// Rewrite `?` placeholders to `$1`, `$2`, … (outside of string literals).
pub fn numbered_placeholders(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len() + 8);
    let mut n = 0;
    let mut in_string = false;
    for c in sql.chars() {
        match c {
            '\'' => {
                in_string = !in_string;
                out.push(c);
            }
            '?' if !in_string => {
                n += 1;
                out.push('$');
                out.push_str(&n.to_string());
            }
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders() {
        assert_eq!(
            numbered_placeholders("SELECT a FROM t WHERE x = ? AND y = '?' AND z = ?"),
            "SELECT a FROM t WHERE x = $1 AND y = '?' AND z = $2"
        );
    }
}
