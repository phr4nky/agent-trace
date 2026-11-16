//! SQLite backend (default; bundled SQLite, WAL mode, private file permissions).

use std::path::Path;

use rusqlite::Connection;
use rusqlite::types::{Value, ValueRef};

use crate::StorageError;
use crate::backend::{Backend, Dialect, SqlValue};

pub struct SqliteBackend {
    conn: Connection,
}

impl SqliteBackend {
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        if let Some(parent) = path.parent() {
            crate::create_private_dir(parent)?;
        }
        let conn = Connection::open(path)?;
        crate::restrict_file(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        Self::init(conn)
    }

    pub fn in_memory() -> Result<Self, StorageError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self, StorageError> {
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        Ok(Self { conn })
    }
}

fn to_sqlite(params: &[SqlValue]) -> Vec<Value> {
    params
        .iter()
        .map(|p| match p {
            SqlValue::Null => Value::Null,
            SqlValue::Int(i) => Value::Integer(*i),
            SqlValue::Text(s) => Value::Text(s.clone()),
        })
        .collect()
}

impl Backend for SqliteBackend {
    fn dialect(&self) -> Dialect {
        Dialect::Sqlite
    }

    fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<u64, StorageError> {
        let n = self
            .conn
            .execute(sql, rusqlite::params_from_iter(to_sqlite(params)))?;
        Ok(n as u64)
    }

    fn query(
        &mut self,
        sql: &str,
        params: &[SqlValue],
    ) -> Result<Vec<Vec<SqlValue>>, StorageError> {
        let mut stmt = self.conn.prepare(sql)?;
        let cols = stmt.column_count();
        let mut rows = stmt.query(rusqlite::params_from_iter(to_sqlite(params)))?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let mut values = Vec::with_capacity(cols);
            for i in 0..cols {
                values.push(match row.get_ref(i)? {
                    ValueRef::Null => SqlValue::Null,
                    ValueRef::Integer(v) => SqlValue::Int(v),
                    ValueRef::Real(v) => SqlValue::Text(v.to_string()),
                    ValueRef::Text(t) | ValueRef::Blob(t) => {
                        SqlValue::Text(String::from_utf8_lossy(t).into_owned())
                    }
                });
            }
            out.push(values);
        }
        Ok(out)
    }
}
