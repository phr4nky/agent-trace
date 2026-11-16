//! PostgreSQL backend (`postgres` driver, TLS via rustls with Mozilla roots).
//!
//! TLS: if the URL has no `sslmode` and the host is not loopback, `sslmode=require`
//! is added. Set `sslmode=disable` explicitly to opt out.

use postgres::types::{ToSql, Type};
use postgres::{Client, NoTls};
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::StorageError;
use crate::backend::{Backend, Dialect, SqlValue, numbered_placeholders};
use crate::config::{host, is_loopback, redact_url};

pub struct PostgresBackend {
    client: Client,
}

/// Apply the secure TLS default to a PostgreSQL URL.
pub(crate) fn effective_url(url: &str) -> String {
    if url.contains("sslmode=") {
        return url.to_owned();
    }
    match host(url) {
        Some(h) if !is_loopback(&h) => {
            let sep = if url.contains('?') { '&' } else { '?' };
            format!("{url}{sep}sslmode=require")
        }
        _ => url.to_owned(),
    }
}

impl PostgresBackend {
    pub fn connect(url: &str) -> Result<Self, StorageError> {
        let url = effective_url(url);
        let wants_no_tls = url.contains("sslmode=disable");
        let client = if wants_no_tls {
            Client::connect(&url, NoTls)
        } else {
            let _ = rustls::crypto::ring::default_provider().install_default();
            Client::connect(&url, MakeRustlsConnect::with_webpki_roots())
        }
        .map_err(|e| {
            let detail = e
                .as_db_error()
                .map(|d| d.message().to_owned())
                .unwrap_or_else(|| e.to_string());
            StorageError::Backend(format!(
                "cannot connect to PostgreSQL at {}: {}",
                redact_url(&url),
                redact_url(&detail)
            ))
        })?;
        Ok(Self { client })
    }
}

fn pg_err(e: postgres::Error) -> StorageError {
    let detail = e
        .as_db_error()
        .map(|d| d.message().to_owned())
        .unwrap_or_else(|| e.to_string());
    StorageError::Backend(format!("postgresql: {detail}"))
}

fn to_pg(params: &[SqlValue]) -> Vec<Box<dyn ToSql + Sync>> {
    params
        .iter()
        .map(|p| -> Box<dyn ToSql + Sync> {
            match p {
                SqlValue::Null => Box::new(None::<String>),
                SqlValue::Int(i) => Box::new(*i),
                SqlValue::Text(s) => Box::new(s.clone()),
            }
        })
        .collect()
}

impl Backend for PostgresBackend {
    fn dialect(&self) -> Dialect {
        Dialect::Postgres
    }

    fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<u64, StorageError> {
        let sql = numbered_placeholders(sql);
        if params.is_empty() {
            // Simple protocol: works for DDL and transaction control.
            self.client.batch_execute(&sql).map_err(pg_err)?;
            return Ok(0);
        }
        let owned = to_pg(params);
        let refs: Vec<&(dyn ToSql + Sync)> = owned.iter().map(AsRef::as_ref).collect();
        self.client.execute(&sql, &refs).map_err(pg_err)
    }

    fn query(
        &mut self,
        sql: &str,
        params: &[SqlValue],
    ) -> Result<Vec<Vec<SqlValue>>, StorageError> {
        let sql = numbered_placeholders(sql);
        let owned = to_pg(params);
        let refs: Vec<&(dyn ToSql + Sync)> = owned.iter().map(AsRef::as_ref).collect();
        let rows = self.client.query(&sql, &refs).map_err(pg_err)?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let mut values = Vec::with_capacity(row.len());
            for (i, col) in row.columns().iter().enumerate() {
                let ty = col.type_();
                let v = if *ty == Type::INT8 {
                    row.try_get::<_, Option<i64>>(i)
                        .map_err(pg_err)?
                        .map(SqlValue::Int)
                } else if *ty == Type::INT4 {
                    row.try_get::<_, Option<i32>>(i)
                        .map_err(pg_err)?
                        .map(|v| SqlValue::Int(i64::from(v)))
                } else if *ty == Type::INT2 {
                    row.try_get::<_, Option<i16>>(i)
                        .map_err(pg_err)?
                        .map(|v| SqlValue::Int(i64::from(v)))
                } else {
                    row.try_get::<_, Option<String>>(i)
                        .map_err(pg_err)?
                        .map(SqlValue::Text)
                };
                values.push(v.unwrap_or(SqlValue::Null));
            }
            out.push(values);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::effective_url;

    #[test]
    fn tls_required_for_remote_hosts() {
        assert_eq!(
            effective_url("postgres://u:p@db.example/t"),
            "postgres://u:p@db.example/t?sslmode=require"
        );
        assert_eq!(
            effective_url("postgres://u:p@db.example/t?application_name=x"),
            "postgres://u:p@db.example/t?application_name=x&sslmode=require"
        );
        assert_eq!(
            effective_url("postgres://u:p@db.example/t?sslmode=disable"),
            "postgres://u:p@db.example/t?sslmode=disable"
        );
        assert_eq!(
            effective_url("postgres://u:p@localhost:5432/t"),
            "postgres://u:p@localhost:5432/t"
        );
    }
}
