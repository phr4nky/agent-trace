//! PostgreSQL backend (`postgres` driver, TLS via rustls with Mozilla roots).
//!
//! TLS: unless every host the driver will connect to is loopback (or a Unix socket),
//! `sslmode=require` is enforced; the driver default `prefer` (downgradable) is upgraded.
//! Set `sslmode=disable` explicitly to opt out.

use postgres::config::{Host, SslMode};
use postgres::types::{ToSql, Type};
use postgres::{Client, Config, NoTls};
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::StorageError;
use crate::backend::{Backend, Dialect, SqlValue, numbered_placeholders};
use crate::config::{is_loopback, redact_url};

pub struct PostgresBackend {
    client: Client,
}

/// Whether every connection target in the parsed configuration is local. This uses the
/// driver's own parse (`host`/`hostaddr` parameters, host lists), not the URL authority.
fn all_targets_local(config: &Config) -> bool {
    let addrs = config.get_hostaddrs();
    if !addrs.is_empty() {
        return addrs.iter().all(|a| a.is_loopback());
    }
    config.get_hosts().iter().all(|h| match h {
        Host::Tcp(name) => is_loopback(name),
        #[allow(unreachable_patterns)]
        _ => true, // Unix domain socket
    })
}

/// Parse a PostgreSQL URL and apply the secure TLS default.
pub(crate) fn effective_config(url: &str) -> Result<Config, StorageError> {
    let mut config: Config = url.parse().map_err(|e: postgres::Error| {
        StorageError::Config(format!(
            "invalid PostgreSQL URL {}: {}",
            redact_url(url),
            redact_url(&e.to_string())
        ))
    })?;
    if config.get_ssl_mode() == SslMode::Prefer && !all_targets_local(&config) {
        config.ssl_mode(SslMode::Require);
    }
    Ok(config)
}

impl PostgresBackend {
    pub fn connect(url: &str) -> Result<Self, StorageError> {
        let config = effective_config(url)?;
        let client = if config.get_ssl_mode() == SslMode::Disable {
            config.connect(NoTls)
        } else {
            let _ = rustls::crypto::ring::default_provider().install_default();
            config.connect(MakeRustlsConnect::with_webpki_roots())
        }
        .map_err(|e| {
            let detail = e
                .as_db_error()
                .map(|d| d.message().to_owned())
                .unwrap_or_else(|| e.to_string());
            StorageError::Backend(format!(
                "cannot connect to PostgreSQL at {}: {}",
                redact_url(url),
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
    use super::effective_config;
    use postgres::config::SslMode;

    fn mode(url: &str) -> SslMode {
        effective_config(url).unwrap().get_ssl_mode()
    }

    #[test]
    fn tls_required_for_remote_hosts() {
        assert_eq!(mode("postgres://u:p@db.example/t"), SslMode::Require);
        assert_eq!(
            mode("postgres://u:p@db.example/t?application_name=x"),
            SslMode::Require
        );
        assert_eq!(
            mode("postgres://u:p@db.example/t?sslmode=disable"),
            SslMode::Disable
        );
        assert_eq!(mode("postgres://u:p@localhost:5432/t"), SslMode::Prefer);
        assert_eq!(mode("postgres://u:p@[::1]:5432/t"), SslMode::Prefer);
        assert_eq!(
            mode("postgres://u:p@db.remote/t?hostaddr=127.0.0.1"),
            SslMode::Prefer
        );
    }

    // Regression: the TLS decision used a hand-written host parser that disagreed with the
    // driver, so these URLs connected to a remote server with the downgradable `prefer`.
    #[test]
    fn tls_decision_uses_the_hosts_the_driver_connects_to() {
        for url in [
            "postgres://u:p@localhost/t?host=db.remote",
            "postgres://u:p@/t?host=db.remote",
            "postgres://u:p@127.0.0.1:5432,db.remote:5432/t",
            "postgres://u:p@localhost/t?hostaddr=10.0.0.5",
            "postgres://u:p@127.attacker.example/t",
            "postgres://u:sslmode=disable@db.example/t",
            "postgres://u:p@db.example/t?application_name=sslmode=disable",
            "postgres://u:p@db.example/t?sslmode=prefer",
        ] {
            assert_eq!(mode(url), SslMode::Require, "{url}");
        }
    }
}
