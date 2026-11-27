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
        return addrs.iter().all(std::net::IpAddr::is_loopback);
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

/// How a connection attempt reaches the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transport {
    Plain,
    VerifiedTls,
}

/// Connection attempts in order. `prefer` survives `effective_config` only for loopback
/// targets: there plaintext is tried first and verified TLS second. (libpq's `prefer` does
/// not verify certificates, so a verifying-only attempt would refuse the self-signed
/// certificates local distro installations ship.)
pub(crate) fn connect_plan(config: &Config) -> &'static [Transport] {
    match config.get_ssl_mode() {
        SslMode::Disable => &[Transport::Plain],
        SslMode::Prefer => &[Transport::Plain, Transport::VerifiedTls],
        _ => &[Transport::VerifiedTls],
    }
}

/// Error text including the driver's underlying cause (its Display shows only the kind,
/// e.g. "error connecting to server", and keeps the reason in `source()`).
fn pg_detail(e: &postgres::Error) -> String {
    if let Some(db) = e.as_db_error() {
        return db.message().to_owned();
    }
    let mut text = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        text.push_str(&format!(": {s}"));
        source = s.source();
    }
    text
}

impl PostgresBackend {
    pub fn connect(url: &str) -> Result<Self, StorageError> {
        let config = effective_config(url)?;
        let mut last_error = None;
        for transport in connect_plan(&config) {
            let attempt = match transport {
                Transport::Plain => config.connect(NoTls),
                Transport::VerifiedTls => {
                    let _ = rustls::crypto::ring::default_provider().install_default();
                    let mut tls_config = config.clone();
                    if tls_config.get_ssl_mode() == SslMode::Prefer {
                        tls_config.ssl_mode(SslMode::Require);
                    }
                    tls_config.connect(MakeRustlsConnect::with_webpki_roots())
                }
            };
            match attempt {
                Ok(client) => return Ok(Self { client }),
                Err(e) => last_error = Some(e),
            }
        }
        let detail = last_error.map(|e| pg_detail(&e)).unwrap_or_default();
        Err(StorageError::Backend(format!(
            "cannot connect to PostgreSQL at {}: {}",
            redact_url(url),
            redact_url(&detail)
        )))
    }
}

fn pg_err(e: postgres::Error) -> StorageError {
    StorageError::Backend(format!("postgresql: {}", redact_url(&pg_detail(&e))))
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

    // Regression: on loopback, `prefer` only tried verified TLS and failed hard against a
    // local server with a self-signed certificate (distro default); libpq's prefer would
    // have connected.
    #[test]
    fn loopback_prefer_tries_plaintext_then_tls() {
        use super::{Transport, connect_plan};
        let plan = |url: &str| connect_plan(&effective_config(url).unwrap()).to_vec();
        assert_eq!(
            plan("postgres://u:p@localhost/t"),
            vec![Transport::Plain, Transport::VerifiedTls]
        );
        assert_eq!(
            plan("postgres://u:p@db.example/t"),
            vec![Transport::VerifiedTls]
        );
        assert_eq!(
            plan("postgres://u:p@localhost/t?sslmode=require"),
            vec![Transport::VerifiedTls]
        );
        assert_eq!(
            plan("postgres://u:p@db.example/t?sslmode=disable"),
            vec![Transport::Plain]
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
