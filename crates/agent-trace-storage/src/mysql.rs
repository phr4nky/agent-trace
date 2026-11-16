//! MySQL / MariaDB backend (`mysql` driver, TLS via rustls with Mozilla roots).
//!
//! TLS is controlled with an `ssl-mode` URL parameter (`disabled` or `required`).
//! Without it, TLS is required for non-loopback hosts.

use mysql::prelude::Queryable;
use mysql::{Conn, Opts, OptsBuilder, Params, Row, SslOpts, Value};

use crate::StorageError;
use crate::backend::{Backend, Dialect, SqlValue};
use crate::config::{host, is_loopback, redact_url};

pub struct MySqlBackend {
    conn: Conn,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SslMode {
    Disabled,
    Required,
}

/// Split our `ssl-mode` parameter from the URL and apply the secure default.
pub(crate) fn split_ssl_mode(url: &str) -> Result<(String, SslMode), StorageError> {
    let (base, query) = match url.split_once('?') {
        Some((b, q)) => (b, q),
        None => (url, ""),
    };
    let mut mode = None;
    let mut rest = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        match pair.split_once('=') {
            Some((k, v))
                if k.eq_ignore_ascii_case("ssl-mode") || k.eq_ignore_ascii_case("ssl_mode") =>
            {
                mode = Some(match v.to_ascii_lowercase().as_str() {
                    "disabled" | "disable" | "false" => SslMode::Disabled,
                    "required" | "require" | "true" | "verify_identity" | "verify_ca" => {
                        SslMode::Required
                    }
                    other => {
                        return Err(StorageError::Config(format!(
                            "unknown ssl-mode {other:?} (use disabled or required)"
                        )));
                    }
                });
            }
            _ => rest.push(pair),
        }
    }
    let mode = mode.unwrap_or_else(|| match host(url) {
        Some(h) if !is_loopback(&h) => SslMode::Required,
        _ => SslMode::Disabled,
    });
    let url = if rest.is_empty() {
        base.to_owned()
    } else {
        format!("{base}?{}", rest.join("&"))
    };
    Ok((url, mode))
}

impl MySqlBackend {
    pub fn connect(url: &str) -> Result<Self, StorageError> {
        let (clean, mode) = split_ssl_mode(url)?;
        let opts = Opts::from_url(&clean)
            .map_err(|e| StorageError::Config(format!("invalid MySQL URL: {e}")))?;
        let mut builder = OptsBuilder::from_opts(opts);
        if mode == SslMode::Required {
            let _ = rustls::crypto::ring::default_provider().install_default();
            builder = builder.ssl_opts(SslOpts::default());
        }
        let mut conn = Conn::new(builder).map_err(|e| {
            StorageError::Backend(format!(
                "cannot connect to MySQL/MariaDB at {}: {e}",
                redact_url(url)
            ))
        })?;
        conn.query_drop("SET SESSION sql_mode = 'STRICT_ALL_TABLES'")
            .map_err(my_err)?;
        Ok(Self { conn })
    }
}

fn my_err(e: mysql::Error) -> StorageError {
    StorageError::Backend(format!("mysql: {e}"))
}

fn to_my(params: &[SqlValue]) -> Params {
    Params::Positional(
        params
            .iter()
            .map(|p| match p {
                SqlValue::Null => Value::NULL,
                SqlValue::Int(i) => Value::Int(*i),
                SqlValue::Text(s) => Value::Bytes(s.clone().into_bytes()),
            })
            .collect(),
    )
}

fn from_my(v: Value) -> SqlValue {
    match v {
        Value::NULL => SqlValue::Null,
        Value::Int(i) => SqlValue::Int(i),
        Value::UInt(u) => SqlValue::Int(i64::try_from(u).unwrap_or(i64::MAX)),
        Value::Bytes(b) => SqlValue::Text(String::from_utf8_lossy(&b).into_owned()),
        other => SqlValue::Text(other.as_sql(true).trim_matches('\'').to_owned()),
    }
}

impl Backend for MySqlBackend {
    fn dialect(&self) -> Dialect {
        Dialect::MySql
    }

    fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<u64, StorageError> {
        if params.is_empty() {
            self.conn.query_drop(sql).map_err(my_err)?;
        } else {
            self.conn.exec_drop(sql, to_my(params)).map_err(my_err)?;
        }
        Ok(self.conn.affected_rows())
    }

    fn query(
        &mut self,
        sql: &str,
        params: &[SqlValue],
    ) -> Result<Vec<Vec<SqlValue>>, StorageError> {
        let rows: Vec<Row> = if params.is_empty() {
            self.conn.query(sql).map_err(my_err)?
        } else {
            self.conn.exec(sql, to_my(params)).map_err(my_err)?
        };
        Ok(rows
            .into_iter()
            .map(|r| r.unwrap().into_iter().map(from_my).collect())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssl_mode_defaults_and_parsing() {
        let (u, m) = split_ssl_mode("mysql://u:p@db.example:3306/t").unwrap();
        assert_eq!(
            (u.as_str(), m),
            ("mysql://u:p@db.example:3306/t", SslMode::Required)
        );
        let (u, m) = split_ssl_mode("mysql://u:p@127.0.0.1:3306/t").unwrap();
        assert_eq!(
            (u.as_str(), m),
            ("mysql://u:p@127.0.0.1:3306/t", SslMode::Disabled)
        );
        let (u, m) =
            split_ssl_mode("mysql://u:p@db.example/t?ssl-mode=disabled&compress=true").unwrap();
        assert_eq!(
            (u.as_str(), m),
            ("mysql://u:p@db.example/t?compress=true", SslMode::Disabled)
        );
        assert!(split_ssl_mode("mysql://h/t?ssl-mode=maybe").is_err());
    }
}
