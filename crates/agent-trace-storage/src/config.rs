//! Database selection from a URL.
//!
//! * `sqlite:///absolute/path.sqlite3`, `sqlite:relative.sqlite3` (default backend)
//! * `postgres://user:pass@host:5432/db` or `postgresql://…`
//! * `mysql://user:pass@host:3306/db` or `mariadb://…`
//!
//! TLS defaults: for non-loopback hosts TLS is **required** unless the URL says
//! otherwise (`sslmode=…` for PostgreSQL, `ssl-mode=disabled|required` for MySQL/MariaDB).

use std::path::PathBuf;

use agent_trace_core::Redactor;

use crate::StorageError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatabaseConfig {
    Sqlite(PathBuf),
    Postgres(String),
    MySql(String),
}

impl DatabaseConfig {
    pub fn parse(url: &str) -> Result<Self, StorageError> {
        let url = url.trim();
        let lower = url.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("sqlite:") {
            let original = &url[url.len() - rest.len()..];
            let path = original.strip_prefix("//").unwrap_or(original);
            if path.is_empty() {
                return Err(StorageError::Config("sqlite URL needs a file path".into()));
            }
            return Ok(Self::Sqlite(PathBuf::from(path)));
        }
        if lower.starts_with("postgres://") || lower.starts_with("postgresql://") {
            return Ok(Self::Postgres(url.to_owned()));
        }
        if lower.starts_with("mysql://") {
            return Ok(Self::MySql(url.to_owned()));
        }
        if lower.starts_with("mariadb://") {
            return Ok(Self::MySql(format!(
                "mysql://{}",
                &url["mariadb://".len()..]
            )));
        }
        Err(StorageError::Config(format!(
            "unsupported database URL {:?}; use sqlite:, postgres://, mysql:// or mariadb://",
            redact_url(url)
        )))
    }

    /// Human-readable location with credentials removed.
    pub fn display_redacted(&self) -> String {
        match self {
            Self::Sqlite(p) => p.display().to_string(),
            Self::Postgres(u) | Self::MySql(u) => redact_url(u),
        }
    }
}

/// Remove passwords from a URL for display (uses the shared redactor).
pub fn redact_url(url: &str) -> String {
    Redactor::new().scrub(url)
}

/// Whether a host name or address (as parsed by the database driver) is loopback.
/// Only `localhost` and literal loopback addresses count; DNS names never do.
pub(crate) fn is_loopback(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    h.eq_ignore_ascii_case("localhost")
        || h.parse::<std::net::IpAddr>().is_ok_and(|a| a.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_urls() {
        assert_eq!(
            DatabaseConfig::parse("sqlite:///tmp/a.sqlite3").unwrap(),
            DatabaseConfig::Sqlite("/tmp/a.sqlite3".into())
        );
        assert_eq!(
            DatabaseConfig::parse("sqlite:rel.db").unwrap(),
            DatabaseConfig::Sqlite("rel.db".into())
        );
        assert!(matches!(
            DatabaseConfig::parse("postgresql://u:p@h/db").unwrap(),
            DatabaseConfig::Postgres(_)
        ));
        assert_eq!(
            DatabaseConfig::parse("mariadb://u:p@h:3306/db").unwrap(),
            DatabaseConfig::MySql("mysql://u:p@h:3306/db".into())
        );
        assert!(DatabaseConfig::parse("oracle://x").is_err());
        assert!(DatabaseConfig::parse("sqlite:").is_err());
    }

    #[test]
    fn redacts_passwords() {
        let cfg =
            DatabaseConfig::parse("postgres://trace:SuperSecret123@db.example:5432/t").unwrap();
        let shown = cfg.display_redacted();
        assert!(!shown.contains("SuperSecret123"), "{shown}");
        assert!(shown.contains("db.example"));
        let err = DatabaseConfig::parse("oracle://u:hunter2pass@h")
            .unwrap_err()
            .to_string();
        assert!(!err.contains("hunter2pass"), "{err}");
    }
}
