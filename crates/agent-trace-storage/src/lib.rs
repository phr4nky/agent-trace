//! `agent-trace-storage`: trace persistence (SQLite, PostgreSQL, MySQL/MariaDB) and
//! JSONL/JSON import-export.
//!
//! Note: SQLite files are *not* encrypted at rest. Files and directories are created
//! private to the current user where the OS supports it.

pub mod backend;
pub mod config;
pub mod jsonl;
pub mod live;
#[cfg(feature = "mysql")]
pub mod mysql;
#[cfg(feature = "postgres")]
pub mod postgres;
pub mod sqlite;
pub mod store;

use std::path::Path;

use thiserror::Error;
use uuid::Uuid;

pub use backend::{Backend, Dialect, SqlValue};
pub use config::DatabaseConfig;
pub use jsonl::{EvidenceReport, Imported, read_jsonl, write_json_report, write_jsonl};
pub use live::LiveWriter;
pub use store::{Store, TraceSource, TraceSummary};

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("time formatting error: {0}")]
    TimeFormat(#[from] time::error::Format),
    #[error("time parsing error: {0}")]
    TimeParse(#[from] time::error::Parse),
    #[error("trace {0} already exists")]
    DuplicateTrace(Uuid),
    #[error("trace {0:?} not found")]
    TraceNotFound(String),
    #[error("trace id prefix {0:?} is ambiguous")]
    AmbiguousTraceId(String),
    #[error("import failed at line {line}: {message}")]
    Import { line: usize, message: String },
    #[error("invalid trace: {0}")]
    Invalid(#[from] agent_trace_core::ValidationError),
    #[error("corrupt database: {0}")]
    Corrupt(String),
    #[error("{0}")]
    Backend(String),
    #[error("database configuration: {0}")]
    Config(String),
}

/// Create a directory (and parents) readable only by the current user where supported.
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    if dir.as_os_str().is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Restrict an existing file to the current user where supported.
pub fn restrict_file(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
