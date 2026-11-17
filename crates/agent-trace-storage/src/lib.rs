//! `agent-trace-storage`: trace persistence (SQLite, PostgreSQL, MySQL/MariaDB) and
//! JSONL/JSON import-export.
//!
//! Note: SQLite files are *not* encrypted at rest. Files and directories are created
//! private to the current user where the OS supports it.

pub mod backend;
pub mod config;
pub mod integrity;
pub mod jsonl;
pub mod live;
#[cfg(feature = "mysql")]
pub mod mysql;
#[cfg(feature = "postgres")]
pub mod postgres;
pub mod sarif;
pub mod shared;
pub mod sqlite;
pub mod store;

use std::path::Path;

use thiserror::Error;
use uuid::Uuid;

pub use backend::{Backend, Dialect, SqlValue};
pub use config::DatabaseConfig;
pub use integrity::{IntegrityRecord, SigningKey, Verified, parse_public_key, public_key_path};
pub use jsonl::{
    EvidenceReport, Imported, read_jsonl, write_json_report, write_jsonl, write_jsonl_signed,
};
pub use live::LiveWriter;
pub use sarif::{SarifTrace, jsonl_event_lines, write_sarif};
pub use shared::SharedTrace;
pub use store::{Store, TraceSource, TraceSummary};

#[derive(Debug, Error)]
pub enum StorageError {
    // The wrapped errors are part of the message and deliberately not exposed as
    // `source()`: error-chain printers (the CLI) would otherwise print them twice.
    #[error("database error: {0}")]
    Sqlite(rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(std::io::Error),
    #[error("JSON error: {0}")]
    Json(serde_json::Error),
    #[error("time formatting error: {0}")]
    TimeFormat(time::error::Format),
    #[error("time parsing error: {0}")]
    TimeParse(time::error::Parse),
    #[error("trace {0} already exists")]
    DuplicateTrace(Uuid),
    #[error("trace {0:?} not found")]
    TraceNotFound(String),
    #[error("trace id prefix {0:?} is ambiguous")]
    AmbiguousTraceId(String),
    #[error("import failed at line {line}: {message}")]
    Import { line: usize, message: String },
    #[error("invalid trace: {0}")]
    Invalid(agent_trace_core::ValidationError),
    #[error("corrupt database: {0}")]
    Corrupt(String),
    #[error("{0}")]
    Backend(String),
    #[error("database configuration: {0}")]
    Config(String),
}

macro_rules! storage_error_from {
    ($($variant:ident($ty:ty)),* $(,)?) => {
        $(impl From<$ty> for StorageError {
            fn from(e: $ty) -> Self {
                Self::$variant(e)
            }
        })*
    };
}

storage_error_from!(
    Sqlite(rusqlite::Error),
    Io(std::io::Error),
    Json(serde_json::Error),
    TimeFormat(time::error::Format),
    TimeParse(time::error::Parse),
    Invalid(agent_trace_core::ValidationError),
);

/// Create a directory (and parents) readable only by the current user where supported.
/// A directory that already exists is left as it is: it may be a project or shared
/// directory the user chose (`sqlite:./traces.db`, `/tmp`), not one agent-trace owns.
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    if dir.as_os_str().is_empty() || dir.is_dir() {
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

/// Create (or truncate) a file that only the current user can read, without a window in
/// which it is readable by others. A symlink at `path` is refused rather than followed.
pub fn create_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing to write through symlink {}", path.display()),
        ));
    }
    open_private_nofollow(path)
}

/// Open `path` for writing without following a symlink at its final component (the check
/// above alone could be raced) and restrict the opened file itself, not whatever the path
/// names afterwards.
fn open_private_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    // An existing file keeps its old mode on open; restrict it before anything is written.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

#[cfg(all(test, unix))]
mod private_file_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // Regression: exports were created with umask permissions and chmod 0600 only after
    // the content was written, and a pre-placed symlink was followed.
    #[test]
    fn private_files_are_0600_from_the_start_and_symlinks_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.json");
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _f = create_private_file(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");

        let victim = dir.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(create_private_file(&link).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");

        // Regression: the symlink check and the open were separate calls, so a symlink
        // swapped in between was followed (and the victim truncated). The open itself must
        // refuse a symlink.
        assert!(open_private_nofollow(&link).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
    }
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
