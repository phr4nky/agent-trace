//! The web UI: files from `--ui-dir`, `index.html` for app routes. A request never leaves the
//! UI directory (no `..`, no encoded characters, and the resolved file must lie inside it).

use std::path::{Path, PathBuf};

use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{Html, IntoResponse, Response};

use crate::{AppState, error};

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "webmanifest" => "application/manifest+json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "ttf" => "font/ttf",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// The file under `root` for a request path, if the path is plain and the file exists inside.
fn resolve(root: &Path, request_path: &str) -> Option<PathBuf> {
    let rel = request_path.trim_start_matches('/');
    if rel.contains(['%', '\\', '\0'])
        || rel
            .split('/')
            .any(|segment| segment == ".." || segment == "." || segment.starts_with('.'))
    {
        return None;
    }
    let root = root.canonicalize().ok()?;
    let file = root.join(rel).canonicalize().ok()?;
    (file.starts_with(&root) && file.is_file()).then_some(file)
}

/// Fallback handler: unknown API paths are 404, everything else comes from the UI directory.
pub(crate) async fn serve(State(state): State<AppState>, uri: Uri) -> Response {
    let path = uri.path();
    if path.starts_with("/api/") {
        return error(StatusCode::NOT_FOUND, "not found");
    }
    let Some(root) = state.inner.ui_dir.clone() else {
        return (
            StatusCode::NOT_FOUND,
            Html("<!doctype html><title>agent-trace-server</title><p>agent-trace-server is running. \
                  The web UI is not installed: build <code>ui/</code> and pass <code>--ui-dir</code>."),
        )
            .into_response();
    };
    // App routes (no file extension) get index.html; missing files with an extension are 404.
    let target = match resolve(&root, path) {
        Some(file) => file,
        None if Path::new(path).extension().is_none() => match resolve(&root, "index.html") {
            Some(index) => index,
            None => return error(StatusCode::NOT_FOUND, "the UI directory has no index.html"),
        },
        None => return error(StatusCode::NOT_FOUND, "not found"),
    };
    match tokio::fs::read(&target).await {
        Ok(bytes) => {
            let mut response = bytes.into_response();
            let headers = response.headers_mut();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(content_type(&target)),
            );
            // Build output names carry a content hash; index.html must always be fresh.
            let cache = if target.file_name().is_some_and(|n| n == "index.html") {
                "no-cache"
            } else {
                "public, max-age=3600"
            };
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
            response
        }
        Err(e) => {
            tracing::warn!("cannot read {}: {e}", target.display());
            error(StatusCode::NOT_FOUND, "not found")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_stay_inside_the_ui_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ui");
        std::fs::create_dir_all(root.join("assets")).unwrap();
        std::fs::write(root.join("index.html"), "<p>ui").unwrap();
        std::fs::write(root.join("assets/app.js"), "x").unwrap();
        std::fs::write(dir.path().join("secret.txt"), "no").unwrap();
        assert!(resolve(&root, "/index.html").is_some());
        assert!(resolve(&root, "/assets/app.js").is_some());
        for bad in [
            "/../secret.txt",
            "/assets/../../secret.txt",
            "/%2e%2e/secret.txt",
            "/assets\\..\\..\\secret.txt",
            "/.hidden",
            "/assets/missing.js",
            "/",
        ] {
            assert!(resolve(&root, bad).is_none(), "{bad}");
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(dir.path().join("secret.txt"), root.join("link.txt"))
                .unwrap();
            assert!(
                resolve(&root, "/link.txt").is_none(),
                "symlink out of the root"
            );
        }
        assert_eq!(
            content_type(Path::new("a.js")),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            content_type(Path::new("a.unknown")),
            "application/octet-stream"
        );
    }
}
