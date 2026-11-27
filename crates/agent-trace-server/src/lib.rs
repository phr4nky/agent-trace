//! `agent-trace-server`: receives traces from recorders (`agent-trace ship`), stores them, and
//! serves a read API and the web UI (`ui/`).
//!
//! * `POST /api/v1/ingest`: one batch of one trace, authenticated with the token of a source
//!   (`Authorization: Bearer ats_…`). Checked, redacted again and analyzed on the server
//!   (see [`agent_trace_storage::ingest`]). `GET /api/v1/whoami` names the token's source.
//! * `GET /api/v1/sources`, `/api/v1/traces?source=ID`, `/api/v1/traces/{id}`: sources, their
//!   traces, and a trace with its findings (the `export --format json` report).
//! * `GET /api/v1/traces/{id}/graph`: the causal graph page of `agent-trace graph`, with its
//!   own Content-Security-Policy; the UI shows it in a sandboxed frame.
//! * Everything else: the web UI from `--ui-dir`.
//!
//! The read API has no login yet: `serve` binds to loopback unless reads are explicitly allowed
//! for a wider network (`--allow-unauthenticated-reads`, e.g. behind your own access control).

pub mod config;
pub mod token;
mod ui;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use agent_trace_core::Analyzer;
use agent_trace_storage::ingest::{IngestBatch, IngestError, IngestReply, ingest};
use agent_trace_storage::jsonl::evidence_report;
use agent_trace_storage::{StorageError, Store, TraceSummary};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

/// Largest request body (one batch of at most 2000 events).
pub const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Content-Security-Policy of the web UI: its own scripts only, no connections elsewhere.
const UI_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
                      img-src 'self' data:; font-src 'self' data:; connect-src 'self'; \
                      frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; \
                      frame-ancestors 'none'";

/// Shared state of the handlers.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    store: Mutex<Store>,
    analyzer: Analyzer,
    ui_dir: Option<PathBuf>,
    trust_forwarded_for: bool,
}

/// Server settings besides the store.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    /// Directory with the built web UI (`ui/dist/agent-trace-ui/browser`).
    pub ui_dir: Option<PathBuf>,
    /// Take the client address from `X-Forwarded-For` (only behind a trusted reverse proxy).
    pub trust_forwarded_for: bool,
}

impl AppState {
    pub fn new(store: Store, analyzer: Analyzer, settings: Settings) -> Self {
        Self {
            inner: Arc::new(Inner {
                store: Mutex::new(store),
                analyzer,
                ui_dir: settings.ui_dir,
                trust_forwarded_for: settings.trust_forwarded_for,
            }),
        }
    }

    /// Run `f` on the store in a blocking thread (the database drivers are synchronous).
    async fn with_store<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Store, &Analyzer) -> T + Send + 'static,
    ) -> Result<T, ApiError> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let mut store = inner
                .store
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            f(&mut store, &inner.analyzer)
        })
        .await
        .map_err(|e| {
            tracing::error!("store task failed: {e}");
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        })
    }
}

/// The application: API, graph pages and web UI.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/ingest", post(ingest_batch))
        .route("/api/v1/whoami", get(whoami))
        .route("/api/v1/sources", get(list_sources))
        .route("/api/v1/traces", get(list_traces))
        .route("/api/v1/traces/{id}", get(trace_report))
        .route("/api/v1/traces/{id}/graph", get(trace_graph))
        .fallback(ui::serve)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

/// Serve `state` on `listener` until `shutdown` completes. The client address of each
/// connection is passed to the handlers (sources' last address).
pub async fn serve(
    listener: tokio::net::TcpListener,
    state: AppState,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}

/// Listen on `addr` and serve in a background task of the current runtime; returns the bound
/// address (for tests and embedding; `127.0.0.1:0` picks a free port).
pub async fn spawn(addr: SocketAddr, state: AppState) -> std::io::Result<SocketAddr> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    tokio::spawn(async move {
        if let Err(e) = serve(listener, state, std::future::pending()).await {
            tracing::error!("server failed: {e}");
        }
    });
    Ok(bound)
}

/// An error answer: a status and a message, sent as `{"error": message}`.
#[derive(Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    message: &'static str,
}

impl ApiError {
    fn new(status: StatusCode, message: &'static str) -> Self {
        Self { status, message }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        error(self.status, self.message)
    }
}

fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

fn storage_error(e: &StorageError) -> Response {
    match e {
        StorageError::TraceNotFound(_) => error(StatusCode::NOT_FOUND, "trace not found"),
        other => {
            tracing::error!("storage error: {other}");
            error(StatusCode::INTERNAL_SERVER_ERROR, "storage error")
        }
    }
}

/// Headers on every response; the web UI's pages get its Content-Security-Policy unless the
/// handler set one (the graph pages carry their own).
async fn security_headers(request: Request, next: Next) -> Response {
    let api = request.uri().path().starts_with("/api/");
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if api {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    let html = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/html"));
    if html && !headers.contains_key(header::CONTENT_SECURITY_POLICY) {
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(UI_CSP),
        );
    }
    response
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}

fn client_ip(state: &AppState, headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    if state.inner.trust_forwarded_for
        && let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse().ok())
    {
        return ip;
    }
    peer.ip()
}

/// `None`: unknown token; otherwise the source's name and the result of the batch.
type IngestOutcome = Result<Option<(String, Result<IngestReply, IngestError>)>, StorageError>;

async fn ingest_batch(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(token) = token::bearer(&headers) else {
        return unauthorized();
    };
    let token_hash = token::hash(token);
    let batch: IngestBatch = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("malformed batch: {e}"),
            );
        }
    };
    let ip = client_ip(&state, &headers, peer).to_string();
    let events = batch.events.len();
    let result = state
        .with_store(move |store, analyzer| -> IngestOutcome {
            let Some(source) = store.source_by_token_hash(&token_hash)? else {
                return Ok(None);
            };
            let reply = ingest(
                store,
                source.source_id,
                batch,
                analyzer,
                time::OffsetDateTime::now_utc(),
            );
            store.touch_source(source.source_id, Some(&ip))?;
            Ok(Some((source.name, reply)))
        })
        .await;
    let (source, reply) = match result {
        Err(e) => return e.into_response(),
        Ok(Err(e)) => return storage_error(&e),
        Ok(Ok(None)) => return unauthorized(),
        Ok(Ok(Some(pair))) => pair,
    };
    match reply {
        Ok(reply) => {
            tracing::info!(
                source = %source,
                trace = %reply.trace_id,
                events,
                stored_seq = reply.stored_seq,
                findings = reply.findings,
                "ingested"
            );
            Json(reply).into_response()
        }
        Err(IngestError::Conflict {
            message,
            stored_seq,
        }) => (
            StatusCode::CONFLICT,
            Json(json!({ "error": message, "stored_seq": stored_seq })),
        )
            .into_response(),
        Err(IngestError::Invalid(message)) => error(StatusCode::UNPROCESSABLE_ENTITY, message),
        Err(IngestError::Storage(e)) => storage_error(&e),
    }
}

/// The source a token belongs to, so a recorder can check its token before it sends.
async fn whoami(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(token) = token::bearer(&headers) else {
        return unauthorized();
    };
    let token_hash = token::hash(token);
    match state
        .with_store(move |store, _| store.source_by_token_hash(&token_hash))
        .await
    {
        Err(e) => e.into_response(),
        Ok(Err(e)) => storage_error(&e),
        Ok(Ok(None)) => unauthorized(),
        Ok(Ok(Some(source))) => {
            Json(json!({ "source_id": source.source_id, "name": source.name })).into_response()
        }
    }
}

fn unauthorized() -> Response {
    let mut response = error(
        StatusCode::UNAUTHORIZED,
        "missing or unknown source token (Authorization: Bearer ats_…)",
    );
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

async fn list_sources(State(state): State<AppState>) -> Response {
    match state.with_store(|store, _| store.sources()).await {
        Err(e) => e.into_response(),
        Ok(Err(e)) => storage_error(&e),
        Ok(Ok(sources)) => Json(sources).into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct TracesQuery {
    source: Option<String>,
}

/// One row of the trace list.
#[derive(Debug, Serialize)]
struct TraceRow {
    trace_id: Uuid,
    name: String,
    status: String,
    created_at: String,
    execution_mode: String,
    events: u64,
    findings: u64,
    max_severity: Option<String>,
}

impl TraceRow {
    fn from_summary(s: TraceSummary) -> Self {
        let created_at = s
            .trace
            .created_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        Self {
            trace_id: s.trace.trace_id,
            name: s.trace.name,
            status: s.trace.status.as_str().to_owned(),
            created_at,
            execution_mode: s.trace.execution_mode.as_str().to_owned(),
            events: s.event_count,
            findings: s.finding_count,
            max_severity: s.max_severity.map(|v| v.as_str().to_owned()),
        }
    }
}

async fn list_traces(State(state): State<AppState>, Query(q): Query<TracesQuery>) -> Response {
    let source = match q.source.as_deref().map(Uuid::parse_str).transpose() {
        Ok(s) => s,
        Err(_) => return error(StatusCode::BAD_REQUEST, "source must be a source id"),
    };
    let result = state
        .with_store(move |store, _| match source {
            Some(id) => store.list_traces_of_source(id),
            None => store.list_traces().map(|mut all| {
                all.reverse();
                all
            }),
        })
        .await;
    match result {
        Err(e) => e.into_response(),
        Ok(Err(e)) => storage_error(&e),
        Ok(Ok(rows)) => Json(
            rows.into_iter()
                .map(TraceRow::from_summary)
                .collect::<Vec<_>>(),
        )
        .into_response(),
    }
}

fn trace_id(raw: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(raw).map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "trace not found"))
}

async fn trace_report(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let id = match trace_id(&id) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let result = state
        .with_store(move |store, _| {
            let record = store.load_trace(id)?;
            let findings = store.load_findings(id)?;
            Ok::<_, StorageError>(evidence_report(&record, &findings))
        })
        .await;
    match result {
        Err(e) => e.into_response(),
        Ok(Err(e)) => storage_error(&e),
        Ok(Ok(report)) => Json(report).into_response(),
    }
}

async fn trace_graph(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let id = match trace_id(&id) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let result = state
        .with_store(move |store, _| {
            let record = store.load_trace(id)?;
            let findings = store.load_findings(id)?;
            agent_trace_storage::graph::render(&record, &findings)
        })
        .await;
    match result {
        Err(e) => e.into_response(),
        Ok(Err(e)) => storage_error(&e),
        Ok(Ok(page)) => {
            let mut response = Html(page).into_response();
            // The page carries its own policy (hashes of its script and style) in a meta
            // element; only who may frame it is set here.
            response.headers_mut().insert(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static("frame-ancestors 'self'"),
            );
            response
        }
    }
}
