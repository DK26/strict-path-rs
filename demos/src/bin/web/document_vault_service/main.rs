//! Document vault service demonstrating tuple marker authorization (Stage 4 pattern).
//!
//! This demo follows the tutorial Stage 4 pattern: check authorization FIRST,
//! THEN encode it in the type via change_marker(). This Actix-lite style Axum demo
//! exposes endpoints for an internal document vault containing confidential data and
//! public reports. Access tokens grant resource-specific permissions (scopes). We
//! validate token scopes FIRST (e.g., `scopes.contains(&Scope::ConfidentialRead)`),
//! THEN call change_marker() to encode proven authorization as tuple markers like
//! `PathBoundary<(ConfidentialDocs, ReadOnly)>`. The type system prevents tokens with
//! only read access from compiling calls to write operations, and keeps audit scope
//! separate from document scope.

mod types;
mod vault;

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use std::{
    fs,
    net::SocketAddr,
    path::Path as StdPath,
    sync::Arc,
};
use tokio::{net::TcpListener, signal};

use types::{
    ApiError, ApiResult, AuditResponse, CaptureAuditRequest, DocumentResponse,
    UpdateDocumentRequest, WriteResponse,
};
use vault::{
    resolve_audit_doc, write_audit_entry, AuditRegistry, TokenStore, VaultAccess, VaultRegistry,
};

const VAULT_ROOT: &str = "demo_data/document_vault";
const AUDIT_ROOT: &str = "demo_data/document_vault/audit";
const SERVER_ADDR: &str = "127.0.0.1:4012";

#[tokio::main]
async fn main() -> Result<()> {
    bootstrap_sample_data()?;

    let token_store = Arc::new(TokenStore::with_samples());
    let vault = VaultRegistry::new(VAULT_ROOT)?;
    let audit = AuditRegistry::new(AUDIT_ROOT)?;

    let state = Arc::new(AppState {
        tokens: token_store,
        vault,
        audit,
    });

    print_launch_instructions(state.clone()).await;

    let app = Router::new()
        .route(
            "/api/vault/confidential/:doc",
            get(fetch_confidential).post(update_confidential),
        )
        .route(
            "/api/vault/reports/:doc",
            get(fetch_report).post(update_report),
        )
        .route("/api/vault/audit", post(capture_audit))
        .with_state(state);

    let addr: SocketAddr = SERVER_ADDR.parse().context("invalid listen address")?;
    println!("\nDocument vault service listening on http://{addr}");
    println!("Press Ctrl+C to stop the server.\n");

    let listener = TcpListener::bind(addr)
        .await
        .context("failed to bind TCP listener")?;

    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    Ok(())
}

async fn shutdown_signal() {
    let _ = signal::ctrl_c().await;
}

async fn print_launch_instructions(state: SharedState) {
    let tokens = state.tokens.all_tokens().await;
    println!("Sample access tokens:");
    for token in tokens {
        println!("  - {token}");
    }
    println!("\nUse the tokens above via the X-Access-Token header.\n");
}

async fn fetch_confidential(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(doc): Path<String>,
) -> ApiResult<Json<DocumentResponse>> {
    let access = state.authorize(&headers).await?;
    let reader = access.confidential_reader()?;
    let document_path = reader
        .strict_join(&doc)
        .map_err(|err| ApiError::forbidden(&format!("Invalid document path: {err}")))?;
    let path_for_read = document_path.clone();
    let contents = tokio::task::spawn_blocking(move || path_for_read.read_to_string())
        .await
        .map_err(|err| ApiError::internal(anyhow!("task join error: {err}")))?
        .map_err(|err| ApiError::internal(anyhow!(err)))?;
    Ok(Json(DocumentResponse::new(document_path, contents)))
}

async fn update_confidential(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(doc): Path<String>,
    Json(body): Json<UpdateDocumentRequest>,
) -> ApiResult<Json<WriteResponse>> {
    let access = state.authorize(&headers).await?;
    let writer = access.confidential_writer()?;

    let document_path = writer
        .strict_join(&doc)
        .map_err(|err| ApiError::forbidden(&format!("Invalid document path: {err}")))?;
    let contents = body.contents.clone();
    let bytes = contents.len();
    tokio::task::spawn_blocking(move || {
        document_path.create_parent_dir_all()?;
        document_path.write(contents.as_bytes())
    })
    .await
    .map_err(|err| ApiError::internal(anyhow!("task join error: {err}")))?
    .map_err(|err| ApiError::internal(anyhow!(err)))?;
    Ok(Json(WriteResponse::from_bytes(bytes)))
}

async fn fetch_report(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(doc): Path<String>,
) -> ApiResult<Json<DocumentResponse>> {
    let access = state.authorize(&headers).await?;
    let reader = access.report_reader()?;
    let report_path = reader
        .strict_join(&doc)
        .map_err(|err| ApiError::forbidden(&format!("Invalid report path: {err}")))?;
    let path_for_read = report_path.clone();
    let contents = tokio::task::spawn_blocking(move || path_for_read.read_to_string())
        .await
        .map_err(|err| ApiError::internal(anyhow!("task join error: {err}")))?
        .map_err(|err| ApiError::internal(anyhow!(err)))?;
    Ok(Json(DocumentResponse::new(report_path, contents)))
}

async fn update_report(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(doc): Path<String>,
    Json(body): Json<UpdateDocumentRequest>,
) -> ApiResult<Json<WriteResponse>> {
    let access = state.authorize(&headers).await?;
    let writer = access.report_writer()?;

    let report_path = writer
        .strict_join(&doc)
        .map_err(|err| ApiError::forbidden(&format!("Invalid report path: {err}")))?;
    let contents = body.contents.clone();
    let bytes = contents.len();
    tokio::task::spawn_blocking(move || {
        report_path.create_parent_dir_all()?;
        report_path.write(contents.as_bytes())
    })
    .await
    .map_err(|err| ApiError::internal(anyhow!("task join error: {err}")))?
    .map_err(|err| ApiError::internal(anyhow!(err)))?;
    Ok(Json(WriteResponse::from_bytes(bytes)))
}

async fn capture_audit(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<CaptureAuditRequest>,
) -> ApiResult<Json<AuditResponse>> {
    let access = state.authorize(&headers).await?;
    let writer = access.audit_writer()?;
    let resolved = resolve_audit_doc(&access, &body.source_doc)?;
    let note = body.note.clone();
    let entry = tokio::task::spawn_blocking(move || write_audit_entry(&writer, &resolved, &note))
        .await
        .map_err(|err| ApiError::internal(anyhow!("task join error: {err}")))?
        .map_err(|err| ApiError::internal(anyhow!(err)))?;
    Ok(Json(AuditResponse::new(entry)))
}

fn bootstrap_sample_data() -> Result<()> {
    let confidential_dir = StdPath::new(VAULT_ROOT).join("confidential");
    let report_dir = StdPath::new(VAULT_ROOT).join("reports");
    let audit_dir = StdPath::new(AUDIT_ROOT);

    fs::create_dir_all(confidential_dir.join("legal"))?;
    fs::create_dir_all(confidential_dir.join("finance"))?;
    fs::create_dir_all(report_dir.join("monthly"))?;
    fs::create_dir_all(audit_dir)?;

    fs::write(
        confidential_dir.join("legal/nda.txt"),
        b"This NDA covers all client conversations.",
    )?;
    fs::write(
        confidential_dir.join("finance/budget.txt"),
        b"Budget 2025: Do not share outside accounting.",
    )?;
    fs::write(
        report_dir.join("monthly/status.txt"),
        b"Monthly project status report.",
    )?;

    Ok(())
}

type SharedState = Arc<AppState>;

#[derive(Clone)]
struct AppState {
    tokens: Arc<TokenStore>,
    vault: VaultRegistry,
    audit: AuditRegistry,
}

impl AppState {
    async fn authorize(&self, headers: &HeaderMap) -> ApiResult<VaultAccess> {
        let token = extract_token(headers)?;
        let grant = self.tokens.authorize(&token).await?;

        let vault = self
            .vault
            .build_access(&grant.scopes)
            .map_err(ApiError::internal)?;
        let audit = self
            .audit
            .build_access(&grant.scopes)
            .map_err(ApiError::internal)?;

        Ok(VaultAccess { vault, audit })
    }
}

fn extract_token(headers: &HeaderMap) -> ApiResult<String> {
    headers
        .get("x-access-token")
        .and_then(|value| value.to_str().ok())
        .map(|token| token.to_string())
        .ok_or_else(|| ApiError::unauthorized("Missing X-Access-Token header"))
}
