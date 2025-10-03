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

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::SocketAddr,
    path::Path as StdPath,
    sync::Arc,
};
use strict_path::{PathBoundary, StrictPath, StrictPathError};
use tokio::{net::TcpListener, signal, sync::RwLock};

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
    let path = reader
        .strict_join(&doc)
        .map_err(|err| ApiError::forbidden(&format!("Invalid document path: {err}")))?;
    let path_for_read = path.clone();
    let contents = tokio::task::spawn_blocking(move || path_for_read.read_to_string())
        .await
        .map_err(|err| ApiError::internal(anyhow!("task join error: {err}")))?
        .map_err(|e| ApiError::internal(anyhow!(e)))?;
    Ok(Json(DocumentResponse::new(path, contents)))
}

async fn update_confidential(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(doc): Path<String>,
    Json(body): Json<UpdateDocumentRequest>,
) -> ApiResult<Json<WriteResponse>> {
    let access = state.authorize(&headers).await?;
    let writer = access.confidential_writer()?;

    let path = writer
        .strict_join(&doc)
        .map_err(|err| ApiError::forbidden(&format!("Invalid document path: {err}")))?;
    let contents = body.contents.clone();
    let bytes = contents.len();
    tokio::task::spawn_blocking(move || {
        path.create_parent_dir_all()?;
        path.write(contents.as_bytes())
    })
    .await
    .map_err(|err| ApiError::internal(anyhow!("task join error: {err}")))?
    .map_err(|e| ApiError::internal(anyhow!(e)))?;
    Ok(Json(WriteResponse::from_bytes(bytes)))
}

async fn fetch_report(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(doc): Path<String>,
) -> ApiResult<Json<DocumentResponse>> {
    let access = state.authorize(&headers).await?;
    let reader = access.report_reader()?;
    let path = reader
        .strict_join(&doc)
        .map_err(|err| ApiError::forbidden(&format!("Invalid report path: {err}")))?;
    let path_for_read = path.clone();
    let contents = tokio::task::spawn_blocking(move || path_for_read.read_to_string())
        .await
        .map_err(|err| ApiError::internal(anyhow!("task join error: {err}")))?
        .map_err(|e| ApiError::internal(anyhow!(e)))?;
    Ok(Json(DocumentResponse::new(path, contents)))
}

async fn update_report(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(doc): Path<String>,
    Json(body): Json<UpdateDocumentRequest>,
) -> ApiResult<Json<WriteResponse>> {
    let access = state.authorize(&headers).await?;
    let writer = access.report_writer()?;

    let path = writer
        .strict_join(&doc)
        .map_err(|err| ApiError::forbidden(&format!("Invalid report path: {err}")))?;
    let contents = body.contents.clone();
    let bytes = contents.len();
    tokio::task::spawn_blocking(move || {
        path.create_parent_dir_all()?;
        path.write(contents.as_bytes())
    })
    .await
    .map_err(|err| ApiError::internal(anyhow!("task join error: {err}")))?
    .map_err(|e| ApiError::internal(anyhow!(e)))?;
    Ok(Json(WriteResponse::from_bytes(bytes)))
}

async fn capture_audit(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<CaptureAuditRequest>,
) -> ApiResult<Json<AuditResponse>> {
    let access = state.authorize(&headers).await?;
    let writer = access.audit_writer()?;
    let source = resolve_audit_source(&access, &body.source_doc)?;
    let note = body.note.clone();
    let entry = tokio::task::spawn_blocking(move || write_audit_entry(&writer, &source, &note))
        .await
        .map_err(|err| ApiError::internal(anyhow!("task join error: {err}")))?
        .map_err(|e| ApiError::internal(anyhow!(e)))?;
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

type ApiResult<T> = std::result::Result<T, ApiError>;
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

#[derive(Clone)]
struct VaultAccess {
    vault: ScopedVaultAccess,
    audit: ScopedAuditAccess,
}

impl VaultAccess {
    fn confidential_reader(&self) -> ApiResult<PathBoundary<(ConfidentialDocs, ReadOnly)>> {
        self.vault
            .confidential_read
            .clone()
            .ok_or_else(|| ApiError::forbidden("Token lacks confidential read scope"))
    }

    fn confidential_reader_opt(&self) -> Option<PathBoundary<(ConfidentialDocs, ReadOnly)>> {
        self.vault.confidential_read.clone()
    }

    fn confidential_writer(&self) -> ApiResult<PathBoundary<(ConfidentialDocs, WriteOnly)>> {
        self.vault
            .confidential_write
            .clone()
            .ok_or_else(|| ApiError::forbidden("Token lacks confidential write scope"))
    }

    fn report_reader(&self) -> ApiResult<PathBoundary<(PublicReports, ReadOnly)>> {
        self.vault
            .report_read
            .clone()
            .ok_or_else(|| ApiError::forbidden("Token lacks report read scope"))
    }

    fn report_reader_opt(&self) -> Option<PathBoundary<(PublicReports, ReadOnly)>> {
        self.vault.report_read.clone()
    }

    fn report_writer(&self) -> ApiResult<PathBoundary<(PublicReports, WriteOnly)>> {
        self.vault
            .report_write
            .clone()
            .ok_or_else(|| ApiError::forbidden("Token lacks report write scope"))
    }

    fn audit_writer(&self) -> ApiResult<PathBoundary<(AuditTrail, WriteOnly)>> {
        self.audit
            .writer
            .clone()
            .ok_or_else(|| ApiError::forbidden("Token lacks audit scope"))
    }
}

#[derive(Clone)]
struct ScopedVaultAccess {
    confidential_read: Option<PathBoundary<(ConfidentialDocs, ReadOnly)>>,
    confidential_write: Option<PathBoundary<(ConfidentialDocs, WriteOnly)>>,
    report_read: Option<PathBoundary<(PublicReports, ReadOnly)>>,
    report_write: Option<PathBoundary<(PublicReports, WriteOnly)>>,
}

impl ScopedVaultAccess {
    fn new(base: PathBoundary<VaultRoot>, scopes: &HashSet<Scope>) -> Result<Self> {
        let confidential_dir = base.strict_join("confidential")?;
        let reports_dir = base.strict_join("reports")?;

        // ✅ Step 1: Check authorization (validate token scope)
        // ✅ Step 2: Encode authorization in type via change_marker()
        let confidential_read = if scopes.contains(&Scope::ConfidentialRead) {
            Some(
                confidential_dir
                    .clone()
                    .change_marker::<(ConfidentialDocs, ReadOnly)>()
                    .try_into_boundary_create()?,
            )
        } else {
            None
        };

        // ✅ Authorization check → change_marker() pattern
        let confidential_write = if scopes.contains(&Scope::ConfidentialWrite) {
            Some(
                confidential_dir
                    .clone()
                    .change_marker::<(ConfidentialDocs, WriteOnly)>()
                    .try_into_boundary_create()?,
            )
        } else {
            None
        };

        // ✅ Authorization check → change_marker() pattern
        let report_read = if scopes.contains(&Scope::ReportRead) {
            Some(
                reports_dir
                    .clone()
                    .change_marker::<(PublicReports, ReadOnly)>()
                    .try_into_boundary_create()?,
            )
        } else {
            None
        };

        // ✅ Authorization check → change_marker() pattern
        let report_write = if scopes.contains(&Scope::ReportWrite) {
            Some(
                reports_dir
                    .clone()
                    .change_marker::<(PublicReports, WriteOnly)>()
                    .try_into_boundary_create()?,
            )
        } else {
            None
        };

        Ok(Self {
            confidential_read,
            confidential_write,
            report_read,
            report_write,
        })
    }
}

#[derive(Clone)]
struct VaultRegistry {
    base: PathBoundary<VaultRoot>,
}

impl VaultRegistry {
    fn new(root: &str) -> Result<Self> {
        let base = PathBoundary::<VaultRoot>::try_new_create(root)?;
        Ok(Self { base })
    }

    fn build_access(&self, scopes: &HashSet<Scope>) -> Result<ScopedVaultAccess> {
        ScopedVaultAccess::new(self.base.clone(), scopes)
    }
}

#[derive(Clone)]
struct ScopedAuditAccess {
    writer: Option<PathBoundary<(AuditTrail, WriteOnly)>>,
}

#[derive(Clone)]
struct AuditRegistry {
    base: PathBoundary<AuditRoot>,
}

impl AuditRegistry {
    fn new(root: &str) -> Result<Self> {
        let base = PathBoundary::<AuditRoot>::try_new_create(root)?;
        Ok(Self { base })
    }

    fn build_access(&self, scopes: &HashSet<Scope>) -> Result<ScopedAuditAccess> {
        // ✅ Step 1: Check authorization (validate token scope)
        // ✅ Step 2: Encode authorization in type via change_marker()
        let writer = if scopes.contains(&Scope::AuditWrite) {
            Some(
                self.base
                    .clone()
                    .into_strictpath()? // ensure directory still exists
                    .change_marker::<(AuditTrail, WriteOnly)>()
                    .try_into_boundary()?,
            )
        } else {
            None
        };
        Ok(ScopedAuditAccess { writer })
    }
}

enum ResolvedDoc {
    Confidential(StrictPath<(ConfidentialDocs, ReadOnly)>),
    Report(StrictPath<(PublicReports, ReadOnly)>),
}

impl ResolvedDoc {
    fn display(&self) -> String {
        match self {
            Self::Confidential(path) => path.strictpath_display().to_string(),
            Self::Report(path) => path.strictpath_display().to_string(),
        }
    }

    fn file_name(&self) -> String {
        let name = match self {
            Self::Confidential(path) => path.strictpath_file_name(),
            Self::Report(path) => path.strictpath_file_name(),
        };
        name.and_then(|value| value.to_str())
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }
}

fn resolve_audit_source(access: &VaultAccess, doc: &str) -> ApiResult<ResolvedDoc> {
    if let Some(reader) = access.confidential_reader_opt() {
        match reader.strict_join(doc) {
            Ok(path) => return Ok(ResolvedDoc::Confidential(path)),
            Err(StrictPathError::PathEscapesBoundary { .. }) => {}
            Err(err) => {
                return Err(ApiError::forbidden(&format!(
                    "Invalid document path: {err}"
                )));
            }
        }
    }

    if let Some(reader) = access.report_reader_opt() {
        match reader.strict_join(doc) {
            Ok(path) => return Ok(ResolvedDoc::Report(path)),
            Err(StrictPathError::PathEscapesBoundary { .. }) => {}
            Err(err) => {
                return Err(ApiError::forbidden(&format!(
                    "Invalid document path: {err}"
                )));
            }
        }
    }

    Err(ApiError::forbidden(
        "Current token cannot read requested document",
    ))
}

fn write_audit_entry(
    writer: &PathBoundary<(AuditTrail, WriteOnly)>,
    source: &ResolvedDoc,
    note: &str,
) -> Result<StrictPath<(AuditTrail, WriteOnly)>> {
    let timestamp = Utc::now().format("%Y%m%d%H%M%S");
    let file_name = format!("audit-{}-{}.txt", timestamp, sanitize(&source.file_name()));
    let entry = writer.strict_join(&file_name)?;
    entry.create_parent_dir_all()?;

    let body = format!("Source: {}\nNote: {}\n", source.display(), note);
    entry.write(body.as_bytes())?;
    Ok(entry)
}

#[derive(Clone)]
struct TokenStore {
    records: Arc<RwLock<HashMap<String, TokenRecord>>>,
}

impl TokenStore {
    fn with_samples() -> Self {
        let mut map = HashMap::new();
        map.insert(
            "legal-reader".to_string(),
            TokenRecord::new([Scope::ConfidentialRead]),
        );
        map.insert(
            "finance-writer".to_string(),
            TokenRecord::new([Scope::ConfidentialRead, Scope::ConfidentialWrite]),
        );
        map.insert(
            "reports-admin".to_string(),
            TokenRecord::new([
                Scope::ReportRead,
                Scope::ReportWrite,
                Scope::ConfidentialRead,
            ]),
        );
        map.insert(
            "audit-team".to_string(),
            TokenRecord::new([
                Scope::ConfidentialRead,
                Scope::ReportRead,
                Scope::AuditWrite,
            ]),
        );
        Self {
            records: Arc::new(RwLock::new(map)),
        }
    }

    async fn all_tokens(&self) -> Vec<String> {
        let guard = self.records.read().await;
        guard.keys().cloned().collect()
    }

    async fn authorize(&self, token: &str) -> ApiResult<TokenGrant> {
        let guard = self.records.read().await;
        let record = guard
            .get(token)
            .ok_or_else(|| ApiError::unauthorized("Invalid access token"))?;
        Ok(TokenGrant {
            scopes: record.scopes.clone(),
        })
    }
}

struct TokenRecord {
    scopes: HashSet<Scope>,
}

impl TokenRecord {
    fn new(scopes: impl IntoIterator<Item = Scope>) -> Self {
        Self {
            scopes: scopes.into_iter().collect(),
        }
    }
}

struct TokenGrant {
    scopes: HashSet<Scope>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Scope {
    ConfidentialRead,
    ConfidentialWrite,
    ReportRead,
    ReportWrite,
    AuditWrite,
}

#[derive(Deserialize)]
struct UpdateDocumentRequest {
    contents: String,
}

#[derive(Serialize)]
struct WriteResponse {
    bytes_written: usize,
}

impl WriteResponse {
    fn from_bytes(bytes: usize) -> Self {
        Self {
            bytes_written: bytes,
        }
    }
}

#[derive(Serialize)]
struct DocumentResponse {
    path: String,
    contents: String,
}

impl DocumentResponse {
    fn new<Resource>(path: StrictPath<(Resource, ReadOnly)>, contents: String) -> Self {
        Self {
            path: path.strictpath_display().to_string(),
            contents,
        }
    }
}

#[derive(Deserialize)]
struct CaptureAuditRequest {
    source_doc: String,
    note: String,
}

#[derive(Serialize)]
struct AuditResponse {
    path: String,
}

impl AuditResponse {
    fn new(path: StrictPath<(AuditTrail, WriteOnly)>) -> Self {
        Self {
            path: path.strictpath_display().to_string(),
        }
    }
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn unauthorized(message: &str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.to_string(),
        }
    }

    fn forbidden(message: &str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.to_string(),
        }
    }

    fn internal(error: anyhow::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({
            "error": self.message,
        }));
        (self.status, body).into_response()
    }
}

fn sanitize(input: &str) -> String {
    input
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        .collect()
}

#[derive(Clone, Copy)]
enum VaultRoot {}
#[derive(Clone, Copy)]
enum ConfidentialDocs {}
#[derive(Clone, Copy)]
enum PublicReports {}
#[derive(Clone, Copy)]
enum ReadOnly {}
#[derive(Clone, Copy)]
enum WriteOnly {}
#[derive(Clone, Copy)]
enum AuditRoot {}
#[derive(Clone, Copy)]
enum AuditTrail {}
