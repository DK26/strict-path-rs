//! Multi-tenant document service with Axum demonstrating marker-based permissions.
//!
//! Tenants authenticate once per request. The authorization layer returns typed
//! capabilities such as `VirtualRoot<(WorkspaceStorage, WorkspaceWrite)>` for
//! writers, `VirtualRoot<(WorkspaceStorage, WorkspaceRead)>` for readers, and
//! `VirtualRoot<(AuditStorage, AuditRead)>` for auditors. The tuple markers encode
//! **resource + permission**, preventing writable paths from leaking into read-only
//! routes (and vice versa).

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
};
use strict_path::{PathBoundary, StrictPath, VirtualPath, VirtualRoot};
use tokio::{net::TcpListener, signal, sync::RwLock};

#[tokio::main]
async fn main() -> Result<()> {
    bootstrap_templates()?;
    let template_library = TemplateLibrary::bootstrap("shared/templates")?;
    let tenant_registry = TenantDirectoryRegistry::new("tenants")?;
    let token_store = TokenStore::with_samples();

    let state = Arc::new(AppState {
        tokens: token_store,
        tenants: tenant_registry,
        templates: template_library,
    });

    print_launch_instructions(state.as_ref()).await;

    let app = Router::new()
        .route(
            "/api/tenant/:tenant_id/documents",
            post(create_document).get(list_documents),
        )
        .route(
            "/api/tenant/:tenant_id/documents/import-template",
            post(import_template),
        )
        .route(
            "/api/tenant/:tenant_id/audit/export",
            post(capture_audit_export),
        )
        .route(
            "/api/tenant/:tenant_id/audit",
            get(list_audit_exports),
        )
        .with_state(state.clone());

    let addr: SocketAddr = "127.0.0.1:4007".parse().expect("valid socket address");
    println!("\nTenant workspace service listening on http://{addr}");
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

async fn print_launch_instructions(state: &AppState) {
    let tokens = state.tokens.all_tokens().await;
    println!("Sample access tokens:");
    for token in tokens {
        println!("  - {}", token);
    }
    println!("\nUse the tokens above via the `X-Access-Token` header.\n");
}

async fn create_document(
    State(state): State<SharedState>,
    Path(tenant_id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<CreateDocumentRequest>,
) -> ApiResult<Json<DocumentResponse>> {
    let access = state.authorize_request(&headers, &tenant_id).await?;
    let workspace = access.workspace_writer()?;

    let CreateDocumentRequest { path, contents } = payload;
    let join_result = tokio::task::spawn_blocking(move || workspace.write_document(&path, &contents))
        .await
        .map_err(|err| ApiError::internal(anyhow!("task join error: {err}")))?;
    let handle = join_result.map_err(ApiError::internal)?;

    Ok(Json(DocumentResponse::from_virtual(&handle)))
}

async fn import_template(
    State(state): State<SharedState>,
    Path(tenant_id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<ImportTemplateRequest>,
) -> ApiResult<Json<DocumentResponse>> {
    let access = state.authorize_request(&headers, &tenant_id).await?;
    let workspace = access.workspace_writer()?;
    let templates = state.templates.clone();

    let ImportTemplateRequest {
        template_name,
        destination,
    } = payload;

    let join_result = tokio::task::spawn_blocking(move || {
        let template = templates.fetch_template(&template_name)?;
        workspace.import_template(&template, &destination)
    })
    .await
    .map_err(|err| ApiError::internal(anyhow!("task join error: {err}")))?;
    let copied = join_result.map_err(ApiError::internal)?;

    Ok(Json(DocumentResponse::from_virtual(&copied)))
}

async fn list_documents(
    State(state): State<SharedState>,
    Path(tenant_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<ListDocumentsResponse>> {
    let access = state.authorize_request(&headers, &tenant_id).await?;
    let workspace = access.workspace_reader()?;

    let join_result = tokio::task::spawn_blocking(move || workspace.list_documents())
        .await
        .map_err(|err| ApiError::internal(anyhow!("task join error: {err}")))?;
    let documents = join_result.map_err(ApiError::internal)?;

    Ok(Json(ListDocumentsResponse::from_documents(documents)))
}

async fn capture_audit_export(
    State(state): State<SharedState>,
    Path(tenant_id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<CaptureAuditRequest>,
) -> ApiResult<Json<AuditResponse>> {
    let access = state.authorize_request(&headers, &tenant_id).await?;
    let workspace_reader = access.workspace_reader()?;
    let audit_reader = access.audit_reader()?;

    let CaptureAuditRequest { source, audit_id } = payload;
    let join_result = tokio::task::spawn_blocking(move || {
        let source_doc = workspace_reader.locate_document(&source)?;
        audit_reader.capture_for_review(&source_doc, &audit_id)
    })
    .await
    .map_err(|err| ApiError::internal(anyhow!("task join error: {err}")))?;
    let result = join_result.map_err(ApiError::internal)?;

    Ok(Json(AuditResponse::from_virtual(&result)))
}

async fn list_audit_exports(
    State(state): State<SharedState>,
    Path(tenant_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<ListAuditResponse>> {
    let access = state.authorize_request(&headers, &tenant_id).await?;
    let audit_reader = access.audit_reader()?;

    let join_result = tokio::task::spawn_blocking(move || audit_reader.list_exports())
        .await
        .map_err(|err| ApiError::internal(anyhow!("task join error: {err}")))?;
    let exports = join_result.map_err(ApiError::internal)?;

    Ok(Json(ListAuditResponse::from_exports(exports)))
}

fn bootstrap_templates() -> Result<()> {
    std::fs::create_dir_all("shared/templates")?;
    std::fs::write(
        "shared/templates/invoice.txt",
        "Invoice Template\nLine items: [[items]]\n",
    )?;
    std::fs::write(
        "shared/templates/security.md",
        "# Security Checklist\n- Enforce markers for every tenant boundary.\n- Never join untrusted paths.\n",
    )?;
    Ok(())
}

type ApiResult<T> = std::result::Result<T, ApiError>;
type SharedState = Arc<AppState>;

#[derive(Clone)]
struct AppState {
    tokens: TokenStore,
    tenants: TenantDirectoryRegistry,
    templates: TemplateLibrary,
}

impl AppState {
    async fn authorize_request(
        &self,
        headers: &HeaderMap,
        tenant_id: &str,
    ) -> ApiResult<TenantAccess> {
        let token = extract_token(headers)?;
        let scopes = self.tokens.authorize(&token, tenant_id).await?;
        self.tenants
            .build_access(tenant_id, scopes)
            .await
            .map_err(ApiError::internal)
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
struct TokenStore {
    records: Arc<RwLock<HashMap<String, TokenRecord>>>,
}

impl TokenStore {
    fn with_samples() -> Self {
        let mut map = HashMap::new();
        map.insert(
            "acme-editor-token".to_string(),
            TokenRecord::new(
                "acme_corp",
                [Scope::WorkspaceRead, Scope::WorkspaceWrite],
            ),
        );
        map.insert(
            "acme-auditor-token".to_string(),
            TokenRecord::new(
                "acme_corp",
                [Scope::WorkspaceRead, Scope::AuditRead],
            ),
        );
        map.insert(
            "globex-editor-token".to_string(),
            TokenRecord::new(
                "globex",
                [Scope::WorkspaceRead, Scope::WorkspaceWrite],
            ),
        );
        Self {
            records: Arc::new(RwLock::new(map)),
        }
    }

    async fn all_tokens(&self) -> Vec<String> {
        let guard = self.records.read().await;
        guard.keys().cloned().collect()
    }

    async fn authorize(&self, token: &str, tenant_id: &str) -> ApiResult<TenantScopes> {
        let guard = self.records.read().await;
        let record = guard
            .get(token)
            .ok_or_else(|| ApiError::unauthorized("Invalid access token"))?;
        if record.tenant_id != tenant_id {
            return Err(ApiError::forbidden("Token does not match tenant"));
        }
        Ok(record.scopes())
    }
}

#[derive(Clone)]
struct TokenRecord {
    tenant_id: String,
    scopes: HashSet<Scope>,
}

impl TokenRecord {
    fn new(tenant_id: &str, scopes: impl IntoIterator<Item = Scope>) -> Self {
        let scopes = scopes.into_iter().collect();
        Self {
            tenant_id: tenant_id.to_string(),
            scopes,
        }
    }

    fn scopes(&self) -> TenantScopes {
        TenantScopes {
            workspace_read: self.scopes.contains(&Scope::WorkspaceRead),
            workspace_write: self.scopes.contains(&Scope::WorkspaceWrite),
            audit_read: self.scopes.contains(&Scope::AuditRead),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Scope {
    WorkspaceRead,
    WorkspaceWrite,
    AuditRead,
}

#[derive(Clone, Copy, Debug)]
struct TenantScopes {
    workspace_read: bool,
    workspace_write: bool,
    audit_read: bool,
}

impl TenantScopes {
    fn workspace_reader_allowed(self) -> bool {
        self.workspace_read || self.workspace_write
    }
}

#[derive(Clone)]
struct TemplateLibrary {
    boundary: PathBoundary<TemplateStorage>,
}

impl TemplateLibrary {
    fn bootstrap(root: &str) -> Result<Self> {
        let boundary = PathBoundary::<TemplateStorage>::try_new(root)?;
        Ok(Self { boundary })
    }

    fn fetch_template(&self, name: &str) -> Result<StrictPath<TemplateStorage>> {
        self.boundary
            .strict_join(name)
            .with_context(|| format!("Template {name} escaped library"))
    }
}

#[derive(Clone)]
struct TenantDirectoryRegistry {
    base: PathBoundary<MultiTenantRoot>,
    cache: Arc<RwLock<HashMap<String, Arc<TenantRoots>>>>,
}

impl TenantDirectoryRegistry {
    fn new(root: &str) -> Result<Self> {
        let base = PathBoundary::<MultiTenantRoot>::try_new_create(root)?;
        Ok(Self {
            base,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    async fn build_access(
        &self,
        tenant_id: &str,
        scopes: TenantScopes,
    ) -> Result<TenantAccess> {
        let roots = self.obtain_roots(tenant_id).await?;
        let workspace_write = if scopes.workspace_write {
            Some(roots.workspace_write_access()?)
        } else {
            None
        };
        let workspace_read = if scopes.workspace_reader_allowed() {
            Some(roots.workspace_read_access()?)
        } else {
            None
        };
        let audit = if scopes.audit_read {
            Some(roots.audit_reader_access()?)
        } else {
            None
        };
        Ok(TenantAccess {
            workspace_write,
            workspace_read,
            audit,
        })
    }

    async fn obtain_roots(&self, tenant_id: &str) -> Result<Arc<TenantRoots>> {
        if let Some(existing) = self.cache.read().await.get(tenant_id).cloned() {
            return Ok(existing);
        }

        let base = self.base.clone();
        let tenant_key = tenant_id.to_string();
        let created = tokio::task::spawn_blocking(move || TenantRoots::create(base, tenant_key))
            .await
            .map_err(|err| anyhow!("tenant creation task failed: {err}"))??;

        let roots = Arc::new(created);
        let mut guard = self.cache.write().await;
        Ok(guard
            .entry(tenant_id.to_string())
            .or_insert_with(|| roots.clone())
            .clone())
    }
}

#[derive(Clone)]
struct TenantAccess {
    workspace_write: Option<WorkspaceWriteAccess>,
    workspace_read: Option<WorkspaceReadAccess>,
    audit: Option<AuditReadAccess>,
}

impl TenantAccess {
    fn workspace_writer(&self) -> ApiResult<WorkspaceWriteAccess> {
        self.workspace_write
            .as_ref()
            .cloned()
            .ok_or_else(|| ApiError::forbidden("Token missing workspace-write scope"))
    }

    fn workspace_reader(&self) -> ApiResult<WorkspaceReadAccess> {
        self.workspace_read
            .as_ref()
            .cloned()
            .ok_or_else(|| ApiError::forbidden("Token missing workspace-read scope"))
    }

    fn audit_reader(&self) -> ApiResult<AuditReadAccess> {
        self.audit
            .as_ref()
            .cloned()
            .ok_or_else(|| ApiError::forbidden("Token missing audit-read scope"))
    }
}

struct TenantRoots {
    workspace_boundary: PathBoundary<WorkspaceStorage>,
    audit_boundary: PathBoundary<AuditStorage>,
}

impl TenantRoots {
    fn create(base: PathBoundary<MultiTenantRoot>, tenant_id: String) -> Result<Self> {
        let tenant_root = base.strict_join(&tenant_id)?;
        tenant_root.create_dir_all()?;

        let workspace_dir = tenant_root.strict_join("workspace")?;
        workspace_dir.create_dir_all()?;
        let audit_dir = tenant_root.strict_join("audit")?;
        audit_dir.create_dir_all()?;

        let workspace_boundary = PathBoundary::<WorkspaceStorage>::try_new(
            workspace_dir.clone().unstrict(),
        )?;
        let audit_boundary =
            PathBoundary::<AuditStorage>::try_new(audit_dir.clone().unstrict())?;

        Ok(Self {
            workspace_boundary,
            audit_boundary,
        })
    }

    fn workspace_write_access(&self) -> Result<WorkspaceWriteAccess> {
        let writer_root = PathBoundary::<(WorkspaceStorage, WorkspaceWrite)>::try_new(
            self.workspace_boundary.as_ref(),
        )?
        .virtualize();
        Ok(WorkspaceWriteAccess { writer_root })
    }

    fn workspace_read_access(&self) -> Result<WorkspaceReadAccess> {
        let reader_root = PathBoundary::<(WorkspaceStorage, WorkspaceRead)>::try_new(
            self.workspace_boundary.as_ref(),
        )?
        .virtualize();
        Ok(WorkspaceReadAccess { root: reader_root })
    }

    fn audit_reader_access(&self) -> Result<AuditReadAccess> {
        let reader_root = PathBoundary::<(AuditStorage, AuditRead)>::try_new(
            self.audit_boundary.as_ref(),
        )?
        .virtualize();
        Ok(AuditReadAccess { root: reader_root })
    }
}

#[derive(Clone)]
struct WorkspaceReadAccess {
    root: VirtualRoot<(WorkspaceStorage, WorkspaceRead)>,
}

impl WorkspaceReadAccess {
    fn list_documents(&self) -> Result<Vec<DocumentRecord>> {
        let mut records = Vec::new();
        let root_path = PathBuf::from(self.root.interop_path());
        for entry in std::fs::read_dir(&root_path)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let file_name = entry.file_name();
                let display_name = file_name.to_string_lossy().to_string();
                let joined = self
                    .root
                    .virtual_join(PathBuf::from(&file_name))
                    .with_context(|| {
                        format!("Workspace entry {display_name} rejected by boundary")
                    })?;
                let size = joined.metadata()?.len();
                records.push(DocumentRecord { path: joined, size });
            }
        }
        records.sort_by(|a, b| {
            let left = a.path.virtualpath_display().to_string();
            let right = b.path.virtualpath_display().to_string();
            left.cmp(&right)
        });
        Ok(records)
    }

    fn locate_document(
        &self,
        relative: &str,
    ) -> Result<VirtualPath<(WorkspaceStorage, WorkspaceRead)>> {
        let document = self.root.virtual_join(relative)?;
        if !document.exists() {
            return Err(anyhow!("Workspace document not found"));
        }
        Ok(document)
    }
}

#[derive(Clone)]
struct WorkspaceWriteAccess {
    writer_root: VirtualRoot<(WorkspaceStorage, WorkspaceWrite)>,
}

impl WorkspaceWriteAccess {
    fn write_document(
        &self,
        relative_path: &str,
        contents: &str,
    ) -> Result<VirtualPath<(WorkspaceStorage, WorkspaceWrite)>> {
        let document = self.writer_root.virtual_join(relative_path)?;
        document.create_parent_dir_all()?;
        document.write(contents.as_bytes())?;
        Ok(document)
    }

    fn import_template(
        &self,
        template: &StrictPath<TemplateStorage>,
        destination: &str,
    ) -> Result<VirtualPath<(WorkspaceStorage, WorkspaceWrite)>> {
        let target = self.writer_root.virtual_join(destination)?;
        target.create_parent_dir_all()?;
        let body = template.read_to_string()?;
        target.write(body.as_bytes())?;
        Ok(target)
    }
}

#[derive(Clone)]
struct AuditReadAccess {
    root: VirtualRoot<(AuditStorage, AuditRead)>,
}

impl AuditReadAccess {
    fn capture_for_review(
        &self,
        workspace_path: &VirtualPath<(WorkspaceStorage, WorkspaceRead)>,
        audit_id: &str,
    ) -> Result<VirtualPath<(AuditStorage, AuditRead)>> {
        let file_name = workspace_path
            .virtualpath_file_name()
            .map(|value| value.to_string_lossy().to_string())
            .ok_or_else(|| anyhow!("Workspace path requires a file name"))?;
        let relative = PathBuf::from("reviews").join(audit_id).join(&file_name);
        let audit_path = self.root.virtual_join(&relative)?;
        audit_path.create_parent_dir_all()?;
        let body = workspace_path.read_to_string()?;
        audit_path.write(body.as_bytes())?;
        Ok(audit_path)
    }

    fn list_exports(&self) -> Result<Vec<AuditRecord>> {
        let mut records = Vec::new();
        let root_path = PathBuf::from(self.root.interop_path());
        for entry in std::fs::read_dir(&root_path)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let file_name = entry.file_name();
                let display_name = file_name.to_string_lossy().to_string();
                let joined = self
                    .root
                    .virtual_join(PathBuf::from(&file_name))
                    .with_context(|| {
                        format!("Audit entry {display_name} rejected by boundary")
                    })?;
                let size = joined.metadata()?.len();
                records.push(AuditRecord { path: joined, size });
            }
        }
        records.sort_by(|a, b| {
            let left = a.path.virtualpath_display().to_string();
            let right = b.path.virtualpath_display().to_string();
            left.cmp(&right)
        });
        Ok(records)
    }
}

struct DocumentRecord {
    path: VirtualPath<(WorkspaceStorage, WorkspaceRead)>,
    size: u64,
}

struct AuditRecord {
    path: VirtualPath<(AuditStorage, AuditRead)>,
    size: u64,
}

#[derive(Deserialize)]
struct CreateDocumentRequest {
    path: String,
    contents: String,
}

#[derive(Deserialize)]
struct ImportTemplateRequest {
    template_name: String,
    destination: String,
}

#[derive(Deserialize)]
struct CaptureAuditRequest {
    source: String,
    audit_id: String,
}

#[derive(Serialize)]
struct DocumentResponse {
    document_path: String,
}

impl DocumentResponse {
    fn from_virtual<Marker>(path: &VirtualPath<Marker>) -> Self {
        Self {
            document_path: path.virtualpath_display().to_string(),
        }
    }
}

#[derive(Serialize)]
struct ListDocumentsResponse {
    documents: Vec<DocumentSummary>,
}

impl ListDocumentsResponse {
    fn from_documents(records: Vec<DocumentRecord>) -> Self {
        let documents = records
            .into_iter()
            .map(|record| DocumentSummary {
                document_path: record.path.virtualpath_display().to_string(),
                size: record.size,
            })
            .collect();
        Self { documents }
    }
}

#[derive(Serialize)]
struct DocumentSummary {
    document_path: String,
    size: u64,
}

#[derive(Serialize)]
struct AuditResponse {
    audit_path: String,
}

impl AuditResponse {
    fn from_virtual<Marker>(path: &VirtualPath<Marker>) -> Self {
        Self {
            audit_path: path.virtualpath_display().to_string(),
        }
    }
}

#[derive(Serialize)]
struct ListAuditResponse {
    exports: Vec<AuditSummary>,
}

impl ListAuditResponse {
    fn from_exports(records: Vec<AuditRecord>) -> Self {
        let exports = records
            .into_iter()
            .map(|record| AuditSummary {
                audit_path: record.path.virtualpath_display().to_string(),
                size: record.size,
            })
            .collect();
        Self { exports }
    }
}

#[derive(Serialize)]
struct AuditSummary {
    audit_path: String,
    size: u64,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
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
        let body = Json(ErrorBody {
            error: self.message,
        });
        (self.status, body).into_response()
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct MultiTenantRoot;
#[derive(Clone, Copy, Debug, Default)]
struct WorkspaceStorage;
#[derive(Clone, Copy, Debug, Default)]
struct WorkspaceRead;
#[derive(Clone, Copy, Debug, Default)]
struct WorkspaceWrite;
#[derive(Clone, Copy, Debug, Default)]
struct AuditStorage;
#[derive(Clone, Copy, Debug, Default)]
struct AuditRead;
#[derive(Clone, Copy, Debug, Default)]
struct TemplateStorage;
