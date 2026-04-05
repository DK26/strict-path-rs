//! Multi-tenant document service with Axum demonstrating marker-based permissions.
//!
//! Tenants authenticate once per request. The authorization layer returns typed
//! capabilities such as `VirtualRoot<(WorkspaceStorage, WorkspaceWrite)>` for
//! writers, `VirtualRoot<(WorkspaceStorage, WorkspaceRead)>` for readers, and
//! `VirtualRoot<(AuditStorage, AuditRead)>` for auditors. The tuple markers encode
//! **resource + permission**, preventing writable paths from leaking into read-only
//! routes (and vice versa).

mod types;
mod workspace;

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::{net::TcpListener, signal};

use types::{
    ApiError, ApiResult, AuditResponse, CaptureAuditRequest, CreateDocumentRequest,
    DocumentResponse, ImportTemplateRequest, ListAuditResponse, ListDocumentsResponse,
};
use workspace::{TemplateLibrary, TenantDirectoryRegistry, TokenStore};

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
    ) -> ApiResult<workspace::TenantAccess> {
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
        .route("/api/tenant/:tenant_id/audit", get(list_audit_exports))
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
        println!("  - {token}");
    }
    println!("\nUse the tokens above via the `X-Access-Token` header.\n");
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

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

async fn create_document(
    State(state): State<SharedState>,
    Path(tenant_id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<CreateDocumentRequest>,
) -> ApiResult<Json<DocumentResponse>> {
    let access = state.authorize_request(&headers, &tenant_id).await?;
    let workspace = access.workspace_writer()?;

    let CreateDocumentRequest { path, contents } = payload;
    let join_result =
        tokio::task::spawn_blocking(move || workspace.write_document(&path, &contents))
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
        let original_doc = workspace_reader.locate_document(&source)?;
        audit_reader.capture_for_review(&original_doc, &audit_id)
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
