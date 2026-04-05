//! JWT-based file service demonstrating authorization token integration.
//!
//! This Axum service demonstrates realistic JWT token handling with strict-path
//! authorization. Users authenticate with JWT tokens that encode their user ID
//! and capabilities. The service validates tokens, extracts capabilities, and
//! creates type-safe paths that encode both the resource domain and proven
//! permissions. This mirrors production authentication flows where JWT tokens
//! carry authorization data that must be validated before filesystem access.

mod auth;
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

use auth::AuthService;
use types::{ApiError, ApiResult, FileResponse, LoginRequest, LoginResponse, WriteFileRequest};
use workspace::{AuthenticatedSession, FileWorkspace};

const SERVICE_ROOT: &str = "demo_data/jwt_token_service";
const SERVER_ADDR: &str = "127.0.0.1:4020";

#[tokio::main]
async fn main() -> Result<()> {
    bootstrap_service_data()?;

    let auth_service = AuthService::new();
    let workspace = FileWorkspace::new(SERVICE_ROOT)?;

    let state = Arc::new(AppState {
        auth_service,
        workspace,
    });

    print_launch_instructions(state.as_ref()).await;

    let app = Router::new()
        .route("/api/auth/login", post(login))
        .route(
            "/api/files/personal/:filename",
            get(read_personal_file)
                .put(write_personal_file)
                .delete(delete_personal_file),
        )
        .route(
            "/api/files/shared/:filename",
            get(read_shared_file).put(write_shared_file),
        )
        .route("/api/admin/logs/:logfile", get(read_admin_logs))
        .with_state(state);

    let addr: SocketAddr = SERVER_ADDR.parse().context("invalid listen address")?;
    println!("\nJWT Token Authorization Service listening on http://{addr}");
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
    println!("Sample user credentials for login:");
    let users = state.auth_service.sample_users().await;
    for user in users {
        println!("  - username: {}, password: password123", user.username);
    }
    println!("\nTo use:");
    println!("1. POST to /api/auth/login with {{\"username\": \"alice\", \"password\": \"password123\"}}");
    println!("2. Use the returned JWT token in Authorization: Bearer <token> header");
    println!("3. Access files based on your capabilities");
    println!();
}

#[derive(Clone)]
struct AppState {
    auth_service: AuthService,
    workspace: FileWorkspace,
}

type SharedState = Arc<AppState>;

impl AppState {
    async fn authorize(&self, headers: &HeaderMap) -> ApiResult<AuthenticatedSession> {
        let token = extract_bearer_token(headers)?;
        let claims = self.auth_service.validate_token(&token).await?;
        let workspace_access = self.workspace.create_session(&claims)?;
        Ok(AuthenticatedSession {
            _claims: claims,
            workspace_access,
        })
    }
}

fn extract_bearer_token(headers: &HeaderMap) -> ApiResult<String> {
    let auth_header = headers
        .get("authorization")
        .ok_or_else(|| ApiError::unauthorized("Missing Authorization header"))?
        .to_str()
        .map_err(|_| ApiError::unauthorized("Invalid Authorization header format"))?;

    if !auth_header.starts_with("Bearer ") {
        return Err(ApiError::unauthorized(
            "Authorization header must use Bearer scheme",
        ));
    }

    Ok(auth_header[7..].to_string())
}

// Authentication endpoint
async fn login(
    State(state): State<SharedState>,
    Json(request): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let token = state
        .auth_service
        .authenticate(&request.username, &request.password)
        .await?;
    Ok(Json(LoginResponse { token }))
}

// Personal file endpoints (require PersonalFiles capability)
async fn read_personal_file(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(requested_file): Path<String>, // Untrusted: from HTTP request path
) -> ApiResult<Json<FileResponse>> {
    let session = state.authorize(&headers).await?;
    let personal_access = session.personal_files_access()?;
    let file_path = personal_access.strict_join(&requested_file)?;

    let content = file_path
        .read_to_string()
        .map_err(|err| ApiError::internal(anyhow!("Failed to read file: {err}")))?;

    Ok(Json(FileResponse {
        filename: requested_file.clone(),
        content,
        message: format!("Read personal file: {requested_file}"),
    }))
}

async fn write_personal_file(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(requested_file): Path<String>, // Untrusted: from HTTP request path
    Json(request): Json<WriteFileRequest>,
) -> ApiResult<Json<FileResponse>> {
    let session = state.authorize(&headers).await?;
    let personal_access = session.personal_files_access_with_write()?;
    let file_path = personal_access.strict_join(&requested_file)?;

    file_path
        .write(&request.content)
        .map_err(|err| ApiError::internal(anyhow!("Failed to write file: {err}")))?;

    Ok(Json(FileResponse {
        filename: requested_file.clone(),
        content: request.content,
        message: format!("Wrote personal file: {requested_file}"),
    }))
}

async fn delete_personal_file(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(requested_file): Path<String>, // Untrusted: from HTTP request path
) -> ApiResult<Json<FileResponse>> {
    let session = state.authorize(&headers).await?;
    let personal_access = session.personal_files_access_with_delete()?;
    let file_path = personal_access.strict_join(&requested_file)?;

    let content = file_path.read_to_string().unwrap_or_default();
    file_path
        .remove_file()
        .map_err(|err| ApiError::internal(anyhow!("Failed to delete file: {err}")))?;

    Ok(Json(FileResponse {
        filename: requested_file.clone(),
        content,
        message: format!("Deleted personal file: {requested_file}"),
    }))
}

// Shared file endpoints (require SharedFiles capability)
async fn read_shared_file(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(requested_file): Path<String>, // Untrusted: from HTTP request path
) -> ApiResult<Json<FileResponse>> {
    let session = state.authorize(&headers).await?;
    let shared_access = session.shared_files_access()?;
    let file_path = shared_access.strict_join(&requested_file)?;

    let content = file_path
        .read_to_string()
        .map_err(|err| ApiError::internal(anyhow!("Failed to read shared file: {err}")))?;

    Ok(Json(FileResponse {
        filename: requested_file.clone(),
        content,
        message: format!("Read shared file: {requested_file}"),
    }))
}

async fn write_shared_file(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(requested_file): Path<String>, // Untrusted: from HTTP request path
    Json(request): Json<WriteFileRequest>,
) -> ApiResult<Json<FileResponse>> {
    let session = state.authorize(&headers).await?;
    let shared_access = session.shared_files_access_with_write()?;
    let file_path = shared_access.strict_join(&requested_file)?;

    file_path
        .write(&request.content)
        .map_err(|err| ApiError::internal(anyhow!("Failed to write shared file: {err}")))?;

    Ok(Json(FileResponse {
        filename: requested_file.clone(),
        content: request.content,
        message: format!("Wrote shared file: {requested_file}"),
    }))
}

// Admin endpoint (requires AdminLogs capability)
async fn read_admin_logs(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(requested_log): Path<String>, // Untrusted: from HTTP request path
) -> ApiResult<Json<FileResponse>> {
    let session = state.authorize(&headers).await?;
    let admin_access = session.admin_logs_access()?;
    let file_path = admin_access.strict_join(&requested_log)?;

    let content = file_path
        .read_to_string()
        .map_err(|err| ApiError::internal(anyhow!("Failed to read log file: {err}")))?;

    Ok(Json(FileResponse {
        filename: requested_log.clone(),
        content,
        message: format!("Read admin log: {requested_log}"),
    }))
}

fn bootstrap_service_data() -> Result<()> {
    let root = std::path::Path::new(SERVICE_ROOT);
    let personal = root.join("personal");
    let shared = root.join("shared");
    let admin = root.join("admin");

    std::fs::create_dir_all(&personal)?;
    std::fs::create_dir_all(&shared)?;
    std::fs::create_dir_all(&admin)?;

    // Create sample files
    std::fs::write(
        personal.join("notes.txt"),
        "Personal notes: Remember to use strict paths!",
    )?;
    std::fs::write(
        personal.join("diary.txt"),
        "Dear diary, today I learned about authorization markers.",
    )?;

    std::fs::write(
        shared.join("team_doc.md"),
        "# Team Document\n\nThis is a shared team document.",
    )?;
    std::fs::write(
        shared.join("project_plan.txt"),
        "Project plan: Implement authorization system",
    )?;

    std::fs::write(admin.join("access.log"), "2024-01-01 10:00:00 - User alice accessed /api/files/personal/notes.txt\n2024-01-01 10:05:00 - User bob attempted unauthorized access")?;
    std::fs::write(
        admin.join("error.log"),
        "2024-01-01 09:55:00 - ERROR: Failed to validate JWT token",
    )?;

    Ok(())
}
