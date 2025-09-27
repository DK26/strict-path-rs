//! JWT-based file service demonstrating authorization token integration.
//!
//! This Axum service demonstrates realistic JWT token handling with strict-path
//! authorization. Users authenticate with JWT tokens that encode their user ID
//! and capabilities. The service validates tokens, extracts capabilities, and
//! creates type-safe paths that encode both the resource domain and proven
//! permissions. This mirrors production authentication flows where JWT tokens
//! carry authorization data that must be validated before filesystem access.

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use strict_path::{PathBoundary, StrictPath};
use tokio::{net::TcpListener, signal, sync::RwLock};

const SERVICE_ROOT: &str = "demo_data/jwt_token_service";
const SERVER_ADDR: &str = "127.0.0.1:4020";
const JWT_SECRET: &[u8] = b"demo_secret_key_not_for_production_use";

type HmacSha256 = Hmac<Sha256>;

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
    Path(filename): Path<String>,
) -> ApiResult<Json<FileResponse>> {
    let session = state.authorize(&headers).await?;
    let personal_access = session.personal_files_access()?;
    let file_path = personal_access.strict_join(&filename)?;

    let content = file_path
        .read_to_string()
        .map_err(|e| ApiError::internal(anyhow!("Failed to read file: {e}")))?;

    Ok(Json(FileResponse {
        filename: filename.clone(),
        content,
        message: format!("Read personal file: {filename}"),
    }))
}

async fn write_personal_file(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(filename): Path<String>,
    Json(request): Json<WriteFileRequest>,
) -> ApiResult<Json<FileResponse>> {
    let session = state.authorize(&headers).await?;
    let personal_access = session.personal_files_access_with_write()?;
    let file_path = personal_access.strict_join(&filename)?;

    file_path
        .write(&request.content)
        .map_err(|e| ApiError::internal(anyhow!("Failed to write file: {e}")))?;

    Ok(Json(FileResponse {
        filename: filename.clone(),
        content: request.content,
        message: format!("Wrote personal file: {filename}"),
    }))
}

async fn delete_personal_file(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(filename): Path<String>,
) -> ApiResult<Json<FileResponse>> {
    let session = state.authorize(&headers).await?;
    let personal_access = session.personal_files_access_with_delete()?;
    let file_path = personal_access.strict_join(&filename)?;

    let content = file_path.read_to_string().unwrap_or_default();
    file_path
        .remove_file()
        .map_err(|e| ApiError::internal(anyhow!("Failed to delete file: {e}")))?;

    Ok(Json(FileResponse {
        filename: filename.clone(),
        content,
        message: format!("Deleted personal file: {filename}"),
    }))
}

// Shared file endpoints (require SharedFiles capability)
async fn read_shared_file(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(filename): Path<String>,
) -> ApiResult<Json<FileResponse>> {
    let session = state.authorize(&headers).await?;
    let shared_access = session.shared_files_access()?;
    let file_path = shared_access.strict_join(&filename)?;

    let content = file_path
        .read_to_string()
        .map_err(|e| ApiError::internal(anyhow!("Failed to read shared file: {e}")))?;

    Ok(Json(FileResponse {
        filename: filename.clone(),
        content,
        message: format!("Read shared file: {filename}"),
    }))
}

async fn write_shared_file(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(filename): Path<String>,
    Json(request): Json<WriteFileRequest>,
) -> ApiResult<Json<FileResponse>> {
    let session = state.authorize(&headers).await?;
    let shared_access = session.shared_files_access_with_write()?;
    let file_path = shared_access.strict_join(&filename)?;

    file_path
        .write(&request.content)
        .map_err(|e| ApiError::internal(anyhow!("Failed to write shared file: {e}")))?;

    Ok(Json(FileResponse {
        filename: filename.clone(),
        content: request.content,
        message: format!("Wrote shared file: {filename}"),
    }))
}

// Admin endpoint (requires AdminLogs capability)
async fn read_admin_logs(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(logfile): Path<String>,
) -> ApiResult<Json<FileResponse>> {
    let session = state.authorize(&headers).await?;
    let admin_access = session.admin_logs_access()?;
    let file_path = admin_access.strict_join(&logfile)?;

    let content = file_path
        .read_to_string()
        .map_err(|e| ApiError::internal(anyhow!("Failed to read log file: {e}")))?;

    Ok(Json(FileResponse {
        filename: logfile.clone(),
        content,
        message: format!("Read admin log: {logfile}"),
    }))
}

#[derive(Clone)]
struct AppState {
    auth_service: AuthService,
    workspace: FileWorkspace,
}

type SharedState = Arc<AppState>;
type ApiResult<T> = std::result::Result<T, ApiError>;

impl AppState {
    async fn authorize(&self, headers: &HeaderMap) -> ApiResult<AuthenticatedSession> {
        let token = extract_bearer_token(headers)?;
        let claims = self.auth_service.validate_token(&token).await?;
        let workspace_access = self.workspace.create_session(&claims)?;
        Ok(AuthenticatedSession {
            claims,
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

#[derive(Clone)]
struct AuthService {
    users: Arc<RwLock<HashMap<String, UserRecord>>>,
}

impl AuthService {
    fn new() -> Self {
        let mut users = HashMap::new();

        // Alice has full permissions
        users.insert(
            "alice".to_string(),
            UserRecord {
                username: "alice".to_string(),
                password_hash: "password123".to_string(), // In reality, this would be hashed
                user_id: 1,
                capabilities: vec![
                    Capability::PersonalFilesRead,
                    Capability::PersonalFilesWrite,
                    Capability::PersonalFilesDelete,
                    Capability::SharedFilesRead,
                    Capability::SharedFilesWrite,
                    Capability::AdminLogsRead,
                ],
            },
        );

        // Bob has read-only access
        users.insert(
            "bob".to_string(),
            UserRecord {
                username: "bob".to_string(),
                password_hash: "password123".to_string(),
                user_id: 2,
                capabilities: vec![Capability::PersonalFilesRead, Capability::SharedFilesRead],
            },
        );

        // Charlie is a moderator with shared file write access
        users.insert(
            "charlie".to_string(),
            UserRecord {
                username: "charlie".to_string(),
                password_hash: "password123".to_string(),
                user_id: 3,
                capabilities: vec![
                    Capability::PersonalFilesRead,
                    Capability::PersonalFilesWrite,
                    Capability::SharedFilesRead,
                    Capability::SharedFilesWrite,
                ],
            },
        );

        Self {
            users: Arc::new(RwLock::new(users)),
        }
    }

    async fn sample_users(&self) -> Vec<UserRecord> {
        self.users.read().await.values().cloned().collect()
    }

    async fn authenticate(&self, username: &str, password: &str) -> ApiResult<String> {
        let users = self.users.read().await;
        let user = users
            .get(username)
            .ok_or_else(|| ApiError::unauthorized("Invalid username or password"))?;

        if user.password_hash != password {
            return Err(ApiError::unauthorized("Invalid username or password"));
        }

        let claims = TokenClaims {
            user_id: user.user_id,
            username: user.username.clone(),
            capabilities: user.capabilities.clone(),
            exp: (Utc::now() + Duration::hours(24)).timestamp() as u64,
            iat: Utc::now().timestamp() as u64,
        };

        self.create_token(&claims)
    }

    fn create_token(&self, claims: &TokenClaims) -> ApiResult<String> {
        let header = JwtHeader {
            alg: "HS256".to_string(),
            typ: "JWT".to_string(),
        };

        let header_json = serde_json::to_string(&header)
            .map_err(|e| ApiError::internal(anyhow!("Failed to serialize header: {e}")))?;
        let claims_json = serde_json::to_string(claims)
            .map_err(|e| ApiError::internal(anyhow!("Failed to serialize claims: {e}")))?;

        let header_b64 = base64_url_encode(header_json.as_bytes());
        let claims_b64 = base64_url_encode(claims_json.as_bytes());

        let message = format!("{}.{}", header_b64, claims_b64);

        let mut mac = HmacSha256::new_from_slice(JWT_SECRET)
            .map_err(|e| ApiError::internal(anyhow!("Failed to create HMAC: {e}")))?;
        mac.update(message.as_bytes());
        let signature = mac.finalize().into_bytes();
        let signature_b64 = base64_url_encode(&signature);

        Ok(format!("{}.{}", message, signature_b64))
    }

    async fn validate_token(&self, token: &str) -> ApiResult<TokenClaims> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(ApiError::unauthorized("Invalid JWT format"));
        }

        let message = format!("{}.{}", parts[0], parts[1]);

        // Verify signature
        let mut mac = HmacSha256::new_from_slice(JWT_SECRET)
            .map_err(|e| ApiError::internal(anyhow!("Failed to create HMAC: {e}")))?;
        mac.update(message.as_bytes());
        let expected_signature = mac.finalize().into_bytes();
        let expected_signature_b64 = base64_url_encode(&expected_signature);

        if parts[2] != expected_signature_b64 {
            return Err(ApiError::unauthorized("Invalid JWT signature"));
        }

        // Decode claims
        let claims_json = base64_url_decode(parts[1])
            .map_err(|_| ApiError::unauthorized("Invalid JWT claims encoding"))?;
        let claims: TokenClaims = serde_json::from_slice(&claims_json)
            .map_err(|_| ApiError::unauthorized("Invalid JWT claims format"))?;

        // Check expiration
        let now = Utc::now().timestamp() as u64;
        if claims.exp < now {
            return Err(ApiError::unauthorized("JWT token has expired"));
        }

        Ok(claims)
    }
}

#[derive(Clone, Debug)]
struct UserRecord {
    username: String,
    password_hash: String,
    user_id: u64,
    capabilities: Vec<Capability>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TokenClaims {
    user_id: u64,
    username: String,
    capabilities: Vec<Capability>,
    exp: u64, // expiration timestamp
    iat: u64, // issued at timestamp
}

#[derive(Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
enum Capability {
    PersonalFilesRead,
    PersonalFilesWrite,
    PersonalFilesDelete,
    SharedFilesRead,
    SharedFilesWrite,
    AdminLogsRead,
}

// Authorization-aware marker types
struct PersonalFiles<Caps>(std::marker::PhantomData<Caps>);
struct SharedFiles<Caps>(std::marker::PhantomData<Caps>);
struct AdminLogs<Caps>(std::marker::PhantomData<Caps>);

// Capability marker types
struct CanRead;
struct CanWrite;
struct CanDelete;

#[derive(Clone)]
struct FileWorkspace {
    personal_root: PathBoundary<PersonalFiles<CanRead>>,
    shared_root: PathBoundary<SharedFiles<CanRead>>,
    admin_root: PathBoundary<AdminLogs<CanRead>>,
}

impl FileWorkspace {
    fn new(root: impl AsRef<Path>) -> Result<Self> {
        let personal_root = PathBoundary::try_new_create(root.join("personal"))?
            .rebrand::<PersonalFiles<CanRead>>();
        let shared_root =
            PathBoundary::try_new_create(root.join("shared"))?.rebrand::<SharedFiles<CanRead>>();
        let admin_root =
            PathBoundary::try_new_create(root.join("admin"))?.rebrand::<AdminLogs<CanRead>>();

        Ok(Self {
            personal_root,
            shared_root,
            admin_root,
        })
    }

    fn create_session(&self, claims: &TokenClaims) -> Result<WorkspaceAccess> {
        Ok(WorkspaceAccess {
            claims: claims.clone(),
            personal_root: self.personal_root.clone(),
            shared_root: self.shared_root.clone(),
            admin_root: self.admin_root.clone(),
        })
    }
}

#[derive(Clone)]
struct WorkspaceAccess {
    claims: TokenClaims,
    personal_root: PathBoundary<PersonalFiles<CanRead>>,
    shared_root: PathBoundary<SharedFiles<CanRead>>,
    admin_root: PathBoundary<AdminLogs<CanRead>>,
}

struct AuthenticatedSession {
    claims: TokenClaims,
    workspace_access: WorkspaceAccess,
}

impl AuthenticatedSession {
    fn personal_files_access(&self) -> ApiResult<&PathBoundary<PersonalFiles<CanRead>>> {
        if self
            .claims
            .capabilities
            .contains(&Capability::PersonalFilesRead)
        {
            Ok(&self.workspace_access.personal_root)
        } else {
            Err(ApiError::forbidden("Missing PersonalFilesRead capability"))
        }
    }

    fn personal_files_access_with_write(
        &self,
    ) -> ApiResult<PathBoundary<PersonalFiles<(CanRead, CanWrite)>>> {
        if self
            .claims
            .capabilities
            .contains(&Capability::PersonalFilesRead)
            && self
                .claims
                .capabilities
                .contains(&Capability::PersonalFilesWrite)
        {
            Ok(self
                .workspace_access
                .personal_root
                .rebrand::<PersonalFiles<(CanRead, CanWrite)>>())
        } else {
            Err(ApiError::forbidden("Missing PersonalFilesWrite capability"))
        }
    }

    fn personal_files_access_with_delete(
        &self,
    ) -> ApiResult<PathBoundary<PersonalFiles<(CanRead, CanWrite, CanDelete)>>> {
        if self
            .claims
            .capabilities
            .contains(&Capability::PersonalFilesRead)
            && self
                .claims
                .capabilities
                .contains(&Capability::PersonalFilesWrite)
            && self
                .claims
                .capabilities
                .contains(&Capability::PersonalFilesDelete)
        {
            Ok(self
                .workspace_access
                .personal_root
                .rebrand::<PersonalFiles<(CanRead, CanWrite, CanDelete)>>())
        } else {
            Err(ApiError::forbidden(
                "Missing PersonalFilesDelete capability",
            ))
        }
    }

    fn shared_files_access(&self) -> ApiResult<&PathBoundary<SharedFiles<CanRead>>> {
        if self
            .claims
            .capabilities
            .contains(&Capability::SharedFilesRead)
        {
            Ok(&self.workspace_access.shared_root)
        } else {
            Err(ApiError::forbidden("Missing SharedFilesRead capability"))
        }
    }

    fn shared_files_access_with_write(
        &self,
    ) -> ApiResult<PathBoundary<SharedFiles<(CanRead, CanWrite)>>> {
        if self
            .claims
            .capabilities
            .contains(&Capability::SharedFilesRead)
            && self
                .claims
                .capabilities
                .contains(&Capability::SharedFilesWrite)
        {
            Ok(self
                .workspace_access
                .shared_root
                .rebrand::<SharedFiles<(CanRead, CanWrite)>>())
        } else {
            Err(ApiError::forbidden("Missing SharedFilesWrite capability"))
        }
    }

    fn admin_logs_access(&self) -> ApiResult<&PathBoundary<AdminLogs<CanRead>>> {
        if self
            .claims
            .capabilities
            .contains(&Capability::AdminLogsRead)
        {
            Ok(&self.workspace_access.admin_root)
        } else {
            Err(ApiError::forbidden("Missing AdminLogsRead capability"))
        }
    }
}

// Request/Response types
#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

#[derive(Deserialize)]
struct WriteFileRequest {
    content: String,
}

#[derive(Serialize)]
struct FileResponse {
    filename: String,
    content: String,
    message: String,
}

// Error handling
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
            "error": self.message
        }));
        (self.status, body).into_response()
    }
}

// Utility functions for base64url encoding (simplified for demo)
fn base64_url_encode(input: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.encode(input)
}

fn base64_url_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.decode(input)
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
