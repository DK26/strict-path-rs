//! Document database service demonstrating authorization with database queries.
//!
//! This service shows how to connect file-system authorization with database
//! authorization patterns. Users have documents stored both in files and database
//! records. The authorization system ensures that a user can only access their
//! own documents through both file paths and database queries. The StrictPath
//! proof serves as compile-time evidence that the caller is authorized to access
//! specific user documents, which then allows database queries scoped to that
//! same user. This prevents authorization mix-ups between filesystem and database.

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{
    sqlite::{SqlitePool, SqlitePoolOptions},
    Row,
};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use strict_path::{PathBoundary, VirtualRoot};
use tokio::{net::TcpListener, signal, sync::RwLock};
use uuid::Uuid;

const SERVICE_ROOT: &str = "demo_data/database_auth_service";
const DATABASE_URL: &str = "sqlite:demo_data/database_auth_service/documents.db";
const SERVER_ADDR: &str = "127.0.0.1:4021";

#[tokio::main]
async fn main() -> Result<()> {
    bootstrap_service().await?;

    let db_pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect(DATABASE_URL)
        .await
        .context("Failed to connect to database")?;

    let auth_service = AuthService::new();
    let workspace = DocumentWorkspace::new(SERVICE_ROOT)?;

    let state = Arc::new(AppState {
        db_pool,
        auth_service,
        workspace,
    });

    print_launch_instructions(state.as_ref()).await;

    let app = Router::new()
        .route("/api/auth/login", post(login))
        .route("/api/documents", get(list_documents).post(create_document))
        .route(
            "/api/documents/:doc_id",
            get(get_document)
                .put(update_document)
                .delete(delete_document),
        )
        .route("/api/documents/:doc_id/content", get(get_document_content))
        .with_state(state);

    let addr: SocketAddr = SERVER_ADDR.parse().context("invalid listen address")?;
    println!("\nDatabase Authorization Service listening on http://{addr}");
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
    println!("Sample user credentials:");
    let users = state.auth_service.sample_users().await;
    for user in users {
        println!("  - User ID: {}, API Key: {}", user.user_id, user.api_key);
    }
    println!("\nTo use:");
    println!("1. POST to /api/auth/login with {{\"user_id\": 1, \"api_key\": \"key_alice\"}}");
    println!("2. Use the session token in X-Session-Token header");
    println!("3. Access documents (users can only see their own documents)");
    println!();
}

// Authentication
async fn login(
    State(state): State<SharedState>,
    Json(request): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let session = state
        .auth_service
        .authenticate(request.user_id, &request.api_key)
        .await?;
    Ok(Json(LoginResponse {
        session_token: session.session_token,
        user_id: session.user_id,
    }))
}

// Document endpoints with combined file + database authorization
async fn list_documents(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> ApiResult<Json<DocumentListResponse>> {
    let session = state.authorize(&headers).await?;
    let user_docs_access = session.user_documents_access()?;

    // Database query is scoped to the authorized user
    let documents = load_user_documents(
        &state.db_pool,
        session.claims.user_id,
        &user_docs_access, // Proof that caller is authorized for this user
        params.limit.unwrap_or(10),
        params.offset.unwrap_or(0),
    )
    .await?;

    Ok(Json(DocumentListResponse {
        documents,
        user_id: session.claims.user_id,
        total: documents.len(),
    }))
}

async fn create_document(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(request): Json<CreateDocumentRequest>,
) -> ApiResult<Json<DocumentResponse>> {
    let session = state.authorize(&headers).await?;
    let user_docs_access = session.user_documents_access_with_write()?;

    let doc_id = Uuid::new_v4();
    let created_at = Utc::now();

    // Create database record
    let document = create_user_document(
        &state.db_pool,
        session.claims.user_id,
        &user_docs_access,
        doc_id,
        &request.title,
        &request.content,
        created_at,
    )
    .await?;

    // Create file on disk
    let file_path = user_docs_access.virtual_join(&format!("{}.txt", doc_id))?;
    file_path
        .write(&request.content)
        .map_err(|e| ApiError::internal(anyhow!("Failed to write document file: {e}")))?;

    Ok(Json(DocumentResponse { document }))
}

async fn get_document(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(doc_id): Path<String>,
) -> ApiResult<Json<DocumentResponse>> {
    let session = state.authorize(&headers).await?;
    let user_docs_access = session.user_documents_access()?;

    let doc_uuid = Uuid::parse_str(&doc_id)
        .map_err(|_| ApiError::bad_request("Invalid document ID format"))?;

    let document = load_user_document_by_id(
        &state.db_pool,
        session.claims.user_id,
        &user_docs_access,
        doc_uuid,
    )
    .await?;

    Ok(Json(DocumentResponse { document }))
}

async fn update_document(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(doc_id): Path<String>,
    Json(request): Json<UpdateDocumentRequest>,
) -> ApiResult<Json<DocumentResponse>> {
    let session = state.authorize(&headers).await?;
    let user_docs_access = session.user_documents_access_with_write()?;

    let doc_uuid = Uuid::parse_str(&doc_id)
        .map_err(|_| ApiError::bad_request("Invalid document ID format"))?;

    // Update database record
    let document = update_user_document(
        &state.db_pool,
        session.claims.user_id,
        &user_docs_access,
        doc_uuid,
        request.title.as_deref(),
        request.content.as_deref(),
    )
    .await?;

    // Update file if content changed
    if let Some(content) = &request.content {
        let file_path = user_docs_access.virtual_join(&format!("{}.txt", doc_uuid))?;
        file_path
            .write(content)
            .map_err(|e| ApiError::internal(anyhow!("Failed to update document file: {e}")))?;
    }

    Ok(Json(DocumentResponse { document }))
}

async fn delete_document(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(doc_id): Path<String>,
) -> ApiResult<Json<DeleteResponse>> {
    let session = state.authorize(&headers).await?;
    let user_docs_access = session.user_documents_access_with_delete()?;

    let doc_uuid = Uuid::parse_str(&doc_id)
        .map_err(|_| ApiError::bad_request("Invalid document ID format"))?;

    // Delete from database
    delete_user_document(
        &state.db_pool,
        session.claims.user_id,
        &user_docs_access,
        doc_uuid,
    )
    .await?;

    // Delete file
    let file_path = user_docs_access.virtual_join(&format!("{}.txt", doc_uuid))?;
    match file_path.remove_file() {
        Ok(()) => {}
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(ApiError::internal(anyhow!(
                    "Failed to delete document file: {e}"
                )));
            }
        }
    }

    Ok(Json(DeleteResponse {
        message: format!("Document {} deleted successfully", doc_id),
        deleted_id: doc_uuid,
    }))
}

async fn get_document_content(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(doc_id): Path<String>,
) -> ApiResult<Json<ContentResponse>> {
    let session = state.authorize(&headers).await?;
    let user_docs_access = session.user_documents_access()?;

    let doc_uuid = Uuid::parse_str(&doc_id)
        .map_err(|_| ApiError::bad_request("Invalid document ID format"))?;

    // Verify user owns this document via database
    let _document = load_user_document_by_id(
        &state.db_pool,
        session.claims.user_id,
        &user_docs_access,
        doc_uuid,
    )
    .await?;

    // Read content from file system
    let file_path = user_docs_access.virtual_join(&format!("{}.txt", doc_uuid))?;
    let content = file_path
        .read_to_string()
        .map_err(|e| ApiError::internal(anyhow!("Failed to read document content: {e}")))?;

    Ok(Json(ContentResponse {
        document_id: doc_uuid,
        content,
    }))
}

#[derive(Clone)]
struct AppState {
    db_pool: SqlitePool,
    auth_service: AuthService,
    workspace: DocumentWorkspace,
}

type SharedState = Arc<AppState>;
type ApiResult<T> = std::result::Result<T, ApiError>;

impl AppState {
    async fn authorize(&self, headers: &HeaderMap) -> ApiResult<AuthenticatedSession> {
        let session_token = extract_session_token(headers)?;
        let claims = self.auth_service.validate_session(&session_token).await?;
        let workspace_access = self.workspace.create_session(&claims)?;

        Ok(AuthenticatedSession {
            claims,
            workspace_access,
        })
    }
}

fn extract_session_token(headers: &HeaderMap) -> ApiResult<String> {
    headers
        .get("x-session-token")
        .ok_or_else(|| ApiError::unauthorized("Missing X-Session-Token header"))?
        .to_str()
        .map_err(|_| ApiError::unauthorized("Invalid session token format"))?
        .to_string()
        .pipe(Ok)
}

// Database integration functions that require authorization proof
async fn load_user_documents<Caps>(
    pool: &SqlitePool,
    user_id: u64,
    _auth_proof: &VirtualRoot<Caps>, // Proof that caller is authorized for this user (capabilities marker)
    limit: u32,
    offset: u32,
) -> Result<Vec<Document>> {
    let rows = sqlx::query(
        "SELECT doc_id, user_id, title, created_at, updated_at 
         FROM documents 
         WHERE user_id = ? 
         ORDER BY created_at DESC 
         LIMIT ? OFFSET ?",
    )
    .bind(user_id as i64)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .context("Failed to load user documents")?;

    let mut documents = Vec::new();
    for row in rows {
        let doc_id: String = row.get("doc_id");
        let user_id: i64 = row.get("user_id");
        let title: String = row.get("title");
        let created_at: String = row.get("created_at");
        let updated_at: String = row.get("updated_at");

        documents.push(Document {
            id: Uuid::parse_str(&doc_id)?,
            user_id: user_id as u64,
            title,
            created_at: DateTime::parse_from_rfc3339(&created_at)?.with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&updated_at)?.with_timezone(&Utc),
        });
    }

    Ok(documents)
}

async fn load_user_document_by_id<Caps>(
    pool: &SqlitePool,
    user_id: u64,
    _auth_proof: &VirtualRoot<Caps>,
    doc_id: Uuid,
) -> ApiResult<Document> {
    let row = sqlx::query(
        "SELECT doc_id, user_id, title, created_at, updated_at 
         FROM documents 
         WHERE user_id = ? AND doc_id = ?",
    )
    .bind(user_id as i64)
    .bind(doc_id.to_string())
    .fetch_optional(pool)
    .await
    .map_err(|e| ApiError::internal(anyhow!("Database error: {e}")))?
    .ok_or_else(|| ApiError::not_found("Document not found or not owned by user"))?;

    let user_id: i64 = row.get("user_id");
    let title: String = row.get("title");
    let created_at: String = row.get("created_at");
    let updated_at: String = row.get("updated_at");

    Ok(Document {
        id: doc_id,
        user_id: user_id as u64,
        title,
        created_at: DateTime::parse_from_rfc3339(&created_at)
            .map_err(|e| ApiError::internal(anyhow!("Date parse error: {e}")))?
            .with_timezone(&Utc),
        updated_at: DateTime::parse_from_rfc3339(&updated_at)
            .map_err(|e| ApiError::internal(anyhow!("Date parse error: {e}")))?
            .with_timezone(&Utc),
    })
}

async fn create_user_document<Caps>(
    pool: &SqlitePool,
    user_id: u64,
    _auth_proof: &VirtualRoot<Caps>,
    doc_id: Uuid,
    title: &str,
    _content: &str, // Content goes in file, not database
    created_at: DateTime<Utc>,
) -> Result<Document> {
    sqlx::query(
        "INSERT INTO documents (doc_id, user_id, title, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(doc_id.to_string())
    .bind(user_id as i64)
    .bind(title)
    .bind(created_at.to_rfc3339())
    .bind(created_at.to_rfc3339())
    .execute(pool)
    .await
    .context("Failed to create document")?;

    Ok(Document {
        id: doc_id,
        user_id,
        title: title.to_string(),
        created_at,
        updated_at: created_at,
    })
}

async fn update_user_document<Caps>(
    pool: &SqlitePool,
    user_id: u64,
    _auth_proof: &VirtualRoot<Caps>,
    doc_id: Uuid,
    title: Option<&str>,
    _content: Option<&str>, // Content updates go to file
) -> ApiResult<Document> {
    let updated_at = Utc::now();

    if let Some(title) = title {
        sqlx::query(
            "UPDATE documents SET title = ?, updated_at = ? 
             WHERE user_id = ? AND doc_id = ?",
        )
        .bind(title)
        .bind(updated_at.to_rfc3339())
        .bind(user_id as i64)
        .bind(doc_id.to_string())
        .execute(pool)
        .await
        .map_err(|e| ApiError::internal(anyhow!("Failed to update document: {e}")))?;
    }

    // Return updated document
    load_user_document_by_id(pool, user_id, _auth_proof, doc_id).await
}

async fn delete_user_document<Caps>(
    pool: &SqlitePool,
    user_id: u64,
    _auth_proof: &VirtualRoot<Caps>,
    doc_id: Uuid,
) -> ApiResult<()> {
    let result = sqlx::query("DELETE FROM documents WHERE user_id = ? AND doc_id = ?")
        .bind(user_id as i64)
        .bind(doc_id.to_string())
        .execute(pool)
        .await
        .map_err(|e| ApiError::internal(anyhow!("Failed to delete document: {e}")))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found(
            "Document not found or not owned by user",
        ));
    }

    Ok(())
}

#[derive(Clone)]
struct AuthService {
    sessions: Arc<RwLock<HashMap<String, SessionClaims>>>,
    users: Arc<RwLock<HashMap<u64, UserRecord>>>,
}

impl AuthService {
    fn new() -> Self {
        let mut users = HashMap::new();

        users.insert(
            1,
            UserRecord {
                user_id: 1,
                username: "alice".to_string(),
                api_key: "key_alice".to_string(),
            },
        );

        users.insert(
            2,
            UserRecord {
                user_id: 2,
                username: "bob".to_string(),
                api_key: "key_bob".to_string(),
            },
        );

        users.insert(
            3,
            UserRecord {
                user_id: 3,
                username: "charlie".to_string(),
                api_key: "key_charlie".to_string(),
            },
        );

        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            users: Arc::new(RwLock::new(users)),
        }
    }

    async fn sample_users(&self) -> Vec<UserRecord> {
        self.users.read().await.values().cloned().collect()
    }

    async fn authenticate(&self, user_id: u64, api_key: &str) -> ApiResult<SessionClaims> {
        let users = self.users.read().await;
        let user = users
            .get(&user_id)
            .ok_or_else(|| ApiError::unauthorized("Invalid user ID or API key"))?;

        if user.api_key != api_key {
            return Err(ApiError::unauthorized("Invalid user ID or API key"));
        }

        let session_token = format!("session_{}_{}", user_id, Utc::now().timestamp());
        let claims = SessionClaims {
            user_id,
            username: user.username.clone(),
            session_token: session_token.clone(),
        };

        self.sessions
            .write()
            .await
            .insert(session_token, claims.clone());
        Ok(claims)
    }

    async fn validate_session(&self, session_token: &str) -> ApiResult<SessionClaims> {
        let sessions = self.sessions.read().await;
        sessions
            .get(session_token)
            .cloned()
            .ok_or_else(|| ApiError::unauthorized("Invalid or expired session token"))
    }
}

#[derive(Clone)]
struct UserRecord {
    user_id: u64,
    username: String,
    api_key: String,
}

#[derive(Clone)]
struct SessionClaims {
    user_id: u64,
    username: String,
    session_token: String,
}

// Authorization marker types (capabilities only; no custom resource marker for demos)

struct CanRead;
struct CanWrite;
struct CanDelete;

// NOTE: Avoid type aliases in demos; use explicit types to keep guarantees visible.

#[derive(Clone)]
struct DocumentWorkspace {
    // Base directory where all users' document dirs live
    user_docs_root: PathBoundary,
}

impl DocumentWorkspace {
    fn new(root: impl AsRef<std::path::Path>) -> Result<Self> {
        let user_docs_root: PathBoundary<()> =
            PathBoundary::try_new_create(root.join("user_documents"))?;

        Ok(Self { user_docs_root })
    }

    fn create_session(&self, claims: &SessionClaims) -> Result<WorkspaceAccess> {
        // Create user-specific directory
        let user_root = self
            .user_docs_root
            .strict_join(&format!("user_{}", claims.user_id))?
            .virtualize()
            .try_into_root_create()? // ensure the per-user root exists
            .rebrand::<CanRead>();

        Ok(WorkspaceAccess {
            claims: claims.clone(),
            user_docs_root: user_root,
        })
    }
}

#[derive(Clone)]
struct WorkspaceAccess {
    claims: SessionClaims,
    // Session-scoped VirtualRoot limited to this user's directory
    user_docs_root: VirtualRoot<CanRead>,
}

struct AuthenticatedSession {
    claims: SessionClaims,
    workspace_access: WorkspaceAccess,
}

impl AuthenticatedSession {
    fn user_documents_access(&self) -> ApiResult<&VirtualRoot<CanRead>> {
        Ok(&self.workspace_access.user_docs_root)
    }

    fn user_documents_access_with_write(&self) -> ApiResult<VirtualRoot<(CanRead, CanWrite)>> {
        Ok(self
            .workspace_access
            .user_docs_root
            .rebrand::<(CanRead, CanWrite)>())
    }

    fn user_documents_access_with_delete(
        &self,
    ) -> ApiResult<VirtualRoot<(CanRead, CanWrite, CanDelete)>> {
        Ok(self
            .workspace_access
            .user_docs_root
            .rebrand::<(CanRead, CanWrite, CanDelete)>())
    }
}

// Data types
#[derive(Clone, Serialize)]
struct Document {
    id: Uuid,
    user_id: u64,
    title: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

// Request/Response types
#[derive(Deserialize)]
struct LoginRequest {
    user_id: u64,
    api_key: String,
}

#[derive(Serialize)]
struct LoginResponse {
    session_token: String,
    user_id: u64,
}

#[derive(Deserialize)]
struct ListParams {
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Deserialize)]
struct CreateDocumentRequest {
    title: String,
    content: String,
}

#[derive(Deserialize)]
struct UpdateDocumentRequest {
    title: Option<String>,
    content: Option<String>,
}

#[derive(Serialize)]
struct DocumentResponse {
    document: Document,
}

#[derive(Serialize)]
struct DocumentListResponse {
    documents: Vec<Document>,
    user_id: u64,
    total: usize,
}

#[derive(Serialize)]
struct ContentResponse {
    document_id: Uuid,
    content: String,
}

#[derive(Serialize)]
struct DeleteResponse {
    message: String,
    deleted_id: Uuid,
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

    fn not_found(message: &str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.to_string(),
        }
    }

    fn bad_request(message: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
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

// Helper trait for better ergonomics
trait Pipe<T> {
    fn pipe<F, R>(self, f: F) -> R
    where
        F: FnOnce(T) -> R;
}

impl<T> Pipe<T> for T {
    fn pipe<F, R>(self, f: F) -> R
    where
        F: FnOnce(T) -> R,
    {
        f(self)
    }
}

async fn bootstrap_service() -> Result<()> {
    let root = std::path::Path::new(SERVICE_ROOT);
    std::fs::create_dir_all(root)?;
    std::fs::create_dir_all(root.join("user_documents"))?;
    std::fs::create_dir_all(root.join("user_documents/user_1"))?;
    std::fs::create_dir_all(root.join("user_documents/user_2"))?;
    std::fs::create_dir_all(root.join("user_documents/user_3"))?;

    // Initialize database
    let pool = SqlitePoolOptions::new().connect(DATABASE_URL).await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS documents (
            doc_id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(&pool)
    .await?;

    // Create sample documents
    let doc1_id = Uuid::new_v4();
    let doc2_id = Uuid::new_v4();
    let doc3_id = Uuid::new_v4();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT OR REPLACE INTO documents (doc_id, user_id, title, created_at, updated_at) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(doc1_id.to_string())
    .bind(1i64)
    .bind("Alice's First Document")
    .bind(&now)
    .bind(&now)
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT OR REPLACE INTO documents (doc_id, user_id, title, created_at, updated_at) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(doc2_id.to_string())
    .bind(2i64)
    .bind("Bob's Project Notes")
    .bind(&now)
    .bind(&now)
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT OR REPLACE INTO documents (doc_id, user_id, title, created_at, updated_at) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(doc3_id.to_string())
    .bind(1i64)
    .bind("Alice's Second Document")
    .bind(&now)
    .bind(&now)
    .execute(&pool)
    .await?;

    // Create corresponding files
    std::fs::write(
        root.join(&format!("user_documents/user_1/{}.txt", doc1_id)),
        "This is Alice's first document content. It contains important user data that should be protected by authorization."
    )?;

    std::fs::write(
        root.join(&format!("user_documents/user_2/{}.txt", doc2_id)),
        "Bob's project notes: Remember to implement proper authorization patterns for database queries."
    )?;

    std::fs::write(
        root.join(&format!("user_documents/user_1/{}.txt", doc3_id)),
        "Alice's second document shows how users can have multiple documents.",
    )?;

    println!("Database and file system initialized with sample data");
    Ok(())
}
