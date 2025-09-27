//! Secure user home backup service demonstrating authorization-aware markers.
//!
//! This Axum server exposes endpoints for listing, editing, and archiving
//! per-user home directories. Access tokens map to specific users and
//! permission levels. After authentication, we construct `PathBoundary<UserHome>`
//! values so every filesystem operation is guaranteed to run inside the caller's
//! home directory. Tokens with the backup scope also receive a typed capability
//! that allows them to create archives in the backup vault; callers without the
//! scope cannot even obtain a `StrictPath<(BackupStorage, BackupPermissionMarker)>`.

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    net::SocketAddr,
    path::Path,
    sync::Arc,
};
use strict_path::{PathBoundary, VirtualPath};
use tar::Builder;
use tokio::{net::TcpListener, signal, sync::RwLock};
use walkdir::WalkDir;

const HOME_ROOT: &str = "demo_data/home_service/user_homes";
const BACKUP_ROOT: &str = "demo_data/home_service/home_backups";
const SERVER_ADDR: &str = "127.0.0.1:4011";

#[tokio::main]
async fn main() -> Result<()> {
    bootstrap_sample_data()?;

    let tokens = Arc::new(TokenStore::with_samples());
    let homes = HomeRegistry::new(HOME_ROOT)?;
    let backups = BackupVault::new(BACKUP_ROOT)?;

    let state = Arc::new(AppState {
        tokens,
        homes,
        backups,
    });

    print_launch_instructions(state.clone()).await;

    let app = Router::new()
        .route(
            "/api/home/files",
            get(list_home_files).post(write_home_file),
        )
        .route("/api/home/backups", get(list_backups).post(create_backup))
        .with_state(state.clone());

    let addr: SocketAddr = SERVER_ADDR.parse().context("invalid listen address")?;
    println!("\nUser home backup service listening on http://{addr}");
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

async fn print_launch_instructions(state: Arc<AppState>) {
    let tokens = state.tokens.all_tokens().await;
    println!("Sample access tokens (use the X-Access-Token header):");
    for token in tokens {
        println!("  - {token}");
    }
    println!();
}

async fn list_home_files(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> ApiResult<Json<ListFilesResponse>> {
    let session = state.authorize(&headers).await?;
    let home = session.home.clone();

    let files = tokio::task::spawn_blocking(move || home.list_files())
        .await
        .map_err(|err| ApiError::internal(anyhow!("task join error: {err}")))?
        .map_err(ApiError::internal)?;

    Ok(Json(ListFilesResponse::from_virtual(files)))
}

async fn write_home_file(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(payload): Json<WriteFileRequest>,
) -> ApiResult<Json<WriteFileResponse>> {
    let session = state.authorize(&headers).await?;
    if !session.scopes.can_write {
        return Err(ApiError::forbidden("Token does not grant write access"));
    }
    let home = session.home.clone();

    let WriteFileRequest { path, contents } = payload;
    let result = tokio::task::spawn_blocking(move || home.write_file(&path, &contents))
        .await
        .map_err(|err| ApiError::internal(anyhow!("task join error: {err}")))?
        .map_err(ApiError::internal)?;

    Ok(Json(WriteFileResponse::from_result(result)))
}

async fn create_backup(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(payload): Json<CreateBackupRequest>,
) -> ApiResult<Json<CreateBackupResponse>> {
    let session = state.authorize(&headers).await?;
    let backup_permission = session
        .scopes
        .backup_permission
        .as_ref()
        .ok_or_else(|| ApiError::forbidden("Token is missing backup scope"))?
        .clone();
    let home = session.home.clone();
    let vault = state.backups.clone();
    let label = payload.label.unwrap_or_else(|| "home-backup".to_string());

    let archive = tokio::task::spawn_blocking(move || {
        let access = vault.access(&session.username, &backup_permission)?;
        access.create_home_archive(&home, &label)
    })
    .await
    .map_err(|err| ApiError::internal(anyhow!("task join error: {err}")))?
    .map_err(ApiError::internal)?;

    Ok(Json(CreateBackupResponse::from_virtual(&archive)))
}

async fn list_backups(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> ApiResult<Json<ListBackupsResponse>> {
    let session = state.authorize(&headers).await?;
    let backup_permission = session
        .scopes
        .backup_permission
        .as_ref()
        .ok_or_else(|| ApiError::forbidden("Token is missing backup scope"))?
        .clone();
    let vault = state.backups.clone();

    let archives = tokio::task::spawn_blocking(move || {
        let access = vault.access(&session.username, &backup_permission)?;
        access.list_archives()
    })
    .await
    .map_err(|err| ApiError::internal(anyhow!("task join error: {err}")))?
    .map_err(ApiError::internal)?;

    Ok(Json(ListBackupsResponse::from_virtual(archives)))
}

fn bootstrap_sample_data() -> Result<()> {
    // Alice has a full token with write + backup rights; Bob can only read.
    let alice_docs = Path::new(HOME_ROOT).join("alice/home/Documents");
    let alice_notes = alice_docs.join("notes");
    let alice_logs = Path::new(HOME_ROOT).join("alice/home/SystemLogs");
    let bob_docs = Path::new(HOME_ROOT).join("bob/home/Documents");

    fs::create_dir_all(&alice_docs)?;
    fs::create_dir_all(&alice_notes)?;
    fs::create_dir_all(&alice_logs)?;
    fs::create_dir_all(&bob_docs)?;
    fs::create_dir_all(Path::new(BACKUP_ROOT))?;

    fs::write(
        alice_docs.join("budget.xlsx"),
        b"Quarterly budget spreadsheet placeholder",
    )?;
    fs::write(
        alice_notes.join("meeting.txt"),
        b"Meeting notes: enforce path boundaries everywhere.",
    )?;
    fs::write(
        alice_logs.join("auth.log"),
        b"INFO: user login successful\nWARN: suspicious token blocked",
    )?;
    fs::write(
        bob_docs.join("travel.txt"),
        b"Flight: LH123\nHotel: Secure Suites",
    )?;

    Ok(())
}

#[derive(Clone)]
struct AppState {
    tokens: Arc<TokenStore>,
    homes: HomeRegistry,
    backups: BackupVault,
}

type SharedState = Arc<AppState>;

type ApiResult<T> = std::result::Result<T, ApiError>;

impl AppState {
    async fn authorize(&self, headers: &HeaderMap) -> ApiResult<UserSession> {
        let token = extract_token(headers)?;
        let grant = self.tokens.authorize(&token).await?;

        let home_proof = UserHome::new();
        let home_access = self
            .homes
            .access(&grant.username, &home_proof)
            .map_err(ApiError::internal)?;

        let backup_permission = if grant.scopes.contains(&Scope::Backup) {
            Some(BackupPermission::new())
        } else {
            None
        };

        Ok(UserSession {
            username: grant.username,
            home: Arc::new(home_access),
            scopes: UserSessionScopes {
                can_write: grant.scopes.contains(&Scope::Write),
                backup_permission,
            },
        })
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
struct UserSession {
    username: String,
    home: Arc<UserHomeAccess>,
    scopes: UserSessionScopes,
}

#[derive(Clone)]
struct UserSessionScopes {
    can_write: bool,
    backup_permission: Option<BackupPermission>,
}

#[derive(Clone)]
struct UserHome {
    _proof: (),
}

impl UserHome {
    fn new() -> Self {
        Self { _proof: () }
    }
}

#[derive(Clone)]
struct BackupPermission {
    _proof: (),
}

impl BackupPermission {
    fn new() -> Self {
        Self { _proof: () }
    }
}

#[derive(Clone)]
struct HomeRegistry {
    base: PathBoundary<HomeRoot>,
}

impl HomeRegistry {
    fn new(root: &str) -> Result<Self> {
        let base = PathBoundary::<HomeRoot>::try_new_create(root)?;
        Ok(Self { base })
    }

    fn access(&self, username: &str, _proof: &UserHome) -> Result<UserHomeAccess> {
        validate_segment(username)?;
        let user_root = self.base.strict_join(username)?;
        let home_dir = user_root.strict_join("home")?;
        home_dir.create_dir_all()?;

        let boundary = home_dir.try_into_boundary_create()?.rebrand::<UserHome>();
        Ok(UserHomeAccess { boundary })
    }
}

#[derive(Clone)]
struct UserHomeAccess {
    boundary: PathBoundary<UserHome>,
}

impl UserHomeAccess {
    fn list_files(&self) -> Result<Vec<VirtualPath<UserHome>>> {
        let mut files = Vec::new();
        let root_path = self.boundary.interop_path();
        for entry in WalkDir::new(root_path).into_iter() {
            let entry = entry?;
            if entry.file_type().is_file() {
                let rel = entry
                    .path()
                    .strip_prefix(root_path)
                    .context("failed to strip prefix")?;
                let virtual_path = self
                    .boundary
                    .clone()
                    .virtualize()
                    .virtual_join(rel)
                    .context("failed to virtualize file path")?;
                files.push(virtual_path);
            }
        }
        files.sort_by_key(|path| path.virtualpath_display().to_string());
        Ok(files)
    }

    fn write_file(&self, relative: &str, contents: &str) -> Result<WriteFileOutcome> {
        let vroot = self.boundary.clone().virtualize();
        let vpath = vroot
            .virtual_join(relative)
            .with_context(|| format!("path {relative} escapes user home"))?;
        vpath.create_parent_dir_all()?;
        vpath.write(contents)?;
        Ok(WriteFileOutcome {
            path: vpath,
            bytes_written: contents.len(),
        })
    }
}

#[derive(Clone)]
struct BackupVault {
    base: PathBoundary<BackupRoot>,
}

impl BackupVault {
    fn new(root: &str) -> Result<Self> {
        let base = PathBoundary::<BackupRoot>::try_new_create(root)?;
        Ok(Self { base })
    }

    fn access(&self, username: &str, _permission: &BackupPermission) -> Result<BackupAccess> {
        validate_segment(username)?;
        let user_dir = self.base.strict_join(username)?;
        user_dir.create_dir_all()?;
        let boundary = user_dir
            .try_into_boundary_create()?
            .rebrand::<BackupStorage>();
        Ok(BackupAccess { boundary })
    }
}

struct BackupAccess {
    boundary: PathBoundary<BackupStorage>,
}

impl BackupAccess {
    fn create_home_archive(
        &self,
        home: &UserHomeAccess,
        label: &str,
    ) -> Result<VirtualPath<BackupStorage>> {
        let file_name = format!("{}-{}.tar", sanitize_label(label), timestamp());
        let archive_path = self.boundary.strict_join(&file_name)?;
        archive_path.create_parent_dir_all()?;

        let file = File::create(archive_path.interop_path())?;
        let mut builder = Builder::new(file);
        builder
            .append_dir_all(".", home.boundary.interop_path())
            .context("failed to append home directory to archive")?;
        builder.finish()?;

        Ok(archive_path.virtualize())
    }

    fn list_archives(&self) -> Result<Vec<VirtualPath<BackupStorage>>> {
        let mut archives = Vec::new();
        let vault_root = self.boundary.strict_join("")?;
        for entry in vault_root.read_dir()? {
            let entry = entry?;
            let file_name = entry.file_name();
            let archive = self.boundary.strict_join(&file_name)?;
            if archive.is_file() {
                archives.push(archive.virtualize());
            }
        }
        archives.sort_by_key(|path| path.virtualpath_display().to_string());
        Ok(archives)
    }
}

#[derive(Clone)]
struct TokenStore {
    records: Arc<RwLock<HashMap<String, TokenRecord>>>,
}

impl TokenStore {
    fn with_samples() -> Self {
        let mut map = HashMap::new();
        map.insert(
            "alice-home-full".to_string(),
            TokenRecord::new("alice", [Scope::Read, Scope::Write, Scope::Backup]),
        );
        map.insert(
            "bob-home-read".to_string(),
            TokenRecord::new("bob", [Scope::Read]),
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
            username: record.username.clone(),
            scopes: record.scopes.clone(),
        })
    }
}

struct TokenRecord {
    username: String,
    scopes: HashSet<Scope>,
}

impl TokenRecord {
    fn new(username: &str, scopes: impl IntoIterator<Item = Scope>) -> Self {
        Self {
            username: username.to_string(),
            scopes: scopes.into_iter().collect(),
        }
    }
}

struct TokenGrant {
    username: String,
    scopes: HashSet<Scope>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Scope {
    Read,
    Write,
    Backup,
}

#[derive(Deserialize)]
struct WriteFileRequest {
    path: String,
    contents: String,
}

#[derive(Serialize)]
struct WriteFileResponse {
    path: String,
    bytes_written: usize,
}

impl WriteFileResponse {
    fn from_result(outcome: WriteFileOutcome) -> Self {
        Self {
            path: outcome.path.virtualpath_display().to_string(),
            bytes_written: outcome.bytes_written,
        }
    }
}

struct WriteFileOutcome {
    path: VirtualPath<UserHome>,
    bytes_written: usize,
}

#[derive(Deserialize)]
struct CreateBackupRequest {
    label: Option<String>,
}

#[derive(Serialize)]
struct CreateBackupResponse {
    archive: String,
}

impl CreateBackupResponse {
    fn from_virtual(path: &VirtualPath<BackupStorage>) -> Self {
        Self {
            archive: path.virtualpath_display().to_string(),
        }
    }
}

#[derive(Serialize)]
struct ListFilesResponse {
    files: Vec<String>,
}

impl ListFilesResponse {
    fn from_virtual(paths: Vec<VirtualPath<UserHome>>) -> Self {
        let files = paths
            .into_iter()
            .map(|p| p.virtualpath_display().to_string())
            .collect();
        Self { files }
    }
}

#[derive(Serialize)]
struct ListBackupsResponse {
    archives: Vec<String>,
}

impl ListBackupsResponse {
    fn from_virtual(paths: Vec<VirtualPath<BackupStorage>>) -> Self {
        let archives = paths
            .into_iter()
            .map(|p| p.virtualpath_display().to_string())
            .collect();
        Self { archives }
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

fn validate_segment(value: &str) -> Result<()> {
    if value.is_empty() || value.starts_with('.') || value.contains(['/', '\\']) {
        anyhow::bail!("Rejected unsafe segment: {value}");
    }
    Ok(())
}

fn sanitize_label(label: &str) -> String {
    let mut sanitized = String::new();
    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            sanitized.push(ch);
        }
    }
    if sanitized.is_empty() {
        "backup".to_string()
    } else {
        sanitized
    }
}

fn timestamp() -> String {
    Utc::now().format("%Y%m%d%H%M%S").to_string()
}

enum HomeRoot {}
enum BackupRoot {}
enum BackupStorage {}
