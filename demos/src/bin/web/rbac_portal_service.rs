//! Role-based content portal demonstrating compile-time RBAC guarantees.
//!
//! Editors, moderators, and administrators often share the same content platform,
//! but the set of directories each role may touch differs. This demo models a
//! realistic content portal with role hierarchies (guest → user → moderator →
//! admin) and three content areas: public announcements, member-only briefs, and
//! administrative audit logs. Marker types encode both the content space and the
//! proven capability (e.g., `(MemberBriefs, CanRead)`), making every filesystem
//! call state the resource being touched and the permission that unlocked it.

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
use std::{net::SocketAddr, sync::Arc};
use strict_path::PathBoundary;
use tokio::{net::TcpListener, signal};

const PORTAL_ROOT: &str = "demo_data/rbac_portal";
const SERVER_ADDR: &str = "127.0.0.1:4014";

#[tokio::main]
async fn main() -> Result<()> {
    bootstrap_portal()?;

    let workspace = PortalWorkspace::new(PORTAL_ROOT)?;
    let tokens = TokenStore::with_samples();
    let state = Arc::new(AppState { workspace, tokens });

    print_launch_instructions(state.as_ref()).await;

    let app = Router::new()
        .route("/api/public/:page", get(fetch_public))
        .route("/api/member/:page", get(fetch_member))
        .route("/api/moderation/:subject/flag", post(flag_content))
        .route("/api/admin/:subject/publish", post(publish_admin_notice))
        .with_state(state.clone());

    let addr: SocketAddr = SERVER_ADDR.parse().context("invalid listen address")?;
    println!("\nRBAC portal service listening on http://{addr}");
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
    let tokens = state.tokens.all_tokens();
    println!("Sample access tokens (use X-Access-Token header):");
    for token in tokens {
        println!("  - {token}");
    }
    println!();
}

async fn fetch_public(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(page): Path<String>,
) -> ApiResult<Json<ContentResponse>> {
    let session = state.authorize(&headers)?;
    let response = match session {
        RoleSession::Guest(access) => access.read_public(&page).await?,
        RoleSession::Member(access) => access.read_public(&page).await?,
        RoleSession::Moderator(access) => access.read_public(&page).await?,
        RoleSession::Admin(access) => access.read_public(&page).await?,
    };
    Ok(Json(response))
}

async fn fetch_member(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(page): Path<String>,
) -> ApiResult<Json<ContentResponse>> {
    let session = state.authorize(&headers)?;
    let response = match session {
        RoleSession::Member(access) => access.read_member(&page).await?,
        RoleSession::Moderator(access) => access.read_member(&page).await?,
        RoleSession::Admin(access) => access.read_member(&page).await?,
        RoleSession::Guest(_) => {
            return Err(ApiError::forbidden(
                "Member-only brief requires an authenticated user token",
            ))
        }
    };
    Ok(Json(response))
}

async fn flag_content(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(subject): Path<String>,
    Json(payload): Json<FlagRequest>,
) -> ApiResult<Json<ModerationResponse>> {
    let session = state.authorize(&headers)?;
    let response = match session {
        RoleSession::Moderator(access) => access.record_flag(&subject, &payload.reason).await?,
        RoleSession::Admin(access) => access.record_flag(&subject, &payload.reason).await?,
        RoleSession::Member(_) | RoleSession::Guest(_) => {
            return Err(ApiError::forbidden(
                "Flagging content is limited to moderators and administrators",
            ))
        }
    };
    Ok(Json(response))
}

async fn publish_admin_notice(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(subject): Path<String>,
    Json(payload): Json<PublishRequest>,
) -> ApiResult<Json<AdminPublishResponse>> {
    let session = state.authorize(&headers)?;
    let response = match session {
        RoleSession::Admin(access) => access.publish_notice(&subject, &payload.contents).await?,
        RoleSession::Moderator(_) | RoleSession::Member(_) | RoleSession::Guest(_) => {
            return Err(ApiError::forbidden(
                "Publishing administrative notices requires an administrator token",
            ))
        }
    };
    Ok(Json(response))
}

fn bootstrap_portal() -> Result<()> {
    let root = std::path::Path::new(PORTAL_ROOT);
    let public = root.join("public");
    let members = root.join("members");
    let admin = root.join("admin");
    let flags = admin.join("moderation_flags");
    let notices = admin.join("notices");

    std::fs::create_dir_all(public.join("announcements"))?;
    std::fs::create_dir_all(members.join("briefs"))?;
    std::fs::create_dir_all(&flags)?;
    std::fs::create_dir_all(&notices)?;

    std::fs::write(
        public.join("announcements/launch.txt"),
        "Welcome to the new portal. Public announcements live here.",
    )?;
    std::fs::write(
        members.join("briefs/roadmap.txt"),
        "Member brief: Q4 roadmap includes new moderation tooling.",
    )?;
    std::fs::write(
        admin.join("audit_log.txt"),
        "Audit log initialized. Moderator actions append here.",
    )?;

    Ok(())
}

#[derive(Clone)]
struct AppState {
    workspace: PortalWorkspace,
    tokens: TokenStore,
}

type SharedState = Arc<AppState>;

type ApiResult<T> = std::result::Result<T, ApiError>;

impl AppState {
    fn authorize(&self, headers: &HeaderMap) -> ApiResult<RoleSession> {
        let token = extract_token(headers)?;
        self.tokens
            .authorize(&token, &self.workspace)
            .map_err(|err| ApiError::unauthorized(&err.to_string()))
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
    records: Vec<TokenRecord>,
}

impl TokenStore {
    fn with_samples() -> Self {
        Self {
            records: vec![
                TokenRecord::new("visitor-token", Persona::Guest),
                TokenRecord::new("member-token", Persona::Member),
                TokenRecord::new("moderator-token", Persona::Moderator),
                TokenRecord::new("admin-token", Persona::Admin),
            ],
        }
    }

    fn all_tokens(&self) -> Vec<&str> {
        self.records
            .iter()
            .map(|record| record.token.as_str())
            .collect()
    }

    fn authorize(&self, token: &str, workspace: &PortalWorkspace) -> Result<RoleSession> {
        let record = self
            .records
            .iter()
            .find(|record| record.token == token)
            .ok_or_else(|| anyhow!("unknown token"))?;
        workspace.session_for(record.persona)
    }
}

#[derive(Clone)]
struct TokenRecord {
    token: String,
    persona: Persona,
}

impl TokenRecord {
    fn new(token: &str, persona: Persona) -> Self {
        Self {
            token: token.to_string(),
            persona,
        }
    }
}

#[derive(Clone, Copy)]
enum Persona {
    Guest,
    Member,
    Moderator,
    Admin,
}

#[derive(Clone)]
struct PortalWorkspace {
    base: PathBoundary<PortalRoot>,
}

impl PortalWorkspace {
    fn new(root: &str) -> Result<Self> {
        let base = PathBoundary::<PortalRoot>::try_new_create(root)?;
        Ok(Self { base })
    }

    fn session_for(&self, persona: Persona) -> Result<RoleSession> {
        // Authorization: persona was verified by TokenStore::authorize()
        // Now grant access to resources based on proven role
        match persona {
            Persona::Guest => self.grant_guest_access(),
            Persona::Member => self.grant_member_access(),
            Persona::Moderator => self.grant_moderator_access(),
            Persona::Admin => self.grant_admin_access(),
        }
    }

    fn grant_guest_access(&self) -> Result<RoleSession> {
        // ✅ Authorization: Guest persona verified by TokenStore::authorize()
        let announcements_dir = self
            .base
            .strict_join("public")?
            .change_marker::<(PublicAnnouncements, CanRead)>()
            .try_into_boundary_create()?;

        Ok(RoleSession::Guest(GuestSession {
            label: "Guest",
            announcements_dir,
        }))
    }

    fn grant_member_access(&self) -> Result<RoleSession> {
        // ✅ Authorization: Member persona verified by TokenStore::authorize()
        let announcements_dir = self
            .base
            .strict_join("public")?
            .change_marker::<(PublicAnnouncements, CanRead)>()
            .try_into_boundary_create()?;
        let briefs_dir = self
            .base
            .strict_join("members")?
            .change_marker::<(MemberBriefs, CanRead)>()
            .try_into_boundary_create()?;

        Ok(RoleSession::Member(MemberSession {
            label: "Member",
            announcements_dir,
            briefs_dir,
        }))
    }

    fn grant_moderator_access(&self) -> Result<RoleSession> {
        // ✅ Authorization: Moderator persona verified by TokenStore::authorize()
        let announcements_dir = self
            .base
            .strict_join("public")?
            .change_marker::<(PublicAnnouncements, CanRead)>()
            .try_into_boundary_create()?;
        let briefs_dir = self
            .base
            .strict_join("members")?
            .change_marker::<(MemberBriefs, CanRead)>()
            .try_into_boundary_create()?;
        let flags_dir = self
            .base
            .strict_join("admin")?
            .strict_join("moderation_flags")?
            .change_marker::<(ModerationFlagArchive, CanModerate)>()
            .try_into_boundary_create()?;

        Ok(RoleSession::Moderator(ModeratorSession {
            label: "Moderator",
            announcements_dir,
            briefs_dir,
            flags_dir,
        }))
    }

    fn grant_admin_access(&self) -> Result<RoleSession> {
        // ✅ Authorization: Admin persona verified by TokenStore::authorize()
        let announcements_dir = self
            .base
            .strict_join("public")?
            .change_marker::<(PublicAnnouncements, CanRead)>()
            .try_into_boundary_create()?;
        let briefs_dir = self
            .base
            .strict_join("members")?
            .change_marker::<(MemberBriefs, CanRead)>()
            .try_into_boundary_create()?;
        let flags_dir = self
            .base
            .strict_join("admin")?
            .strict_join("moderation_flags")?
            .change_marker::<(ModerationFlagArchive, CanModerate)>()
            .try_into_boundary_create()?;
        let notices_dir = self
            .base
            .strict_join("admin")?
            .strict_join("notices")?
            .change_marker::<(AdminNotices, CanPublish)>()
            .try_into_boundary_create()?;

        Ok(RoleSession::Admin(AdminSession {
            label: "Administrator",
            announcements_dir,
            briefs_dir,
            flags_dir,
            notices_dir,
        }))
    }
}

#[derive(Clone)]
struct GuestSession {
    label: &'static str,
    announcements_dir: PathBoundary<(PublicAnnouncements, CanRead)>,
}

impl GuestSession {
    fn label(&self) -> &'static str {
        self.label
    }

    async fn read_public(&self, page: &str) -> ApiResult<ContentResponse> {
        read_document(self.label(), &self.announcements_dir, page, "public page").await
    }
}

#[derive(Clone)]
struct MemberSession {
    label: &'static str,
    announcements_dir: PathBoundary<(PublicAnnouncements, CanRead)>,
    briefs_dir: PathBoundary<(MemberBriefs, CanRead)>,
}

impl MemberSession {
    fn label(&self) -> &'static str {
        self.label
    }

    async fn read_public(&self, page: &str) -> ApiResult<ContentResponse> {
        read_document(self.label(), &self.announcements_dir, page, "public page").await
    }

    async fn read_member(&self, page: &str) -> ApiResult<ContentResponse> {
        read_document(self.label(), &self.briefs_dir, page, "member brief").await
    }
}

#[derive(Clone)]
struct ModeratorSession {
    label: &'static str,
    announcements_dir: PathBoundary<(PublicAnnouncements, CanRead)>,
    briefs_dir: PathBoundary<(MemberBriefs, CanRead)>,
    flags_dir: PathBoundary<(ModerationFlagArchive, CanModerate)>,
}

impl ModeratorSession {
    fn label(&self) -> &'static str {
        self.label
    }

    async fn read_public(&self, page: &str) -> ApiResult<ContentResponse> {
        read_document(self.label(), &self.announcements_dir, page, "public page").await
    }

    async fn read_member(&self, page: &str) -> ApiResult<ContentResponse> {
        read_document(self.label(), &self.briefs_dir, page, "member brief").await
    }

    async fn record_flag(&self, subject: &str, reason: &str) -> ApiResult<ModerationResponse> {
        archive_moderation_flag(self.label(), &self.flags_dir, subject, reason).await
    }
}

#[derive(Clone)]
struct AdminSession {
    label: &'static str,
    announcements_dir: PathBoundary<(PublicAnnouncements, CanRead)>,
    briefs_dir: PathBoundary<(MemberBriefs, CanRead)>,
    flags_dir: PathBoundary<(ModerationFlagArchive, CanModerate)>,
    notices_dir: PathBoundary<(AdminNotices, CanPublish)>,
}

impl AdminSession {
    fn label(&self) -> &'static str {
        self.label
    }

    async fn read_public(&self, page: &str) -> ApiResult<ContentResponse> {
        read_document(self.label(), &self.announcements_dir, page, "public page").await
    }

    async fn read_member(&self, page: &str) -> ApiResult<ContentResponse> {
        read_document(self.label(), &self.briefs_dir, page, "member brief").await
    }

    async fn record_flag(&self, subject: &str, reason: &str) -> ApiResult<ModerationResponse> {
        archive_moderation_flag(self.label(), &self.flags_dir, subject, reason).await
    }

    async fn publish_notice(
        &self,
        subject: &str,
        contents: &str,
    ) -> ApiResult<AdminPublishResponse> {
        persist_admin_notice(self.label(), &self.notices_dir, subject, contents).await
    }
}

async fn read_document<Marker>(
    role_label: &'static str,
    boundary: &PathBoundary<Marker>,
    page: &str,
    context: &str,
) -> ApiResult<ContentResponse>
where
    Marker: Send + Sync + 'static,
{
    let strict_path = boundary
        .strict_join(page)
        .map_err(|err| ApiError::forbidden(&format!("Invalid {context}: {err}")))?;
    let virtual_path = boundary
        .clone()
        .virtualize()
        .virtual_join(page)
        .map_err(|err| ApiError::forbidden(&format!("Invalid {context}: {err}")))?;
    let body = tokio::task::spawn_blocking(move || strict_path.read_to_string())
        .await
        .map_err(|err| ApiError::internal(&format!("task join error: {err}")))?
        .map_err(|err| ApiError::internal(&format!("failed to read {context}: {err}")))?;
    Ok(ContentResponse::new(
        role_label,
        &virtual_path.virtualpath_display().to_string(),
        body,
    ))
}

async fn archive_moderation_flag(
    role_label: &'static str,
    boundary: &PathBoundary<(ModerationFlagArchive, CanModerate)>,
    subject: &str,
    reason: &str,
) -> ApiResult<ModerationResponse> {
    let filename = format!("{subject}-{}.log", Utc::now().timestamp());
    let log_path = boundary
        .strict_join(&filename)
        .map_err(|err| ApiError::forbidden(&format!("Invalid flag path: {err}")))?;
    let display = boundary
        .clone()
        .virtualize()
        .virtual_join(&filename)
        .map_err(|err| ApiError::forbidden(&format!("Invalid flag path: {err}")))?;
    let entry = format!("{} :: {} :: {}", role_label, subject, reason);
    let payload = entry.clone();
    tokio::task::spawn_blocking(move || {
        log_path.create_parent_dir_all()?;
        log_path.write(payload.as_bytes())
    })
    .await
    .map_err(|err| ApiError::internal(&format!("task join error: {err}")))?
    .map_err(|err| ApiError::internal(&format!("failed to write moderation flag: {err}")))?;
    Ok(ModerationResponse::new(
        role_label,
        &display.virtualpath_display().to_string(),
    ))
}

async fn persist_admin_notice(
    role_label: &'static str,
    boundary: &PathBoundary<(AdminNotices, CanPublish)>,
    subject: &str,
    contents: &str,
) -> ApiResult<AdminPublishResponse> {
    let filename = format!("{subject}.txt");
    let notice_path = boundary
        .strict_join(&filename)
        .map_err(|err| ApiError::forbidden(&format!("Invalid admin notice path: {err}")))?;
    let display = boundary
        .clone()
        .virtualize()
        .virtual_join(&filename)
        .map_err(|err| ApiError::forbidden(&format!("Invalid admin notice path: {err}")))?;
    let payload = contents.to_owned();
    let write_payload = payload.clone();
    tokio::task::spawn_blocking(move || {
        notice_path.create_parent_dir_all()?;
        notice_path.write(write_payload.as_bytes())
    })
    .await
    .map_err(|err| ApiError::internal(&format!("task join error: {err}")))?
    .map_err(|err| ApiError::internal(&format!("failed to write admin notice: {err}")))?;
    Ok(AdminPublishResponse::new(
        role_label,
        &display.virtualpath_display().to_string(),
        payload,
    ))
}

#[derive(Serialize, Deserialize)]
struct FlagRequest {
    reason: String,
}

#[derive(Serialize, Deserialize)]
struct PublishRequest {
    contents: String,
}

#[derive(Serialize)]
struct ContentResponse {
    role: &'static str,
    virtual_path: String,
    body: String,
}

impl ContentResponse {
    fn new(role: &'static str, virtual_path: &str, body: String) -> Self {
        Self {
            role,
            virtual_path: virtual_path.to_string(),
            body,
        }
    }
}

#[derive(Serialize)]
struct ModerationResponse {
    role: &'static str,
    log_path: String,
}

impl ModerationResponse {
    fn new(role: &'static str, log_path: &str) -> Self {
        Self {
            role,
            log_path: log_path.to_string(),
        }
    }
}

#[derive(Serialize)]
struct AdminPublishResponse {
    role: &'static str,
    virtual_path: String,
    contents: String,
}

impl AdminPublishResponse {
    fn new(role: &'static str, virtual_path: &str, contents: String) -> Self {
        Self {
            role,
            virtual_path: virtual_path.to_string(),
            contents,
        }
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
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

    fn internal(message: &str) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ErrorResponse {
            error: self.message,
        });
        (self.status, body).into_response()
    }
}

#[derive(Clone, Copy)]
struct PortalRoot;

// Resource markers describe on-disk domains. They intentionally name the
// directory contents so reviewers can see which area is being accessed.
#[derive(Clone, Copy)]
struct PublicAnnouncements;
#[derive(Clone, Copy)]
struct MemberBriefs;
#[derive(Clone, Copy)]
struct ModerationFlagArchive;
#[derive(Clone, Copy)]
struct AdminNotices;

// Capability markers carry the proof that the caller passed authorization for a
// given action within the paired resource.
#[derive(Clone, Copy)]
struct CanRead;
#[derive(Clone, Copy)]
struct CanModerate;
#[derive(Clone, Copy)]
struct CanPublish;

#[derive(Clone)]
enum RoleSession {
    Guest(GuestSession),
    Member(MemberSession),
    Moderator(ModeratorSession),
    Admin(AdminSession),
}
