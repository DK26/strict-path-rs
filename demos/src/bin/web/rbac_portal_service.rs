//! Role-based content portal demonstrating compile-time RBAC guarantees.
//!
//! Editors, moderators, and administrators often share the same content platform,
//! but the set of directories each role may touch differs. This demo models a
//! realistic content portal with role hierarchies (guest → user → moderator →
//! admin) and three content areas: public announcements, member-only briefs, and
//! administrative audit logs. Marker types encode both the content space and the
//! role, so compile-time trait bounds enforce who may read or mutate each area.

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
use std::{marker::PhantomData, net::SocketAddr, sync::Arc};
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

    std::fs::create_dir_all(public.join("announcements"))?;
    std::fs::create_dir_all(members.join("briefs"))?;
    std::fs::create_dir_all(&flags)?;

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
        match persona {
            Persona::Guest => Ok(RoleSession::Guest(self.guest()?)),
            Persona::Member => Ok(RoleSession::Member(self.member()?)),
            Persona::Moderator => Ok(RoleSession::Moderator(self.moderator()?)),
            Persona::Admin => Ok(RoleSession::Admin(self.admin()?)),
        }
    }

    fn guest(&self) -> Result<PortalSession<Guest>> {
        let public = self.public_boundary::<Guest>()?;
        Ok(PortalSession::new("Guest", public, None, None))
    }

    fn member(&self) -> Result<PortalSession<User>> {
        let public = self.public_boundary::<User>()?;
        let member = Some(self.member_boundary::<User>()?);
        Ok(PortalSession::new("Member", public, member, None))
    }

    fn moderator(&self) -> Result<PortalSession<Moderator>> {
        let public = self.public_boundary::<Moderator>()?;
        let member = Some(self.member_boundary::<Moderator>()?);
        let admin = Some(self.admin_boundary::<Moderator>()?);
        Ok(PortalSession::new("Moderator", public, member, admin))
    }

    fn admin(&self) -> Result<PortalSession<Admin>> {
        let public = self.public_boundary::<Admin>()?;
        let member = Some(self.member_boundary::<Admin>()?);
        let admin = Some(self.admin_boundary::<Admin>()?);
        Ok(PortalSession::new("Administrator", public, member, admin))
    }

    fn public_boundary<Role>(&self) -> Result<PathBoundary<PublicContent<Role>>> {
        let root = self.base.strict_join("public")?;
        Ok(root
            .try_into_boundary_create()? // ensures directory existence
            .rebrand::<PublicContent<Role>>())
    }

    fn member_boundary<Role>(&self) -> Result<PathBoundary<UserContent<Role>>> {
        let root = self.base.strict_join("members")?;
        Ok(root
            .try_into_boundary_create()? // ensures directory existence
            .rebrand::<UserContent<Role>>())
    }

    fn admin_boundary<Role>(&self) -> Result<PathBoundary<AdminContent<Role>>> {
        let root = self.base.strict_join("admin")?;
        Ok(root
            .try_into_boundary_create()? // ensures directory existence
            .rebrand::<AdminContent<Role>>())
    }
}

#[derive(Clone)]
struct PortalSession<Role> {
    label: &'static str,
    public: PathBoundary<PublicContent<Role>>,
    member: Option<PathBoundary<UserContent<Role>>>,
    admin: Option<PathBoundary<AdminContent<Role>>>,
}

impl<Role> PortalSession<Role> {
    fn new(
        label: &'static str,
        public: PathBoundary<PublicContent<Role>>,
        member: Option<PathBoundary<UserContent<Role>>>,
        admin: Option<PathBoundary<AdminContent<Role>>>,
    ) -> Self {
        Self {
            label,
            public,
            member,
            admin,
        }
    }

    fn label(&self) -> &'static str {
        self.label
    }
}

impl<Role> PortalSession<Role>
where
    Role: RoleHierarchy<Guest> + Send + Sync + 'static,
{
    async fn read_public(&self, page: &str) -> ApiResult<ContentResponse> {
        let path = self
            .public
            .strict_join(page)
            .map_err(|err| ApiError::forbidden(&format!("Invalid public page: {err}")))?;
        let display = self
            .public
            .clone()
            .virtualize()
            .virtual_join(page)
            .map_err(|err| ApiError::forbidden(&format!("Invalid public page: {err}")))?;
        let body = tokio::task::spawn_blocking(move || path.read_to_string())
            .await
            .map_err(|err| ApiError::internal(&format!("task join error: {err}")))?
            .map_err(|err| ApiError::internal(&format!("failed to read page: {err}")))?;
        Ok(ContentResponse::new(
            self.label(),
            &display.virtualpath_display().to_string(),
            body,
        ))
    }
}

impl<Role> PortalSession<Role>
where
    Role: CanAccess<UserContent<User>> + Send + Sync + 'static,
{
    async fn read_member(&self, page: &str) -> ApiResult<ContentResponse> {
        let boundary = self
            .member
            .as_ref()
            .ok_or_else(|| ApiError::forbidden("Role lacks member access"))?;
        let path = boundary
            .strict_join(page)
            .map_err(|err| ApiError::forbidden(&format!("Invalid member page: {err}")))?;
        let display = boundary
            .clone()
            .virtualize()
            .virtual_join(page)
            .map_err(|err| ApiError::forbidden(&format!("Invalid member page: {err}")))?;
        let body = tokio::task::spawn_blocking(move || path.read_to_string())
            .await
            .map_err(|err| ApiError::internal(&format!("task join error: {err}")))?
            .map_err(|err| ApiError::internal(&format!("failed to read member content: {err}")))?;
        Ok(ContentResponse::new(
            self.label(),
            &display.virtualpath_display().to_string(),
            body,
        ))
    }
}

impl<Role> PortalSession<Role>
where
    Role: RoleHierarchy<Moderator> + Send + Sync + 'static,
{
    async fn record_flag(&self, subject: &str, reason: &str) -> ApiResult<ModerationResponse> {
        let admin_boundary = self
            .admin
            .as_ref()
            .ok_or_else(|| ApiError::forbidden("Role lacks moderation archive access"))?;
        let flags_dir = admin_boundary
            .strict_join("moderation_flags")
            .map_err(|err| ApiError::forbidden(&format!("Invalid flag directory: {err}")))?;
        let filename = format!("{subject}-{}.log", Utc::now().timestamp());
        let log_path = flags_dir
            .strict_join(&filename)
            .map_err(|err| ApiError::forbidden(&format!("Invalid flag path: {err}")))?;
        let entry = format!("{} :: {} :: {}", self.label(), subject, reason);
        let display = admin_boundary
            .clone()
            .virtualize()
            .virtual_join("moderation_flags")
            .and_then(|v| v.virtual_join(&filename))
            .map_err(|err| ApiError::forbidden(&format!("Invalid flag path: {err}")))?;
        let payload = entry.clone();
        tokio::task::spawn_blocking(move || {
            log_path.create_parent_dir_all()?;
            log_path.write(payload.as_bytes())
        })
        .await
        .map_err(|err| ApiError::internal(&format!("task join error: {err}")))?
        .map_err(|err| ApiError::internal(&format!("failed to write moderation flag: {err}")))?;
        Ok(ModerationResponse::new(
            self.label(),
            &display.virtualpath_display().to_string(),
        ))
    }
}

impl<Role> PortalSession<Role>
where
    Role: RoleHierarchy<Admin> + Send + Sync + 'static,
{
    async fn publish_notice(
        &self,
        subject: &str,
        contents: &str,
    ) -> ApiResult<AdminPublishResponse> {
        let admin_boundary = self
            .admin
            .as_ref()
            .ok_or_else(|| ApiError::forbidden("Role lacks admin publishing access"))?;
        let rel = format!("notices/{subject}.txt");
        let path = admin_boundary
            .strict_join(&rel)
            .map_err(|err| ApiError::forbidden(&format!("Invalid admin notice path: {err}")))?;
        let display = admin_boundary
            .clone()
            .virtualize()
            .virtual_join(&rel)
            .map_err(|err| ApiError::forbidden(&format!("Invalid admin notice path: {err}")))?;
        let payload = contents.to_owned();
        let write_payload = payload.clone();
        tokio::task::spawn_blocking(move || {
            path.create_parent_dir_all()?;
            path.write(write_payload.as_bytes())
        })
        .await
        .map_err(|err| ApiError::internal(&format!("task join error: {err}")))?
        .map_err(|err| ApiError::internal(&format!("failed to write admin notice: {err}")))?;
        Ok(AdminPublishResponse::new(
            self.label(),
            &display.virtualpath_display().to_string(),
            payload,
        ))
    }
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
#[derive(Clone, Copy)]
struct Guest;
#[derive(Clone, Copy)]
struct User;
#[derive(Clone, Copy)]
struct Moderator;
#[derive(Clone, Copy)]
struct Admin;

#[derive(Clone, Copy)]
struct PublicContent<Role>(PhantomData<Role>);
#[derive(Clone, Copy)]
struct UserContent<Role>(PhantomData<Role>);
#[derive(Clone, Copy)]
struct AdminContent<Role>(PhantomData<Role>);

trait RoleHierarchy<Role> {}

impl RoleHierarchy<Guest> for Guest {}
impl RoleHierarchy<Guest> for User {}
impl RoleHierarchy<User> for User {}
impl RoleHierarchy<Guest> for Moderator {}
impl RoleHierarchy<User> for Moderator {}
impl RoleHierarchy<Moderator> for Moderator {}
impl RoleHierarchy<Guest> for Admin {}
impl RoleHierarchy<User> for Admin {}
impl RoleHierarchy<Moderator> for Admin {}
impl RoleHierarchy<Admin> for Admin {}

trait CanAccess<Resource> {}

impl<R> CanAccess<PublicContent<Guest>> for R where R: RoleHierarchy<Guest> {}
impl<R> CanAccess<UserContent<User>> for R where R: RoleHierarchy<User> {}
impl<R> CanAccess<AdminContent<Admin>> for R where R: RoleHierarchy<Admin> {}

#[derive(Clone)]
enum RoleSession {
    Guest(PortalSession<Guest>),
    Member(PortalSession<User>),
    Moderator(PortalSession<Moderator>),
    Admin(PortalSession<Admin>),
}
