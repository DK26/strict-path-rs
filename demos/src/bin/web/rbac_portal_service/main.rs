//! Role-based content portal demonstrating compile-time RBAC guarantees.
//!
//! Editors, moderators, and administrators often share the same content platform,
//! but the set of directories each role may touch differs. This demo models a
//! realistic content portal with role hierarchies (guest → user → moderator →
//! admin) and three content areas: public announcements, member-only briefs, and
//! administrative audit logs. Marker types encode both the content space and the
//! proven capability (e.g., `(MemberBriefs, CanRead)`), making every filesystem
//! call state the resource being touched and the permission that unlocked it.

mod auth;
mod types;

use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::{net::TcpListener, signal};

use auth::{extract_token, PortalWorkspace, RoleSession, TokenStore};
use types::{
    AdminPublishResponse, ApiError, ApiResult, ContentResponse, FlagRequest, ModerationResponse,
    PublishRequest,
};

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

impl AppState {
    fn authorize(&self, headers: &HeaderMap) -> ApiResult<RoleSession> {
        let token = extract_token(headers)?;
        self.tokens
            .authorize(&token, &self.workspace)
            .map_err(|err| ApiError::unauthorized(&err.to_string()))
    }
}
