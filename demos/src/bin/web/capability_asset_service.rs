//! Capability-driven brand asset service demonstrating compile-time capability checks.
//!
//! Creative teams often need stronger guarantees that staging editors can update
//! campaign assets while read-only stakeholders can preview them without risk of
//! accidental modification. This Axum service encodes capabilities into the
//! marker type so that only sessions with the appropriate capability can compile
//! calls to the write/delete helpers. Tokens map to real user personas: a
//! read-only agency reviewer, an in-house brand editor, and the brand director
//! with full control over the asset vault.

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::Path as StdPath, sync::Arc};
use strict_path::{PathBoundary, StrictPath};
use tokio::{net::TcpListener, signal};

const SERVICE_ROOT: &str = "demo_data/capability_asset_service";
const SERVER_ADDR: &str = "127.0.0.1:4013";

#[tokio::main]
async fn main() -> Result<()> {
    bootstrap_sample_assets()?;

    let workspace = AssetWorkspace::new(SERVICE_ROOT)?;
    let tokens = TokenStore::with_samples();
    let state = Arc::new(AppState { workspace, tokens });

    print_launch_instructions(state.as_ref()).await;

    let app = Router::new()
        .route(
            "/api/assets/:file",
            get(fetch_asset).post(update_asset).delete(delete_asset),
        )
        .with_state(state.clone());

    let addr: SocketAddr = SERVER_ADDR.parse().context("invalid listen address")?;
    println!("\nCapability Asset service listening on http://{addr}");
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
    println!("Sample access tokens (include via X-Access-Token header):");
    for token in tokens {
        println!("  - {token}");
    }
    println!();
}

async fn fetch_asset(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(file): Path<String>,
) -> ApiResult<Json<AssetResponse>> {
    let session = state.authorize(&headers)?;
    let asset = match session {
        CapabilitySession::AgencyReviewer(ws) => ws.read_asset(&file).await?,
        CapabilitySession::BrandEditor(ws) => ws.read_asset(&file).await?,
        CapabilitySession::BrandDirector(ws) => ws.read_asset(&file).await?,
    };
    Ok(Json(asset))
}

async fn update_asset(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(file): Path<String>,
    Json(payload): Json<UpdateAssetRequest>,
) -> ApiResult<Json<AssetResponse>> {
    let session = state.authorize(&headers)?;
    let asset = match session {
        CapabilitySession::BrandEditor(ws) => ws.write_asset(&file, &payload.contents).await?,
        CapabilitySession::BrandDirector(ws) => ws.write_asset(&file, &payload.contents).await?,
        CapabilitySession::AgencyReviewer(_) => {
            return Err(ApiError::forbidden(
                "Token only grants read access; editing requires editor privileges",
            ))
        }
    };
    Ok(Json(asset))
}

async fn delete_asset(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(file): Path<String>,
) -> ApiResult<Json<DeleteResponse>> {
    let session = state.authorize(&headers)?;
    let result = match session {
        CapabilitySession::BrandDirector(ws) => ws.delete_asset(&file).await?,
        CapabilitySession::BrandEditor(_) | CapabilitySession::AgencyReviewer(_) => {
            return Err(ApiError::forbidden(
                "Token does not grant delete capability",
            ))
        }
    };
    Ok(Json(result))
}

fn bootstrap_sample_assets() -> Result<()> {
    let root = StdPath::new(SERVICE_ROOT);
    let agencies = root.join("agency_review");
    let editors = root.join("brand_editors");
    let directors = root.join("brand_director");

    std::fs::create_dir_all(&agencies)?;
    std::fs::create_dir_all(&editors)?;
    std::fs::create_dir_all(&directors)?;

    std::fs::write(
        agencies.join("summer_campaign/hero.txt"),
        "Hero headline draft for agency review.",
    )?;
    std::fs::create_dir_all(editors.join("summer_campaign"))?;
    std::fs::write(
        editors.join("summer_campaign/copy.txt"),
        "Initial copy draft awaiting approvals.",
    )?;
    std::fs::create_dir_all(directors.join("archive"))?;
    std::fs::write(
        directors.join("archive/legacy_guidelines.txt"),
        "Final brand guidelines from 2022 rollout.",
    )?;

    Ok(())
}

#[derive(Clone)]
struct AppState {
    workspace: AssetWorkspace,
    tokens: TokenStore,
}

type SharedState = Arc<AppState>;

type ApiResult<T> = std::result::Result<T, ApiError>;

impl AppState {
    fn authorize(&self, headers: &HeaderMap) -> ApiResult<CapabilitySession> {
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
                TokenRecord::new(
                    "agency-review-token",
                    Persona::AgencyReviewer,
                    CapabilitySet::ReadOnly,
                ),
                TokenRecord::new(
                    "brand-editor-token",
                    Persona::BrandEditor,
                    CapabilitySet::ReadWrite,
                ),
                TokenRecord::new(
                    "brand-director-token",
                    Persona::BrandDirector,
                    CapabilitySet::FullControl,
                ),
            ],
        }
    }

    fn all_tokens(&self) -> Vec<&str> {
        self.records
            .iter()
            .map(|record| record.token.as_str())
            .collect()
    }

    fn authorize(&self, token: &str, workspace: &AssetWorkspace) -> Result<CapabilitySession> {
        let record = self
            .records
            .iter()
            .find(|record| record.token == token)
            .ok_or_else(|| anyhow!("unknown token"))?;
        workspace.session_for(record.persona, record.caps)
    }
}

#[derive(Clone)]
struct TokenRecord {
    token: String,
    persona: Persona,
    caps: CapabilitySet,
}

impl TokenRecord {
    fn new(token: &str, persona: Persona, caps: CapabilitySet) -> Self {
        Self {
            token: token.to_string(),
            persona,
            caps,
        }
    }
}

#[derive(Clone, Copy)]
enum Persona {
    AgencyReviewer,
    BrandEditor,
    BrandDirector,
}

#[derive(Clone, Copy)]
enum CapabilitySet {
    ReadOnly,
    ReadWrite,
    FullControl,
}

#[derive(Clone)]
struct AssetWorkspace {
    base: PathBoundary<AssetRoot>,
}

impl AssetWorkspace {
    fn new(root: &str) -> Result<Self> {
        let base = PathBoundary::<AssetRoot>::try_new_create(root)?;
        Ok(Self { base })
    }

    fn session_for(&self, persona: Persona, caps: CapabilitySet) -> Result<CapabilitySession> {
        match (persona, caps) {
            (Persona::AgencyReviewer, CapabilitySet::ReadOnly) => {
                Ok(CapabilitySession::AgencyReviewer(self.agency_reviewer()?))
            }
            (Persona::BrandEditor, CapabilitySet::ReadWrite) => {
                Ok(CapabilitySession::BrandEditor(self.brand_editor()?))
            }
            (Persona::BrandDirector, CapabilitySet::FullControl) => {
                Ok(CapabilitySession::BrandDirector(self.brand_director()?))
            }
            _ => Err(anyhow!("token configuration mismatch")),
        }
    }

    fn agency_reviewer(&self) -> Result<PersonaWorkspace<(AgencyReviewAssets, CanRead)>> {
        Ok(PersonaWorkspace::new(
            "Agency Reviewer",
            self.base
                .strict_join("agency_review")?
                .try_into_boundary_create()? // ensures directory exists
                .rebrand::<(AgencyReviewAssets, CanRead)>(),
        ))
    }

    fn brand_editor(&self) -> Result<PersonaWorkspace<(BrandEditorWorkspace, CanRead, CanWrite)>> {
        Ok(PersonaWorkspace::new(
            "Brand Editor",
            self.base
                .strict_join("brand_editors")?
                .try_into_boundary_create()? // ensures directory exists
                .rebrand::<(BrandEditorWorkspace, CanRead, CanWrite)>(),
        ))
    }

    fn brand_director(
        &self,
    ) -> Result<PersonaWorkspace<(BrandDirectorArchive, CanRead, CanWrite, CanDelete)>> {
        Ok(PersonaWorkspace::new(
            "Brand Director",
            self.base
                .strict_join("brand_director")?
                .try_into_boundary_create()? // ensures directory exists
                .rebrand::<(BrandDirectorArchive, CanRead, CanWrite, CanDelete)>(),
        ))
    }
}

struct PersonaWorkspace<M> {
    actor: &'static str,
    boundary: PathBoundary<M>,
}

impl<M> PersonaWorkspace<M> {
    fn new(actor: &'static str, boundary: PathBoundary<M>) -> Self {
        Self { actor, boundary }
    }

    fn strict_path(&self, file: &str) -> Result<StrictPath<M>, ApiError> {
        self.boundary
            .strict_join(file)
            .map_err(|err| ApiError::forbidden(&format!("Invalid asset path: {err}")))
    }

    fn actor(&self) -> &'static str {
        self.actor
    }
}

impl<M> Clone for PersonaWorkspace<M> {
    fn clone(&self) -> Self {
        Self {
            actor: self.actor,
            boundary: self.boundary.clone(),
        }
    }
}

// Read access for Agency Reviewer (read-only)
impl PersonaWorkspace<(AgencyReviewAssets, CanRead)> {
    async fn read_asset(&self, file: &str) -> ApiResult<AssetResponse> {
        let path = self.strict_path(file)?;
        let display = self
            .boundary
            .clone()
            .virtualize()
            .virtual_join(file)
            .map_err(|err| ApiError::forbidden(&format!("Invalid asset path: {err}")))?;
        let actor = self.actor();
        let contents = tokio::task::spawn_blocking(move || path.read_to_string())
            .await
            .map_err(|err| ApiError::internal(&format!("task join error: {err}")))?
            .map_err(|err| ApiError::internal(&format!("failed to read asset: {err}")))?;
        Ok(AssetResponse::new(
            actor,
            &display.virtualpath_display().to_string(),
            contents,
        ))
    }
}

// Read/write access for Brand Editor
impl PersonaWorkspace<(BrandEditorWorkspace, CanRead, CanWrite)> {
    async fn read_asset(&self, file: &str) -> ApiResult<AssetResponse> {
        let path = self.strict_path(file)?;
        let display = self
            .boundary
            .clone()
            .virtualize()
            .virtual_join(file)
            .map_err(|err| ApiError::forbidden(&format!("Invalid asset path: {err}")))?;
        let actor = self.actor();
        let contents = tokio::task::spawn_blocking(move || path.read_to_string())
            .await
            .map_err(|err| ApiError::internal(&format!("task join error: {err}")))?
            .map_err(|err| ApiError::internal(&format!("failed to read asset: {err}")))?;
        Ok(AssetResponse::new(
            actor,
            &display.virtualpath_display().to_string(),
            contents,
        ))
    }

    async fn write_asset(&self, file: &str, contents: &str) -> ApiResult<AssetResponse> {
        let path = self.strict_path(file)?;
        let display = self
            .boundary
            .clone()
            .virtualize()
            .virtual_join(file)
            .map_err(|err| ApiError::forbidden(&format!("Invalid asset path: {err}")))?;
        let payload = contents.to_owned();
        let write_payload = payload.clone();
        tokio::task::spawn_blocking(move || {
            path.create_parent_dir_all()?;
            path.write(write_payload.as_bytes())
        })
        .await
        .map_err(|err| ApiError::internal(&format!("task join error: {err}")))?
        .map_err(|err| ApiError::internal(&format!("failed to write asset: {err}")))?;
        let actor = self.actor();
        Ok(AssetResponse::new(
            actor,
            &display.virtualpath_display().to_string(),
            payload,
        ))
    }
}

// Full control (read/write/delete) for Brand Director
impl PersonaWorkspace<(BrandDirectorArchive, CanRead, CanWrite, CanDelete)> {
    async fn read_asset(&self, file: &str) -> ApiResult<AssetResponse> {
        let path = self.strict_path(file)?;
        let display = self
            .boundary
            .clone()
            .virtualize()
            .virtual_join(file)
            .map_err(|err| ApiError::forbidden(&format!("Invalid asset path: {err}")))?;
        let actor = self.actor();
        let contents = tokio::task::spawn_blocking(move || path.read_to_string())
            .await
            .map_err(|err| ApiError::internal(&format!("task join error: {err}")))?
            .map_err(|err| ApiError::internal(&format!("failed to read asset: {err}")))?;
        Ok(AssetResponse::new(
            actor,
            &display.virtualpath_display().to_string(),
            contents,
        ))
    }

    async fn delete_asset(&self, file: &str) -> ApiResult<DeleteResponse> {
        let path = self.strict_path(file)?;
        let display = self
            .boundary
            .clone()
            .virtualize()
            .virtual_join(file)
            .map_err(|err| ApiError::forbidden(&format!("Invalid asset path: {err}")))?;
        tokio::task::spawn_blocking(move || path.remove_file())
            .await
            .map_err(|err| ApiError::internal(&format!("task join error: {err}")))?
            .map_err(|err| ApiError::internal(&format!("failed to delete asset: {err}")))?;
        Ok(DeleteResponse::new(
            self.actor(),
            &display.virtualpath_display().to_string(),
        ))
    }

    async fn write_asset(&self, file: &str, contents: &str) -> ApiResult<AssetResponse> {
        let path = self.strict_path(file)?;
        let display = self
            .boundary
            .clone()
            .virtualize()
            .virtual_join(file)
            .map_err(|err| ApiError::forbidden(&format!("Invalid asset path: {err}")))?;
        let payload = contents.to_owned();
        let write_payload = payload.clone();
        tokio::task::spawn_blocking(move || {
            path.create_parent_dir_all()?;
            path.write(write_payload.as_bytes())
        })
        .await
        .map_err(|err| ApiError::internal(&format!("task join error: {err}")))?
        .map_err(|err| ApiError::internal(&format!("failed to write asset: {err}")))?;
        let actor = self.actor();
        Ok(AssetResponse::new(
            actor,
            &display.virtualpath_display().to_string(),
            payload,
        ))
    }
}

#[derive(Serialize, Deserialize)]
struct UpdateAssetRequest {
    contents: String,
}

#[derive(Serialize)]
struct AssetResponse {
    actor: &'static str,
    virtual_path: String,
    contents: String,
}

impl AssetResponse {
    fn new(actor: &'static str, virtual_path: &str, contents: String) -> Self {
        Self {
            actor,
            virtual_path: virtual_path.to_string(),
            contents,
        }
    }
}

#[derive(Serialize)]
struct DeleteResponse {
    actor: &'static str,
    virtual_path: String,
}

impl DeleteResponse {
    fn new(actor: &'static str, virtual_path: &str) -> Self {
        Self {
            actor,
            virtual_path: virtual_path.to_string(),
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

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Clone, Copy)]
struct CanRead;
#[derive(Clone, Copy)]
struct CanWrite;
#[derive(Clone, Copy)]
struct CanDelete;

#[derive(Clone, Copy)]
struct AssetRoot;

#[derive(Clone, Copy)]
struct AgencyReviewAssets;

#[derive(Clone, Copy)]
struct BrandEditorWorkspace;

#[derive(Clone, Copy)]
struct BrandDirectorArchive;

enum CapabilitySession {
    AgencyReviewer(PersonaWorkspace<(AgencyReviewAssets, CanRead)>),
    BrandEditor(PersonaWorkspace<(BrandEditorWorkspace, CanRead, CanWrite)>),
    BrandDirector(PersonaWorkspace<(BrandDirectorArchive, CanRead, CanWrite, CanDelete)>),
}

impl Clone for CapabilitySession {
    fn clone(&self) -> Self {
        match self {
            CapabilitySession::AgencyReviewer(ws) => CapabilitySession::AgencyReviewer(ws.clone()),
            CapabilitySession::BrandEditor(ws) => CapabilitySession::BrandEditor(ws.clone()),
            CapabilitySession::BrandDirector(ws) => CapabilitySession::BrandDirector(ws.clone()),
        }
    }
}
