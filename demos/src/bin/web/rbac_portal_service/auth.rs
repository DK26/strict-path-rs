//! RBAC logic, permission checking, and session management.

use anyhow::{anyhow, Result};
use axum::http::HeaderMap;
use chrono::Utc;
use strict_path::PathBoundary;

use crate::types::{
    AdminNotices, AdminPublishResponse, ApiError, ApiResult, CanModerate, CanPublish, CanRead,
    ContentResponse, MemberBriefs, ModerationFlagArchive, ModerationResponse, Persona,
    PublicAnnouncements,
};

// ---------------------------------------------------------------------------
// TokenStore
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct TokenStore {
    records: Vec<TokenRecord>,
}

impl TokenStore {
    pub fn with_samples() -> Self {
        Self {
            records: vec![
                TokenRecord::new("visitor-token", Persona::Guest),
                TokenRecord::new("member-token", Persona::Member),
                TokenRecord::new("moderator-token", Persona::Moderator),
                TokenRecord::new("admin-token", Persona::Admin),
            ],
        }
    }

    pub fn all_tokens(&self) -> Vec<&str> {
        self.records
            .iter()
            .map(|record| record.token.as_str())
            .collect()
    }

    pub fn authorize(&self, token: &str, workspace: &PortalWorkspace) -> Result<RoleSession> {
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

// ---------------------------------------------------------------------------
// PortalWorkspace — creates role sessions from verified personas
// ---------------------------------------------------------------------------

use crate::types::PortalRoot;

#[derive(Clone)]
pub struct PortalWorkspace {
    base: PathBoundary<PortalRoot>,
}

impl PortalWorkspace {
    pub fn new(root: &str) -> Result<Self> {
        let base = PathBoundary::<PortalRoot>::try_new_create(root)?;
        Ok(Self { base })
    }

    pub fn session_for(&self, persona: Persona) -> Result<RoleSession> {
        match persona {
            Persona::Guest => self.grant_guest_access(),
            Persona::Member => self.grant_member_access(),
            Persona::Moderator => self.grant_moderator_access(),
            Persona::Admin => self.grant_admin_access(),
        }
    }

    fn grant_guest_access(&self) -> Result<RoleSession> {
        // Authorization: Guest persona verified by TokenStore::authorize()
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
        // Authorization: Member persona verified by TokenStore::authorize()
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
        // Authorization: Moderator persona verified by TokenStore::authorize()
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
        // Authorization: Admin persona verified by TokenStore::authorize()
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

// ---------------------------------------------------------------------------
// Role sessions
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub enum RoleSession {
    Guest(GuestSession),
    Member(MemberSession),
    Moderator(ModeratorSession),
    Admin(AdminSession),
}

#[derive(Clone)]
pub struct GuestSession {
    label: &'static str,
    announcements_dir: PathBoundary<(PublicAnnouncements, CanRead)>,
}

impl GuestSession {
    pub fn label(&self) -> &'static str {
        self.label
    }

    pub async fn read_public(&self, page: &str) -> ApiResult<ContentResponse> {
        read_document(self.label(), &self.announcements_dir, page, "public page").await
    }
}

#[derive(Clone)]
pub struct MemberSession {
    label: &'static str,
    announcements_dir: PathBoundary<(PublicAnnouncements, CanRead)>,
    briefs_dir: PathBoundary<(MemberBriefs, CanRead)>,
}

impl MemberSession {
    pub fn label(&self) -> &'static str {
        self.label
    }

    pub async fn read_public(&self, page: &str) -> ApiResult<ContentResponse> {
        read_document(self.label(), &self.announcements_dir, page, "public page").await
    }

    pub async fn read_member(&self, page: &str) -> ApiResult<ContentResponse> {
        read_document(self.label(), &self.briefs_dir, page, "member brief").await
    }
}

#[derive(Clone)]
pub struct ModeratorSession {
    label: &'static str,
    announcements_dir: PathBoundary<(PublicAnnouncements, CanRead)>,
    briefs_dir: PathBoundary<(MemberBriefs, CanRead)>,
    flags_dir: PathBoundary<(ModerationFlagArchive, CanModerate)>,
}

impl ModeratorSession {
    pub fn label(&self) -> &'static str {
        self.label
    }

    pub async fn read_public(&self, page: &str) -> ApiResult<ContentResponse> {
        read_document(self.label(), &self.announcements_dir, page, "public page").await
    }

    pub async fn read_member(&self, page: &str) -> ApiResult<ContentResponse> {
        read_document(self.label(), &self.briefs_dir, page, "member brief").await
    }

    pub async fn record_flag(&self, subject: &str, reason: &str) -> ApiResult<ModerationResponse> {
        archive_moderation_flag(self.label(), &self.flags_dir, subject, reason).await
    }
}

#[derive(Clone)]
pub struct AdminSession {
    label: &'static str,
    announcements_dir: PathBoundary<(PublicAnnouncements, CanRead)>,
    briefs_dir: PathBoundary<(MemberBriefs, CanRead)>,
    flags_dir: PathBoundary<(ModerationFlagArchive, CanModerate)>,
    notices_dir: PathBoundary<(AdminNotices, CanPublish)>,
}

impl AdminSession {
    pub fn label(&self) -> &'static str {
        self.label
    }

    pub async fn read_public(&self, page: &str) -> ApiResult<ContentResponse> {
        read_document(self.label(), &self.announcements_dir, page, "public page").await
    }

    pub async fn read_member(&self, page: &str) -> ApiResult<ContentResponse> {
        read_document(self.label(), &self.briefs_dir, page, "member brief").await
    }

    pub async fn record_flag(&self, subject: &str, reason: &str) -> ApiResult<ModerationResponse> {
        archive_moderation_flag(self.label(), &self.flags_dir, subject, reason).await
    }

    pub async fn publish_notice(
        &self,
        subject: &str,
        contents: &str,
    ) -> ApiResult<AdminPublishResponse> {
        persist_admin_notice(self.label(), &self.notices_dir, subject, contents).await
    }
}

// ---------------------------------------------------------------------------
// Token extraction helper
// ---------------------------------------------------------------------------

pub fn extract_token(headers: &HeaderMap) -> ApiResult<String> {
    headers
        .get("x-access-token")
        .and_then(|value| value.to_str().ok())
        .map(|token| token.to_string())
        .ok_or_else(|| ApiError::unauthorized("Missing X-Access-Token header"))
}

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------

async fn read_document<Marker>(
    role_label: &'static str,
    content_dir: &PathBoundary<Marker>,
    page: &str,
    context: &str,
) -> ApiResult<ContentResponse>
where
    Marker: Send + Sync + 'static,
{
    let strict_path = content_dir
        .strict_join(page)
        .map_err(|err| ApiError::forbidden(&format!("Invalid {context}: {err}")))?;
    let virtual_path = content_dir
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
    flag_archive_dir: &PathBoundary<(ModerationFlagArchive, CanModerate)>,
    subject: &str,
    reason: &str,
) -> ApiResult<ModerationResponse> {
    let flag_log_filename = format!("{subject}-{}.log", Utc::now().timestamp());
    let log_path = flag_archive_dir
        .strict_join(&flag_log_filename)
        .map_err(|err| ApiError::forbidden(&format!("Invalid flag path: {err}")))?;
    let display = flag_archive_dir
        .clone()
        .virtualize()
        .virtual_join(&flag_log_filename)
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
    notices_dir: &PathBoundary<(AdminNotices, CanPublish)>,
    subject: &str,
    contents: &str,
) -> ApiResult<AdminPublishResponse> {
    let filename = format!("{subject}.txt");
    let notice_path = notices_dir
        .strict_join(&filename)
        .map_err(|err| ApiError::forbidden(&format!("Invalid admin notice path: {err}")))?;
    let display = notices_dir
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
