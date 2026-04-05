//! FileWorkspace, WorkspaceAccess, and AuthenticatedSession.

use anyhow::Result;
use strict_path::PathBoundary;

use crate::auth::{Capability, TokenClaims};
use crate::types::{ApiError, ApiResult};

// Resource marker types
pub struct PersonalFiles;
pub struct SharedFiles;
pub struct AdminLogs;

// Capability marker types
pub struct CanRead;
pub struct CanWrite;
pub struct CanDelete;

#[derive(Clone)]
pub struct FileWorkspace {
    personal_dir: PathBoundary<PersonalFiles>,
    shared_dir: PathBoundary<SharedFiles>,
    admin_dir: PathBoundary<AdminLogs>,
}

impl FileWorkspace {
    pub fn new(root: impl AsRef<std::path::Path>) -> Result<Self> {
        let root_ref = root.as_ref();
        let personal_dir = PathBoundary::try_new_create(root_ref.join("personal"))?;
        let shared_dir = PathBoundary::try_new_create(root_ref.join("shared"))?;
        let admin_dir = PathBoundary::try_new_create(root_ref.join("admin"))?;

        Ok(Self {
            personal_dir,
            shared_dir,
            admin_dir,
        })
    }

    pub fn create_session(&self, claims: &TokenClaims) -> Result<WorkspaceAccess> {
        let has_pr = claims.capabilities.contains(&Capability::PersonalFilesRead);
        let has_pw = claims
            .capabilities
            .contains(&Capability::PersonalFilesWrite);
        let has_pd = claims
            .capabilities
            .contains(&Capability::PersonalFilesDelete);

        let personal_files_readonly = self
            .personal_dir
            .clone()
            .into_strictpath()?
            .change_marker::<(PersonalFiles, CanRead)>()
            .try_into_boundary()?;

        let personal_files_readwrite = if has_pr && has_pw {
            Some(
                self.personal_dir
                    .clone()
                    .into_strictpath()?
                    .change_marker::<(PersonalFiles, CanRead, CanWrite)>()
                    .try_into_boundary()?,
            )
        } else {
            None
        };

        let personal_files_full = if has_pr && has_pw && has_pd {
            Some(
                self.personal_dir
                    .clone()
                    .into_strictpath()?
                    .change_marker::<(PersonalFiles, CanRead, CanWrite, CanDelete)>()
                    .try_into_boundary()?,
            )
        } else {
            None
        };

        let has_sr = claims.capabilities.contains(&Capability::SharedFilesRead);
        let has_sw = claims.capabilities.contains(&Capability::SharedFilesWrite);

        let shared_files_readonly = self
            .shared_dir
            .clone()
            .into_strictpath()?
            .change_marker::<(SharedFiles, CanRead)>()
            .try_into_boundary()?;

        let shared_files_readwrite = if has_sr && has_sw {
            Some(
                self.shared_dir
                    .clone()
                    .into_strictpath()?
                    .change_marker::<(SharedFiles, CanRead, CanWrite)>()
                    .try_into_boundary()?,
            )
        } else {
            None
        };

        let admin_logs_readonly = self
            .admin_dir
            .clone()
            .into_strictpath()?
            .change_marker::<(AdminLogs, CanRead)>()
            .try_into_boundary()?;

        Ok(WorkspaceAccess {
            _claims: claims.clone(),
            personal_files_readonly,
            personal_files_readwrite,
            personal_files_full,
            shared_files_readonly,
            shared_files_readwrite,
            admin_logs_readonly,
        })
    }
}

#[derive(Clone)]
pub struct WorkspaceAccess {
    pub _claims: TokenClaims, // Stored for auditing; not used in this demo
    // Personal files directory with different capability levels
    pub personal_files_readonly: PathBoundary<(PersonalFiles, CanRead)>,
    pub personal_files_readwrite: Option<PathBoundary<(PersonalFiles, CanRead, CanWrite)>>,
    pub personal_files_full: Option<PathBoundary<(PersonalFiles, CanRead, CanWrite, CanDelete)>>,
    // Shared files directory with different capability levels
    pub shared_files_readonly: PathBoundary<(SharedFiles, CanRead)>,
    pub shared_files_readwrite: Option<PathBoundary<(SharedFiles, CanRead, CanWrite)>>,
    // Admin logs directory (read-only)
    pub admin_logs_readonly: PathBoundary<(AdminLogs, CanRead)>,
}

pub struct AuthenticatedSession {
    pub _claims: TokenClaims, // Stored for auditing; not used in this demo
    pub workspace_access: WorkspaceAccess,
}

impl AuthenticatedSession {
    pub fn personal_files_access(&self) -> ApiResult<&PathBoundary<(PersonalFiles, CanRead)>> {
        Ok(&self.workspace_access.personal_files_readonly)
    }

    pub fn personal_files_access_with_write(
        &self,
    ) -> ApiResult<PathBoundary<(PersonalFiles, CanRead, CanWrite)>> {
        self.workspace_access
            .personal_files_readwrite
            .clone()
            .ok_or_else(|| ApiError::forbidden("Missing PersonalFilesWrite capability"))
    }

    pub fn personal_files_access_with_delete(
        &self,
    ) -> ApiResult<PathBoundary<(PersonalFiles, CanRead, CanWrite, CanDelete)>> {
        self.workspace_access
            .personal_files_full
            .clone()
            .ok_or_else(|| ApiError::forbidden("Missing PersonalFilesDelete capability"))
    }

    pub fn shared_files_access(&self) -> ApiResult<&PathBoundary<(SharedFiles, CanRead)>> {
        Ok(&self.workspace_access.shared_files_readonly)
    }

    pub fn shared_files_access_with_write(
        &self,
    ) -> ApiResult<PathBoundary<(SharedFiles, CanRead, CanWrite)>> {
        self.workspace_access
            .shared_files_readwrite
            .clone()
            .ok_or_else(|| ApiError::forbidden("Missing SharedFilesWrite capability"))
    }

    pub fn admin_logs_access(&self) -> ApiResult<&PathBoundary<(AdminLogs, CanRead)>> {
        Ok(&self.workspace_access.admin_logs_readonly)
    }
}
