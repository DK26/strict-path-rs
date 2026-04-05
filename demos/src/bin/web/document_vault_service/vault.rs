//! Document vault logic, access control, and audit trail management.

use anyhow::Result;
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use strict_path::{PathBoundary, StrictPath, StrictPathError};
use tokio::sync::RwLock;

use crate::types::{
    ApiError, ApiResult, AuditRoot, AuditTrail, ConfidentialDocs, PublicReports, ReadOnly, Scope,
    TokenGrant, TokenRecord, VaultRoot, WriteOnly,
};

// ---------------------------------------------------------------------------
// TokenStore
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct TokenStore {
    records: Arc<RwLock<HashMap<String, TokenRecord>>>,
}

impl TokenStore {
    pub fn with_samples() -> Self {
        let mut map = HashMap::new();
        map.insert(
            "legal-reader".to_string(),
            TokenRecord::new([Scope::ConfidentialRead]),
        );
        map.insert(
            "finance-writer".to_string(),
            TokenRecord::new([Scope::ConfidentialRead, Scope::ConfidentialWrite]),
        );
        map.insert(
            "reports-admin".to_string(),
            TokenRecord::new([
                Scope::ReportRead,
                Scope::ReportWrite,
                Scope::ConfidentialRead,
            ]),
        );
        map.insert(
            "audit-team".to_string(),
            TokenRecord::new([
                Scope::ConfidentialRead,
                Scope::ReportRead,
                Scope::AuditWrite,
            ]),
        );
        Self {
            records: Arc::new(RwLock::new(map)),
        }
    }

    pub async fn all_tokens(&self) -> Vec<String> {
        let guard = self.records.read().await;
        guard.keys().cloned().collect()
    }

    pub async fn authorize(&self, token: &str) -> ApiResult<TokenGrant> {
        let guard = self.records.read().await;
        let record = guard
            .get(token)
            .ok_or_else(|| ApiError::unauthorized("Invalid access token"))?;
        Ok(TokenGrant {
            scopes: record.scopes.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// VaultRegistry — creates scoped access from token grants
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct VaultRegistry {
    base: PathBoundary<VaultRoot>,
}

impl VaultRegistry {
    pub fn new(root: &str) -> Result<Self> {
        let base = PathBoundary::<VaultRoot>::try_new_create(root)?;
        Ok(Self { base })
    }

    pub fn build_access(&self, scopes: &HashSet<Scope>) -> Result<ScopedVaultAccess> {
        ScopedVaultAccess::new(self.base.clone(), scopes)
    }
}

#[derive(Clone)]
pub struct ScopedVaultAccess {
    pub confidential_read: Option<PathBoundary<(ConfidentialDocs, ReadOnly)>>,
    pub confidential_write: Option<PathBoundary<(ConfidentialDocs, WriteOnly)>>,
    pub report_read: Option<PathBoundary<(PublicReports, ReadOnly)>>,
    pub report_write: Option<PathBoundary<(PublicReports, WriteOnly)>>,
}

impl ScopedVaultAccess {
    fn new(base: PathBoundary<VaultRoot>, scopes: &HashSet<Scope>) -> Result<Self> {
        let confidential_dir = base.strict_join("confidential")?;
        let reports_dir = base.strict_join("reports")?;

        // Step 1: Check authorization (validate token scope)
        // Step 2: Encode authorization in type via change_marker()
        let confidential_read = if scopes.contains(&Scope::ConfidentialRead) {
            Some(
                confidential_dir
                    .clone()
                    .change_marker::<(ConfidentialDocs, ReadOnly)>()
                    .try_into_boundary_create()?,
            )
        } else {
            None
        };

        // Authorization check → change_marker() pattern
        let confidential_write = if scopes.contains(&Scope::ConfidentialWrite) {
            Some(
                confidential_dir
                    .clone()
                    .change_marker::<(ConfidentialDocs, WriteOnly)>()
                    .try_into_boundary_create()?,
            )
        } else {
            None
        };

        // Authorization check → change_marker() pattern
        let report_read = if scopes.contains(&Scope::ReportRead) {
            Some(
                reports_dir
                    .clone()
                    .change_marker::<(PublicReports, ReadOnly)>()
                    .try_into_boundary_create()?,
            )
        } else {
            None
        };

        // Authorization check → change_marker() pattern
        let report_write = if scopes.contains(&Scope::ReportWrite) {
            Some(
                reports_dir
                    .clone()
                    .change_marker::<(PublicReports, WriteOnly)>()
                    .try_into_boundary_create()?,
            )
        } else {
            None
        };

        Ok(Self {
            confidential_read,
            confidential_write,
            report_read,
            report_write,
        })
    }
}

// ---------------------------------------------------------------------------
// AuditRegistry
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AuditRegistry {
    base: PathBoundary<AuditRoot>,
}

impl AuditRegistry {
    pub fn new(root: &str) -> Result<Self> {
        let base = PathBoundary::<AuditRoot>::try_new_create(root)?;
        Ok(Self { base })
    }

    pub fn build_access(&self, scopes: &HashSet<Scope>) -> Result<ScopedAuditAccess> {
        // Step 1: Check authorization (validate token scope)
        // Step 2: Encode authorization in type via change_marker()
        let writer = if scopes.contains(&Scope::AuditWrite) {
            Some(
                self.base
                    .clone()
                    .into_strictpath()?
                    .change_marker::<(AuditTrail, WriteOnly)>()
                    .try_into_boundary()?,
            )
        } else {
            None
        };
        Ok(ScopedAuditAccess { writer })
    }
}

#[derive(Clone)]
pub struct ScopedAuditAccess {
    pub writer: Option<PathBoundary<(AuditTrail, WriteOnly)>>,
}

// ---------------------------------------------------------------------------
// VaultAccess — combined, per-request access object
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct VaultAccess {
    pub vault: ScopedVaultAccess,
    pub audit: ScopedAuditAccess,
}

impl VaultAccess {
    pub fn confidential_reader(&self) -> ApiResult<PathBoundary<(ConfidentialDocs, ReadOnly)>> {
        self.vault
            .confidential_read
            .clone()
            .ok_or_else(|| ApiError::forbidden("Token lacks confidential read scope"))
    }

    pub fn confidential_reader_opt(&self) -> Option<PathBoundary<(ConfidentialDocs, ReadOnly)>> {
        self.vault.confidential_read.clone()
    }

    pub fn confidential_writer(&self) -> ApiResult<PathBoundary<(ConfidentialDocs, WriteOnly)>> {
        self.vault
            .confidential_write
            .clone()
            .ok_or_else(|| ApiError::forbidden("Token lacks confidential write scope"))
    }

    pub fn report_reader(&self) -> ApiResult<PathBoundary<(PublicReports, ReadOnly)>> {
        self.vault
            .report_read
            .clone()
            .ok_or_else(|| ApiError::forbidden("Token lacks report read scope"))
    }

    pub fn report_reader_opt(&self) -> Option<PathBoundary<(PublicReports, ReadOnly)>> {
        self.vault.report_read.clone()
    }

    pub fn report_writer(&self) -> ApiResult<PathBoundary<(PublicReports, WriteOnly)>> {
        self.vault
            .report_write
            .clone()
            .ok_or_else(|| ApiError::forbidden("Token lacks report write scope"))
    }

    pub fn audit_writer(&self) -> ApiResult<PathBoundary<(AuditTrail, WriteOnly)>> {
        self.audit
            .writer
            .clone()
            .ok_or_else(|| ApiError::forbidden("Token lacks audit scope"))
    }
}

// ---------------------------------------------------------------------------
// ResolvedDoc — typed union of readable document paths
// ---------------------------------------------------------------------------

pub enum ResolvedDoc {
    Confidential(StrictPath<(ConfidentialDocs, ReadOnly)>),
    Report(StrictPath<(PublicReports, ReadOnly)>),
}

impl ResolvedDoc {
    pub fn display(&self) -> String {
        match self {
            Self::Confidential(path) => path.strictpath_display().to_string(),
            Self::Report(path) => path.strictpath_display().to_string(),
        }
    }

    pub fn file_name(&self) -> String {
        let name = match self {
            Self::Confidential(path) => path.strictpath_file_name(),
            Self::Report(path) => path.strictpath_file_name(),
        };
        name.and_then(|value| value.to_str())
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }
}

// ---------------------------------------------------------------------------
// Business logic helpers
// ---------------------------------------------------------------------------

pub fn resolve_audit_doc(access: &VaultAccess, doc: &str) -> ApiResult<ResolvedDoc> {
    if let Some(reader) = access.confidential_reader_opt() {
        match reader.strict_join(doc) {
            Ok(path) => return Ok(ResolvedDoc::Confidential(path)),
            Err(StrictPathError::PathEscapesBoundary { .. }) => {}
            Err(err) => {
                return Err(ApiError::forbidden(&format!(
                    "Invalid document path: {err}"
                )));
            }
        }
    }

    if let Some(reader) = access.report_reader_opt() {
        match reader.strict_join(doc) {
            Ok(path) => return Ok(ResolvedDoc::Report(path)),
            Err(StrictPathError::PathEscapesBoundary { .. }) => {}
            Err(err) => {
                return Err(ApiError::forbidden(&format!(
                    "Invalid document path: {err}"
                )));
            }
        }
    }

    Err(ApiError::forbidden(
        "Current token cannot read requested document",
    ))
}

pub fn write_audit_entry(
    writer: &PathBoundary<(AuditTrail, WriteOnly)>,
    resolved: &ResolvedDoc,
    note: &str,
) -> Result<StrictPath<(AuditTrail, WriteOnly)>> {
    let timestamp = Utc::now().format("%Y%m%d%H%M%S");
    let file_name = format!(
        "audit-{}-{}.txt",
        timestamp,
        sanitize(&resolved.file_name())
    );
    let entry = writer.strict_join(&file_name)?;
    entry.create_parent_dir_all()?;

    let body = format!("Source: {}\nNote: {}\n", resolved.display(), note);
    entry.write(body.as_bytes())?;
    Ok(entry)
}

pub fn sanitize(input: &str) -> String {
    input
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        .collect()
}
