//! Business logic: token store, template library, tenant directory registry,
//! and access-capability structs for workspace and audit operations.

use anyhow::{anyhow, Context, Result};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
};
use strict_path::{PathBoundary, StrictPath, VirtualPath, VirtualRoot};
use tokio::sync::RwLock;

use crate::types::{
    ApiError, ApiResult, AuditRead, AuditRecord, AuditStorage, DocumentRecord, MultiTenantRoot,
    Scope, TemplateStorage, TenantScopes, WorkspaceRead, WorkspaceStorage, WorkspaceWrite,
};

// ---------------------------------------------------------------------------
// TokenRecord
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct TokenRecord {
    pub tenant_id: String,
    pub scopes: HashSet<Scope>,
}

impl TokenRecord {
    pub fn new(tenant_id: &str, scopes: impl IntoIterator<Item = Scope>) -> Self {
        let scopes = scopes.into_iter().collect();
        Self {
            tenant_id: tenant_id.to_string(),
            scopes,
        }
    }

    pub fn scopes(&self) -> TenantScopes {
        TenantScopes {
            workspace_read: self.scopes.contains(&Scope::WorkspaceRead),
            workspace_write: self.scopes.contains(&Scope::WorkspaceWrite),
            audit_read: self.scopes.contains(&Scope::AuditRead),
        }
    }
}

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
            "acme-editor-token".to_string(),
            TokenRecord::new("acme_corp", [Scope::WorkspaceRead, Scope::WorkspaceWrite]),
        );
        map.insert(
            "acme-auditor-token".to_string(),
            TokenRecord::new("acme_corp", [Scope::WorkspaceRead, Scope::AuditRead]),
        );
        map.insert(
            "globex-editor-token".to_string(),
            TokenRecord::new("globex", [Scope::WorkspaceRead, Scope::WorkspaceWrite]),
        );
        Self {
            records: Arc::new(RwLock::new(map)),
        }
    }

    pub async fn all_tokens(&self) -> Vec<String> {
        let guard = self.records.read().await;
        guard.keys().cloned().collect()
    }

    pub async fn authorize(&self, token: &str, tenant_id: &str) -> ApiResult<TenantScopes> {
        let guard = self.records.read().await;
        let record = guard
            .get(token)
            .ok_or_else(|| ApiError::unauthorized("Invalid access token"))?;
        if record.tenant_id != tenant_id {
            return Err(ApiError::forbidden("Token does not match tenant"));
        }
        Ok(record.scopes())
    }
}

// ---------------------------------------------------------------------------
// TemplateLibrary
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct TemplateLibrary {
    templates_dir: PathBoundary<TemplateStorage>,
}

impl TemplateLibrary {
    pub fn bootstrap(root: &str) -> Result<Self> {
        let templates_dir = PathBoundary::<TemplateStorage>::try_new(root)?;
        Ok(Self { templates_dir })
    }

    pub fn fetch_template(&self, name: &str) -> Result<StrictPath<TemplateStorage>> {
        self.templates_dir
            .strict_join(name)
            .with_context(|| format!("Template {name} escaped library"))
    }
}

// ---------------------------------------------------------------------------
// WorkspaceReadAccess
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct WorkspaceReadAccess {
    pub root: VirtualRoot<(WorkspaceStorage, WorkspaceRead)>,
}

impl WorkspaceReadAccess {
    pub fn list_documents(&self) -> Result<Vec<DocumentRecord>> {
        let mut records = Vec::new();
        for entry in self.root.read_dir()? {
            let entry = entry?;
            let file_name = entry.file_name();
            let display_name = file_name.to_string_lossy().to_string();
            let joined = self
                .root
                .virtual_join(file_name)
                .with_context(|| format!("Workspace entry {display_name} rejected by boundary"))?;
            let meta = joined.metadata()?;
            if meta.is_file() {
                let size = meta.len();
                records.push(DocumentRecord { path: joined, size });
            }
        }
        records.sort_by(|a, b| {
            let left = a.path.virtualpath_display().to_string();
            let right = b.path.virtualpath_display().to_string();
            left.cmp(&right)
        });
        Ok(records)
    }

    pub fn locate_document(
        &self,
        relative: &str,
    ) -> Result<VirtualPath<(WorkspaceStorage, WorkspaceRead)>> {
        let document = self.root.virtual_join(relative)?;
        if !document.exists() {
            return Err(anyhow!("Workspace document not found"));
        }
        Ok(document)
    }
}

// ---------------------------------------------------------------------------
// WorkspaceWriteAccess
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct WorkspaceWriteAccess {
    pub writer_root: VirtualRoot<(WorkspaceStorage, WorkspaceWrite)>,
}

impl WorkspaceWriteAccess {
    pub fn write_document(
        &self,
        relative_path: &str,
        contents: &str,
    ) -> Result<VirtualPath<(WorkspaceStorage, WorkspaceWrite)>> {
        let document = self.writer_root.virtual_join(relative_path)?;
        document.create_parent_dir_all()?;
        document.write(contents.as_bytes())?;
        Ok(document)
    }

    pub fn import_template(
        &self,
        template: &StrictPath<TemplateStorage>,
        destination: &str,
    ) -> Result<VirtualPath<(WorkspaceStorage, WorkspaceWrite)>> {
        let target = self.writer_root.virtual_join(destination)?;
        target.create_parent_dir_all()?;
        let body = template.read_to_string()?;
        target.write(body.as_bytes())?;
        Ok(target)
    }
}

// ---------------------------------------------------------------------------
// AuditReadAccess
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AuditReadAccess {
    pub root: VirtualRoot<(AuditStorage, AuditRead)>,
}

impl AuditReadAccess {
    pub fn capture_for_review(
        &self,
        workspace_path: &VirtualPath<(WorkspaceStorage, WorkspaceRead)>,
        audit_id: &str,
    ) -> Result<VirtualPath<(AuditStorage, AuditRead)>> {
        let file_name = workspace_path
            .virtualpath_file_name()
            .map(|value| value.to_string_lossy().to_string())
            .ok_or_else(|| anyhow!("Workspace path requires a file name"))?;
        let relative = PathBuf::from("reviews").join(audit_id).join(&file_name);
        let audit_path = self.root.virtual_join(&relative)?;
        audit_path.create_parent_dir_all()?;
        let body = workspace_path.read_to_string()?;
        audit_path.write(body.as_bytes())?;
        Ok(audit_path)
    }

    pub fn list_exports(&self) -> Result<Vec<AuditRecord>> {
        let mut records = Vec::new();
        for entry in self.root.read_dir()? {
            let entry = entry?;
            let file_name = entry.file_name();
            let display_name = file_name.to_string_lossy().to_string();
            let joined = self
                .root
                .virtual_join(file_name)
                .with_context(|| format!("Audit entry {display_name} rejected by boundary"))?;
            let meta = joined.metadata()?;
            if meta.is_file() {
                let size = meta.len();
                records.push(AuditRecord { path: joined, size });
            }
        }
        records.sort_by(|a, b| {
            let left = a.path.virtualpath_display().to_string();
            let right = b.path.virtualpath_display().to_string();
            left.cmp(&right)
        });
        Ok(records)
    }
}

// ---------------------------------------------------------------------------
// TenantAccess
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct TenantAccess {
    pub workspace_write: Option<WorkspaceWriteAccess>,
    pub workspace_read: Option<WorkspaceReadAccess>,
    pub audit: Option<AuditReadAccess>,
}

impl TenantAccess {
    pub fn workspace_writer(&self) -> ApiResult<WorkspaceWriteAccess> {
        self.workspace_write
            .as_ref()
            .cloned()
            .ok_or_else(|| ApiError::forbidden("Token missing workspace-write scope"))
    }

    pub fn workspace_reader(&self) -> ApiResult<WorkspaceReadAccess> {
        self.workspace_read
            .as_ref()
            .cloned()
            .ok_or_else(|| ApiError::forbidden("Token missing workspace-read scope"))
    }

    pub fn audit_reader(&self) -> ApiResult<AuditReadAccess> {
        self.audit
            .as_ref()
            .cloned()
            .ok_or_else(|| ApiError::forbidden("Token missing audit-read scope"))
    }
}

// ---------------------------------------------------------------------------
// TenantRoots
// ---------------------------------------------------------------------------

pub struct TenantRoots {
    workspace_dir: PathBoundary<WorkspaceStorage>,
    audit_dir: PathBoundary<AuditStorage>,
}

impl TenantRoots {
    pub fn create(base: PathBoundary<MultiTenantRoot>, tenant_id: String) -> Result<Self> {
        let tenant_root = base.strict_join(&tenant_id)?;
        tenant_root.create_dir_all()?;

        let workspace_dir = tenant_root.strict_join("workspace")?;
        workspace_dir.create_dir_all()?;
        let audit_dir = tenant_root.strict_join("audit")?;
        audit_dir.create_dir_all()?;

        let workspace_dir =
            PathBoundary::<WorkspaceStorage>::try_new(workspace_dir.clone().unstrict())?;
        let audit_dir = PathBoundary::<AuditStorage>::try_new(audit_dir.clone().unstrict())?;

        Ok(Self {
            workspace_dir,
            audit_dir,
        })
    }

    pub fn workspace_write_access(&self) -> Result<WorkspaceWriteAccess> {
        let writer_root = PathBoundary::<(WorkspaceStorage, WorkspaceWrite)>::try_new(
            self.workspace_dir.as_ref(),
        )?
        .virtualize();
        Ok(WorkspaceWriteAccess { writer_root })
    }

    pub fn workspace_read_access(&self) -> Result<WorkspaceReadAccess> {
        let reader_root = PathBoundary::<(WorkspaceStorage, WorkspaceRead)>::try_new(
            self.workspace_dir.as_ref(),
        )?
        .virtualize();
        Ok(WorkspaceReadAccess { root: reader_root })
    }

    pub fn audit_reader_access(&self) -> Result<AuditReadAccess> {
        let reader_root =
            PathBoundary::<(AuditStorage, AuditRead)>::try_new(self.audit_dir.as_ref())?
                .virtualize();
        Ok(AuditReadAccess { root: reader_root })
    }
}

// ---------------------------------------------------------------------------
// TenantDirectoryRegistry
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct TenantDirectoryRegistry {
    base: PathBoundary<MultiTenantRoot>,
    cache: Arc<RwLock<HashMap<String, Arc<TenantRoots>>>>,
}

impl TenantDirectoryRegistry {
    pub fn new(root: &str) -> Result<Self> {
        let base = PathBoundary::<MultiTenantRoot>::try_new_create(root)?;
        Ok(Self {
            base,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn build_access(
        &self,
        tenant_id: &str,
        scopes: TenantScopes,
    ) -> Result<TenantAccess> {
        let roots = self.obtain_roots(tenant_id).await?;
        let workspace_write = if scopes.workspace_write {
            Some(roots.workspace_write_access()?)
        } else {
            None
        };
        let workspace_read = if scopes.workspace_reader_allowed() {
            Some(roots.workspace_read_access()?)
        } else {
            None
        };
        let audit = if scopes.audit_read {
            Some(roots.audit_reader_access()?)
        } else {
            None
        };
        Ok(TenantAccess {
            workspace_write,
            workspace_read,
            audit,
        })
    }

    async fn obtain_roots(&self, tenant_id: &str) -> Result<Arc<TenantRoots>> {
        if let Some(existing) = self.cache.read().await.get(tenant_id).cloned() {
            return Ok(existing);
        }

        let base = self.base.clone();
        let tenant_key = tenant_id.to_string();
        let created = tokio::task::spawn_blocking(move || TenantRoots::create(base, tenant_key))
            .await
            .map_err(|err| anyhow!("tenant creation task failed: {err}"))??;

        let roots = Arc::new(created);
        let mut guard = self.cache.write().await;
        Ok(guard
            .entry(tenant_id.to_string())
            .or_insert_with(|| roots.clone())
            .clone())
    }
}
