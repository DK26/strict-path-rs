//! Marker types, request/response structs, error types, and record types
//! used across the tenant workspace service.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use strict_path::VirtualPath;

// ---------------------------------------------------------------------------
// Marker types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default)]
pub struct MultiTenantRoot;
#[derive(Clone, Copy, Debug, Default)]
pub struct WorkspaceStorage;
#[derive(Clone, Copy, Debug, Default)]
pub struct WorkspaceRead;
#[derive(Clone, Copy, Debug, Default)]
pub struct WorkspaceWrite;
#[derive(Clone, Copy, Debug, Default)]
pub struct AuditStorage;
#[derive(Clone, Copy, Debug, Default)]
pub struct AuditRead;
#[derive(Clone, Copy, Debug, Default)]
pub struct TemplateStorage;

// ---------------------------------------------------------------------------
// Permission scopes
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    WorkspaceRead,
    WorkspaceWrite,
    AuditRead,
}

#[derive(Clone, Copy, Debug)]
pub struct TenantScopes {
    pub workspace_read: bool,
    pub workspace_write: bool,
    pub audit_read: bool,
}

impl TenantScopes {
    pub fn workspace_reader_allowed(self) -> bool {
        self.workspace_read || self.workspace_write
    }
}

// ---------------------------------------------------------------------------
// Internal record types
// ---------------------------------------------------------------------------

pub struct DocumentRecord {
    pub path: VirtualPath<(WorkspaceStorage, WorkspaceRead)>,
    pub size: u64,
}

pub struct AuditRecord {
    pub path: VirtualPath<(AuditStorage, AuditRead)>,
    pub size: u64,
}

// ---------------------------------------------------------------------------
// HTTP request types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateDocumentRequest {
    pub path: String,
    pub contents: String,
}

#[derive(Deserialize)]
pub struct ImportTemplateRequest {
    pub template_name: String,
    pub destination: String,
}

#[derive(Deserialize)]
pub struct CaptureAuditRequest {
    pub source: String,
    pub audit_id: String,
}

// ---------------------------------------------------------------------------
// HTTP response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct DocumentResponse {
    pub document_path: String,
}

impl DocumentResponse {
    pub fn from_virtual<Marker>(virtual_path: &VirtualPath<Marker>) -> Self {
        Self {
            document_path: virtual_path.virtualpath_display().to_string(),
        }
    }
}

#[derive(Serialize)]
pub struct ListDocumentsResponse {
    pub documents: Vec<DocumentSummary>,
}

impl ListDocumentsResponse {
    pub fn from_documents(records: Vec<DocumentRecord>) -> Self {
        let documents = records
            .into_iter()
            .map(|record| DocumentSummary {
                document_path: record.path.virtualpath_display().to_string(),
                size: record.size,
            })
            .collect();
        Self { documents }
    }
}

#[derive(Serialize)]
pub struct DocumentSummary {
    pub document_path: String,
    pub size: u64,
}

#[derive(Serialize)]
pub struct AuditResponse {
    pub audit_path: String,
}

impl AuditResponse {
    pub fn from_virtual<Marker>(virtual_path: &VirtualPath<Marker>) -> Self {
        Self {
            audit_path: virtual_path.virtualpath_display().to_string(),
        }
    }
}

#[derive(Serialize)]
pub struct ListAuditResponse {
    pub exports: Vec<AuditSummary>,
}

impl ListAuditResponse {
    pub fn from_exports(records: Vec<AuditRecord>) -> Self {
        let exports = records
            .into_iter()
            .map(|record| AuditSummary {
                audit_path: record.path.virtualpath_display().to_string(),
                size: record.size,
            })
            .collect();
        Self { exports }
    }
}

#[derive(Serialize)]
pub struct AuditSummary {
    pub audit_path: String,
    pub size: u64,
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }

    pub fn internal(error: anyhow::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ErrorBody {
            error: self.message,
        });
        (self.status, body).into_response()
    }
}

pub type ApiResult<T> = std::result::Result<T, ApiError>;
