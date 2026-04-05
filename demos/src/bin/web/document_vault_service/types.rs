//! Marker types, request/response types for the document vault service.

use serde::{Deserialize, Serialize};
use strict_path::StrictPath;

// ---------------------------------------------------------------------------
// Root / resource / permission markers
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub enum VaultRoot {}

#[derive(Clone, Copy)]
pub enum ConfidentialDocs {}

#[derive(Clone, Copy)]
pub enum PublicReports {}

#[derive(Clone, Copy)]
pub enum ReadOnly {}

#[derive(Clone, Copy)]
pub enum WriteOnly {}

#[derive(Clone, Copy)]
pub enum AuditRoot {}

#[derive(Clone, Copy)]
pub enum AuditTrail {}

// ---------------------------------------------------------------------------
// Token / scope types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    ConfidentialRead,
    ConfidentialWrite,
    ReportRead,
    ReportWrite,
    AuditWrite,
}

pub struct TokenRecord {
    pub scopes: std::collections::HashSet<Scope>,
}

impl TokenRecord {
    pub fn new(scopes: impl IntoIterator<Item = Scope>) -> Self {
        Self {
            scopes: scopes.into_iter().collect(),
        }
    }
}

pub struct TokenGrant {
    pub scopes: std::collections::HashSet<Scope>,
}

// ---------------------------------------------------------------------------
// HTTP request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct UpdateDocumentRequest {
    pub contents: String,
}

#[derive(Serialize)]
pub struct WriteResponse {
    pub bytes_written: usize,
}

impl WriteResponse {
    pub fn from_bytes(bytes: usize) -> Self {
        Self {
            bytes_written: bytes,
        }
    }
}

#[derive(Serialize)]
pub struct DocumentResponse {
    pub path: String,
    pub contents: String,
}

impl DocumentResponse {
    pub fn new<Resource>(path: StrictPath<(Resource, ReadOnly)>, contents: String) -> Self {
        Self {
            path: path.strictpath_display().to_string(),
            contents,
        }
    }
}

#[derive(Deserialize)]
pub struct CaptureAuditRequest {
    pub source_doc: String,
    pub note: String,
}

#[derive(Serialize)]
pub struct AuditResponse {
    pub path: String,
}

impl AuditResponse {
    pub fn new(path: StrictPath<(AuditTrail, WriteOnly)>) -> Self {
        Self {
            path: path.strictpath_display().to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// ApiError
// ---------------------------------------------------------------------------

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    pub fn unauthorized(message: &str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.to_string(),
        }
    }

    pub fn forbidden(message: &str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.to_string(),
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
        let body = Json(serde_json::json!({
            "error": self.message,
        }));
        (self.status, body).into_response()
    }
}

pub type ApiResult<T> = std::result::Result<T, ApiError>;
