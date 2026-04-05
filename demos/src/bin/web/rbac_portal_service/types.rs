//! Marker types, request/response types, role and permission types.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Root marker
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct PortalRoot;

// ---------------------------------------------------------------------------
// Resource markers — name the on-disk domain being accessed.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct PublicAnnouncements;

#[derive(Clone, Copy)]
pub struct MemberBriefs;

#[derive(Clone, Copy)]
pub struct ModerationFlagArchive;

#[derive(Clone, Copy)]
pub struct AdminNotices;

// ---------------------------------------------------------------------------
// Capability markers — carry proof that the caller passed authorization.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct CanRead;

#[derive(Clone, Copy)]
pub struct CanModerate;

#[derive(Clone, Copy)]
pub struct CanPublish;

// ---------------------------------------------------------------------------
// Persona
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub enum Persona {
    Guest,
    Member,
    Moderator,
    Admin,
}

// ---------------------------------------------------------------------------
// HTTP request types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct FlagRequest {
    pub reason: String,
}

#[derive(Serialize, Deserialize)]
pub struct PublishRequest {
    pub contents: String,
}

// ---------------------------------------------------------------------------
// HTTP response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct ContentResponse {
    pub role: &'static str,
    pub virtual_path: String,
    pub body: String,
}

impl ContentResponse {
    pub fn new(role: &'static str, virtual_path: &str, body: String) -> Self {
        Self {
            role,
            virtual_path: virtual_path.to_string(),
            body,
        }
    }
}

#[derive(Serialize)]
pub struct ModerationResponse {
    pub role: &'static str,
    pub log_path: String,
}

impl ModerationResponse {
    pub fn new(role: &'static str, log_path: &str) -> Self {
        Self {
            role,
            log_path: log_path.to_string(),
        }
    }
}

#[derive(Serialize)]
pub struct AdminPublishResponse {
    pub role: &'static str,
    pub virtual_path: String,
    pub contents: String,
}

impl AdminPublishResponse {
    pub fn new(role: &'static str, virtual_path: &str, contents: String) -> Self {
        Self {
            role,
            virtual_path: virtual_path.to_string(),
            contents,
        }
    }
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
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

    pub fn internal(message: &str) -> Self {
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

pub type ApiResult<T> = std::result::Result<T, ApiError>;
