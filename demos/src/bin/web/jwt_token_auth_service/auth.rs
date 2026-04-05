//! AuthService, TokenClaims, Capability, UserRecord, and JWT logic.

use anyhow::anyhow;
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

use crate::types::{ApiError, ApiResult};

pub const JWT_SECRET: &[u8] = b"demo_secret_key_not_for_production_use";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Capability {
    PersonalFilesRead,
    PersonalFilesWrite,
    PersonalFilesDelete,
    SharedFilesRead,
    SharedFilesWrite,
    AdminLogsRead,
}

#[derive(Clone, Debug)]
pub struct UserRecord {
    pub username: String,
    pub password_hash: String,
    pub user_id: u64,
    pub capabilities: Vec<Capability>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub user_id: u64,
    pub username: String,
    pub capabilities: Vec<Capability>,
    pub exp: u64, // expiration timestamp
    pub iat: u64, // issued at timestamp
}

#[derive(Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
}

#[derive(Clone)]
pub struct AuthService {
    users: Arc<RwLock<HashMap<String, UserRecord>>>,
}

impl AuthService {
    pub fn new() -> Self {
        let mut users = HashMap::new();

        // Alice has full permissions
        users.insert(
            "alice".to_string(),
            UserRecord {
                username: "alice".to_string(),
                password_hash: "password123".to_string(), // In reality, this would be hashed
                user_id: 1,
                capabilities: vec![
                    Capability::PersonalFilesRead,
                    Capability::PersonalFilesWrite,
                    Capability::PersonalFilesDelete,
                    Capability::SharedFilesRead,
                    Capability::SharedFilesWrite,
                    Capability::AdminLogsRead,
                ],
            },
        );

        // Bob has read-only access
        users.insert(
            "bob".to_string(),
            UserRecord {
                username: "bob".to_string(),
                password_hash: "password123".to_string(),
                user_id: 2,
                capabilities: vec![Capability::PersonalFilesRead, Capability::SharedFilesRead],
            },
        );

        // Charlie is a moderator with shared file write access
        users.insert(
            "charlie".to_string(),
            UserRecord {
                username: "charlie".to_string(),
                password_hash: "password123".to_string(),
                user_id: 3,
                capabilities: vec![
                    Capability::PersonalFilesRead,
                    Capability::PersonalFilesWrite,
                    Capability::SharedFilesRead,
                    Capability::SharedFilesWrite,
                ],
            },
        );

        Self {
            users: Arc::new(RwLock::new(users)),
        }
    }

    pub async fn sample_users(&self) -> Vec<UserRecord> {
        self.users.read().await.values().cloned().collect()
    }

    pub async fn authenticate(&self, username: &str, password: &str) -> ApiResult<String> {
        let users = self.users.read().await;
        let user = users
            .get(username)
            .ok_or_else(|| ApiError::unauthorized("Invalid username or password"))?;

        if user.password_hash != password {
            return Err(ApiError::unauthorized("Invalid username or password"));
        }

        let claims = TokenClaims {
            user_id: user.user_id,
            username: user.username.clone(),
            capabilities: user.capabilities.clone(),
            exp: (Utc::now() + Duration::hours(24)).timestamp() as u64,
            iat: Utc::now().timestamp() as u64,
        };

        self.create_token(&claims)
    }

    pub fn create_token(&self, claims: &TokenClaims) -> ApiResult<String> {
        let header = JwtHeader {
            alg: "HS256".to_string(),
            typ: "JWT".to_string(),
        };

        let header_json = serde_json::to_string(&header)
            .map_err(|err| ApiError::internal(anyhow!("Failed to serialize header: {err}")))?;
        let claims_json = serde_json::to_string(claims)
            .map_err(|err| ApiError::internal(anyhow!("Failed to serialize claims: {err}")))?;

        let header_b64 = base64_url_encode(header_json.as_bytes());
        let claims_b64 = base64_url_encode(claims_json.as_bytes());

        let message = format!("{header_b64}.{claims_b64}");

        let mut mac = HmacSha256::new_from_slice(JWT_SECRET)
            .map_err(|err| ApiError::internal(anyhow!("Failed to create HMAC: {err}")))?;
        mac.update(message.as_bytes());
        let signature = mac.finalize().into_bytes();
        let signature_b64 = base64_url_encode(&signature);

        Ok(format!("{message}.{signature_b64}"))
    }

    pub async fn validate_token(&self, token: &str) -> ApiResult<TokenClaims> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(ApiError::unauthorized("Invalid JWT format"));
        }

        let message = format!("{}.{}", parts[0], parts[1]);

        // Verify signature
        let mut mac = HmacSha256::new_from_slice(JWT_SECRET)
            .map_err(|err| ApiError::internal(anyhow!("Failed to create HMAC: {err}")))?;
        mac.update(message.as_bytes());
        let expected_signature = mac.finalize().into_bytes();
        let expected_signature_b64 = base64_url_encode(&expected_signature);

        if parts[2] != expected_signature_b64 {
            return Err(ApiError::unauthorized("Invalid JWT signature"));
        }

        // Decode claims
        let claims_json = base64_url_decode(parts[1])
            .map_err(|_| ApiError::unauthorized("Invalid JWT claims encoding"))?;
        let claims: TokenClaims = serde_json::from_slice(&claims_json)
            .map_err(|_| ApiError::unauthorized("Invalid JWT claims format"))?;

        // Check expiration
        let now = Utc::now().timestamp() as u64;
        if claims.exp < now {
            return Err(ApiError::unauthorized("JWT token has expired"));
        }

        Ok(claims)
    }
}

pub fn base64_url_encode(input: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.encode(input)
}

pub fn base64_url_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.decode(input)
}
