use serde::Deserialize;
use strict_path::{PathBoundary, StrictPath, VirtualPath, VirtualRoot};

// ============================================================================
// Marker Types
// ============================================================================

pub struct AppData;
pub struct UserUploads;
pub struct SystemCache;
pub struct ApplicationLogs;
pub struct SecurityCerts;

// ============================================================================
// Application Environment
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AppEnvironment {
    #[default]
    Development,
    Testing,
    Production,
}

// ============================================================================
// Raw Configuration (from config files - strings only)
// ============================================================================

/// Raw configuration structure with untrusted string paths.
/// This is what we deserialize from config files.
#[derive(Debug, Deserialize)]
pub struct RawAppConfig {
    pub app_name: String,
    pub version: String,

    #[serde(default)]
    pub environment: AppEnvironment,

    #[serde(default)]
    pub debug: bool,

    pub server: RawServerConfig,
    pub storage: RawStorageConfig,
    pub security: RawSecurityConfig,
    pub logging: RawLoggingConfig,
}

#[derive(Debug, Deserialize)]
pub struct RawServerConfig {
    pub host: String,
    pub port: u16,

    #[serde(default = "default_workers")]
    pub workers: usize,

    // Path as string - needs validation
    pub uploads_dir: String,

    // Optional path
    pub static_files_dir: Option<String>,
}

pub fn default_workers() -> usize {
    4
}

#[derive(Debug, Deserialize)]
pub struct RawStorageConfig {
    // Root directories as strings
    pub data_root: String,
    pub cache_root: String,

    // Specific paths within roots
    pub database_path: String,
    pub backup_dir: String,

    // Optional paths
    pub export_dir: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RawSecurityConfig {
    pub cert_dir: String,
    pub key_file: String,

    #[serde(default)]
    pub allowed_origins: Vec<String>,

    #[serde(default = "default_session_timeout")]
    pub session_timeout_seconds: u64,
}

pub fn default_session_timeout() -> u64 {
    3600
}

#[derive(Debug, Deserialize)]
pub struct RawLoggingConfig {
    pub level: String,
    pub format: String,

    // Log file path
    pub log_file: Option<String>,

    #[serde(default = "default_max_size_mb")]
    pub max_size_mb: u64,
}

pub fn default_max_size_mb() -> u64 {
    100
}

// ============================================================================
// Validated Configuration (with typed, secure paths)
// ============================================================================

/// Validated configuration with typed, boundary-checked paths.
/// All paths have been validated and are guaranteed to be within their boundaries.
#[derive(Debug)]
pub struct ValidatedAppConfig {
    pub app_name: String,
    pub version: String,
    pub environment: AppEnvironment,
    pub debug: bool,

    pub server: ValidatedServerConfig,
    pub storage: ValidatedStorageConfig,
    pub security: ValidatedSecurityConfig,
    pub logging: ValidatedLoggingConfig,
}

#[derive(Debug)]
pub struct ValidatedServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,

    // Validated virtual root for uploads
    pub uploads_root: VirtualRoot<UserUploads>,

    // Optional static files boundary
    pub static_files_dir: Option<PathBoundary<AppData>>,
}

#[derive(Debug)]
pub struct ValidatedStorageConfig {
    // Virtual roots for user-facing paths
    pub data_root: VirtualRoot<AppData>,
    pub cache_dir: PathBoundary<SystemCache>,

    // Validated paths within roots
    pub database_file: VirtualPath<AppData>,
    pub backup_dir: VirtualPath<AppData>,

    // Optional paths
    pub export_dir: Option<VirtualPath<AppData>>,
}

#[derive(Debug)]
pub struct ValidatedSecurityConfig {
    // Strict paths for security-critical files
    pub certs_dir: PathBoundary<SecurityCerts>,
    pub key_file: StrictPath<SecurityCerts>,

    pub allowed_origins: Vec<String>,
    pub session_timeout_seconds: u64,
}

#[derive(Debug)]
pub struct ValidatedLoggingConfig {
    pub level: String,
    pub format: String,

    // Optional log file path
    pub log_file: Option<VirtualPath<ApplicationLogs>>,

    pub max_size_mb: u64,
}
