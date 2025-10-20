//! Configuration Management Example
//!
//! Demonstrates the recommended pattern for loading and validating configuration
//! with the `config` crate and strict-path. Shows how to:
//!
//! 1. Load hierarchical configuration (defaults → files → env vars → overrides)
//! 2. Deserialize to raw string paths (untrusted input)
//! 3. **Manually validate paths** using strict_join/virtual_join
//! 4. Store validated paths in application structs
//! 5. Handle multiple config formats (TOML, JSON, YAML)
//! 6. Environment-specific configuration
//!
//! **Key Pattern**: Config files contain strings → validate → store typed paths
//!
//! ```text
//! Config File (TOML/JSON/YAML)
//!     ↓ deserialize
//! RawConfig { paths: Vec<String> }
//!     ↓ validate via strict_join/virtual_join
//! ValidatedConfig { paths: Vec<VirtualPath<_>> }
//!     ↓ use safely
//! Application logic
//! ```

use anyhow::{Context, Result};
use config::{Config, Environment, File};
use serde::Deserialize;
use std::path::Path;
use strict_path::{PathBoundary, StrictPath, VirtualPath, VirtualRoot};

// ============================================================================
// Marker Types
// ============================================================================

struct AppData;
struct UserUploads;
struct SystemCache;
struct ApplicationLogs;
struct SecurityCerts;

// ============================================================================
// Application Environment
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
enum AppEnvironment {
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
struct RawAppConfig {
    app_name: String,
    version: String,

    #[serde(default)]
    environment: AppEnvironment,

    #[serde(default)]
    debug: bool,

    server: RawServerConfig,
    storage: RawStorageConfig,
    security: RawSecurityConfig,
    logging: RawLoggingConfig,
}

#[derive(Debug, Deserialize)]
struct RawServerConfig {
    host: String,
    port: u16,

    #[serde(default = "default_workers")]
    workers: usize,

    // Path as string - needs validation
    uploads_dir: String,

    // Optional path
    static_files_dir: Option<String>,
}

fn default_workers() -> usize {
    4
}

#[derive(Debug, Deserialize)]
struct RawStorageConfig {
    // Root directories as strings
    data_root: String,
    cache_root: String,

    // Specific paths within roots
    database_path: String,
    backup_dir: String,

    // Optional paths
    export_dir: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawSecurityConfig {
    cert_dir: String,
    key_file: String,

    #[serde(default)]
    allowed_origins: Vec<String>,

    #[serde(default = "default_session_timeout")]
    session_timeout_seconds: u64,
}

fn default_session_timeout() -> u64 {
    3600
}

#[derive(Debug, Deserialize)]
struct RawLoggingConfig {
    level: String,
    format: String,

    // Log file path
    log_file: Option<String>,

    #[serde(default = "default_max_size_mb")]
    max_size_mb: u64,
}

fn default_max_size_mb() -> u64 {
    100
}

// ============================================================================
// Validated Configuration (with typed, secure paths)
// ============================================================================

/// Validated configuration with typed, boundary-checked paths.
/// All paths have been validated and are guaranteed to be within their boundaries.
#[derive(Debug)]
struct ValidatedAppConfig {
    app_name: String,
    version: String,
    environment: AppEnvironment,
    debug: bool,

    server: ValidatedServerConfig,
    storage: ValidatedStorageConfig,
    security: ValidatedSecurityConfig,
    logging: ValidatedLoggingConfig,
}

#[derive(Debug)]
struct ValidatedServerConfig {
    host: String,
    port: u16,
    workers: usize,

    // Validated virtual root for uploads
    uploads_root: VirtualRoot<UserUploads>,

    // Optional static files boundary
    static_files_boundary: Option<PathBoundary<AppData>>,
}

#[derive(Debug)]
struct ValidatedStorageConfig {
    // Virtual roots for user-facing paths
    data_root: VirtualRoot<AppData>,
    cache_boundary: PathBoundary<SystemCache>,

    // Validated paths within roots
    database_file: VirtualPath<AppData>,
    backup_dir: VirtualPath<AppData>,

    // Optional paths
    export_dir: Option<VirtualPath<AppData>>,
}

#[derive(Debug)]
struct ValidatedSecurityConfig {
    // Strict paths for security-critical files
    cert_boundary: PathBoundary<SecurityCerts>,
    key_file: StrictPath<SecurityCerts>,

    allowed_origins: Vec<String>,
    session_timeout_seconds: u64,
}

#[derive(Debug)]
struct ValidatedLoggingConfig {
    level: String,
    format: String,

    // Optional log file path
    log_file: Option<VirtualPath<ApplicationLogs>>,

    max_size_mb: u64,
}

// ============================================================================
// Configuration Manager
// ============================================================================

struct ConfigManager;

impl ConfigManager {
    /// Load configuration with hierarchical precedence:
    /// 1. Built-in defaults
    /// 2. Base config file (config.toml)
    /// 3. Environment-specific config (config.{env}.toml)
    /// 4. Environment variables (APP_*)
    /// 5. User config file (optional)
    pub fn load_config(
        config_dir: &Path,
        environment: AppEnvironment,
        user_config: Option<&Path>,
    ) -> Result<ValidatedAppConfig> {
        println!("📁 Loading configuration from: {}", config_dir.display());
        println!("🌍 Environment: {:?}", environment);

        let mut builder = Config::builder();

        // 1. Set defaults
        builder = Self::add_defaults(builder)?;

        // 2. Load base config
        let base_path = config_dir.join("config.toml");
        if base_path.exists() {
            println!("  ✓ Loading base config: {}", base_path.display());
            builder = builder.add_source(File::from(base_path));
        }

        // 3. Load environment-specific config
        let env_name = match environment {
            AppEnvironment::Development => "dev",
            AppEnvironment::Testing => "test",
            AppEnvironment::Production => "prod",
        };
        let env_path = config_dir.join(format!("config.{env_name}.toml"));
        if env_path.exists() {
            println!("  ✓ Loading {env_name} config: {}", env_path.display());
            builder = builder.add_source(File::from(env_path));
        }

        // 4. Add environment variables with APP_ prefix
        builder = builder.add_source(
            Environment::with_prefix("APP")
                .separator("__")
                .try_parsing(true),
        );

        // 5. Add user config if provided
        if let Some(user_path) = user_config {
            if user_path.exists() {
                println!("  ✓ Loading user config: {}", user_path.display());
                builder = builder.add_source(File::from(user_path));
            }
        }

        // Build and deserialize to raw config
        let config = builder.build().context("Failed to build configuration")?;

        let raw_config: RawAppConfig = config
            .try_deserialize()
            .context("Failed to deserialize configuration")?;

        // Use environment from config file if present, otherwise use parameter
        let resolved_environment = raw_config.environment;
        println!("  ✓ Resolved environment: {resolved_environment:?}");

        println!("\n🔍 Validating configuration paths...");

        // 6. Validate and convert to secure path types
        Self::validate_config(raw_config, environment)
    }

    fn add_defaults(
        mut builder: config::ConfigBuilder<config::builder::DefaultState>,
    ) -> Result<config::ConfigBuilder<config::builder::DefaultState>> {
        builder = builder
            // App defaults
            .set_default("app_name", "SecureApp")?
            .set_default("version", "1.0.0")?
            .set_default("debug", false)?
            // Server defaults
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 8080)?
            .set_default("server.workers", 4)?
            .set_default("server.uploads_dir", "./uploads")?
            // Storage defaults
            .set_default("storage.data_root", "./data")?
            .set_default("storage.cache_root", "./cache")?
            .set_default("storage.database_path", "app.db")?
            .set_default("storage.backup_dir", "backups")?
            // Security defaults
            .set_default("security.cert_dir", "./certs")?
            .set_default("security.key_file", "private.key")?
            .set_default("security.session_timeout_seconds", 3600)?
            // Logging defaults
            .set_default("logging.level", "info")?
            .set_default("logging.format", "json")?
            .set_default("logging.max_size_mb", 100)?;

        Ok(builder)
    }

    /// **Core validation logic**: Convert raw string paths to validated types.
    ///
    /// This is the recommended pattern:
    /// 1. Deserialize config to raw strings
    /// 2. Create boundaries/roots for base directories
    /// 3. Validate paths using strict_join/virtual_join
    /// 4. Return validated config with typed paths
    fn validate_config(
        raw: RawAppConfig,
        environment: AppEnvironment,
    ) -> Result<ValidatedAppConfig> {
        // Validate server configuration
        let server = Self::validate_server(&raw.server)
            .context("Failed to validate server configuration")?;

        // Validate storage configuration
        let storage = Self::validate_storage(&raw.storage)
            .context("Failed to validate storage configuration")?;

        // Validate security configuration
        let security = Self::validate_security(&raw.security)
            .context("Failed to validate security configuration")?;

        // Validate logging configuration
        let logging = Self::validate_logging(&raw.logging, &storage.data_root)
            .context("Failed to validate logging configuration")?;

        println!("\n✅ Configuration validation successful!");

        Ok(ValidatedAppConfig {
            app_name: raw.app_name,
            version: raw.version,
            environment,
            debug: raw.debug,
            server,
            storage,
            security,
            logging,
        })
    }

    fn validate_server(server: &RawServerConfig) -> Result<ValidatedServerConfig> {
        println!("\n🌐 Validating server configuration...");

        // Create virtual root for uploads (user-facing paths)
        let uploads_root = VirtualRoot::<UserUploads>::try_new_create(&server.uploads_dir)
            .with_context(|| {
                format!("Failed to create uploads directory: {}", server.uploads_dir)
            })?;

        println!(
            "  ✓ Uploads root: {}",
            uploads_root.as_unvirtual().strictpath_display()
        );

        // Validate optional static files directory
        let static_files_boundary = if let Some(ref static_dir) = server.static_files_dir {
            let boundary =
                PathBoundary::<AppData>::try_new_create(static_dir).with_context(|| {
                    format!("Failed to create static files directory: {static_dir}")
                })?;

            println!("  ✓ Static files: {}", boundary.strictpath_display());
            Some(boundary)
        } else {
            println!("  ⚠ No static files directory configured");
            None
        };

        Ok(ValidatedServerConfig {
            host: server.host.clone(),
            port: server.port,
            workers: server.workers,
            uploads_root,
            static_files_boundary,
        })
    }

    fn validate_storage(storage: &RawStorageConfig) -> Result<ValidatedStorageConfig> {
        println!("\n💾 Validating storage configuration...");

        // Create virtual root for application data
        let data_root = VirtualRoot::<AppData>::try_new_create(&storage.data_root)
            .with_context(|| format!("Failed to create data directory: {}", storage.data_root))?;

        println!(
            "  ✓ Data root: {}",
            data_root.as_unvirtual().strictpath_display()
        );

        // Validate database path within data root
        let database_file = data_root
            .virtual_join(&storage.database_path)
            .with_context(|| format!("Invalid database path: {}", storage.database_path))?;

        println!("  ✓ Database: {}", database_file.virtualpath_display());

        // Validate backup directory within data root
        let backup_dir = data_root
            .virtual_join(&storage.backup_dir)
            .with_context(|| format!("Invalid backup directory: {}", storage.backup_dir))?;

        // Ensure backup directory exists
        backup_dir.create_dir_all()?;
        println!("  ✓ Backup dir: {}", backup_dir.virtualpath_display());

        // Validate optional export directory
        let export_dir = if let Some(ref export) = storage.export_dir {
            let dir = data_root
                .virtual_join(export)
                .with_context(|| format!("Invalid export directory: {export}"))?;
            dir.create_dir_all()?;
            println!("  ✓ Export dir: {}", dir.virtualpath_display());
            Some(dir)
        } else {
            None
        };

        // Create cache boundary (strict, not virtual - for system use)
        let cache_boundary = PathBoundary::<SystemCache>::try_new_create(&storage.cache_root)
            .with_context(|| format!("Failed to create cache directory: {}", storage.cache_root))?;

        println!("  ✓ Cache root: {}", cache_boundary.strictpath_display());

        Ok(ValidatedStorageConfig {
            data_root,
            cache_boundary,
            database_file,
            backup_dir,
            export_dir,
        })
    }

    fn validate_security(security: &RawSecurityConfig) -> Result<ValidatedSecurityConfig> {
        println!("\n🔒 Validating security configuration...");

        // Create strict boundary for certificates (security-critical)
        let cert_boundary = PathBoundary::<SecurityCerts>::try_new_create(&security.cert_dir)
            .with_context(|| {
                format!(
                    "Failed to create certificate directory: {}",
                    security.cert_dir
                )
            })?;

        println!(
            "  ✓ Certificate directory: {}",
            cert_boundary.strictpath_display()
        );

        // Validate key file within certificate boundary
        let key_file = cert_boundary
            .strict_join(&security.key_file)
            .with_context(|| format!("Invalid key file path: {}", security.key_file))?;

        if !key_file.exists() {
            println!(
                "  ⚠ Key file does not exist yet: {}",
                key_file.strictpath_display()
            );
        } else {
            println!("  ✓ Key file: {}", key_file.strictpath_display());
        }

        if !security.allowed_origins.is_empty() {
            println!("  ✓ Allowed origins: {:?}", security.allowed_origins);
        }

        Ok(ValidatedSecurityConfig {
            cert_boundary,
            key_file,
            allowed_origins: security.allowed_origins.clone(),
            session_timeout_seconds: security.session_timeout_seconds,
        })
    }

    fn validate_logging(
        logging: &RawLoggingConfig,
        data_root: &VirtualRoot<AppData>,
    ) -> Result<ValidatedLoggingConfig> {
        println!("\n📝 Validating logging configuration...");

        // Validate optional log file path
        let log_file = if let Some(ref log_path) = logging.log_file {
            // Create logs subdirectory in data root
            let logs_subdir = data_root
                .virtual_join("logs")
                .context("Invalid logs directory")?;
            logs_subdir.create_dir_all()?;

            // Validate log file path within logs directory
            let logs_root = VirtualRoot::<ApplicationLogs>::try_new(logs_subdir.interop_path())
                .context("Failed to create logs virtual root")?;

            let file = logs_root
                .virtual_join(log_path)
                .with_context(|| format!("Invalid log file path: {log_path}"))?;

            println!("  ✓ Log file: {}", file.virtualpath_display());
            Some(file)
        } else {
            println!("  ⚠ No log file configured (logging to stdout)");
            None
        };

        Ok(ValidatedLoggingConfig {
            level: logging.level.clone(),
            format: logging.format.clone(),
            log_file,
            max_size_mb: logging.max_size_mb,
        })
    }
}

// ============================================================================
// Demo Application
// ============================================================================

/// Demonstrates using validated configuration in application code
struct DemoApp {
    config: ValidatedAppConfig,
}

impl DemoApp {
    fn new(config: ValidatedAppConfig) -> Self {
        Self { config }
    }

    /// Simulate handling a file upload using validated paths
    fn handle_upload(&self, filename: &str, _content: &[u8]) -> Result<()> {
        println!("\n📤 Handling file upload: {filename}");

        // The uploads_root is already validated - we can safely join user input
        let upload_file = self
            .config
            .server
            .uploads_root
            .virtual_join(filename)
            .context("Invalid filename")?;

        // Demonstrate safe operations
        println!("  Would save to: {}", upload_file.virtualpath_display());
        println!(
            "  System path: {}",
            upload_file.as_unvirtual().strictpath_display()
        );

        Ok(())
    }

    /// Access database using validated path
    fn access_database(&self) -> Result<()> {
        println!("\n💾 Accessing database...");

        let db_path = &self.config.storage.database_file;
        println!("  Database location: {}", db_path.virtualpath_display());

        // In real code, you'd open the database using db_path.interop_path()
        // let conn = Connection::open(db_path.interop_path())?;

        Ok(())
    }

    /// Perform backup using validated paths
    fn create_backup(&self, backup_name: &str) -> Result<()> {
        println!("\n💾 Creating backup: {backup_name}");

        let backup_file = self
            .config
            .storage
            .backup_dir
            .virtual_join(backup_name)
            .context("Invalid backup filename")?;

        println!("  Backup location: {}", backup_file.virtualpath_display());

        // Demonstrate creating parent directories
        backup_file.create_parent_dir_all()?;

        Ok(())
    }

    /// Access security certificate
    fn load_certificate(&self) -> Result<()> {
        println!("\n🔒 Loading security certificate...");

        let cert_file = self
            .config
            .security
            .cert_boundary
            .strict_join("server.crt")
            .context("Invalid certificate filename")?;

        println!("  Certificate: {}", cert_file.strictpath_display());

        if cert_file.exists() {
            println!("  ✓ Certificate file found");
        } else {
            println!("  ⚠ Certificate file not found");
        }

        Ok(())
    }

    fn print_summary(&self) {
        println!("\n{}", "=".repeat(60));
        println!("📋 Application Configuration Summary");
        println!("{}", "=".repeat(60));
        println!(
            "🏷️  Name: {} v{}",
            self.config.app_name, self.config.version
        );
        println!("🌍 Environment: {:?}", self.config.environment);
        println!("🐛 Debug mode: {}", self.config.debug);
        println!("\n🌐 Server:");
        println!(
            "  • Address: {}:{}",
            self.config.server.host, self.config.server.port
        );
        println!("  • Workers: {}", self.config.server.workers);
        if self.config.server.static_files_boundary.is_some() {
            println!("  • Static files: enabled");
        }
        println!("\n💾 Storage:");
        if let Some(ref export) = self.config.storage.export_dir {
            println!("  • Export dir: {}", export.virtualpath_display());
        }
        println!(
            "  • Cache: {}",
            self.config.storage.cache_boundary.strictpath_display()
        );
        println!("\n� Security:");
        println!(
            "  • Key file: {}",
            self.config.security.key_file.strictpath_display()
        );
        println!(
            "  • Session timeout: {}s",
            self.config.security.session_timeout_seconds
        );
        println!(
            "  • Allowed origins: {}",
            self.config.security.allowed_origins.len()
        );
        println!("\n�📝 Logging:");
        println!("  • Level: {}", self.config.logging.level);
        println!("  • Format: {}", self.config.logging.format);
        if let Some(ref log_file) = self.config.logging.log_file {
            println!("  • File: {}", log_file.virtualpath_display());
        }
        println!("  • Max size: {} MB", self.config.logging.max_size_mb);
        println!("{}", "=".repeat(60));
    }
}

// ============================================================================
// Main Function
// ============================================================================

fn main() -> Result<()> {
    println!("🚀 Configuration Management Example");
    println!("Demonstrates manual path validation with the config crate\n");

    // Setup demo config files
    setup_demo_configs()?;

    // Determine environment (from env var or default to development)
    let environment = std::env::var("APP_ENVIRONMENT")
        .ok()
        .and_then(|s| match s.to_lowercase().as_str() {
            "development" | "dev" => Some(AppEnvironment::Development),
            "testing" | "test" => Some(AppEnvironment::Testing),
            "production" | "prod" => Some(AppEnvironment::Production),
            _ => None,
        })
        .unwrap_or_default();

    // Load and validate configuration
    let config = ConfigManager::load_config(
        Path::new("./config"),
        environment,
        None, // No user config for this demo
    )?;

    // Create application with validated config
    let app = DemoApp::new(config);

    // Print configuration summary
    app.print_summary();

    // Demonstrate using validated paths
    println!("\n{}", "=".repeat(60));
    println!("🎯 Demonstrating Safe Operations");
    println!("{}", "=".repeat(60));

    app.handle_upload("user_document.pdf", b"fake content")?;
    app.access_database()?;
    app.create_backup("daily_backup.tar.gz")?;
    app.load_certificate()?;

    // Cleanup demo files
    cleanup_demo()?;

    println!("\n✅ Demo completed successfully!");
    println!("\n💡 Key Takeaways:");
    println!("  1. Deserialize config to raw strings (RawAppConfig)");
    println!("  2. Validate paths using strict_join/virtual_join");
    println!("  3. Store validated types (ValidatedAppConfig)");
    println!("  4. Use validated paths safely in application");

    Ok(())
}

// ============================================================================
// Demo Setup/Teardown
// ============================================================================

fn setup_demo_configs() -> Result<()> {
    println!("🔧 Setting up demo configuration files...\n");

    std::fs::create_dir_all("./config")?;

    // Base config (config.toml)
    let base_config = r#"
app_name = "SecureFileManager"
version = "2.1.0"
debug = false

[server]
host = "0.0.0.0"
port = 8080
workers = 8
uploads_dir = "./uploads"
static_files_dir = "./public"

[storage]
data_root = "./app_data"
cache_root = "./cache"
database_path = "database.db"
backup_dir = "db_backups"
export_dir = "exports"

[security]
cert_dir = "./certs"
key_file = "server.key"
allowed_origins = ["https://example.com", "https://app.example.com"]
session_timeout_seconds = 7200

[logging]
level = "info"
format = "json"
log_file = "app.log"
max_size_mb = 50
"#;
    std::fs::write("./config/config.toml", base_config)?;

    // Development config (config.dev.toml)
    let dev_config = r#"
debug = true

[server]
host = "127.0.0.1"
workers = 2

[logging]
level = "debug"
format = "pretty"
"#;
    std::fs::write("./config/config.dev.toml", dev_config)?;

    // Production config (config.prod.toml)
    let prod_config = r#"
debug = false

[server]
workers = 16

[logging]
level = "warn"
max_size_mb = 200
"#;
    std::fs::write("./config/config.prod.toml", prod_config)?;

    println!("  ✓ Created config/config.toml (base)");
    println!("  ✓ Created config/config.dev.toml (development)");
    println!("  ✓ Created config/config.prod.toml (production)\n");

    Ok(())
}

fn cleanup_demo() -> Result<()> {
    println!("\n🧹 Cleaning up demo files...");

    // Remove created directories
    let dirs_to_remove = vec![
        "./config",
        "./uploads",
        "./public",
        "./app_data",
        "./cache",
        "./certs",
    ];

    for dir in dirs_to_remove {
        if Path::new(dir).exists() {
            std::fs::remove_dir_all(dir).ok();
            println!("  ✓ Removed {dir}");
        }
    }

    Ok(())
}
