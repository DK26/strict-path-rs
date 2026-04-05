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
use std::path::Path;

mod config_manager;
mod types;

use config_manager::ConfigManager;
use types::{AppEnvironment, ValidatedAppConfig};

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
        println!("\nHandling file upload: {filename}");

        // The uploads_root is already validated - we can safely join user input
        let upload_file = self
            .config
            .server
            .uploads_root
            .virtual_join(filename)
            .context("Invalid filename")?;

        // Demonstrate safe operations
        let upload_vpath = upload_file.virtualpath_display();
        let upload_spath = upload_file.as_unvirtual().strictpath_display();
        println!("  Would save to: {upload_vpath}");
        println!("  System path: {upload_spath}");

        Ok(())
    }

    /// Access database using validated path
    fn access_database(&self) -> Result<()> {
        println!("\nAccessing database...");

        let db_path = &self.config.storage.database_file;
        let db_display = db_path.virtualpath_display();
        println!("  Database location: {db_display}");

        // In real code, you'd open the database using db_path.interop_path()
        // let conn = Connection::open(db_path.interop_path())?;

        Ok(())
    }

    /// Perform backup using validated paths
    fn create_backup(&self, backup_name: &str) -> Result<()> {
        println!("\nCreating backup: {backup_name}");

        let backup_file = self
            .config
            .storage
            .backup_dir
            .virtual_join(backup_name)
            .context("Invalid backup filename")?;

        let backup_display = backup_file.virtualpath_display();
        println!("  Backup location: {backup_display}");

        // Demonstrate creating parent directories
        backup_file.create_parent_dir_all()?;

        Ok(())
    }

    /// Access security certificate
    fn load_certificate(&self) -> Result<()> {
        println!("\nLoading security certificate...");

        let cert_file = self
            .config
            .security
            .certs_dir
            .strict_join("server.crt")
            .context("Invalid certificate filename")?;

        let cert_display = cert_file.strictpath_display();
        println!("  Certificate: {cert_display}");

        if cert_file.exists() {
            println!("  Certificate file found");
        } else {
            println!("  Certificate file not found");
        }

        Ok(())
    }

    fn print_summary(&self) {
        let sep = "=".repeat(60);
        println!("\n{sep}");
        println!("Application Configuration Summary");
        println!("{sep}");
        let app_name = &self.config.app_name;
        let version = &self.config.version;
        println!("Name: {app_name} v{version}");
        println!("Environment: {:?}", self.config.environment);
        let debug = self.config.debug;
        println!("Debug mode: {debug}");
        println!("\nServer:");
        let host = &self.config.server.host;
        let port = self.config.server.port;
        println!("  Address: {host}:{port}");
        let workers = self.config.server.workers;
        println!("  Workers: {workers}");
        if self.config.server.static_files_dir.is_some() {
            println!("  Static files: enabled");
        }
        println!("\nStorage:");
        if let Some(ref export) = self.config.storage.export_dir {
            let export_display = export.virtualpath_display();
            println!("  Export dir: {export_display}");
        }
        let cache_display = self.config.storage.cache_dir.strictpath_display();
        println!("  Cache: {cache_display}");
        println!("\nSecurity:");
        let key_display = self.config.security.key_file.strictpath_display();
        println!("  Key file: {key_display}");
        let timeout = self.config.security.session_timeout_seconds;
        println!("  Session timeout: {timeout}s");
        let origins_count = self.config.security.allowed_origins.len();
        println!("  Allowed origins: {origins_count}");
        println!("\nLogging:");
        let level = &self.config.logging.level;
        let format = &self.config.logging.format;
        println!("  Level: {level}");
        println!("  Format: {format}");
        if let Some(ref log_file) = self.config.logging.log_file {
            let log_display = log_file.virtualpath_display();
            println!("  File: {log_display}");
        }
        let max_size = self.config.logging.max_size_mb;
        println!("  Max size: {max_size} MB");
        println!("{sep}");
    }
}

// ============================================================================
// Main Function
// ============================================================================

fn main() -> Result<()> {
    println!("Configuration Management Example");
    println!("Demonstrates manual path validation with the config crate\n");

    // Setup demo config files
    setup_demo_configs()?;

    // Determine environment (from env var or default to development)
    let environment = std::env::var("APP_ENVIRONMENT")
        .ok()
        .and_then(|env_str| match env_str.to_lowercase().as_str() {
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
    let sep = "=".repeat(60);
    println!("\n{sep}");
    println!("Demonstrating Safe Operations");
    println!("{sep}");

    app.handle_upload("user_document.pdf", b"fake content")?;
    app.access_database()?;
    app.create_backup("daily_backup.tar.gz")?;
    app.load_certificate()?;

    // Cleanup demo files
    cleanup_demo()?;

    println!("\nDemo completed successfully!");
    println!("\nKey Takeaways:");
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
    println!("Setting up demo configuration files...\n");

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

    println!("  Created config/config.toml (base)");
    println!("  Created config/config.dev.toml (development)");
    println!("  Created config/config.prod.toml (production)\n");

    Ok(())
}

fn cleanup_demo() -> Result<()> {
    println!("\nCleaning up demo files...");

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
            println!("  Removed {dir}");
        }
    }

    Ok(())
}
