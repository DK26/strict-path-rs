use anyhow::{Context, Result};
use config::{Config, Environment, File};
use std::path::Path;
use strict_path::{PathBoundary, VirtualRoot};

use crate::types::{
    AppData, AppEnvironment, ApplicationLogs, RawAppConfig, RawLoggingConfig, RawSecurityConfig,
    RawServerConfig, RawStorageConfig, SecurityCerts, SystemCache, UserUploads,
    ValidatedAppConfig, ValidatedLoggingConfig, ValidatedSecurityConfig, ValidatedServerConfig,
    ValidatedStorageConfig,
};

pub struct ConfigManager;

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
        println!("Loading configuration from: {}", config_dir.display());
        println!("Environment: {environment:?}");

        let mut builder = Config::builder();

        // 1. Set defaults
        builder = Self::add_defaults(builder)?;

        // 2. Load base config
        let base_path = config_dir.join("config.toml");
        if base_path.exists() {
            println!("  Loading base config: {}", base_path.display());
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
            println!("  Loading {env_name} config: {}", env_path.display());
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
                println!("  Loading user config: {}", user_path.display());
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
        println!("  Resolved environment: {resolved_environment:?}");

        println!("\nValidating configuration paths...");

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

        println!("\nConfiguration validation successful!");

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
        println!("\nValidating server configuration...");

        // Create virtual root for uploads (user-facing paths)
        let uploads_root = VirtualRoot::<UserUploads>::try_new_create(&server.uploads_dir)
            .with_context(|| {
                format!("Failed to create uploads directory: {}", server.uploads_dir)
            })?;

        println!(
            "  Uploads root: {}",
            uploads_root.as_unvirtual().strictpath_display()
        );

        // Validate optional static files directory
        let static_files_dir = if let Some(ref static_dir) = server.static_files_dir {
            let static_files_dir =
                PathBoundary::<AppData>::try_new_create(static_dir).with_context(|| {
                    format!("Failed to create static files directory: {static_dir}")
                })?;

            println!("  Static files: {}", static_files_dir.strictpath_display());
            Some(static_files_dir)
        } else {
            println!("  No static files directory configured");
            None
        };

        Ok(ValidatedServerConfig {
            host: server.host.clone(),
            port: server.port,
            workers: server.workers,
            uploads_root,
            static_files_dir,
        })
    }

    fn validate_storage(storage: &RawStorageConfig) -> Result<ValidatedStorageConfig> {
        println!("\nValidating storage configuration...");

        // Create virtual root for application data
        let data_root = VirtualRoot::<AppData>::try_new_create(&storage.data_root)
            .with_context(|| format!("Failed to create data directory: {}", storage.data_root))?;

        println!(
            "  Data root: {}",
            data_root.as_unvirtual().strictpath_display()
        );

        // Validate database path within data root
        let database_file = data_root
            .virtual_join(&storage.database_path)
            .with_context(|| format!("Invalid database path: {}", storage.database_path))?;

        println!("  Database: {}", database_file.virtualpath_display());

        // Validate backup directory within data root
        let backup_dir = data_root
            .virtual_join(&storage.backup_dir)
            .with_context(|| format!("Invalid backup directory: {}", storage.backup_dir))?;

        // Ensure backup directory exists
        backup_dir.create_dir_all()?;
        println!("  Backup dir: {}", backup_dir.virtualpath_display());

        // Validate optional export directory
        let export_dir = if let Some(ref export) = storage.export_dir {
            let dir = data_root
                .virtual_join(export)
                .with_context(|| format!("Invalid export directory: {export}"))?;
            dir.create_dir_all()?;
            println!("  Export dir: {}", dir.virtualpath_display());
            Some(dir)
        } else {
            None
        };

        // Create cache boundary (strict, not virtual - for system use)
        let cache_dir = PathBoundary::<SystemCache>::try_new_create(&storage.cache_root)
            .with_context(|| {
                format!("Failed to create cache directory: {}", storage.cache_root)
            })?;

        println!("  Cache root: {}", cache_dir.strictpath_display());

        Ok(ValidatedStorageConfig {
            data_root,
            cache_dir,
            database_file,
            backup_dir,
            export_dir,
        })
    }

    fn validate_security(security: &RawSecurityConfig) -> Result<ValidatedSecurityConfig> {
        println!("\nValidating security configuration...");

        // Create strict boundary for certificates (security-critical)
        let certs_dir = PathBoundary::<SecurityCerts>::try_new_create(&security.cert_dir)
            .with_context(|| {
                format!(
                    "Failed to create certificate directory: {}",
                    security.cert_dir
                )
            })?;

        println!("  Certificate directory: {}", certs_dir.strictpath_display());

        // Validate key file within certificate boundary
        let key_file = certs_dir
            .strict_join(&security.key_file)
            .with_context(|| format!("Invalid key file path: {}", security.key_file))?;

        if !key_file.exists() {
            println!(
                "  Key file does not exist yet: {}",
                key_file.strictpath_display()
            );
        } else {
            println!("  Key file: {}", key_file.strictpath_display());
        }

        if !security.allowed_origins.is_empty() {
            println!("  Allowed origins: {:?}", security.allowed_origins);
        }

        Ok(ValidatedSecurityConfig {
            certs_dir,
            key_file,
            allowed_origins: security.allowed_origins.clone(),
            session_timeout_seconds: security.session_timeout_seconds,
        })
    }

    fn validate_logging(
        logging: &RawLoggingConfig,
        data_root: &VirtualRoot<AppData>,
    ) -> Result<ValidatedLoggingConfig> {
        println!("\nValidating logging configuration...");

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

            println!("  Log file: {}", file.virtualpath_display());
            Some(file)
        } else {
            println!("  No log file configured (logging to stdout)");
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
