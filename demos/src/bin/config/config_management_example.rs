// Configuration management with the popular `config` crate + strict-path serde integration
//
// This example demonstrates:
// 1. Hierarchical config loading (defaults -> environment -> user config -> CLI overrides)
// 2. Multiple config formats (TOML, JSON, YAML) with automatic detection
// 3. Environment-specific configuration management
// 4. Proper serde integration with VirtualPath/StrictPath types
// 5. Validation and error handling patterns
// 6. Configuration merging and precedence rules

use anyhow::{Context, Result};
use config::{Config, Environment, File, FileFormat, Value};
use serde::{de::DeserializeSeed, Deserialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use strict_path::{
    serde_ext::{WithBoundary, WithVirtualRoot},
    PathBoundary, StrictPath, VirtualPath, VirtualRoot,
};

// Application environment types
#[derive(Debug, Clone, PartialEq)]
enum AppEnvironment {
    Development,
    Testing,
    Production,
}

impl std::str::FromStr for AppEnvironment {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "dev" | "development" => Ok(AppEnvironment::Development),
            "test" | "testing" => Ok(AppEnvironment::Testing),
            "prod" | "production" => Ok(AppEnvironment::Production),
            _ => Err(format!("Invalid environment: {}", s)),
        }
    }
}

// Type markers for different path contexts
#[derive(Clone, Default, Debug)]
struct DataDir;

#[derive(Clone, Default, Debug)]
struct CacheDir;

#[derive(Clone, Default, Debug)]
struct TempDir;

#[derive(Clone, Default, Debug)]
struct LogDir;

// Raw configuration structure (from config files - untrusted strings)
#[derive(Debug, Deserialize)]
struct RawAppConfig {
    // Application settings
    app_name: String,
    version: String,
    debug: bool,

    // Server configuration
    server: RawServerConfig,

    // Database configuration
    database: RawDatabaseConfig,

    // Path configurations (as strings - not yet validated)
    paths: RawPathsConfig,

    // Security settings
    security: RawSecurityConfig,

    // Logging configuration
    logging: RawLoggingConfig,

    // Environment-specific overrides
    #[serde(default)]
    environment_overrides: HashMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct RawServerConfig {
    host: String,
    port: u16,
    workers: usize,
    max_connections: u32,

    // Static file serving paths (strings)
    static_files: Option<String>,
    upload_dir: String,
}

#[derive(Debug, Deserialize)]
struct RawDatabaseConfig {
    url: String,
    max_connections: u32,

    // Database-related paths
    backup_dir: String,
    migration_dir: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawPathsConfig {
    // Core application directories
    data_dir: String,
    cache_dir: String,
    temp_dir: String,
    log_dir: String,

    // Optional paths
    config_dir: Option<String>,
    plugin_dir: Option<String>,

    // Path arrays
    #[serde(default)]
    allowed_upload_dirs: Vec<String>,
    #[serde(default)]
    trusted_data_sources: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawSecurityConfig {
    // Security-related paths
    cert_dir: String,
    key_file: String,

    // Access control
    #[serde(default)]
    allowed_origins: Vec<String>,
    session_timeout: u64,

    // Sandboxing paths
    sandbox_root: String,
    #[serde(default)]
    strict_paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawLoggingConfig {
    level: String,
    format: String,

    // Log output paths
    file_path: Option<String>,
    error_log: Option<String>,
    access_log: Option<String>,

    // Rotation settings
    max_size_mb: u64,
    max_files: u32,
}

// Validated configuration structure (with proper VirtualPath/StrictPath types)
#[derive(Debug)]
struct ValidatedAppConfig {
    // Application settings (validated)
    app_name: String,
    version: String,
    debug: bool,
    environment: AppEnvironment,

    // Server configuration (with validated paths)
    server: ValidatedServerConfig,

    // Database configuration (with validated paths)
    database: ValidatedDatabaseConfig,

    // Validated path configurations
    paths: ValidatedPathsConfig,

    // Security configuration (with validated paths)
    security: ValidatedSecurityConfig,

    // Logging configuration (with validated paths)
    logging: ValidatedLoggingConfig,
}

#[derive(Debug)]
struct ValidatedServerConfig {
    host: String,
    port: u16,
    workers: usize,
    max_connections: u32,

    // Validated paths
    static_files: Option<VirtualPath<DataDir>>,
    upload_dir: VirtualPath<DataDir>,
}

#[derive(Debug)]
struct ValidatedDatabaseConfig {
    url: String,
    max_connections: u32,

    // Validated database paths
    backup_dir: VirtualPath<DataDir>,
    migration_dir: Option<VirtualPath<DataDir>>,
}

#[derive(Debug)]
struct ValidatedPathsConfig {
    // Core validated directories
    data_dir: VirtualRoot<DataDir>,
    cache_dir: VirtualRoot<CacheDir>,
    temp_dir: VirtualRoot<TempDir>,
    log_dir: VirtualRoot<LogDir>,

    // Optional validated paths
    config_dir: Option<VirtualRoot<DataDir>>,
    plugin_dir: Option<VirtualPath<DataDir>>,

    // Validated path collections
    allowed_upload_dirs: Vec<VirtualPath<DataDir>>,
    trusted_data_sources: Vec<StrictPath<DataDir>>,
}

#[derive(Debug)]
struct ValidatedSecurityConfig {
    // Validated security paths
    cert_dir: StrictPath<DataDir>,
    key_file: StrictPath<DataDir>,

    // Access control (strings are fine)
    allowed_origins: Vec<String>,
    session_timeout: u64,

    // Validated sandboxing paths
    sandbox_root: PathBoundary<DataDir>,
    strict_paths: Vec<StrictPath<DataDir>>,
}

#[derive(Debug)]
struct ValidatedLoggingConfig {
    level: String,
    format: String,

    // Validated log paths
    file_path: Option<VirtualPath<LogDir>>,
    error_log: Option<VirtualPath<LogDir>>,
    access_log: Option<VirtualPath<LogDir>>,

    // Rotation settings
    max_size_mb: u64,
    max_files: u32,
}

// Configuration manager - handles the entire config lifecycle
struct ConfigManager {
    environment: AppEnvironment,
    base_dir: PathBuf,
}

impl ConfigManager {
    pub fn new(environment: AppEnvironment) -> Result<Self> {
        let base_dir = std::env::current_dir().context("Failed to get current directory")?;

        Ok(ConfigManager {
            environment,
            base_dir,
        })
    }

    /// Load configuration with hierarchical precedence:
    /// 1. Built-in defaults
    /// 2. Base config file (config.toml)
    /// 3. Environment-specific config (config.dev.toml, config.prod.toml, etc.)
    /// 4. Environment variables (APP_*)
    /// 5. User config file (if specified)
    /// 6. Command-line overrides (if any)
    pub fn load_config(&self, user_config_path: Option<&Path>) -> Result<ValidatedAppConfig> {
        let mut config_builder = Config::builder();

        // 1. Set built-in defaults
        config_builder = self.add_defaults(config_builder)?;

        // 2. Load base configuration file
        config_builder = self.add_base_config(config_builder)?;

        // 3. Load environment-specific configuration
        config_builder = self.add_environment_config(config_builder)?;

        // 4. Add environment variables
        config_builder = self.add_environment_variables(config_builder)?;

        // 5. Add user configuration file if provided
        if let Some(user_path) = user_config_path {
            config_builder = self.add_user_config(config_builder, user_path)?;
        }

        // Build the final configuration
        let raw_config: RawAppConfig = config_builder
            .build()
            .context("Failed to build configuration")?
            .try_deserialize()
            .context("Failed to deserialize configuration")?;

        // 6. Validate and convert to secure path types
        self.validate_config(raw_config)
    }

    fn add_defaults(
        &self,
        mut builder: config::ConfigBuilder<config::builder::DefaultState>,
    ) -> Result<config::ConfigBuilder<config::builder::DefaultState>> {
        // Set application defaults
        builder = builder
            .set_default("app_name", "MySecureApp")?
            .set_default("version", "1.0.0")?
            .set_default("debug", false)?
            // Server defaults
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 8080)?
            .set_default("server.workers", 4)?
            .set_default("server.max_connections", 1000)?
            .set_default("server.upload_dir", "./uploads")?
            // Database defaults
            .set_default("database.url", "sqlite:./data/app.db")?
            .set_default("database.max_connections", 10)?
            .set_default("database.backup_dir", "./backups")?
            // Path defaults
            .set_default("paths.data_dir", "./data")?
            .set_default("paths.cache_dir", "./cache")?
            .set_default("paths.temp_dir", "./tmp")?
            .set_default("paths.log_dir", "./logs")?
            // Security defaults
            .set_default("security.cert_dir", "./certs")?
            .set_default("security.key_file", "./certs/private.key")?
            .set_default("security.session_timeout", 3600)?
            .set_default("security.sandbox_root", "./sandbox")?
            // Logging defaults
            .set_default("logging.level", "info")?
            .set_default("logging.format", "json")?
            .set_default("logging.max_size_mb", 100)?
            .set_default("logging.max_files", 10)?;

        Ok(builder)
    }

    fn add_base_config(
        &self,
        builder: config::ConfigBuilder<config::builder::DefaultState>,
    ) -> Result<config::ConfigBuilder<config::builder::DefaultState>> {
        let config_path = self.base_dir.join("config");

        // Try multiple formats in order of preference
        let formats = [
            ("config.toml", FileFormat::Toml),
            ("config.json", FileFormat::Json),
            ("config.yaml", FileFormat::Yaml),
            ("config.yml", FileFormat::Yaml),
        ];

        for (filename, format) in formats {
            let path = config_path.join(filename);
            if path.exists() {
                println!("📁 Loading base config from: {}", path.display());
                return Ok(builder.add_source(File::from(path).format(format).required(false)));
            }
        }

        println!("ℹ️  No base configuration file found, using defaults");
        Ok(builder)
    }

    fn add_environment_config(
        &self,
        builder: config::ConfigBuilder<config::builder::DefaultState>,
    ) -> Result<config::ConfigBuilder<config::builder::DefaultState>> {
        let config_path = self.base_dir.join("config");
        let env_suffix = match self.environment {
            AppEnvironment::Development => "dev",
            AppEnvironment::Testing => "test",
            AppEnvironment::Production => "prod",
        };

        // Try environment-specific configs
        let env_files = [
            (format!("config.{}.toml", env_suffix), FileFormat::Toml),
            (format!("config.{}.json", env_suffix), FileFormat::Json),
            (format!("config.{}.yaml", env_suffix), FileFormat::Yaml),
            (format!("config.{}.yml", env_suffix), FileFormat::Yaml),
        ];

        for (filename, format) in env_files {
            let path = config_path.join(&filename);
            if path.exists() {
                println!("🌍 Loading environment config from: {}", path.display());
                return Ok(builder.add_source(File::from(path).format(format).required(false)));
            }
        }

        println!(
            "ℹ️  No environment-specific configuration found for: {:?}",
            self.environment
        );
        Ok(builder)
    }

    fn add_environment_variables(
        &self,
        builder: config::ConfigBuilder<config::builder::DefaultState>,
    ) -> Result<config::ConfigBuilder<config::builder::DefaultState>> {
        println!("🔧 Loading environment variables with prefix: APP_");
        Ok(builder.add_source(
            Environment::with_prefix("APP")
                .separator("_")
                .try_parsing(true),
        ))
    }

    fn add_user_config(
        &self,
        builder: config::ConfigBuilder<config::builder::DefaultState>,
        user_path: &Path,
    ) -> Result<config::ConfigBuilder<config::builder::DefaultState>> {
        if !user_path.exists() {
            return Err(anyhow::anyhow!(
                "User config file not found: {}",
                user_path.display()
            ));
        }

        // Auto-detect format from extension
        let format = match user_path.extension().and_then(|ext| ext.to_str()) {
            Some("toml") => FileFormat::Toml,
            Some("json") => FileFormat::Json,
            Some("yaml") | Some("yml") => FileFormat::Yaml,
            _ => {
                return Err(anyhow::anyhow!(
                    "Unsupported config file format: {}",
                    user_path.display()
                ))
            }
        };

        println!("👤 Loading user config from: {}", user_path.display());
        Ok(builder.add_source(File::from(user_path).format(format).required(true)))
    }

    /// Convert raw configuration to validated configuration with proper path types
    fn validate_config(&self, raw: RawAppConfig) -> Result<ValidatedAppConfig> {
        println!("✅ Validating configuration and converting paths to secure types...");

        // Check for environment-specific overrides
        if !raw.environment_overrides.is_empty() {
            println!(
                "🔧 Found {} environment overrides",
                raw.environment_overrides.len()
            );
            for (key, value) in &raw.environment_overrides {
                println!("  Override: {} = {:?}", key, value);
            }
        }

        // Validate server paths
        let server = self
            .validate_server_config(&raw.server)
            .context("Failed to validate server configuration")?;

        // Validate database paths
        let database = self
            .validate_database_config(&raw.database)
            .context("Failed to validate database configuration")?;

        // Validate core paths
        let paths = self
            .validate_paths_config(&raw.paths)
            .context("Failed to validate paths configuration")?;

        // Validate security paths
        let security = self
            .validate_security_config(&raw.security)
            .context("Failed to validate security configuration")?;

        // Validate logging paths
        let logging = self
            .validate_logging_config(&raw.logging)
            .context("Failed to validate logging configuration")?;

        println!("🎉 Configuration validation completed successfully!");

        Ok(ValidatedAppConfig {
            app_name: raw.app_name,
            version: raw.version,
            debug: raw.debug,
            environment: self.environment.clone(),
            server,
            database,
            paths,
            security,
            logging,
        })
    }

    fn validate_server_config(&self, server: &RawServerConfig) -> Result<ValidatedServerConfig> {
        println!("🌐 Validating server configuration...");

        // Create virtual root for upload directory
        let upload_boundary = PathBoundary::try_new_create(&server.upload_dir)
            .with_context(|| format!("Failed to create upload directory: {}", server.upload_dir))?;
        let upload_vroot = upload_boundary.virtualize();

        // Validate upload_dir using serde
        let upload_dir =
            self.deserialize_virtual_path(&server.upload_dir, &upload_vroot, "upload_dir")?;

        // Validate optional static_files path
        let static_files = if let Some(static_path) = &server.static_files {
            let static_boundary = PathBoundary::try_new_create(static_path).with_context(|| {
                format!("Failed to create static files directory: {}", static_path)
            })?;
            let static_vroot = static_boundary.virtualize();
            Some(self.deserialize_virtual_path(static_path, &static_vroot, "static_files")?)
        } else {
            None
        };

        println!("  ✓ Upload directory: {}", upload_dir.virtualpath_display());
        if let Some(ref sf) = static_files {
            println!("  ✓ Static files: {}", sf.virtualpath_display());
        }

        Ok(ValidatedServerConfig {
            host: server.host.clone(),
            port: server.port,
            workers: server.workers,
            max_connections: server.max_connections,
            static_files,
            upload_dir,
        })
    }

    fn validate_database_config(&self, db: &RawDatabaseConfig) -> Result<ValidatedDatabaseConfig> {
        println!("💾 Validating database configuration...");

        // Create virtual root for backup directory
        let backup_boundary = PathBoundary::try_new_create(&db.backup_dir)
            .with_context(|| format!("Failed to create backup directory: {}", db.backup_dir))?;
        let backup_vroot = backup_boundary.virtualize();

        let backup_dir =
            self.deserialize_virtual_path(&db.backup_dir, &backup_vroot, "backup_dir")?;

        // Validate optional migration directory
        let migration_dir = if let Some(migration_path) = &db.migration_dir {
            let migration_boundary =
                PathBoundary::try_new_create(migration_path).with_context(|| {
                    format!("Failed to create migration directory: {}", migration_path)
                })?;
            let migration_vroot = migration_boundary.virtualize();
            Some(self.deserialize_virtual_path(
                migration_path,
                &migration_vroot,
                "migration_dir",
            )?)
        } else {
            None
        };

        println!("  ✓ Backup directory: {}", backup_dir.virtualpath_display());
        if let Some(ref md) = migration_dir {
            println!("  ✓ Migration directory: {}", md.virtualpath_display());
        }

        Ok(ValidatedDatabaseConfig {
            url: db.url.clone(),
            max_connections: db.max_connections,
            backup_dir,
            migration_dir,
        })
    }

    fn validate_paths_config(&self, paths: &RawPathsConfig) -> Result<ValidatedPathsConfig> {
        println!("📁 Validating core paths configuration...");

        // Validate core directories as VirtualRoots
        let data_dir = VirtualRoot::try_new_create(&paths.data_dir)
            .with_context(|| format!("Failed to create data directory: {}", paths.data_dir))?;

        let cache_dir = VirtualRoot::try_new_create(&paths.cache_dir)
            .with_context(|| format!("Failed to create cache directory: {}", paths.cache_dir))?;

        let temp_dir = VirtualRoot::try_new_create(&paths.temp_dir)
            .with_context(|| format!("Failed to create temp directory: {}", paths.temp_dir))?;

        let log_dir = VirtualRoot::try_new_create(&paths.log_dir)
            .with_context(|| format!("Failed to create log directory: {}", paths.log_dir))?;

        // Validate optional directories
        let config_dir =
            if let Some(config_path) = &paths.config_dir {
                Some(VirtualRoot::try_new_create(config_path).with_context(|| {
                    format!("Failed to create config directory: {}", config_path)
                })?)
            } else {
                None
            };

        let plugin_dir = if let Some(plugin_path) = &paths.plugin_dir {
            let plugin_boundary = PathBoundary::try_new_create(plugin_path)
                .with_context(|| format!("Failed to create plugin directory: {}", plugin_path))?;
            let plugin_vroot = plugin_boundary.virtualize();
            Some(self.deserialize_virtual_path(plugin_path, &plugin_vroot, "plugin_dir")?)
        } else {
            None
        };

        // Validate path arrays
        let mut allowed_upload_dirs = Vec::new();
        for (i, upload_dir) in paths.allowed_upload_dirs.iter().enumerate() {
            let upload_boundary = PathBoundary::try_new_create(upload_dir).with_context(|| {
                format!(
                    "Failed to create allowed upload directory {}: {}",
                    i, upload_dir
                )
            })?;
            let upload_vroot = upload_boundary.virtualize();
            let validated_path = self.deserialize_virtual_path(
                upload_dir,
                &upload_vroot,
                &format!("allowed_upload_dirs[{}]", i),
            )?;
            allowed_upload_dirs.push(validated_path);
        }

        let mut trusted_data_sources = Vec::new();
        for (i, data_source) in paths.trusted_data_sources.iter().enumerate() {
            let source_boundary = PathBoundary::try_new_create(data_source).with_context(|| {
                format!(
                    "Failed to create trusted data source {}: {}",
                    i, data_source
                )
            })?;
            let validated_path = self.deserialize_strict_path(
                data_source,
                &source_boundary,
                &format!("trusted_data_sources[{}]", i),
            )?;
            trusted_data_sources.push(validated_path);
        }

        println!(
            "  ✓ Data directory: {}",
            data_dir.as_unvirtual().strictpath_display()
        );
        println!(
            "  ✓ Cache directory: {}",
            cache_dir.as_unvirtual().strictpath_display()
        );
        println!(
            "  ✓ Temp directory: {}",
            temp_dir.as_unvirtual().strictpath_display()
        );
        println!(
            "  ✓ Log directory: {}",
            log_dir.as_unvirtual().strictpath_display()
        );
        println!(
            "  ✓ Allowed upload directories: {}",
            allowed_upload_dirs.len()
        );
        println!("  ✓ Trusted data sources: {}", trusted_data_sources.len());

        Ok(ValidatedPathsConfig {
            data_dir,
            cache_dir,
            temp_dir,
            log_dir,
            config_dir,
            plugin_dir,
            allowed_upload_dirs,
            trusted_data_sources,
        })
    }

    fn validate_security_config(
        &self,
        security: &RawSecurityConfig,
    ) -> Result<ValidatedSecurityConfig> {
        println!("🔒 Validating security configuration...");

        // Validate certificate directory as StrictPath (must exist as directory)
        let cert_boundary =
            PathBoundary::try_new_create(&security.cert_dir).with_context(|| {
                format!(
                    "Failed to access certificate directory: {}",
                    security.cert_dir
                )
            })?;
        let cert_dir =
            self.deserialize_strict_path(&security.cert_dir, &cert_boundary, "cert_dir")?;

        // For key file, use the cert directory as boundary and create a StrictPath within it
        let key_file =
            cert_boundary
                .strict_join(Path::new(&security.key_file).file_name().ok_or_else(|| {
                    anyhow::anyhow!("Invalid key file path: {}", security.key_file)
                })?)
                .with_context(|| {
                    format!(
                        "Failed to validate key file in cert directory: {}",
                        security.key_file
                    )
                })?;

        // Validate sandbox root as PathBoundary
        let sandbox_root = PathBoundary::try_new_create(&security.sandbox_root)
            .with_context(|| format!("Failed to create sandbox root: {}", security.sandbox_root))?;

        // Validate restricted paths
        let mut strict_paths = Vec::new();
        for (i, strict_path) in security.strict_paths.iter().enumerate() {
            let restricted_boundary =
                PathBoundary::try_new_create(strict_path).with_context(|| {
                    format!("Failed to access restricted path {}: {}", i, strict_path)
                })?;
            let validated_path = self.deserialize_strict_path(
                strict_path,
                &restricted_boundary,
                &format!("strict_paths[{}]", i),
            )?;
            strict_paths.push(validated_path);
        }

        println!(
            "  ✓ Certificate directory: {}",
            cert_dir.strictpath_display()
        );
        println!("  ✓ Key file: {}", key_file.strictpath_display());
        println!("  ✓ Sandbox root: {}", sandbox_root.strictpath_display());
        println!("  ✓ Restricted paths: {}", strict_paths.len());

        Ok(ValidatedSecurityConfig {
            cert_dir,
            key_file,
            allowed_origins: security.allowed_origins.clone(),
            session_timeout: security.session_timeout,
            sandbox_root,
            strict_paths,
        })
    }

    fn validate_logging_config(
        &self,
        logging: &RawLoggingConfig,
    ) -> Result<ValidatedLoggingConfig> {
        println!("📝 Validating logging configuration...");

        // Create virtual root for log directory (we'll use the main log_dir from paths)
        let log_boundary = PathBoundary::try_new_create("./runtime-data/development/logs") // Use default, could be improved
            .context("Failed to create log directory for validation")?;
        let log_vroot = log_boundary.virtualize();

        // Validate optional log file paths
        let file_path = if let Some(file_path_str) = &logging.file_path {
            Some(self.deserialize_virtual_path(file_path_str, &log_vroot, "file_path")?)
        } else {
            None
        };

        let error_log = if let Some(error_log_str) = &logging.error_log {
            Some(self.deserialize_virtual_path(error_log_str, &log_vroot, "error_log")?)
        } else {
            None
        };

        let access_log = if let Some(access_log_str) = &logging.access_log {
            Some(self.deserialize_virtual_path(access_log_str, &log_vroot, "access_log")?)
        } else {
            None
        };

        if let Some(ref fp) = file_path {
            println!("  ✓ Log file: {}", fp.virtualpath_display());
        }
        if let Some(ref el) = error_log {
            println!("  ✓ Error log: {}", el.virtualpath_display());
        }
        if let Some(ref al) = access_log {
            println!("  ✓ Access log: {}", al.virtualpath_display());
        }

        Ok(ValidatedLoggingConfig {
            level: logging.level.clone(),
            format: logging.format.clone(),
            file_path,
            error_log,
            access_log,
            max_size_mb: logging.max_size_mb,
            max_files: logging.max_files,
        })
    }

    // Helper function to deserialize a string path into a VirtualPath using serde
    fn deserialize_virtual_path<T>(
        &self,
        path_str: &str,
        vroot: &VirtualRoot<T>,
        field_name: &str,
    ) -> Result<VirtualPath<T>>
    where
        T: Clone + Default,
    {
        let json_str = format!("\"{}\"", path_str);
        let mut de = serde_json::Deserializer::from_str(&json_str);
        WithVirtualRoot(vroot)
            .deserialize(&mut de)
            .with_context(|| {
                format!(
                    "Failed to validate {} path '{}' with serde",
                    field_name, path_str
                )
            })
    }

    // Helper function to deserialize a string path into a StrictPath using serde
    fn deserialize_strict_path<T>(
        &self,
        path_str: &str,
        boundary: &PathBoundary<T>,
        field_name: &str,
    ) -> Result<StrictPath<T>>
    where
        T: Clone + Default,
    {
        let json_str = format!("\"{}\"", path_str);
        let mut de = serde_json::Deserializer::from_str(&json_str);
        WithBoundary(boundary)
            .deserialize(&mut de)
            .with_context(|| {
                format!(
                    "Failed to validate {} path '{}' with serde",
                    field_name, path_str
                )
            })
    }
}

// Example usage and demonstration
fn main() -> Result<()> {
    println!("🚀 Config Management Example with `config` crate + strict-path serde integration\n");

    // Determine environment from environment variable or default to Development
    let environment = std::env::var("APP_ENV")
        .unwrap_or_else(|_| "development".to_string())
        .parse::<AppEnvironment>()
        .unwrap_or(AppEnvironment::Development);

    println!("🌍 Running in environment: {:?}", environment);

    // Initialize configuration manager
    let config_manager = ConfigManager::new(environment)?;

    // Load configuration (hierarchical loading)
    let user_config_path = std::env::args().nth(1).map(PathBuf::from);

    if let Some(ref path) = user_config_path {
        println!("👤 User config provided: {}", path.display());
    }

    match config_manager.load_config(user_config_path.as_deref()) {
        Ok(validated_config) => {
            println!("\n🎉 Configuration loaded and validated successfully!");
            display_config_summary(&validated_config);

            // Demonstrate usage of validated paths
            demonstrate_secure_operations(&validated_config)?;
        }
        Err(e) => {
            eprintln!("\n❌ Configuration validation failed: {}", e);

            // Show the error chain for debugging
            let mut source = e.source();
            while let Some(err) = source {
                eprintln!("  Caused by: {}", err);
                source = err.source();
            }

            std::process::exit(1);
        }
    }

    Ok(())
}

fn display_config_summary(config: &ValidatedAppConfig) {
    println!("\n📋 Configuration Summary:");
    println!(
        "  App: {} v{} (debug: {})",
        config.app_name, config.version, config.debug
    );
    println!("  Environment: {:?}", config.environment);
    println!(
        "  Server: {}:{} ({} workers)",
        config.server.host, config.server.port, config.server.workers
    );
    println!(
        "  Database: {} (max: {} connections)",
        config.database.url, config.database.max_connections
    );

    println!("\n🔒 Secure Path Summary:");
    println!(
        "  Data directory: {}",
        config.paths.data_dir.as_unvirtual().strictpath_display()
    );
    println!(
        "  Upload directory: {}",
        config.server.upload_dir.virtualpath_display()
    );
    println!(
        "  Backup directory: {}",
        config.database.backup_dir.virtualpath_display()
    );
    println!(
        "  Certificate directory: {}",
        config.security.cert_dir.strictpath_display()
    );
    println!(
        "  Sandbox root: {}",
        config.security.sandbox_root.strictpath_display()
    );

    if !config.paths.allowed_upload_dirs.is_empty() {
        println!("  Allowed upload directories:");
        for (i, dir) in config.paths.allowed_upload_dirs.iter().enumerate() {
            println!("    {}: {}", i + 1, dir.virtualpath_display());
        }
    }
}

fn demonstrate_secure_operations(config: &ValidatedAppConfig) -> Result<()> {
    println!("\n🔧 Demonstrating secure path operations:");

    // Example 1: Safe file creation in upload directory (from VirtualPath root)
    let upload_vroot = config.server.upload_dir.as_unvirtual().clone().virtualize();
    let upload_file = upload_vroot.virtual_join("example.txt")?;
    println!(
        "  ✓ Safe upload path: {}",
        upload_file.virtualpath_display()
    );

    // Example 2: Safe backup file creation (from VirtualPath root)
    let backup_vroot = config
        .database
        .backup_dir
        .as_unvirtual()
        .clone()
        .virtualize();
    let backup_file = backup_vroot.virtual_join("backup_20231211.sql")?;
    println!(
        "  ✓ Safe backup path: {}",
        backup_file.virtualpath_display()
    );

    // Example 3: Certificate validation (StrictPath - must exist)
    println!(
        "  ✓ Certificate directory validated: {}",
        config.security.cert_dir.strictpath_display()
    );

    // Example 4: Sandbox containment
    match config
        .security
        .sandbox_root
        .clone()
        .virtualize()
        .virtual_join("user_data/file.txt")
    {
        Ok(sandboxed_path) => {
            println!(
                "  ✓ Sandboxed path: {}",
                sandboxed_path.virtualpath_display()
            );
        }
        Err(e) => {
            println!("  ⚠️  Sandbox violation prevented: {}", e);
        }
    }

    // Use server configuration fields
    println!(
        "  ✓ Server max connections: {}",
        config.server.max_connections
    );
    if let Some(ref static_files) = config.server.static_files {
        println!(
            "  ✓ Static files directory: {}",
            static_files.virtualpath_display()
        );
    }

    // Use database migration directory
    if let Some(ref migration_dir) = config.database.migration_dir {
        println!(
            "  ✓ Migration directory: {}",
            migration_dir.virtualpath_display()
        );
    }

    // Use paths configuration
    println!(
        "  ✓ Cache directory: {}",
        config.paths.cache_dir.as_unvirtual().strictpath_display()
    );
    println!(
        "  ✓ Temp directory: {}",
        config.paths.temp_dir.as_unvirtual().strictpath_display()
    );
    println!(
        "  ✓ Log directory: {}",
        config.paths.log_dir.as_unvirtual().strictpath_display()
    );

    if let Some(ref config_dir) = config.paths.config_dir {
        println!(
            "  ✓ Config directory: {}",
            config_dir.as_unvirtual().strictpath_display()
        );
    }
    if let Some(ref plugin_dir) = config.paths.plugin_dir {
        println!("  ✓ Plugin directory: {}", plugin_dir.virtualpath_display());
    }

    println!(
        "  ✓ Trusted data sources: {} configured",
        config.paths.trusted_data_sources.len()
    );
    for (i, source) in config.paths.trusted_data_sources.iter().enumerate() {
        println!("    {}: {}", i + 1, source.strictpath_display());
    }

    // Use security configuration
    println!(
        "  ✓ Security key file: {}",
        config.security.key_file.strictpath_display()
    );
    println!(
        "  ✓ Allowed origins: {}",
        config.security.allowed_origins.join(", ")
    );
    println!("  ✓ Session timeout: {}s", config.security.session_timeout);
    println!(
        "  ✓ Restricted paths: {} configured",
        config.security.strict_paths.len()
    );

    // Use logging configuration
    println!(
        "  ✓ Logging level: {}, format: {}",
        config.logging.level, config.logging.format
    );
    if let Some(ref file_path) = config.logging.file_path {
        println!("  ✓ Log file: {}", file_path.virtualpath_display());
    }
    if let Some(ref error_log) = config.logging.error_log {
        println!("  ✓ Error log: {}", error_log.virtualpath_display());
    }
    if let Some(ref access_log) = config.logging.access_log {
        println!("  ✓ Access log: {}", access_log.virtualpath_display());
    }
    println!(
        "  ✓ Log rotation: max {}MB, {} files",
        config.logging.max_size_mb, config.logging.max_files
    );

    println!("\n✅ All secure operations completed successfully!");
    Ok(())
}
