//! Portable Application Directory Demo
//!
//! Demonstrates integration with the app-path crate for portable applications.
//! Shows how to combine app-path's executable-relative paths with strict-path's
//! security boundaries.
//!
//! Pattern: AppPath::with("subdir") → PathBoundary::try_new_create() → portable operations

#![cfg_attr(not(feature = "with-app-path"), allow(unused))]

#[cfg(not(feature = "with-app-path"))]
compile_error!("Enable with --features with-app-path to run this example");

use anyhow::Result;
use app_path::AppPath;
use serde::{Deserialize, Serialize};
use strict_path::{PathBoundary, StrictPath, VirtualPath, VirtualRoot};

/// Marker types for different application directories
struct AppConfig;
struct AppData;
struct AppLogs;
struct AppPlugins;

/// Configuration structure for our portable app
#[derive(Serialize, Deserialize, Debug, Clone)]
struct PortableAppConfig {
    app_name: String,
    version: String,
    portable_mode: bool,
    data_encryption: bool,
    max_log_files: usize,
    plugin_auto_load: bool,
}

impl Default for PortableAppConfig {
    fn default() -> Self {
        Self {
            app_name: "PortableDemo".to_string(),
            version: "1.0.0".to_string(),
            portable_mode: true,
            data_encryption: false,
            max_log_files: 10,
            plugin_auto_load: true,
        }
    }
}

/// Manages a portable application using strict-path's app-path integration
struct PortableApp {
    config_dir: PathBoundary<AppConfig>,
    data_root: VirtualRoot<AppData>,
    logs_dir: PathBoundary<AppLogs>,
    plugins_dir: PathBoundary<AppPlugins>,
    config: PortableAppConfig,
}

impl PortableApp {
    /// Create a new portable app instance using app-path crate integration
    fn new() -> Result<Self> {
        println!("🚀 Initializing Portable Application");
        println!("Using app-path crate for executable-relative paths\n");

        // Use app-path crate to get executable-relative paths, then create boundaries
        let config_dir = PathBoundary::<AppConfig>::try_new_create(AppPath::with("config"))?;
        let data_dir = PathBoundary::<AppData>::try_new_create(AppPath::with("data"))?;
        let logs_dir = PathBoundary::<AppLogs>::try_new_create(AppPath::with("logs"))?;
        let plugins_dir = PathBoundary::<AppPlugins>::try_new_create(AppPath::with("plugins"))?;

        // Convert data directory to VirtualRoot for user-facing path operations
        let data_root = VirtualRoot::try_new(data_dir.interop_path())?;

        println!("✅ Application directories created:");
        println!("   Config:  {}", config_dir.strictpath_display());
        println!(
            "   Data:    {}",
            data_root.as_unvirtual().strictpath_display()
        );
        println!("   Logs:    {}", logs_dir.strictpath_display());
        println!("   Plugins: {}", plugins_dir.strictpath_display());

        // Load or create config
        let config = Self::load_config(&config_dir)?;

        Ok(Self {
            config_dir,
            data_root,
            logs_dir,
            plugins_dir,
            config,
        })
    }

    /// Load configuration with fallback to defaults
    fn load_config(config_dir: &PathBoundary<AppConfig>) -> Result<PortableAppConfig> {
        let config_file = config_dir.strict_join("app.toml")?;

        if config_file.exists() {
            let content = config_file.read_to_string()?;
            let config: PortableAppConfig = toml::from_str(&content)?;
            println!(
                "📖 Loaded existing config from: {}",
                config_file.strictpath_display()
            );
            Ok(config)
        } else {
            let config = PortableAppConfig::default();
            let content = toml::to_string_pretty(&config)?;
            config_file.write(&content)?;
            println!(
                "📝 Created default config at: {}",
                config_file.strictpath_display()
            );
            Ok(config)
        }
    }

    /// Save current configuration
    fn save_config(&self) -> Result<()> {
        let config_file = self.config_dir.strict_join("app.toml")?;
        let content = toml::to_string_pretty(&self.config)?;
        config_file.write(&content)?;
        println!("💾 Saved config to: {}", config_file.strictpath_display());
        Ok(())
    }

    /// Create a user document with virtual path (user-friendly paths)
    fn create_document(&self, virtual_path: &str, content: &str) -> Result<VirtualPath<AppData>> {
        println!("\n📝 Creating document: /{virtual_path}");

        let doc_path = self.data_root.virtual_join(virtual_path)?;
        doc_path.create_parent_dir_all()?;

        doc_path.write(content)?;
        println!("✅ Document created: {}", doc_path.virtualpath_display());
        Ok(doc_path)
    }

    /// List all documents with virtual paths
    fn list_documents(&self) -> Result<Vec<String>> {
        let mut documents = Vec::new();
        self.collect_documents_recursive("", &mut documents)?;
        documents.sort();
        Ok(documents)
    }

    /// Recursively collect documents showing virtual paths
    fn collect_documents_recursive(
        &self,
        virtual_subdir: &str,
        documents: &mut Vec<String>,
    ) -> Result<()> {
        let read_dir_result = if virtual_subdir.is_empty() {
            self.data_root.read_dir()
        } else {
            let vpath = self.data_root.virtual_join(virtual_subdir)?;
            vpath.read_dir()
        };

        if let Ok(entries) = read_dir_result {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if let Some(name_str) = name.to_str() {
                    let virtual_path = if virtual_subdir.is_empty() {
                        name_str.to_string()
                    } else {
                        format!("{virtual_subdir}/{name_str}")
                    };

                    if let Ok(candidate) = self.data_root.virtual_join(&virtual_path) {
                        if candidate.is_dir() {
                            self.collect_documents_recursive(&virtual_path, documents)?;
                        } else {
                            documents.push(format!("/{virtual_path}"));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Log application events
    fn log_event(&self, level: &str, message: &str) -> Result<()> {
        let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
        let log_entry = format!("[{timestamp}] [{level}] {message}\n");

        let log_file = self.logs_dir.strict_join("app.log")?;

        // Emulate append using read-modify-write via StrictPath I/O
        if log_file.exists() {
            let mut existing = log_file.read_to_string().unwrap_or_default();
            existing.push_str(&log_entry);
            log_file.write(existing)?;
        } else {
            log_file.write(log_entry)?;
        }
        println!("📋 Logged: [{level}] {message}");
        Ok(())
    }

    /// Install a "plugin" (demo of plugin directory management)
    fn install_plugin(
        &self,
        plugin_name: &str,
        plugin_content: &str,
    ) -> Result<StrictPath<AppPlugins>> {
        println!("\n🔌 Installing plugin: {plugin_name}");

        let plugin_file = self
            .plugins_dir
            .strict_join(format!("{plugin_name}.plugin"))?; // remove needless borrow per clippy
        plugin_file.write(plugin_content)?;

        self.log_event("INFO", &format!("Plugin installed: {plugin_name}"))?;
        println!("✅ Plugin installed: {}", plugin_file.strictpath_display());
        Ok(plugin_file)
    }

    /// List installed plugins
    fn list_plugins(&self) -> Result<Vec<String>> {
        let mut plugins = Vec::new();

        if let Ok(entries) = self.plugins_dir.read_dir() {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if let Ok(sp) = self.plugins_dir.strict_join(name) {
                        if sp.is_file() && name.ends_with(".plugin") {
                            let plugin_name = name.strip_suffix(".plugin").unwrap_or(name);
                            plugins.push(plugin_name.to_string());
                        }
                    }
                }
            }
        }

        plugins.sort();
        Ok(plugins)
    }

    /// Show application status and directory info
    fn show_status(&self) -> Result<()> {
        println!("\n📊 Application Status");
        println!("===================");
        println!("Config: {}", self.config.app_name);
        println!("Version: {}", self.config.version);
        println!("Portable Mode: {}", self.config.portable_mode);

        let doc_count = self.list_documents()?.len();
        let plugin_count = self.list_plugins()?.len();

        println!("Documents: {doc_count}");
        println!("Plugins: {plugin_count}");

        // Show actual directory locations
        println!("\n📁 Directory Locations:");
        let config = self.config_dir.strictpath_display();
        println!("Config:  {config}");
        let data = self.data_root.as_unvirtual().strictpath_display();
        println!("Data:    {data}");
        let logs = self.logs_dir.strictpath_display();
        println!("Logs:    {logs}");
        let plugins = self.plugins_dir.strictpath_display();
        println!("Plugins: {plugins}");

        Ok(())
    }

    /// Demonstrate environment override functionality
    fn demonstrate_env_overrides(&self) -> Result<()> {
        println!("\n🌍 Environment Override Demonstration");
        println!("====================================");

        println!("The app-path integration supports environment variable overrides:");
        println!("  PORTABLE_DEMO_CONFIG -> overrides ./config directory");
        println!("  PORTABLE_DEMO_DATA   -> overrides ./data directory");
        println!("  PORTABLE_DEMO_LOGS   -> overrides ./logs directory");
        println!("  PORTABLE_DEMO_PLUGINS -> overrides ./plugins directory");

        println!("\nTo test, set an environment variable and restart:");
        println!("  Windows: set PORTABLE_DEMO_CONFIG=C:\\MyApp\\CustomConfig");
        println!("  Unix:    export PORTABLE_DEMO_CONFIG=/home/user/myapp/config");

        Ok(())
    }
}

/// Demonstrate application backup and restore functionality
fn demonstrate_backup_restore() -> Result<()> {
    println!("\n💾 Demonstrating backup and restore...");

    let data_dir = PathBoundary::<AppData>::try_new_create(AppPath::with("data"))?;
    let backup_dir = PathBoundary::<AppData>::try_new_create(AppPath::with("backups"))?;

    // Create backup with timestamp
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let backup_name = format!("backup_{timestamp}");
    let backup_path = backup_dir.strict_join(&backup_name)?;
    backup_path.create_dir_all()?;

    // Copy all data files to backup
    let mut backup_count = 0;
    if let Ok(entries) = data_dir.read_dir() {
        for entry in entries.flatten() {
            if let Some(filename) = entry.file_name().to_str() {
                let src = data_dir.strict_join(filename)?;
                if src.is_file() {
                    let dst = backup_path.strict_join(filename)?;
                    // Use strict-path I/O to copy validated files
                    let bytes = src.read()?;
                    dst.write(&bytes)?;
                    backup_count += 1;
                }
            }
        }
    }

    println!("✅ Backup created: {backup_name} ({backup_count} files)");

    // Show backup listing
    println!("📦 Available backups:");
    if let Ok(entries) = backup_dir.read_dir() {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                let sp = backup_dir.strict_join(name)?;
                if sp.is_dir() {
                    println!("  • {name}");
                }
            }
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    println!("🚀 Portable Application Directory Demo");
    println!("Showcasing strict-path's app-path feature integration\n");

    // Initialize the portable app
    let mut app = PortableApp::new()?;

    // Create some sample documents
    app.create_document("readme.txt", "Welcome to the Portable Demo App!\n\nThis app stores all its data relative to the executable.")?;

    app.create_document(
        "projects/demo-project.md",
        "# Demo Project\n\nThis is a sample project created by the portable app.\n\n## Features\n- Portable storage\n- Secure path handling\n- Virtual path display"
    )?;

    app.create_document(
        "settings/user-preferences.json",
        r#"{
  "theme": "dark",
  "auto_save": true,
  "notifications": false
}"#,
    )?;

    // Install some sample plugins
    app.install_plugin("backup", "Plugin for creating backups of user data")?;
    app.install_plugin("export", "Plugin for exporting data to various formats")?;

    // Log some events
    app.log_event("INFO", "Application started successfully")?;
    app.log_event("INFO", "Sample documents created")?;
    app.log_event("INFO", "Plugins installed")?;

    // Show current status
    app.show_status()?;

    // List all documents with their virtual paths
    println!("\n📂 Documents (virtual paths):");
    let documents = app.list_documents()?;
    for doc in documents {
        println!("  {doc}");
    }

    // List plugins
    println!("\n🔌 Installed Plugins:");
    let plugins = app.list_plugins()?;
    for plugin in plugins {
        println!("  • {plugin}");
    }

    // Demonstrate environment overrides
    app.demonstrate_env_overrides()?;

    // Update config and save
    app.config.data_encryption = true;
    app.config.max_log_files = 5;
    app.save_config()?;

    // Demonstrate security
    demonstrate_backup_restore()?;

    println!("\n✨ Demo complete!");
    println!("All application data is stored portably relative to the executable.");
    println!("The app can be moved to any location and will continue to work.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_portable_app_initialization() -> Result<()> {
        let app = PortableApp::new()?;

        // All directories should exist
        assert!(app.config_dir.exists());
        assert!(app.data_root.exists());
        assert!(app.logs_dir.exists());
        assert!(app.plugins_dir.exists());

        // Config should be loaded
        assert_eq!(app.config.app_name, "PortableDemo");
        assert!(app.config.portable_mode);

        Ok(())
    }

    #[test]
    fn test_document_creation_and_listing() -> Result<()> {
        let app = PortableApp::new()?;

        // Create test document
        app.create_document("test.txt", "test content")?;

        // Should appear in listing
        let docs = app.list_documents()?;
        assert!(docs.contains(&"/test.txt".to_string()));

        Ok(())
    }

    #[test]
    fn test_plugin_management() -> Result<()> {
        let app = PortableApp::new()?;

        // Install test plugin
        app.install_plugin("test_plugin", "test plugin content")?;

        // Should appear in listing
        let plugins = app.list_plugins()?;
        assert!(plugins.contains(&"test_plugin".to_string()));

        Ok(())
    }
}
