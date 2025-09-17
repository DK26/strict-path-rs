//! System Directories Integration Demo  
//!
//! Demonstrates the `dirs` feature integration with strict-path.
//! Shows how to use `PathBoundary::try_new_os_config()`, `try_new_os_data()`, and `try_new_os_cache()`
//! for secure access to platform-appropriate system directories.

#![cfg_attr(not(feature = "with-dirs"), allow(unused))]

#[cfg(not(feature = "with-dirs"))]
compile_error!("Enable with --features with-dirs to run this example");

use anyhow::Result;
use serde::{Deserialize, Serialize};
use strict_path::{PathBoundary, StrictPath};

/// Marker types for different system directory purposes
struct Config;
struct Data;
struct Cache;

/// Application configuration that gets stored in the config directory
#[derive(Serialize, Deserialize, Debug)]
struct AppConfig {
    app_name: String,
    version: String,
    auto_save: bool,
    theme: String,
    max_cache_size_mb: u64,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            app_name: "SystemDirsDemo".to_string(),
            version: "1.0.0".to_string(),
            auto_save: true,
            theme: "dark".to_string(),
            max_cache_size_mb: 100,
        }
    }
}

/// Manages application data across platform-appropriate system directories
struct SystemDirectoryManager {
    config_dir: PathBoundary<Config>,
    data_dir: PathBoundary<Data>,
    cache_dir: PathBoundary<Cache>,
}

impl SystemDirectoryManager {
    /// Create a new manager using strict-path's dirs integration
    fn new(app_name: &str) -> Result<Self> {
        println!("🔧 Setting up system directories for: {app_name}");

        // Use library's dirs integration - creates directories if needed!
        let config_dir = PathBoundary::<Config>::try_new_os_config(app_name)?;
        let data_dir = PathBoundary::<Data>::try_new_os_data(app_name)?;
        let cache_dir = PathBoundary::<Cache>::try_new_os_cache(app_name)?;

        println!("✅ Config: {}", config_dir.strictpath_display());
        println!("✅ Data:   {}", data_dir.strictpath_display());
        println!("✅ Cache:  {}", cache_dir.strictpath_display());

        Ok(Self {
            config_dir,
            data_dir,
            cache_dir,
        })
    }

    /// Load or create default application configuration
    fn load_config(&self) -> Result<AppConfig> {
        println!("\n📖 Loading application configuration...");

        let config_file = self.config_dir.strict_join("config.toml")?;

        if config_file.exists() {
            let content = config_file.read_to_string()?;
            let config: AppConfig = toml::from_str(&content)?;
            println!(
                "✅ Loaded existing config from: {}",
                config_file.strictpath_display()
            );
            Ok(config)
        } else {
            let config = AppConfig::default();
            self.save_config(&config)?;
            println!(
                "✅ Created default config at: {}",
                config_file.strictpath_display()
            );
            Ok(config)
        }
    }

    /// Save application configuration
    fn save_config(&self, config: &AppConfig) -> Result<StrictPath<Config>> {
        let config_file = self.config_dir.strict_join("config.toml")?;
        let content = toml::to_string_pretty(config)?;

        config_file.write(&content)?;
        println!("💾 Saved config to: {}", config_file.strictpath_display());
        Ok(config_file)
    }

    /// Store application data (databases, user files, etc.)
    fn save_user_data(&self, filename: &str, content: &str) -> Result<StrictPath<Data>> {
        println!("\n💾 Saving user data: {filename}");

        let data_file = self.data_dir.strict_join(filename)?;
        data_file.create_parent_dir_all()?;

        data_file.write(content)?;
        println!("✅ Saved to: {}", data_file.strictpath_display());
        Ok(data_file)
    }

    /// Manage cache files with size limits
    fn cache_data(&self, key: &str, data: &str) -> Result<StrictPath<Cache>> {
        println!("\n🗂️  Caching data with key: {key}");

        let cache_file = self.cache_dir.strict_join(format!("{key}.cache"))?;
        cache_file.write(data)?;

        // Check total cache size (simplified example)
        let cache_size = self.calculate_cache_size()?;
        println!("📊 Current cache size: {} bytes", cache_size);

        if cache_size > 1024 * 1024 {
            // 1MB limit for demo
            println!("🧹 Cache size exceeded, cleaning up...");
            self.cleanup_old_cache_files()?;
        }

        println!("✅ Cached to: {}", cache_file.strictpath_display());
        Ok(cache_file)
    }

    /// Calculate total cache directory size
    fn calculate_cache_size(&self) -> Result<u64> {
        let mut total_size = 0;

        if let Ok(entries) = self.cache_dir.read_dir() {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if let Ok(file_path) = self.cache_dir.strict_join(name) {
                        if let Ok(metadata) = file_path.metadata() {
                            if metadata.is_file() {
                                total_size += metadata.len();
                            }
                        }
                    }
                }
            }
        }

        Ok(total_size)
    }

    /// Clean up old cache files (simplified LRU)
    fn cleanup_old_cache_files(&self) -> Result<()> {
        if let Ok(entries) = self.cache_dir.read_dir() {
            use std::time::UNIX_EPOCH;
            let mut files: Vec<(StrictPath<Cache>, std::time::SystemTime)> = entries
                .filter_map(|entry| entry.ok())
                .filter_map(|entry| {
                    let name = entry.file_name();
                    let name = name.to_str()?;
                    let sp = self.cache_dir.strict_join(name).ok()?;
                    let meta = sp.metadata().ok()?;
                    if meta.is_file() {
                        let mtime = meta.modified().unwrap_or(UNIX_EPOCH);
                        Some((sp, mtime))
                    } else {
                        None
                    }
                })
                .collect();

            // Sort by modification time (oldest first)
            files.sort_by_key(|(_, mtime)| *mtime);

            // Remove oldest files until we're under the limit
            let files_to_remove = files.len().saturating_sub(5); // Keep newest 5 files

            for (sp, _) in files.into_iter().take(files_to_remove) {
                if let Err(e) = sp.remove_file() {
                    println!(
                        "⚠️  Failed to remove cache file {}: {}",
                        sp.strictpath_display(),
                        e
                    );
                } else {
                    println!("🗑️  Removed old cache file: {}", sp.strictpath_display());
                }
            }
        }

        Ok(())
    }

    /// List all data files
    fn list_user_data(&self) -> Result<Vec<String>> {
        let mut files = Vec::new();

        if let Ok(entries) = self.data_dir.read_dir() {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if let Ok(sp) = self.data_dir.strict_join(name) {
                        if sp.is_file() {
                            files.push(name.to_string());
                        }
                    }
                }
            }
        }

        files.sort();
        Ok(files)
    }

    /// Create organized subdirectories for different data types
    fn setup_data_organization(&self) -> Result<()> {
        println!("\n📁 Setting up organized data structure...");

        let subdirs = ["projects", "templates", "exports", "backups"];

        for subdir in &subdirs {
            let subdir_path = self.data_dir.strict_join(subdir)?;
            subdir_path.create_dir_all()?;
            println!("📂 Created: {}", subdir_path.strictpath_display());
        }

        Ok(())
    }
}

/// Demonstrate cross-platform directory behavior
fn show_platform_info() {
    println!("\n🌍 Platform-specific directories:");

    #[cfg(target_os = "windows")]
    {
        println!("🪟 Windows:");
        println!("   Config: %APPDATA%\\<app>");
        println!("   Data:   %APPDATA%\\<app>");
        println!("   Cache:  %LOCALAPPDATA%\\<app>");
    }

    #[cfg(target_os = "macos")]
    {
        println!("🍎 macOS:");
        println!("   Config: ~/Library/Preferences/<app>");
        println!("   Data:   ~/Library/Application Support/<app>");
        println!("   Cache:  ~/Library/Caches/<app>");
    }

    #[cfg(target_os = "linux")]
    {
        println!("🐧 Linux:");
        println!("   Config: ~/.config/<app> or $XDG_CONFIG_HOME/<app>");
        println!("   Data:   ~/.local/share/<app> or $XDG_DATA_HOME/<app>");
        println!("   Cache:  ~/.cache/<app> or $XDG_CACHE_HOME/<app>");
    }
}

/// Demonstrate cross-platform configuration management
fn demonstrate_config_migration() -> Result<()> {
    println!("\n� Demonstrating configuration migration...");

    let config_dir = PathBoundary::<Config>::try_new_os_config("StrictPathDemo")?;
    let old_config = config_dir.strict_join("config_v1.toml")?;
    let new_config = config_dir.strict_join("config_v2.toml")?;

    // Simulate upgrading from v1 to v2 config format
    if old_config.exists() {
        println!("📄 Found old config, migrating to new format...");
        let old_data = old_config.read_to_string()?;

        // Simple migration example
        let new_data = old_data.replace("old_setting", "new_setting");
        new_config.write(&new_data)?;

        // Archive the old config
        let archive = config_dir.strict_join("archive")?;
        archive.create_dir_all()?;
        let archived = archive.strict_join("config_v1_backup.toml")?;
        archived.write(&old_data)?;

        println!("✅ Config migrated and old version archived");
    } else {
        println!("ℹ️  No legacy config found");
    }

    Ok(())
}

fn main() -> Result<()> {
    println!("🚀 System Directories Integration Demo");
    println!("Showcasing strict-path's dirs feature integration\n");

    show_platform_info();

    // Create manager for our demo app
    let manager = SystemDirectoryManager::new("StrictPathDemo")?;

    // Load/create configuration
    let mut config = manager.load_config()?;
    println!("📋 Current config: {config:#?}");

    // Update config and save
    config.theme = "light".to_string();
    config.max_cache_size_mb = 150;
    manager.save_config(&config)?;

    // Set up organized data directories
    manager.setup_data_organization()?;

    // Save some user data
    manager.save_user_data(
        "projects/project1.md",
        "# Project 1\nThis is a sample project file.",
    )?;

    manager.save_user_data(
        "templates/letter.txt",
        "Dear [NAME],\n\nThank you for your interest in our product.\n\nBest regards,\n[SENDER]",
    )?;

    // Cache some data
    manager.cache_data(
        "api_response_users",
        r#"{"users": [{"id": 1, "name": "Alice"}]}"#,
    )?;
    manager.cache_data("processed_image_thumb", "fake_image_data_here")?;

    // Show what we have
    println!("\n📂 User data files:");
    let files = manager.list_user_data()?;
    for file in files {
        println!("  • {file}");
    }

    // Show config migration patterns
    demonstrate_config_migration()?;

    // Exercise advanced configuration patterns to demonstrate usage
    demonstrate_advanced_config_patterns()?;

    println!("\n✨ Demo complete!");
    println!("All data is stored in platform-appropriate directories using best practices.");

    Ok(())
}

/// Example showing advanced configuration management patterns
fn demonstrate_advanced_config_patterns() -> Result<()> {
    println!("\n⚙️ Advanced configuration patterns:");

    // Multi-environment configs
    let config_dir = PathBoundary::<Config>::try_new_os_config("MultiEnvApp")?;

    let environments = ["development", "staging", "production"];

    for env in &environments {
        let env_config_file = config_dir.strict_join(format!("config.{env}.toml"))?;

        let config = AppConfig {
            app_name: format!("MultiEnvApp-{env}"),
            version: "1.0.0".to_string(),
            auto_save: *env != "production", // Different behavior per env
            theme: if *env == "development" {
                "debug".to_string()
            } else {
                "clean".to_string()
            },
            max_cache_size_mb: match *env {
                "development" => 50,
                "staging" => 100,
                "production" => 500,
                _ => 100,
            },
        };

        let content = toml::to_string_pretty(&config)?;
        env_config_file.write(&content)?;

        println!(
            "📝 Created {env} config: {}",
            env_config_file.strictpath_display()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_dirs_are_different() -> Result<()> {
        let config_dir = PathBoundary::<Config>::try_new_os_config("test_app")?;
        let data_dir = PathBoundary::<Data>::try_new_os_data("test_app")?;
        let cache_dir = PathBoundary::<Cache>::try_new_os_cache("test_app")?;

        // Platform-specific expectations:
        // - Windows: Config and Data are both under %APPDATA% (<Roaming>), Cache under %LOCALAPPDATA% (<Local>)
        // - macOS/Linux: XDG-style locations are distinct for Config/Data/Cache
        #[cfg(target_os = "windows")]
        {
            assert_eq!(config_dir.interop_path(), data_dir.interop_path());
            assert_ne!(config_dir.interop_path(), cache_dir.interop_path());
        }

        #[cfg(not(target_os = "windows"))]
        {
            assert_ne!(config_dir.interop_path(), data_dir.interop_path());
            assert_ne!(config_dir.interop_path(), cache_dir.interop_path());
            assert_ne!(data_dir.interop_path(), cache_dir.interop_path());
        }

        // All should exist (created automatically)
        assert!(config_dir.exists());
        assert!(data_dir.exists());
        assert!(cache_dir.exists());

        Ok(())
    }

    #[test]
    fn test_config_roundtrip() -> Result<()> {
        let manager = SystemDirectoryManager::new("test_roundtrip")?;

        let original_config = AppConfig {
            app_name: "test".to_string(),
            version: "2.0.0".to_string(),
            auto_save: false,
            theme: "custom".to_string(),
            max_cache_size_mb: 999,
        };

        // Save and reload
        manager.save_config(&original_config)?;
        let loaded_config = manager.load_config()?;

        // Should be identical
        assert_eq!(original_config.app_name, loaded_config.app_name);
        assert_eq!(original_config.version, loaded_config.version);
        assert_eq!(original_config.auto_save, loaded_config.auto_save);
        assert_eq!(original_config.theme, loaded_config.theme);
        assert_eq!(
            original_config.max_cache_size_mb,
            loaded_config.max_cache_size_mb
        );

        Ok(())
    }
}
