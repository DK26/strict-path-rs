//! # Configuration Manager Example
//!
//! This example demonstrates how to use `Jail` to create a configuration manager
//! that reads configuration files from a specific directory. This prevents the
//! application from accessing files outside of the designated config directory.

use anyhow::Result;
use jailed_path::Jail;
use std::collections::HashMap;
use std::fs;

/// A simple configuration manager.
struct ConfigManager {
    config_jail: Jail<()>,
}

impl ConfigManager {
    /// Initializes the configuration manager with a config directory.
    pub fn new(config_dir: &str) -> Result<Self> {
        fs::create_dir_all(config_dir)?;
        let config_jail =
            Jail::<()>::try_new(config_dir).map_err(|e| anyhow::anyhow!("Jail error: {e}"))?;
        Ok(Self { config_jail })
    }

    /// Reads a configuration file.
    pub fn get_config(&self, name: &str) -> Result<HashMap<String, String>> {
        let config_path = self
            .config_jail
            .try_path(name)
            .map_err(|e| anyhow::anyhow!("Jail error: {e}"))?;

        if !config_path.exists() {
            return Ok(HashMap::new()); // Return empty config if file doesn't exist
        }

        let content = config_path.read_to_string()?;
        let mut config = HashMap::new();
        for line in content.lines() {
            if let Some((key, value)) = line.split_once('=') {
                config.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
        Ok(config)
    }
}

fn main() -> Result<()> {
    let config_manager = ConfigManager::new("test_config")?;

    // Create a dummy config file
    let config_content = "host = localhost\nport = 8080";
    fs::write("test_config/app.conf", config_content)?;

    // --- Legitimate Config Request ---
    let app_config = config_manager.get_config("app.conf")?;
    println!("Loaded app.conf: {app_config:?}");
    assert_eq!(
        app_config.get("host").map(|s| s.as_str()),
        Some("localhost")
    );
    assert_eq!(app_config.get("port").map(|s| s.as_str()), Some("8080"));

    // --- Request for non-existent config ---
    let db_config = config_manager.get_config("db.conf")?;
    println!("Loaded db.conf: {db_config:?}");
    assert!(db_config.is_empty());

    // --- Malicious Config Request ---
    let result = config_manager.get_config("../../../etc/hosts");
    assert!(result.is_ok());
    if let Ok(config) = result {
        assert!(config.is_empty());
    }

    // Clean up
    fs::remove_dir_all("test_config")?;

    Ok(())
}
