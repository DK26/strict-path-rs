//! An example of a secure configuration loader that uses a jail to
//! ensure that it only reads configuration files from a designated
//! directory, preventing any access to sensitive files elsewhere on
//! the system.

use anyhow::Result;
use jailed_path::{Jail, JailedPath};
use std::collections::HashMap;
use std::fs;

// --- Marker Type for the Configuration Context ---

/// Marker for the configuration files jail.
#[derive(Clone)]
struct Config;

// --- Configuration Loading Logic ---

/// A simple configuration loader.
struct ConfigLoader {
    jail: Jail<Config>,
}

impl ConfigLoader {
    /// Creates a new `ConfigLoader` that is jailed to the specified directory.
    pub fn new(config_dir: &str) -> Result<Self> {
        fs::create_dir_all(config_dir)?;
        let jail =
            Jail::<Config>::try_new(config_dir).map_err(|e| anyhow::anyhow!("jail init: {e}"))?;
        Ok(Self { jail })
    }

    /// Reads a configuration file and parses it as a simple key-value store.
    ///
    /// The `filename` is validated against the jail before being used.
    pub fn load_config(&self, filename: &str) -> Result<HashMap<String, String>> {
        println!("[Config] Attempting to load: {filename}");

        // Validate the user-provided filename against the jail.
        let config_path = self
            .jail
            .systempath_join(filename)
            .map_err(|e| anyhow::anyhow!("Jail error: {e}"))?;

        // The `read_config_file` function requires a `JailedPath<Config>`,
        // which we can only get from our `jail`.
        read_config_file(&config_path)
    }
}

/// Reads and parses a configuration file.
///
/// This function's signature guarantees that it can only be called with a path
/// that has been validated by the `Config` jail.
fn read_config_file(path: &JailedPath<Config>) -> Result<HashMap<String, String>> {
    if !path.is_file() {
        return Err(anyhow::anyhow!("Config file not found."));
    }

    let content = path.read_to_string()?;
    let mut config = HashMap::new();
    for line in content.lines() {
        if let Some((key, value)) = line.split_once('=') {
            config.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    println!("  -> Loaded config from: {path}");
    Ok(config)
}

// --- Main Simulation ---

fn main() -> Result<()> {
    // --- Setup: Create a config directory and some dummy files ---
    fs::create_dir_all("config")?;
    fs::write("config/app.conf", "host = 127.0.0.1\nport = 8080\n")?;
    fs::write(
        "config/db.conf",
        "database_url = postgres://user:pass@host/db\n",
    )?;
    // A sensitive file outside the config directory that we should not be able to access.
    fs::write("secret_api_key.txt", "SECRET_KEY_12345")?;

    // --- Create the secure config loader ---
    let config_loader = ConfigLoader::new("config")?;

    println!("--- Config Loader Simulation ---");

    // --- Simulate loading various config files ---
    let configs_to_load = vec![
        "app.conf",
        "db.conf",
        "../secret_api_key.txt", // Malicious attempt
        "non_existent.conf",
    ];

    for filename in configs_to_load {
        match config_loader.load_config(filename) {
            Ok(config) => println!("  -> Success! Config: {config:?}"),
            Err(e) => println!("  -> Error: {e}"),
        }
        println!("--------------------");
    }

    println!("--- Simulation Complete ---");

    // --- Cleanup ---
    fs::remove_dir_all("config")?;
    fs::remove_file("secret_api_key.txt")?;

    Ok(())
}



