//! An example of a secure configuration loader that uses a PathBoundary to
//! ensure that it only reads configuration files from a designated
//! directory, preventing any access to sensitive files elsewhere on
//! the system.

use anyhow::Result;
use strict_path::{PathBoundary, StrictPath};
use std::collections::HashMap;
use std::fs;

// --- Marker Type for the Configuration Context ---

/// Marker for the configuration files PathBoundary.
#[derive(Clone)]
struct Config;

// --- Configuration Loading Logic ---

/// A simple configuration loader.
struct ConfigLoader {
    PathBoundary: PathBoundary<Config>,
}

impl ConfigLoader {
    /// Creates a new `ConfigLoader` that is jailed to the specified directory.
    pub fn new(config_dir: &str) -> Result<Self> {
        fs::create_dir_all(config_dir)?;
        let PathBoundary =
            PathBoundary::<Config>::try_new(config_dir).map_err(|e| anyhow::anyhow!("PathBoundary init: {e}"))?;
        Ok(Self { PathBoundary })
    }

    /// Reads a configuration file and parses it as a simple key-value store.
    ///
    /// The `filename` is validated against the PathBoundary before being used.
    pub fn load_config(&self, filename: &str) -> Result<HashMap<String, String>> {
        println!("[Config] Attempting to load: {filename}");

        // Validate the user-provided filename against the PathBoundary.
        let config_path = self
            .PathBoundary
            .strict_join(filename)
            .map_err(|e| anyhow::anyhow!("PathBoundary error: {e}"))?;

        // The `read_config_file` function requires a `StrictPath<Config>`,
        // which we can only get from our `PathBoundary`.
        read_config_file(&config_path)
    }
}

/// Reads and parses a configuration file.
///
/// This function's signature guarantees that it can only be called with a path
/// that has been validated by the `Config` PathBoundary.
fn read_config_file(path: &StrictPath<Config>) -> Result<HashMap<String, String>> {
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
    let disp = path.strictpath_display();
    println!("  -> Loaded config from: {disp}");
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
