//! Configuration Loader Example
//!
//! This example demonstrates how to build a secure configuration manager that loads
//! files from different, strictly separated directories. It uses marker types to create
//! two distinct jails:
//!
//! 1.  `AppConfigJail`: For loading the main `app.conf` file.
//! 2.  `ThemeJail`: For loading user-specified theme files (e.g., `blue.css`, `dark.css`).
//!
//! The use of `StrictPath<AppConfigJail>` and `StrictPath<ThemeJail>` ensures at
//! compile time that a function designed to load themes cannot be accidentally used
//! to access the main application configuration, and vice-versa.
//!
//! ## Usage
//!
//! Run the example with: `cargo run --example config_loader`
//!
//! It will simulate loading a valid config, a valid theme, and show a failed
//! attempt to load a theme from the config directory.

use strict_path::{PathBoundary, StrictPath};
use std::fs;
use std::path::Path;

// --- Marker Types for Type-Safe Jails ---

/// Marker type for the application configuration directory.
struct AppConfigJail;

/// Marker type for the user themes directory.
struct ThemeJail;

// --- Configuration Loading Logic ---

/// Loads the main application configuration.
///
/// This function's signature requires a `StrictPath` locked to the `AppConfigJail`.
/// It is impossible to pass a path from another PathBoundary (like the theme PathBoundary) to it.
fn load_app_config(config_path: &StrictPath<AppConfigJail>) -> Result<String, std::io::Error> {
    let disp = config_path.strictpath_display();
    println!("Attempting to load app config from System path: {disp}");
    config_path.read_to_string()
}

/// Loads a user theme file.
///
/// This function's signature requires a `StrictPath` locked to the `ThemeJail`.
/// It cannot be used to read application config files.
fn load_theme_file(theme_path: &StrictPath<ThemeJail>) -> Result<String, std::io::Error> {
    let disp = theme_path.strictpath_display();
    println!("Attempting to load theme from System path: {disp}");
    theme_path.read_to_string()
}

/// Sets up the file system environment for the example.
fn setup_environment() -> std::io::Result<()> {
    // Clean up previous runs
    if Path::new("example_config").exists() {
        fs::remove_dir_all("example_config")?;
    }
    if Path::new("example_themes").exists() {
        fs::remove_dir_all("example_themes")?;
    }

    // Create directories
    fs::create_dir("example_config")?;
    fs::create_dir("example_themes")?;

    // Create sample files
    fs::write(
        "example_config/app.conf",
        "host = \"127.0.0.1\"
port = 8080",
    )?;
    fs::write("example_themes/dark.css", "body { color: white; }")?;
    fs::write("example_themes/light.css", "body { color: black; }")?;

    println!("Created example config and theme directories.");
    Ok(())
}

fn main() {
    // 1. Set up the environment.
    if let Err(e) = setup_environment() {
        eprintln!("Failed to set up environment: {e}");
        return;
    }

    // 2. Create two separate, type-safe jails.
    let config_jail: PathBoundary<AppConfigJail> =
        PathBoundary::try_new_create("example_config").expect("Failed to create config PathBoundary");
    let theme_jail: PathBoundary<ThemeJail> =
        PathBoundary::try_new_create("example_themes").expect("Failed to create theme PathBoundary");

    println!("\n--- Scenario 1: Loading valid app config ---");
    let app_config_filename = "app.conf";
    match config_jail.strict_join(app_config_filename) {
        Ok(safe_config_path) => match load_app_config(&safe_config_path) {
            Ok(content) => println!("Successfully loaded app.conf:\n---\n{content}\n---"),
            Err(e) => eprintln!("Error reading config: {e}"),
        },
        Err(e) => eprintln!("Invalid config path: {e}"),
    }

    println!("\n--- Scenario 2: Loading valid theme ---");
    let theme_filename = "dark.css"; // Imagine this comes from user input
    match theme_jail.strict_join(theme_filename) {
        Ok(safe_theme_path) => match load_theme_file(&safe_theme_path) {
            Ok(content) => println!("Successfully loaded dark.css:\n---\n{content}\n---"),
            Err(e) => eprintln!("Error reading theme: {e}"),
        },
        Err(e) => eprintln!("Invalid theme path: {e}"),
    }

    println!("\n--- Scenario 3: Attempting to cross-load a theme as a config ---");
    let malicious_theme_filename = "dark.css";
    match config_jail.strict_join(malicious_theme_filename) {
        Ok(path_from_wrong_jail) => {
            // The following line would cause a compile error, demonstrating the power
            // of type-safe jails. Uncomment it to see for yourself!
            //
            // load_app_config(&path_from_wrong_jail);
            // ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
            // error[E0308]: mismatched types
            //   --> examples/config_loader.rs:…
            //    |
            //    = note: expected reference `&StrictPath<AppConfigJail>`
            //               found reference `&StrictPath<_>`
            //
            // We can't even call the function, so we'll just print a message.
            let disp = path_from_wrong_jail.strictpath_display();
            println!("Successfully created a StrictPath: {disp}");
            println!("However, we cannot pass it to `load_app_config` due to a type mismatch. COMPILE ERROR PREVENTED!");
        }
        Err(e) => {
            // This part would not even be reached for a simple filename,
            // but it would catch traversal attacks like "../example_themes/dark.css".
            eprintln!("Path validation failed: {e}");
        }
    }

    // Clean up the created directories
    fs::remove_dir_all("example_config").ok();
    fs::remove_dir_all("example_themes").ok();
}



