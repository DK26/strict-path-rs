//! App-Path Integration Example
//!
//! Demonstrates composing strict-path with the app-path crate for truly portable
//! applications. Shows how executable-relative paths enable USB drive deployment,
//! network share usage, and non-installation scenarios.
//!
//! Key app-path API:
//! - `AppPath::new()` → Returns executable directory
//! - `AppPath::with("subdir")` → Returns executable_dir/subdir
//! - `AppPath::with_override("subdir", Some("ENV_VAR"))` → Environment override support
//! - Implements `Deref<Target=Path>` for seamless path operations
//!
//! Integration with app-path v1.1.2: https://crates.io/crates/app-path
//!
//! Run with: cargo run --example app_path_integration

use app_path::AppPath;
use strict_path::PathBoundary;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== App-Path Integration Examples ===\n");
    println!("Pattern: AppPath::with(\"subdir\") → PathBoundary::try_new_create() → portable operations\n");

    // Example 1: Basic portable app
    println!("1️⃣  Basic Portable Application:");
    basic_portable_app()?;

    // Example 2: Multi-directory structure
    println!("\n2️⃣  Multi-Directory Portable App Structure:");
    multi_dir_portable_app()?;

    // Example 3: Environment override for testing/CI
    println!("\n3️⃣  Environment Variable Override (Testing/CI):");
    env_override_pattern()?;

    println!("\n✅ All examples completed successfully!");
    println!("\n💡 Portable apps: config/data/cache travel with the executable");
    println!("   Perfect for: USB drives, network shares, no-install deployment");
    Ok(())
}

/// Basic portable application - all files relative to executable
fn basic_portable_app() -> Result<(), Box<dyn std::error::Error>> {
    // AppPath::with() creates path relative to executable
    let app_dir = AppPath::with("portable-demo");

    println!("   Executable-relative path: {}", app_dir.display());

    // Establish boundary for security
    let boundary: PathBoundary = PathBoundary::try_new_create(app_dir)?;

    // Create configuration
    let config = boundary.strict_join("config.ini")?;
    config.write(b"[Settings]\nportable=true\nversion=1.0\n")?;
    println!("   ✓ Created config.ini");

    // Create user data
    let data = boundary.strict_join("userdata.txt")?;
    data.write(b"User preferences saved locally")?;
    println!("   ✓ Created userdata.txt");

    // Read it back
    println!(
        "   ✓ Config content:\n{}",
        config
            .read_to_string()?
            .lines()
            .map(|line| format!("     {}", line))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // Clean up demo
    boundary.remove_dir_all().ok();

    Ok(())
}

/// Multi-directory portable app with organized structure
fn multi_dir_portable_app() -> Result<(), Box<dyn std::error::Error>> {
    struct ConfigDir;
    struct DataDir;
    struct CacheDir;

    struct AppPaths {
        config: PathBoundary<ConfigDir>,
        data: PathBoundary<DataDir>,
        cache: PathBoundary<CacheDir>,
    }

    impl AppPaths {
        fn new(app_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
            // Base directory relative to executable
            let base_dir = AppPath::with(app_name);

            Ok(Self {
                config: PathBoundary::try_new_create(base_dir.join("config"))?,
                data: PathBoundary::try_new_create(base_dir.join("data"))?,
                cache: PathBoundary::try_new_create(base_dir.join("cache"))?,
            })
        }
    }

    let paths = AppPaths::new("portable-demo")?;

    // Config: application settings
    let settings = paths.config.strict_join("settings.toml")?;
    settings.write(b"[app]\ntheme = 'dark'\nlanguage = 'en'\n")?;
    println!("   ✓ Config: {}", settings.strictpath_display());

    // Data: persistent user data
    let user_db = paths.data.strict_join("users/alice.json")?;
    user_db.create_parent_dir_all()?;
    user_db.write(br#"{"name": "Alice", "role": "admin"}"#)?;
    println!("   ✓ Data: {}", user_db.strictpath_display());

    // Cache: temporary/regenerable data
    let cache_file = paths.cache.strict_join("thumbnails/img1.cache")?;
    cache_file.create_parent_dir_all()?;
    cache_file.write(b"cached thumbnail data")?;
    println!("   ✓ Cache: {}", cache_file.strictpath_display());

    println!("\n   📁 Portable app structure:");
    println!("     executable.exe");
    println!("     portable-demo/");
    println!("       ├─ config/settings.toml");
    println!("       ├─ data/users/alice.json");
    println!("       └─ cache/thumbnails/img1.cache");

    // Clean up demo
    paths.config.remove_dir_all().ok();
    paths.data.remove_dir_all().ok();
    paths.cache.remove_dir_all().ok();

    Ok(())
}

/// Environment variable override for testing/CI/CD pipelines
fn env_override_pattern() -> Result<(), Box<dyn std::error::Error>> {
    // AppPath has built-in override support for testing/CI
    let env_var = "DEMO_APP_DATA_DIR";

    // Check if override is set
    let is_overridden = std::env::var(env_var).is_ok();

    // with_override checks environment and falls back to executable-relative
    let app_path = AppPath::with_override("portable-demo", Some(env_var));

    if is_overridden {
        println!("   🔧 Using override from ${}", env_var);
        println!("      Path: {}", app_path.display());
    } else {
        println!("   📁 Using executable-relative (no override set)");
        println!("      Path: {}", app_path.display());
        println!("      Tip: Set {} to override location", env_var);
    }

    let boundary: PathBoundary = PathBoundary::try_new_create(app_path)?;

    // Application works the same regardless of location
    let log_file = boundary.strict_join("app.log")?;
    log_file.write(b"[INFO] Application started\n[INFO] Initialization complete\n")?;
    println!("   ✓ Created app.log");

    println!("\n   💡 Use cases:");
    println!("      • Production: files next to executable");
    println!("      • CI: ${} = /tmp/ci-test", env_var);
    println!("      • Development: override to project directory");

    // Clean up demo
    boundary.remove_dir_all().ok();

    Ok(())
}
