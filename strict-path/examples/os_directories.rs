//! OS Standard Directory Constructors
//!
//! Demonstrates using OS-specific standard directories with secure path boundaries.
//! Each constructor follows cross-platform conventions (XDG on Linux, Known Folder API
//! on Windows, Apple Standard Directories on macOS) and enforces path boundaries.
//!
//! Integration with the `dirs` crate v6.0.0: https://crates.io/crates/dirs

#[cfg(feature = "dirs")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use strict_path::{PathBoundary, VirtualRoot};

    println!("=== OS Standard Directory Examples ===\n");

    // Application directories (with app-specific subdirectories)
    println!("📁 Application Directories:");

    let config_dir = PathBoundary::<()>::try_new_os_config("myapp")?;
    println!("Config: {}", config_dir.strictpath_display());
    let settings = config_dir.strict_join("settings.toml")?;
    settings.write("theme = 'dark'\nversion = '1.0'")?;
    println!("  └─ settings.toml: {}", settings.read_to_string()?);

    let data_dir = PathBoundary::<()>::try_new_os_data("myapp")?;
    println!("Data: {}", data_dir.strictpath_display());
    let database = data_dir.strict_join("app.db")?;
    database.write("-- SQLite database placeholder")?;

    let cache_dir = PathBoundary::<()>::try_new_os_cache("myapp")?;
    println!("Cache: {}", cache_dir.strictpath_display());
    let temp_cache = cache_dir.strict_join("temp.json")?;
    temp_cache.write(r#"{"cached_at": "2024-01-01"}"#)?;

    // Platform-specific local directories (Windows/Linux only)
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    {
        println!("\n📍 Platform-Specific Local Directories:");

        let config_local = PathBoundary::<()>::try_new_os_config_local("myapp")?;
        println!("Config Local: {}", config_local.strictpath_display());

        let data_local = PathBoundary::<()>::try_new_os_data_local("myapp")?;
        println!("Data Local: {}", data_local.strictpath_display());
    }

    println!("\n📱 User Directories:");

    // User directories (direct access, no app subdirectory)
    let downloads = PathBoundary::<()>::try_new_os_downloads()?;
    println!("Downloads: {}", downloads.strictpath_display());

    let documents = PathBoundary::<()>::try_new_os_documents()?;
    println!("Documents: {}", documents.strictpath_display());

    let pictures = PathBoundary::<()>::try_new_os_pictures()?;
    println!("Pictures: {}", pictures.strictpath_display());

    println!("\n🎵 Media Directories:");

    let audio = PathBoundary::<()>::try_new_os_audio()?;
    println!("Audio: {}", audio.strictpath_display());

    let videos = PathBoundary::<()>::try_new_os_videos()?;
    println!("Videos: {}", videos.strictpath_display());

    println!("\n🏠 System Directories:");

    let home = PathBoundary::<()>::try_new_os_home()?;
    println!("Home: {}", home.strictpath_display());

    let desktop = PathBoundary::<()>::try_new_os_desktop()?;
    println!("Desktop: {}", desktop.strictpath_display());

    // Unix-specific directories
    #[cfg(unix)]
    {
        println!("\n🛠️ Unix System Directories:");

        if let Ok(executables) = PathBoundary::<()>::try_new_os_executables() {
            println!("Executables: {}", executables.strictpath_display());
        }

        if let Ok(runtime) = PathBoundary::<()>::try_new_os_runtime() {
            println!("Runtime: {}", runtime.strictpath_display());
        }
    }

    // Linux-specific directories
    #[cfg(target_os = "linux")]
    {
        println!("\n🐧 Linux-Specific Directories:");

        let state_dir = PathBoundary::<()>::try_new_os_state("myapp")?;
        println!("State: {}", state_dir.strictpath_display());
    }

    // Virtual root example - app sees clean paths
    println!("\n=== Virtual Root Example ===");

    let vroot = VirtualRoot::<()>::try_new_os_config("demo-app")?;
    println!(
        "Virtual root at: {}",
        vroot.as_unvirtual().strictpath_display()
    );

    let vconfig = vroot.virtual_join("app.toml")?;
    println!("Virtual path: {}", vconfig.virtualpath_display());
    // App sees "/app.toml", system stores in OS config directory

    vconfig.write("name = 'Demo App'\nversion = '1.0'")?;
    println!("Content: {}", vconfig.read_to_string()?);

    println!("\n✅ All OS directory operations completed successfully!");
    Ok(())
}

#[cfg(not(feature = "dirs"))]
fn main() {
    println!("This example requires the 'dirs' feature.");
    println!("Run with: cargo run --example os_directories --features dirs");
}
