//! OS Standard Directory Integration
//!
//! Demonstrates using OS-specific standard directories with secure path boundaries.
//! Shows the ergonomic integration pattern: dirs crate provides the base directory,
//! strict-path provides the security boundary.
//!
//! Each example follows cross-platform conventions (XDG on Linux, Known Folder API
//! on Windows, Apple Standard Directories on macOS) and enforces path boundaries.
//!
//! Integration with the `dirs` crate v6.0.0: https://crates.io/crates/dirs
//!
//! Run with: cargo run --example dirs_integration

use strict_path::PathBoundary;

#[cfg(feature = "virtual-path")]
use strict_path::VirtualRoot;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== OS Standard Directory Examples ===\n");
    println!("Pattern: dirs::*_dir() → PathBoundary::try_new_create() → secure operations\n");

    // Application directories (with app-specific subdirectories)
    println!("📁 Application Directories:");

    if let Some(config_base) = dirs::config_dir() {
        let config_dir: PathBoundary = PathBoundary::try_new_create(config_base.join("myapp"))?;
        println!("Config: {}", config_dir.strictpath_display());
        let settings = config_dir.strict_join("settings.toml")?;
        settings.write(b"theme = 'dark'\nversion = '1.0'")?;
        println!("  └─ settings.toml: {}", settings.read_to_string()?);

        // Clean up
        config_dir.remove_dir_all().ok();
    }

    if let Some(data_base) = dirs::data_dir() {
        let data_dir: PathBoundary = PathBoundary::try_new_create(data_base.join("myapp"))?;
        println!("Data: {}", data_dir.strictpath_display());
        let database = data_dir.strict_join("app.db")?;
        database.write(b"-- SQLite database placeholder")?;

        // Clean up
        data_dir.remove_dir_all().ok();
    }

    if let Some(cache_base) = dirs::cache_dir() {
        let cache_dir: PathBoundary = PathBoundary::try_new_create(cache_base.join("myapp"))?;
        println!("Cache: {}", cache_dir.strictpath_display());
        let temp_cache = cache_dir.strict_join("temp.json")?;
        temp_cache.write(br#"{"cached_at": "2024-01-01"}"#)?;

        // Clean up
        cache_dir.remove_dir_all().ok();
    }

    // Platform-specific local directories (Windows/Linux only)
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    {
        println!("\n📍 Platform-Specific Local Directories:");

        if let Some(config_local_base) = dirs::config_local_dir() {
            let config_local: PathBoundary =
                PathBoundary::try_new_create(config_local_base.join("myapp"))?;
            println!("Config Local: {}", config_local.strictpath_display());
            config_local.remove_dir_all().ok();
        }

        if let Some(data_local_base) = dirs::data_local_dir() {
            let data_local: PathBoundary =
                PathBoundary::try_new_create(data_local_base.join("myapp"))?;
            println!("Data Local: {}", data_local.strictpath_display());
            data_local.remove_dir_all().ok();
        }
    }

    println!("\n📱 User Directories:");

    // User directories (direct access, no app subdirectory)
    if let Some(downloads_base) = dirs::download_dir() {
        let downloads: PathBoundary = PathBoundary::try_new(downloads_base)?;
        println!("Downloads: {}", downloads.strictpath_display());
    }

    if let Some(documents_base) = dirs::document_dir() {
        let documents: PathBoundary = PathBoundary::try_new(documents_base)?;
        println!("Documents: {}", documents.strictpath_display());
    }

    if let Some(pictures_base) = dirs::picture_dir() {
        let pictures: PathBoundary = PathBoundary::try_new(pictures_base)?;
        println!("Pictures: {}", pictures.strictpath_display());
    }

    println!("\n🎵 Media Directories:");

    if let Some(audio_base) = dirs::audio_dir() {
        let audio: PathBoundary = PathBoundary::try_new(audio_base)?;
        println!("Audio: {}", audio.strictpath_display());
    }

    if let Some(videos_base) = dirs::video_dir() {
        let videos: PathBoundary = PathBoundary::try_new(videos_base)?;
        println!("Videos: {}", videos.strictpath_display());
    }

    println!("\n🏠 System Directories:");

    if let Some(home_base) = dirs::home_dir() {
        let home: PathBoundary = PathBoundary::try_new(home_base)?;
        println!("Home: {}", home.strictpath_display());
    }

    if let Some(desktop_base) = dirs::desktop_dir() {
        let desktop: PathBoundary = PathBoundary::try_new(desktop_base)?;
        println!("Desktop: {}", desktop.strictpath_display());
    }

    // Unix-specific directories
    #[cfg(unix)]
    {
        println!("\n🛠️ Unix System Directories:");

        if let Some(executables_base) = dirs::executable_dir() {
            let executables: PathBoundary = PathBoundary::try_new(executables_base)?;
            println!("Executables: {}", executables.strictpath_display());
        }

        if let Some(runtime_base) = dirs::runtime_dir() {
            let runtime: PathBoundary = PathBoundary::try_new(runtime_base)?;
            println!("Runtime: {}", runtime.strictpath_display());
        }
    }

    // Linux-specific directories
    #[cfg(target_os = "linux")]
    {
        println!("\n🐧 Linux-Specific Directories:");

        if let Some(state_base) = dirs::state_dir() {
            let state_dir: PathBoundary = PathBoundary::try_new_create(state_base.join("myapp"))?;
            println!("State: {}", state_dir.strictpath_display());
            state_dir.remove_dir_all().ok();
        }
    }

    // Virtual root example - app sees clean paths
    #[cfg(feature = "virtual-path")]
    {
        println!("\n=== Virtual Root Example ===");

        if let Some(config_base) = dirs::config_dir() {
            let vroot: VirtualRoot = VirtualRoot::try_new_create(config_base.join("demo-app"))?;
            println!(
                "Virtual root at: {}",
                vroot.as_unvirtual().strictpath_display()
            );

            let vconfig = vroot.virtual_join("app.toml")?;
            println!("Virtual path: {}", vconfig.virtualpath_display());
            // App sees "/app.toml", system stores in OS config directory

            vconfig.write(b"name = 'Demo App'\nversion = '1.0'")?;
            println!("Content: {}", vconfig.read_to_string()?);

            // Clean up
            vroot.remove_dir_all().ok();
        }
    }

    println!("\n✅ All OS directory operations completed successfully!");
    println!("\n💡 One extra line for explicit security:");
    println!("   let base = dirs::config_dir().unwrap();");
    println!("   let boundary = PathBoundary::try_new_create(base.join(\"myapp\"))?;");
    Ok(())
}
