//! OS Standard Directories Demo
//!
//! Demonstrates a realistic application using OS-specific standard directories
//! for configuration, data, cache, and user content management.
//!
//! This simulates a cross-platform media organizer application that:
//! - Stores config in OS standard config directory
//! - Manages media database in OS data directory  
//! - Uses OS cache for thumbnails and metadata
//! - Organizes user media from standard directories
//! - Provides secure sandboxing for all file operations
//!
//! **OS Directory Integration**: Built on the [`dirs`](https://crates.io/crates/dirs) crate v6.0.0
//! which provides cross-platform standard directory discovery following XDG Base Directory
//! Specification (Linux), Known Folder API (Windows), and Apple Standard Directories (macOS).
//!
//! Repository: <https://github.com/dirs-dev/dirs-rs>

use std::collections::HashMap;
use strict_path::{PathBoundary, VirtualRoot};

#[derive(Debug)]
struct MediaOrganizerApp {
    name: String,
    config_root: PathBoundary<()>,
    data_root: PathBoundary<()>,
    cache_root: PathBoundary<()>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct AppConfig {
    theme: String,
    auto_organize: bool,
    thumbnail_quality: u8,
    supported_formats: Vec<String>,
    last_scan_path: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            theme: "dark".to_string(),
            auto_organize: true,
            thumbnail_quality: 85,
            supported_formats: vec![
                "jpg".to_string(),
                "jpeg".to_string(),
                "png".to_string(),
                "mp4".to_string(),
                "mov".to_string(),
                "mp3".to_string(),
                "wav".to_string(),
                "flac".to_string(),
            ],
            last_scan_path: None,
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct MediaEntry {
    path: String,
    file_type: String,
    size_bytes: u64,
    created: String,
    has_thumbnail: bool,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct MediaDatabase {
    entries: HashMap<String, MediaEntry>,
    total_files: usize,
    last_updated: String,
}

impl MediaOrganizerApp {
    /// Initialize the application with OS standard directories
    fn new(app_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        println!(
            "🚀 Initializing {} with OS standard directories...",
            app_name
        );

        // Use dirs crate to discover OS directories, then create secure boundaries
        let config_root = PathBoundary::<()>::try_new_create(
            dirs::config_dir()
                .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?
                .join(app_name),
        )?;
        let data_root = PathBoundary::<()>::try_new_create(
            dirs::data_dir()
                .ok_or_else(|| anyhow::anyhow!("Could not determine data directory"))?
                .join(app_name),
        )?;
        let cache_root = PathBoundary::<()>::try_new_create(
            dirs::cache_dir()
                .ok_or_else(|| anyhow::anyhow!("Could not determine cache directory"))?
                .join(app_name),
        )?;

        println!("📁 Config directory: {}", config_root.strictpath_display());
        println!("💾 Data directory: {}", data_root.strictpath_display());
        println!("🗄️ Cache directory: {}", cache_root.strictpath_display());

        Ok(Self {
            name: app_name.to_string(),
            config_root,
            data_root,
            cache_root,
        })
    }

    /// Load or create application configuration
    fn load_config(&self) -> Result<AppConfig, Box<dyn std::error::Error>> {
        let config_file = self.config_root.strict_join("config.json")?;

        if config_file.exists() {
            println!("📄 Loading existing configuration...");
            let content = config_file.read_to_string()?;
            let config: AppConfig = serde_json::from_str(&content)?;
            Ok(config)
        } else {
            println!("🆕 Creating default configuration...");
            let config = AppConfig::default();
            self.save_config(&config)?;
            Ok(config)
        }
    }

    /// Save application configuration
    fn save_config(&self, config: &AppConfig) -> Result<(), Box<dyn std::error::Error>> {
        let config_file = self.config_root.strict_join("config.json")?;
        let content = serde_json::to_string_pretty(config)?;
        config_file.write(content)?;
        println!("💾 Configuration saved");
        Ok(())
    }

    /// Initialize or load media database
    fn load_database(&self) -> Result<MediaDatabase, Box<dyn std::error::Error>> {
        let db_file = self.data_root.strict_join("media_database.json")?;

        if db_file.exists() {
            println!("🗃️ Loading media database...");
            let content = db_file.read_to_string()?;
            let db: MediaDatabase = serde_json::from_str(&content)?;
            println!("   Found {} media entries", db.entries.len());
            Ok(db)
        } else {
            println!("🆕 Creating new media database...");
            let db = MediaDatabase {
                entries: HashMap::new(),
                total_files: 0,
                last_updated: chrono::Utc::now().to_rfc3339(),
            };
            self.save_database(&db)?;
            Ok(db)
        }
    }

    /// Save media database
    fn save_database(&self, db: &MediaDatabase) -> Result<(), Box<dyn std::error::Error>> {
        let db_file = self.data_root.strict_join("media_database.json")?;
        let content = serde_json::to_string_pretty(db)?;
        db_file.write(content)?;
        println!("💾 Media database saved with {} entries", db.entries.len());
        Ok(())
    }

    /// Scan user media directories and catalog files
    fn scan_user_media(
        &self,
        config: &mut AppConfig,
    ) -> Result<MediaDatabase, Box<dyn std::error::Error>> {
        let mut db = self.load_database()?;

        // Scan standard user media directories using dirs crate
        let media_directories: Vec<(&str, Option<PathBoundary<()>>)> = vec![
            (
                "Pictures",
                dirs::picture_dir().map(PathBoundary::try_new).transpose()?,
            ),
            (
                "Music",
                dirs::audio_dir().map(PathBoundary::try_new).transpose()?,
            ),
            (
                "Videos",
                dirs::video_dir().map(PathBoundary::try_new).transpose()?,
            ),
            (
                "Downloads",
                dirs::download_dir()
                    .map(PathBoundary::try_new)
                    .transpose()?,
            ),
        ];

        println!("\n🔍 Scanning user media directories...");

        for (dir_name, dir_path_opt) in media_directories {
            if let Some(dir_path) = dir_path_opt {
                println!(
                    "📂 Scanning {}: {}",
                    dir_name,
                    dir_path.strictpath_display()
                );

                // In a real app, you'd recursively scan for media files
                // For demo purposes, we'll simulate finding some files
                let simulated_files = match dir_name {
                    "Pictures" => vec!["vacation.jpg", "family.png", "screenshot.png"],
                    "Music" => vec!["song1.mp3", "album.flac", "podcast.wav"],
                    "Videos" => vec!["movie.mp4", "recording.mov"],
                    "Downloads" => vec!["wallpaper.jpg", "music.mp3"],
                    _ => vec![],
                };

                for filename in simulated_files {
                    // Demonstrate proper StrictPath operations for file handling
                    if let Ok(media_file) = dir_path.strict_join(filename) {
                        // Extract filename and extension using StrictPath methods
                        let actual_filename = media_file
                            .strictpath_file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or("unknown");

                        let extension = media_file
                            .strictpath_extension()
                            .and_then(|ext| ext.to_str())
                            .unwrap_or("");

                        if config.supported_formats.contains(&extension.to_string()) {
                            let entry = MediaEntry {
                                path: media_file.strictpath_display().to_string(),
                                file_type: extension.to_string(),
                                size_bytes: 1024 * 1024, // 1MB example size
                                created: chrono::Utc::now().to_rfc3339(),
                                has_thumbnail: false,
                            };

                            db.entries
                                .insert(media_file.strictpath_display().to_string(), entry);
                            println!("   ✅ Added: {}", actual_filename);
                        }
                    }
                }
            } else {
                println!("⚠️  Directory not available: {}", dir_name);
            }
        }

        db.total_files = db.entries.len();
        db.last_updated = chrono::Utc::now().to_rfc3339();
        config.last_scan_path = Some("All standard directories".to_string());

        Ok(db)
    }

    /// Generate thumbnails and cache metadata
    fn generate_thumbnails(
        &self,
        db: &mut MediaDatabase,
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n🖼️ Generating thumbnails and caching metadata...");

        let thumbnails_dir = self.cache_root.strict_join("thumbnails")?;
        thumbnails_dir.create_dir_all()?;

        let metadata_dir = self.cache_root.strict_join("metadata")?;
        metadata_dir.create_dir_all()?;

        for (path_key, entry) in db.entries.iter_mut() {
            // Best practice: store filename in database or reconstruct StrictPath from stored path
            // For this demo, we'll extract filename properly from the path key
            // In a real app, you'd either:
            // 1. Store the filename separately in MediaEntry
            // 2. Reconstruct the StrictPath and use strictpath_file_name()
            let filename = if let Some(last_slash) = path_key.rfind('/') {
                &path_key[last_slash + 1..]
            } else if let Some(last_backslash) = path_key.rfind('\\') {
                &path_key[last_backslash + 1..]
            } else {
                path_key
            };

            // Create safe filename for cache (the filename is already clean from StrictPath)
            let safe_filename = filename;

            let thumb_file = thumbnails_dir.strict_join(format!("{}.thumb", safe_filename))?;
            thumb_file.write(b"simulated thumbnail data")?;

            let meta_file = metadata_dir.strict_join(format!("{}.meta", safe_filename))?;
            let metadata = serde_json::json!({
                "original_path": path_key,
                "file_type": entry.file_type,
                "processed_at": chrono::Utc::now().to_rfc3339(),
                "thumbnail_generated": true
            });
            meta_file.write(metadata.to_string())?;

            entry.has_thumbnail = true;
            println!("   🖼️ Generated thumbnail for: {}", safe_filename);
        }

        Ok(())
    }

    /// Clean up old cache files
    fn cleanup_cache(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n🧹 Cleaning up old cache files...");

        // In a real app, you'd check file ages and remove old entries
        let cache_info_file = self.cache_root.strict_join("cache_info.json")?;
        let cache_info = serde_json::json!({
            "last_cleanup": chrono::Utc::now().to_rfc3339(),
            "cache_size_mb": 45.2,
            "files_cleaned": 3
        });

        cache_info_file.write(cache_info.to_string())?;
        println!("   ✅ Cache cleanup completed");

        Ok(())
    }

    /// Display application status and statistics
    fn show_status(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n📊 {} Status Report", self.name);
        println!("═══════════════════════════════════════");

        let config = self.load_config()?;
        let db = self.load_database()?;

        println!("📁 Directories:");
        println!("   Config: {}", self.config_root.strictpath_display());
        println!("   Data:   {}", self.data_root.strictpath_display());
        println!("   Cache:  {}", self.cache_root.strictpath_display());

        println!("\n⚙️ Configuration:");
        println!("   Theme: {}", config.theme);
        println!("   Auto-organize: {}", config.auto_organize);
        println!("   Supported formats: {}", config.supported_formats.len());

        println!("\n📊 Media Database:");
        println!("   Total files: {}", db.total_files);
        println!("   Last updated: {}", db.last_updated);

        // Count by type
        let mut type_counts = HashMap::new();
        for entry in db.entries.values() {
            *type_counts.entry(&entry.file_type).or_insert(0) += 1;
        }

        println!("   File types:");
        for (file_type, count) in type_counts {
            println!("     {}: {}", file_type, count);
        }

        Ok(())
    }

    /// Demonstrate virtual root usage for user-facing paths
    fn demonstrate_virtual_root(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n🌐 Virtual Root Demo (User-Facing Paths)");
        println!("═══════════════════════════════════════════");

        // Create a virtual root for user workspace using dirs crate
        let workspace = VirtualRoot::<()>::try_new(
            dirs::document_dir()
                .ok_or_else(|| anyhow::anyhow!("Could not determine documents directory"))?,
        )?;
        println!(
            "📁 User workspace: {}",
            workspace.as_unvirtual().strictpath_display()
        );

        // App sees clean virtual paths, system manages real location
        let project_file = workspace.virtual_join("projects/media-organizer/notes.txt")?;
        println!("📝 Virtual path: {}", project_file.virtualpath_display());
        println!(
            "🔗 Real path: {}",
            project_file.as_unvirtual().strictpath_display()
        );

        // Create the file through virtual path
        project_file.create_parent_dir_all()?;
        project_file.write(
            b"Media Organizer Project Notes\n\
              - Uses OS standard directories\n\
              - Secure path boundaries\n\
              - Cross-platform compatibility",
        )?;

        println!("✅ Created project file through virtual path");

        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🎬 Media Organizer - OS Directories Demo");
    println!("════════════════════════════════════════════════");

    // Initialize app with OS standard directories
    let app = MediaOrganizerApp::new("MediaOrganizer")?;

    // Load configuration
    let mut config = app.load_config()?;

    // Scan user media directories
    let mut database = app.scan_user_media(&mut config)?;

    // Save updated config and database
    app.save_config(&config)?;
    app.save_database(&database)?;

    // Generate thumbnails and cache
    app.generate_thumbnails(&mut database)?;
    app.save_database(&database)?;

    // Cleanup cache
    app.cleanup_cache()?;

    // Show application status
    app.show_status()?;

    // Demonstrate virtual root usage
    app.demonstrate_virtual_root()?;

    println!("\n🎉 Media Organizer demo completed successfully!");
    println!("   All operations were performed within secure OS directory boundaries.");

    Ok(())
}
