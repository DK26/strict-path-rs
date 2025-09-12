// Cargo.toml
// [dependencies]
// strict-path = "0.1.0-alpha.1"
// clap = { version = "4.0", features = ["derive"] }
// serde = { version = "1.0", features = ["derive"] }
// serde_json = "1.0"
// chrono = { version = "0.4", features = ["serde"] }
// walkdir = "2.0"

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strict_path::PathBoundary;
use walkdir::WalkDir;

// Type markers for different backup contexts
struct BackupDestination;
struct BackupSource;
// ConfigFiles was unused in this example; removed to avoid dead_code warning.

#[derive(Parser)]
#[command(name = "secure-backup")]
#[command(about = "A secure backup tool that prevents directory traversal")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new backup destination
    Init {
        /// Backup destination directory
        #[arg(short, long)]
        destination: String,
    },
    /// Create a backup from source to destination
    Backup {
        /// Source directory to backup
        #[arg(short, long)]
        source: String,
        /// Backup destination directory
        #[arg(short, long)]
        destination: String,
        /// Backup name/identifier
        #[arg(short, long)]
        name: String,
    },
    /// Restore files from a backup
    Restore {
        /// Backup destination directory
        #[arg(short, long)]
        destination: String,
        /// Backup name to restore
        #[arg(short, long)]
        name: String,
        /// Directory to restore to
        #[arg(short, long)]
        target: String,
    },
    /// List available backups
    List {
        /// Backup destination directory
        #[arg(short, long)]
        destination: String,
    },
}

#[derive(Serialize, Deserialize)]
struct BackupManifest {
    name: String,
    created_at: chrono::DateTime<chrono::Utc>,
    source_path: String,
    files: Vec<BackupFileEntry>,
}

#[derive(Serialize, Deserialize)]
struct BackupFileEntry {
    relative_path: String,
    size: u64,
    is_file: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { destination } => init_backup_destination(&destination),
        Commands::Backup {
            source,
            destination,
            name,
        } => create_backup(&source, &destination, &name),
        Commands::Restore {
            destination,
            name,
            target,
        } => restore_backup(&destination, &name, &target),
        Commands::List { destination } => list_backups(&destination),
    }
}

fn init_backup_destination(dest_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Initializing secure backup destination: {dest_path}");

    // Create and validate the backup destination PathBoundary
    let backup_jail: PathBoundary<BackupDestination> = PathBoundary::try_new_create(dest_path)?;

    // Create metadata directory
    let metadata_dir = backup_jail.strict_join("_metadata")?;
    metadata_dir.create_dir_all()?;

    // Create initial registry
    let registry_path = backup_jail.strict_join("_metadata/registry.json")?;
    let empty_registry: HashMap<String, String> = HashMap::new();
    let registry_content = serde_json::to_string_pretty(&empty_registry)?;
    registry_path.write_string(&registry_content)?;

    println!(
        "Backup destination initialized at: {}",
        backup_jail.strictpath_display()
    );
    Ok(())
}

fn create_backup(
    source_path: &str,
    dest_path: &str,
    backup_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Creating backup '{backup_name}' from {source_path} to {dest_path}");

    // Create secure jails for source and destination
    let source_dir: PathBoundary<BackupSource> = PathBoundary::try_new_create(source_path)?;
    let backup_dir: PathBoundary<BackupDestination> = PathBoundary::try_new_create(dest_path)?;

    // Create backup directory
    let backup_dir_path = format!("backups/{backup_name}");
    let backup_dir = backup_dir.strict_join(&backup_dir_path)?;
    backup_dir.create_dir_all()?;

    // Collect files to backup
    let mut backup_files = Vec::new();
    let source_root_os = source_dir.interop_path();

    for entry in WalkDir::new(source_root_os) {
        let entry = entry?;
        let entry_path = entry.path();

        // Get relative path from source root
        let relative = entry_path.strip_prefix(source_root_os)?;
        if relative.as_os_str().is_empty() {
            continue;
        }

        let relative_str = format!("{}", relative.display());

        // Validate the relative path through source PathBoundary
        let source_file = source_dir.strict_join(&relative_str)?;

        if source_file.is_file() {
            // Copy file to backup location
            let backup_file_path = format!("{backup_dir_path}/{relative_str}");
            let backup_file = backup_dir.strict_join(&backup_file_path)?;

            // Create parent directories if needed
            backup_file.create_parent_dir_all()?;

            // Copy file content
            let content = source_file.read_bytes()?;
            backup_file.write_bytes(&content)?;

            backup_files.push(BackupFileEntry {
                relative_path: relative_str.clone(),
                size: content.len() as u64,
                is_file: true,
            });

            println!("  Backed up: {relative_str}");
        } else if source_file.is_dir() {
            let backup_dir_path_new = format!("{backup_dir_path}/{relative_str}");
            let backup_subdir = backup_dir.strict_join(&backup_dir_path_new)?;
            backup_subdir.create_dir_all()?;

            backup_files.push(BackupFileEntry {
                relative_path: relative_str,
                size: 0,
                is_file: false,
            });
        }
    }

    // Create manifest
    let manifest = BackupManifest {
        name: backup_name.to_string(),
        created_at: chrono::Utc::now(),
        source_path: source_path.to_string(),
        files: backup_files,
    };

    let manifest_path = format!("_metadata/{backup_name}.json");
    let manifest_file = backup_dir.strict_join(manifest_path)?;
    let manifest_content = serde_json::to_string_pretty(&manifest)?;
    manifest_file.write_string(&manifest_content)?;

    println!(
        "Backup '{}' created successfully with {} items",
        backup_name,
        manifest.files.len()
    );
    Ok(())
}

fn restore_backup(
    dest_path: &str,
    backup_name: &str,
    target_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Restoring backup '{backup_name}' from {dest_path} to {target_path}");

    let backup_jail: PathBoundary<BackupDestination> = PathBoundary::try_new_create(dest_path)?;
    let target_jail: PathBoundary<BackupSource> = PathBoundary::try_new_create(target_path)?;

    // Load manifest
    let manifest_path = format!("_metadata/{backup_name}.json");
    let manifest_file = backup_jail.strict_join(&manifest_path)?;
    let manifest_content = manifest_file.read_to_string()?;
    let manifest: BackupManifest = serde_json::from_str(&manifest_content)?;

    println!(
        "Restoring {} items from backup created at {}",
        manifest.files.len(),
        manifest.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );

    // Restore each file
    for file_entry in &manifest.files {
        if file_entry.is_file {
            // Read from backup
            let backup_file_path = format!("backups/{}/{}", backup_name, file_entry.relative_path);
            let backup_file = backup_jail.strict_join(&backup_file_path)?;
            let content = backup_file.read_bytes()?;

            // Write to target (securely validated path)
            let target_file = target_jail.strict_join(&file_entry.relative_path)?;

            // Create parent directories
            target_file.create_parent_dir_all()?;

            target_file.write_bytes(&content)?;
            println!(
                "  Restored: {} ({} bytes)",
                file_entry.relative_path, file_entry.size
            );
        } else {
            // Create directory
            let target_dir = target_jail.strict_join(&file_entry.relative_path)?;
            target_dir.create_dir_all()?;
            println!("  Created directory: {}", file_entry.relative_path);
        }
    }

    println!("Backup '{backup_name}' restored successfully to {target_path}");
    Ok(())
}

fn list_backups(dest_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let backup_jail: PathBoundary<BackupDestination> = PathBoundary::try_new_create(dest_path)?;
    let metadata_dir = backup_jail.strict_join("_metadata")?;

    if !metadata_dir.exists() {
        println!("No backups found. Initialize the backup destination first.");
        return Ok(());
    }

    println!("Available backups in {dest_path}:");
    println!(
        "{:<20} {:<25} {:<15} {:<10}",
        "Name", "Created", "Source", "Files"
    );
    println!("{}", "-".repeat(75));

    // In a real implementation, you'd iterate through metadata directory
    // This shows the secure pattern for accessing backup metadata
    let manifest_examples = vec!["documents", "photos", "config"];

    for name in manifest_examples {
        let manifest_path = format!("_metadata/{name}.json");
        if let Ok(manifest_file) = backup_jail.strict_join(&manifest_path) {
            if manifest_file.exists() {
                let content = manifest_file.read_to_string()?;
                if let Ok(manifest) = serde_json::from_str::<BackupManifest>(&content) {
                    println!(
                        "{:<20} {:<25} {:<15} {:<10}",
                        manifest.name,
                        manifest.created_at.format("%Y-%m-%d %H:%M:%S"),
                        manifest.source_path.chars().take(15).collect::<String>(),
                        manifest.files.len()
                    );
                }
            }
        }
    }

    Ok(())
}
