// Docker Volume Manager (secure demo)
//
// Demonstrates managing volumes using type-safe jails.
// Subcommands: create, list, backup, restore, inspect, cleanup.

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use strict_path::PathBoundary;
use uuid::Uuid;

#[derive(Clone)]
struct DockerVolumes;
#[derive(Clone)]
struct VolumeBackups;

#[derive(Parser)]
#[command(name = "docker-vol-mgr")]
#[command(about = "Secure Docker volume management tool")]
struct Cli {
    #[arg(long, default_value = "/var/lib/docker-volumes")]
    volumes_root: String,
    #[arg(long, default_value = "./volume-backups")]
    backups_root: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Create {
        name: String,
        #[arg(long)]
        size_mb: Option<u64>,
    },
    List,
    Backup {
        volume: String,
        #[arg(long)]
        name: Option<String>,
    },
    Restore {
        volume: String,
        backup: String,
    },
    Inspect {
        volume: String,
        #[arg(long)]
        path: Option<String>,
    },
    Cleanup {
        #[arg(long, default_value = "30")]
        older_than_days: u64,
    },
}

#[derive(Serialize, Deserialize, Debug)]
struct VolumeMetadata {
    name: String,
    id: String,
    created_at: chrono::DateTime<chrono::Utc>,
    size_mb: Option<u64>,
    last_accessed: chrono::DateTime<chrono::Utc>,
    container_count: u32,
    description: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct BackupMetadata {
    volume_name: String,
    backup_name: String,
    created_at: chrono::DateTime<chrono::Utc>,
    size_bytes: u64,
    file_count: u32,
    compression: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    println!("Docker Volume Manager");
    match cli.command {
        Commands::Create { ref name, size_mb } => create_volume(&cli, name, size_mb),
        Commands::List => list_volumes(&cli),
        Commands::Backup {
            ref volume,
            ref name,
        } => backup_volume(&cli, volume, name.clone()),
        Commands::Restore {
            ref volume,
            ref backup,
        } => restore_volume(&cli, volume, backup),
        Commands::Inspect {
            ref volume,
            ref path,
        } => inspect_volume(&cli, volume, path.clone()),
        Commands::Cleanup { older_than_days } => cleanup_volumes(&cli, older_than_days),
    }
}

fn create_volume(
    cli: &Cli,
    volume_name: &str,
    size_mb: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Creating Docker volume: {volume_name}");

    // Setup secure path boundary
    let volumes_dir: PathBoundary<DockerVolumes> = PathBoundary::try_new_create(&cli.volumes_root)?;
    let volume_path = volumes_dir.strict_join(volume_name)?;

    // Check if volume already exists
    if volume_path.exists() {
        return Err(format!("Volume '{volume_name}' already exists").into());
    }

    // Create volume directories
    volume_path.create_dir_all()?;
    let data_dir = volume_path.strict_join("_data")?;
    data_dir.create_dir_all()?;

    // Create volume metadata
    let metadata = VolumeMetadata {
        name: volume_name.to_string(),
        id: Uuid::new_v4().to_string(),
        created_at: chrono::Utc::now(),
        size_mb,
        last_accessed: chrono::Utc::now(),
        container_count: 0,
        description: None,
    };

    // Save metadata
    let metadata_file = volume_path.strict_join("metadata.json")?;
    metadata_file.write_string(&serde_json::to_string_pretty(&metadata)?)?;

    // Report success
    println!("Volume '{volume_name}' created successfully");
    let volume_path_display = volume_path.strictpath_display();
    println!("  Path: {volume_path_display}");
    println!("  ID: {}", metadata.id);
    Ok(())
}

fn list_volumes(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    println!("Listing Docker volumes in: {}", &cli.volumes_root);

    // Setup secure path boundary (creates directory if it doesn't exist)
    let volumes_dir: PathBoundary<DockerVolumes> = PathBoundary::try_new_create(&cli.volumes_root)?;
    // Walk actual entries under the volumes root
    println!(
        "{:<20} {:<15} {:<20} {:<10} {:<12}",
        "Name", "Size (MB)", "Created", "Containers", "Status"
    );
    println!("{}", "-".repeat(80));
    for entry in std::fs::read_dir(volumes_dir.interop_path())? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name_os = entry.file_name();
        let Some(name) = name_os.to_str() else {
            continue;
        };
        let path = volumes_dir.strict_join(name)?;
        let meta = path.strict_join("metadata.json")?;
        if !meta.exists() {
            continue;
        }
        if let Ok(content) = meta.read_to_string() {
            if let Ok(metadata) = serde_json::from_str::<VolumeMetadata>(&content) {
                let size_str = metadata
                    .size_mb
                    .map(|mb| mb.to_string())
                    .unwrap_or_else(|| "unlimited".to_string());
                println!(
                    "{:<20} {:<15} {:<20} {:<10} {:<12}",
                    metadata.name,
                    size_str,
                    metadata.created_at.format("%Y-%m-%d %H:%M"),
                    metadata.container_count,
                    if metadata.container_count > 0 {
                        "in-use"
                    } else {
                        "available"
                    }
                );
            }
        }
    }
    Ok(())
}

fn backup_volume(
    cli: &Cli,
    volume_name: &str,
    backup_name: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Setup secure paths
    let volumes_dir: PathBoundary<DockerVolumes> = PathBoundary::try_new(&cli.volumes_root)?;
    let backups_dir: PathBoundary<VolumeBackups> = PathBoundary::try_new_create(&cli.backups_root)?;

    // Verify volume exists
    let volume_path = volumes_dir.strict_join(volume_name)?;
    if !volume_path.exists() {
        return Err(format!("Volume '{volume_name}' not found").into());
    }

    // Generate backup name
    let backup_name =
        backup_name.unwrap_or_else(|| chrono::Utc::now().format("%Y%m%d%H%M%S").to_string());

    // Create backup directories
    let backup_path = backups_dir.strict_join(&backup_name)?;
    backup_path.create_dir_all()?;
    let backup_data_dir = backup_path.strict_join("data")?;
    backup_data_dir.create_dir_all()?;

    // Copy files recursively from _data
    let mut file_count = 0u32;
    let mut total_size = 0u64;
    let data_root = volume_path.strict_join("_data")?;
    if data_root.exists() {
        for entry in walkdir::WalkDir::new(data_root.interop_path()) {
            let entry = entry?;
            if !entry.file_type().is_file() {
                continue;
            }
            let entry_path = entry.path();
            let relative_path = match entry_path.strip_prefix(data_root.interop_path()) {
                Ok(rp) => rp,
                Err(_) => continue,
            };
            let dest_file = backup_data_dir.strict_join(relative_path)?;
            dest_file.create_parent_dir_all()?;
            let bytes = std::fs::read(entry_path)?;
            total_size += bytes.len() as u64;
            dest_file.write_bytes(&bytes)?;
            file_count += 1;
        }
    }
    // Create backup metadata
    let backup_metadata = BackupMetadata {
        volume_name: volume_name.to_string(),
        backup_name: backup_name.clone(),
        created_at: chrono::Utc::now(),
        size_bytes: total_size,
        file_count,
        compression: "none".into(),
    };

    let backup_meta_file = backup_path.strict_join("backup.json")?;
    backup_meta_file.write_string(&serde_json::to_string_pretty(&backup_metadata)?)?;

    // Report success
    println!("Backup '{backup_name}' created successfully");
    println!("   Files: {file_count}");
    println!("   Size: {total_size} bytes");
    let backup_path_display = backup_path.strictpath_display();
    println!("   Path: {backup_path_display}");
    Ok(())
}

fn restore_volume(
    cli: &Cli,
    volume_name: &str,
    backup_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Restoring volume '{volume_name}' from backup '{backup_name}'");

    // Setup secure paths
    let volumes_dir: PathBoundary<DockerVolumes> = PathBoundary::try_new(&cli.volumes_root)?;
    let backups_dir: PathBoundary<VolumeBackups> = PathBoundary::try_new(&cli.backups_root)?;

    // Verify backup exists
    let backup_path = backups_dir.strict_join(backup_name)?;
    if !backup_path.exists() {
        return Err(format!("Backup '{backup_name}' not found").into());
    }

    // Setup paths
    let backup_data_dir = backup_path.strict_join("data")?;
    let volume_path = volumes_dir.strict_join(volume_name)?;
    volume_path.create_dir_all()?;

    // Clean existing data directory
    let data_dir = volume_path.strict_join("_data")?;
    if data_dir.exists() {
        data_dir.remove_dir_all()?;
    }
    data_dir.create_dir_all()?;

    // Restore all files in the backup
    for entry in walkdir::WalkDir::new(backup_data_dir.interop_path()) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let entry_path = entry.path();
        let relative_path = match entry_path.strip_prefix(backup_data_dir.interop_path()) {
            Ok(rp) => rp,
            Err(_) => continue,
        };
        let dest_file = data_dir.strict_join(relative_path)?;
        dest_file.create_parent_dir_all()?;
        let bytes = std::fs::read(entry_path)?;
        dest_file.write_bytes(&bytes)?;
    }
    // Update metadata
    let volume_metadata = VolumeMetadata {
        name: volume_name.to_string(),
        id: Uuid::new_v4().to_string(),
        created_at: chrono::Utc::now(),
        size_mb: None,
        last_accessed: chrono::Utc::now(),
        container_count: 0,
        description: Some(format!("Restored from backup '{backup_name}'")),
    };
    let volume_meta_file = volume_path.strict_join("metadata.json")?;
    volume_meta_file.write_string(&serde_json::to_string_pretty(&volume_metadata)?)?;
    println!("Volume '{volume_name}' restored successfully from backup '{backup_name}'");
    Ok(())
}

fn inspect_volume(
    cli: &Cli,
    volume_name: &str,
    inspect_path: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let volumes_dir: PathBoundary<DockerVolumes> = PathBoundary::try_new(&cli.volumes_root)?;
    let volume_path = volumes_dir.strict_join(volume_name)?;
    if !volume_path.exists() {
        return Err(format!("Volume '{volume_name}' not found").into());
    }
    // Load metadata
    let meta_file = volume_path.strict_join("metadata.json")?;
    if meta_file.exists() {
        if let Ok(content) = meta_file.read_to_string() {
            if let Ok(metadata) = serde_json::from_str::<VolumeMetadata>(&content) {
                println!("Volume Information:");
                println!("   Name: {}", metadata.name);
                println!("   ID: {}", metadata.id);
                println!(
                    "   Created: {}",
                    metadata.created_at.format("%Y-%m-%d %H:%M:%S UTC")
                );
                println!(
                    "   Last Accessed: {}",
                    metadata.last_accessed.format("%Y-%m-%d %H:%M:%S UTC")
                );
                println!("   Container Count: {}", metadata.container_count);
                if let Some(size_mb) = metadata.size_mb {
                    println!("   Size Limit: {size_mb} MB");
                }
                if let Some(desc) = &metadata.description {
                    println!("   Description: {desc}");
                }
            }
        }
    }
    // Inspect path or root
    let data_dir = volume_path.strict_join("_data")?;
    let target = if let Some(requested_path) = inspect_path {
        data_dir.strict_join(requested_path)?
    } else {
        data_dir
    };
    println!("\nContents:");
    if target.exists() {
        if target.is_file() {
            let size = target.metadata()?.len();
            println!("   File: {size} bytes");
        } else {
            println!("   Directory (listing omitted in demo)");
        }
    } else {
        println!("   (empty)");
    }
    Ok(())
}

fn cleanup_volumes(cli: &Cli, older_than_days: u64) -> Result<(), Box<dyn std::error::Error>> {
    println!("Cleaning up volumes older than {older_than_days} days");
    let volumes_dir: PathBoundary<DockerVolumes> = PathBoundary::try_new(&cli.volumes_root)?;
    let cutoff = chrono::Utc::now() - chrono::Duration::days(older_than_days as i64);
    let mut cleaned_count = 0u32;
    let mut cleaned_size = 0u64;
    for entry in std::fs::read_dir(volumes_dir.interop_path())? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name_os = entry.file_name();
        let Some(name) = name_os.to_str() else {
            continue;
        };
        if let Ok(path) = volumes_dir.strict_join(name) {
            let meta_file = path.strict_join("metadata.json")?;
            if !meta_file.exists() {
                continue;
            }
            if let Ok(m) = serde_json::from_str::<VolumeMetadata>(&meta_file.read_to_string()?) {
                if m.last_accessed < cutoff && m.container_count == 0 {
                    // Approximate space freed
                    let data = path.strict_join("_data")?;
                    if data.exists() {
                        for entry in walkdir::WalkDir::new(data.interop_path()) {
                            let entry = entry?;
                            if entry.file_type().is_file() {
                                cleaned_size += entry.metadata()?.len();
                            }
                        }
                    }
                    path.remove_dir_all()?;
                    cleaned_count += 1;
                }
            }
        }
    }
    println!("Cleanup completed:");
    println!("   Volumes removed: {cleaned_count}");
    println!("   Space freed: {} MB", cleaned_size / (1024 * 1024));
    Ok(())
}
