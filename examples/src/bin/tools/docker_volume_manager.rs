// Docker Volume Manager (secure demo)
//
// Demonstrates managing volumes using type-safe jails.
// Subcommands: create, list, backup, restore, inspect, cleanup.

use clap::{Parser, Subcommand};
use jailed_path::Jail;
use serde::{Deserialize, Serialize};
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
    Create { name: String, #[arg(long)] size_mb: Option<u64> },
    List,
    Backup { volume: String, #[arg(long)] name: Option<String> },
    Restore { volume: String, backup: String },
    Inspect { volume: String, #[arg(long)] path: Option<String> },
    Cleanup { #[arg(long, default_value = "30")] older_than_days: u64 },
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
        Commands::Backup { ref volume, ref name } => backup_volume(&cli, volume, name.clone()),
        Commands::Restore { ref volume, ref backup } => restore_volume(&cli, volume, backup),
        Commands::Inspect { ref volume, ref path } => inspect_volume(&cli, volume, path.clone()),
        Commands::Cleanup { older_than_days } => cleanup_volumes(&cli, older_than_days),
    }
}

fn create_volume(cli: &Cli, volume_name: &str, size_mb: Option<u64>) -> Result<(), Box<dyn std::error::Error>> {
    println!("Creating Docker volume: {volume_name}");
    let volumes_jail: Jail<DockerVolumes> = Jail::try_new_create(&cli.volumes_root)?;
    let volume_path = volumes_jail.jailed_join(volume_name)?;
    if volume_path.exists() {
        return Err(format!("Volume '{volume_name}' already exists").into());
    }
    volume_path.create_dir_all()?;
    let data_dir = volume_path.jailed_join("_data")?;
    data_dir.create_dir_all()?;
    let metadata = VolumeMetadata {
        name: volume_name.to_string(),
        id: Uuid::new_v4().to_string(),
        created_at: chrono::Utc::now(),
        size_mb,
        last_accessed: chrono::Utc::now(),
        container_count: 0,
        description: None,
    };
    let metadata_file = volume_path.jailed_join("metadata.json")?;
    metadata_file.write_string(&serde_json::to_string_pretty(&metadata)?)?;
    println!("Volume '{volume_name}' created successfully");
    let p = volume_path.jailedpath_display();
    println!("  Path: {p}");
    println!("  ID: {}", metadata.id);
    Ok(())
}

fn list_volumes(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    println!("Listing Docker volumes in: {}", &cli.volumes_root);
    let volumes_jail: Jail<DockerVolumes> = Jail::try_new_create(&cli.volumes_root)?;
    let root = volumes_jail.jailed_join(".")?;
    if !root.exists() {
        println!("No volumes directory found.");
        return Ok(());
    }
    // Demo: print a header and a few sample entries
    println!("{:<20} {:<15} {:<20} {:<10} {:<12}", "Name", "Size (MB)", "Created", "Containers", "Status");
    println!("{}", "-".repeat(80));
    for name in ["webapp-data", "db-storage", "cache-volume"] {
        let path = volumes_jail.jailed_join(name)?;
        if path.exists() {
            let meta = path.jailed_join("metadata.json")?;
            if meta.exists() {
                if let Ok(content) = meta.read_to_string() {
                    if let Ok(m) = serde_json::from_str::<VolumeMetadata>(&content) {
                        let size_str = m.size_mb.map(|s| s.to_string()).unwrap_or_else(|| "unlimited".to_string());
                        println!(
                            "{:<20} {:<15} {:<20} {:<10} {:<12}",
                            m.name,
                            size_str,
                            m.created_at.format("%Y-%m-%d %H:%M"),
                            m.container_count,
                            if m.container_count > 0 { "in-use" } else { "available" }
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

fn backup_volume(cli: &Cli, volume_name: &str, backup_name: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let volumes_jail: Jail<DockerVolumes> = Jail::try_new(&cli.volumes_root)?;
    let backups_jail: Jail<VolumeBackups> = Jail::try_new_create(&cli.backups_root)?;
    let volume_path = volumes_jail.jailed_join(volume_name)?;
    if !volume_path.exists() {
        return Err(format!("Volume '{volume_name}' not found").into());
    }
    let backup_name = backup_name.unwrap_or_else(|| chrono::Utc::now().format("%Y%m%d%H%M%S").to_string());
    let backup_path = backups_jail.jailed_join(&backup_name)?;
    backup_path.create_dir_all()?;
    let backup_data_dir = backup_path.jailed_join("data")?;
    backup_data_dir.create_dir_all()?;
    // Demo: simulate copying a few files
    let mut file_count = 0u32;
    let mut total_size = 0u64;
    for rel in ["config.json", "logs/app.log", "uploads/image.jpg"] {
        let src = volume_path.jailed_join(format!("_data/{rel}"))?;
        if src.exists() {
            let dst = backup_data_dir.jailed_join(rel)?;
            dst.create_parent_dir_all()?;
            let bytes = src.read_bytes()?;
            total_size += bytes.len() as u64;
            dst.write_bytes(&bytes)?;
            file_count += 1;
        }
    }
    let meta = BackupMetadata { volume_name: volume_name.to_string(), backup_name: backup_name.clone(), created_at: chrono::Utc::now(), size_bytes: total_size, file_count, compression: "none".into() };
    let meta_file = backup_path.jailed_join("backup.json")?;
    meta_file.write_string(&serde_json::to_string_pretty(&meta)?)?;
    println!("Backup '{backup_name}' created successfully");
    println!("   Files: {file_count}");
    println!("   Size: {total_size} bytes");
    let p = backup_path.jailedpath_display();
    println!("   Path: {p}");
    Ok(())
}

fn restore_volume(cli: &Cli, volume_name: &str, backup_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Restoring volume '{volume_name}' from backup '{backup_name}'");
    let volumes_jail: Jail<DockerVolumes> = Jail::try_new(&cli.volumes_root)?;
    let backups_jail: Jail<VolumeBackups> = Jail::try_new(&cli.backups_root)?;
    let backup_path = backups_jail.jailed_join(backup_name)?;
    if !backup_path.exists() { return Err(format!("Backup '{backup_name}' not found").into()); }
    let backup_data_dir = backup_path.jailed_join("data")?;
    let volume_path = volumes_jail.jailed_join(volume_name)?;
    volume_path.create_dir_all()?;
    let data_dir = volume_path.jailed_join("_data")?;
    if data_dir.exists() { data_dir.remove_dir_all()?; }
    data_dir.create_dir_all()?;
    // Demo: simulate restoring a few files
    for rel in ["config.json", "logs/app.log", "uploads/image.jpg"] {
        let src = backup_data_dir.jailed_join(rel)?;
        if src.exists() {
            let dst = data_dir.jailed_join(rel)?;
            dst.create_parent_dir_all()?;
            let bytes = src.read_bytes()?;
            dst.write_bytes(&bytes)?;
        }
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
    let volume_meta_file = volume_path.jailed_join("metadata.json")?;
    volume_meta_file.write_string(&serde_json::to_string_pretty(&volume_metadata)?)?;
    println!("Volume '{volume_name}' restored successfully from backup '{backup_name}'");
    Ok(())
}

fn inspect_volume(cli: &Cli, volume_name: &str, inspect_path: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let volumes_jail: Jail<DockerVolumes> = Jail::try_new(&cli.volumes_root)?;
    let volume_path = volumes_jail.jailed_join(volume_name)?;
    if !volume_path.exists() { return Err(format!("Volume '{volume_name}' not found").into()); }
    // Load metadata
    let meta_file = volume_path.jailed_join("metadata.json")?;
    if meta_file.exists() {
        if let Ok(content) = meta_file.read_to_string() {
            if let Ok(m) = serde_json::from_str::<VolumeMetadata>(&content) {
                println!("Volume Information:");
                println!("   Name: {}", m.name);
                println!("   ID: {}", m.id);
                println!("   Created: {}", m.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
                println!("   Last Accessed: {}", m.last_accessed.format("%Y-%m-%d %H:%M:%S UTC"));
                println!("   Container Count: {}", m.container_count);
                if let Some(size_mb) = m.size_mb { println!("   Size Limit: {size_mb} MB"); }
                if let Some(desc) = &m.description { println!("   Description: {desc}"); }
            }
        }
    }
    // Inspect path or root
    let data_dir = volume_path.jailed_join("_data")?;
    let target = if let Some(p) = inspect_path { data_dir.jailed_join(p)? } else { data_dir };
    println!("\nContents:");
    if target.exists() {
        if target.is_file() {
            let size = target.metadata()?.len();
            println!("   File: {size} bytes");
        } else {
            println!("   Directory (listing omitted in demo)");
        }
    } else { println!("   (empty)"); }
    Ok(())
}

fn cleanup_volumes(cli: &Cli, older_than_days: u64) -> Result<(), Box<dyn std::error::Error>> {
    println!("Cleaning up volumes older than {older_than_days} days");
    let volumes_jail: Jail<DockerVolumes> = Jail::try_new(&cli.volumes_root)?;
    let cutoff = chrono::Utc::now() - chrono::Duration::days(older_than_days as i64);
    let mut cleaned_count = 0u32;
    let mut cleaned_size = 0u64;
    for name in ["old-cache", "temp-data", "legacy-logs"] {
        if let Ok(path) = volumes_jail.jailed_join(name) {
            if path.exists() {
                let meta_file = path.jailed_join("metadata.json")?;
                if meta_file.exists() {
                    if let Ok(m) = serde_json::from_str::<VolumeMetadata>(&meta_file.read_to_string()?) {
                        if m.last_accessed < cutoff && m.container_count == 0 {
                            let data = path.jailed_join("_data")?;
                            if data.exists() { cleaned_size += 100 * 1024 * 1024; }
                            path.remove_dir_all()?;
                            cleaned_count += 1;
                        }
                    }
                }
            }
        }
    }
    println!("Cleanup completed:");
    println!("   Volumes removed: {cleaned_count}");
    println!("   Space freed: {} MB", cleaned_size / (1024 * 1024));
    Ok(())
}

