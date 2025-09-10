// Cargo.toml
// [dependencies]
// jailed-path = "0.0.4"
// zip = "0.6"
// tar = "0.4"
// flate2 = "1.0"
// clap = { version = "4.0", features = ["derive"] }
// indicatif = "0.17"

use clap::{Parser, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle};
use jailed_path::{Jail, JailedPath};
use std::fs::File;
use std::io::Read;
use std::path::Path;

// Type markers for different archive contexts
struct ArchiveInput;
struct ExtractionOutput;

#[derive(Parser)]
#[command(name = "secure-extract")]
#[command(about = "Securely extract archives without zip-slip vulnerabilities")]
struct Cli {
    /// Archive file to extract
    #[arg(short, long)]
    archive: String,

    /// Output directory for extraction
    #[arg(short, long)]
    output: String,

    /// Archive format (auto-detected if not specified)
    #[arg(short, long)]
    format: Option<ArchiveFormat>,

    /// Maximum number of files to extract (security limit)
    #[arg(long, default_value = "10000")]
    max_files: usize,

    /// Maximum total size to extract in MB (security limit)
    #[arg(long, default_value = "1000")]
    max_size_mb: u64,

    /// Show verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(ValueEnum, Clone, Debug)]
enum ArchiveFormat {
    Zip,
    Tar,
    TarGz,
}

struct ExtractionStats {
    files_extracted: usize,
    directories_created: usize,
    total_bytes: u64,
    blocked_paths: Vec<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    println!("🔒 Secure Archive Extractor");
    println!("Archive: {}", cli.archive);
    println!("Output: {}", cli.output);

    // Validate input archive exists and is readable
    let input_jail: Jail<ArchiveInput> =
        Jail::try_new_create(Path::new(&cli.archive).parent().unwrap_or(Path::new(".")))?;
    let archive_filename = Path::new(&cli.archive)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid archive filename")?;
    let archive_path = input_jail.jailed_join(archive_filename)?;

    if !archive_path.exists() {
        return Err(format!("Archive file not found: {}", cli.archive).into());
    }

    // Create secure extraction jail
    let extraction_jail: Jail<ExtractionOutput> = Jail::try_new_create(&cli.output)?;

    // Detect archive format if not specified
    let format = match &cli.format {
        Some(f) => f.clone(),
        None => detect_archive_format(&cli.archive).unwrap_or(ArchiveFormat::Zip),
    };

    println!("Format: {format:?}");
    println!(
        "Security limits: {} files, {} MB",
        cli.max_files, cli.max_size_mb
    );
    println!();

    // Extract based on format
    let stats = match format {
        ArchiveFormat::Zip => extract_zip(&archive_path, &extraction_jail, &cli)?,
        ArchiveFormat::Tar => extract_tar(&archive_path, &extraction_jail, &cli)?,
        ArchiveFormat::TarGz => extract_tar_gz(&archive_path, &extraction_jail, &cli)?,
    };

    // Report results
    println!("\n✅ Extraction completed successfully!");
    println!("Files extracted: {}", stats.files_extracted);
    println!("Directories created: {}", stats.directories_created);
    println!(
        "Total bytes extracted: {} MB",
        stats.total_bytes / 1_048_576
    );

    if !stats.blocked_paths.is_empty() {
        println!(
            "\n🛡️  Security: Blocked {} malicious paths:",
            stats.blocked_paths.len()
        );
        for (i, blocked) in stats.blocked_paths.iter().take(5).enumerate() {
            println!("  {}. {}", i + 1, blocked);
        }
        if stats.blocked_paths.len() > 5 {
            println!("  ... and {} more", stats.blocked_paths.len() - 5);
        }
    }

    Ok(())
}

fn detect_archive_format(path: &str) -> Option<ArchiveFormat> {
    let path_lower = path.to_lowercase();
    if path_lower.ends_with(".zip") {
        Some(ArchiveFormat::Zip)
    } else if path_lower.ends_with(".tar.gz") || path_lower.ends_with(".tgz") {
        Some(ArchiveFormat::TarGz)
    } else if path_lower.ends_with(".tar") {
        Some(ArchiveFormat::Tar)
    } else {
        None
    }
}

fn extract_zip(
    archive_path: &JailedPath<ArchiveInput>,
    extraction_jail: &Jail<ExtractionOutput>,
    cli: &Cli,
) -> Result<ExtractionStats, Box<dyn std::error::Error>> {
    let file = File::open(archive_path.interop_path())?;
    let mut archive = zip::ZipArchive::new(file)?;

    let mut stats = ExtractionStats {
        files_extracted: 0,
        directories_created: 0,
        total_bytes: 0,
        blocked_paths: Vec::new(),
    };

    let progress = ProgressBar::new(archive.len() as u64);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
            .unwrap(),
    );

    for i in 0..archive.len() {
        if stats.files_extracted >= cli.max_files {
            println!("\n⚠️  Reached maximum file limit ({})", cli.max_files);
            break;
        }

        if stats.total_bytes > cli.max_size_mb * 1_048_576 {
            println!("\n⚠️  Reached maximum size limit ({} MB)", cli.max_size_mb);
            break;
        }

        let mut zip_file = archive.by_index(i)?;
        let entry_path = zip_file.name().to_string();

        // CRITICAL SECURITY: Validate path through jail - prevents zip slip
        match extraction_jail.jailed_join(&entry_path) {
            Ok(safe_path) => {
                progress.set_message(format!("Extracting: {entry_path}"));

                if zip_file.is_dir() {
                    safe_path.create_dir_all()?;
                    stats.directories_created += 1;
                    if cli.verbose {
                        println!("📁 Created directory: {entry_path}");
                    }
                } else {
                    // Create parent directories
                    safe_path.create_parent_dir_all()?;

                    // Extract file content
                    let mut content = Vec::new();
                    zip_file.read_to_end(&mut content)?;

                    safe_path.write_bytes(&content)?;
                    stats.files_extracted += 1;
                    stats.total_bytes += content.len() as u64;

                    if cli.verbose {
                        println!("📄 Extracted: {} ({} bytes)", entry_path, content.len());
                    }
                }
            }
            Err(_) => {
                // Path validation failed - likely a zip slip attempt
                stats.blocked_paths.push(entry_path.clone());
                if cli.verbose {
                    println!("🚫 Blocked malicious path: {entry_path}");
                }
            }
        }

        progress.inc(1);
    }

    progress.finish_with_message("Extraction complete");
    Ok(stats)
}

fn extract_tar(
    archive_path: &JailedPath<ArchiveInput>,
    extraction_jail: &Jail<ExtractionOutput>,
    cli: &Cli,
) -> Result<ExtractionStats, Box<dyn std::error::Error>> {
    let file = File::open(archive_path.interop_path())?;
    let mut archive = tar::Archive::new(file);

    extract_tar_entries(archive.entries()?, extraction_jail, cli)
}

fn extract_tar_gz(
    archive_path: &JailedPath<ArchiveInput>,
    extraction_jail: &Jail<ExtractionOutput>,
    cli: &Cli,
) -> Result<ExtractionStats, Box<dyn std::error::Error>> {
    let file = File::open(archive_path.interop_path())?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);

    extract_tar_entries(archive.entries()?, extraction_jail, cli)
}

fn extract_tar_entries<R: Read>(
    entries: tar::Entries<R>,
    extraction_jail: &Jail<ExtractionOutput>,
    cli: &Cli,
) -> Result<ExtractionStats, Box<dyn std::error::Error>> {
    let mut stats = ExtractionStats {
        files_extracted: 0,
        directories_created: 0,
        total_bytes: 0,
        blocked_paths: Vec::new(),
    };

    for entry in entries {
        if stats.files_extracted >= cli.max_files {
            println!("\n⚠️  Reached maximum file limit ({})", cli.max_files);
            break;
        }

        if stats.total_bytes > cli.max_size_mb * 1_048_576 {
            println!("\n⚠️  Reached maximum size limit ({} MB)", cli.max_size_mb);
            break;
        }

        let mut entry = entry?;
        let entry_path = entry.path()?.to_string_lossy().to_string();

        // CRITICAL SECURITY: Validate path through jail - prevents tar slip
        match extraction_jail.jailed_join(&entry_path) {
            Ok(safe_path) => {
                let header = entry.header();

                if header.entry_type().is_dir() {
                    safe_path.create_dir_all()?;
                    stats.directories_created += 1;
                    if cli.verbose {
                        println!("📁 Created directory: {entry_path}");
                    }
                } else if header.entry_type().is_file() {
                    // Create parent directories
                    safe_path.create_parent_dir_all()?;

                    // Extract file content
                    let mut content = Vec::new();
                    entry.read_to_end(&mut content)?;

                    safe_path.write_bytes(&content)?;
                    stats.files_extracted += 1;
                    stats.total_bytes += content.len() as u64;

                    if cli.verbose {
                        println!("📄 Extracted: {} ({} bytes)", entry_path, content.len());
                    }
                }
            }
            Err(_) => {
                // Path validation failed - likely a tar slip attempt
                stats.blocked_paths.push(entry_path.clone());
                if cli.verbose {
                    println!("🚫 Blocked malicious path: {entry_path}");
                }
            }
        }
    }

    Ok(stats)
}



