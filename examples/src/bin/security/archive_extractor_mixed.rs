// Enhanced archive_extractor: clap + serde config validation
use clap::{Parser, ValueEnum};
use serde::de::DeserializeSeed;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use strict_path::{serde_ext::WithVirtualRoot, VirtualPath, VirtualRoot};

// Type marker for extraction context
#[derive(Clone, Default)]
struct ExtractionOutput;

// Raw configuration file structure (untrusted string paths)
#[derive(Deserialize)]
struct RawExtractorConfig {
    /// Default output directory from config (raw string)
    default_output: Option<String>,

    /// Security limits from config
    max_files: Option<usize>,
    max_size_mb: Option<u64>,

    /// Allowed extraction targets (raw strings)
    allowed_outputs: Option<Vec<String>>,
}

// Safe configuration structure (validated paths)
struct SafeExtractorConfig {
    /// Default output directory (validated VirtualPath)
    default_output: Option<VirtualPath<ExtractionOutput>>,

    /// Security limits from config
    max_files: Option<usize>,
    max_size_mb: Option<u64>,

    /// Allowed extraction targets (validated VirtualPaths)
    allowed_outputs: Option<Vec<VirtualPath<ExtractionOutput>>>,
}

#[derive(Parser)]
#[command(name = "secure-extract")]
#[command(about = "Archive extractor with clap + serde config validation")]
struct Cli {
    /// Archive file to extract
    #[arg(short, long)]
    archive: PathBuf,

    /// Output directory (overrides config file)
    #[arg(short, long)]
    output: Option<VirtualRoot<ExtractionOutput>>,

    /// Configuration file with default settings and validation rules
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Archive format (auto-detected if not specified)
    #[arg(short, long)]
    format: Option<ArchiveFormat>,

    /// Maximum number of files (overrides config)
    #[arg(long)]
    max_files: Option<usize>,

    /// Maximum total size in MB (overrides config)
    #[arg(long)]
    max_size_mb: Option<u64>,

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

struct ExtractionSettings {
    output_root: VirtualRoot<ExtractionOutput>,
    max_files: usize,
    max_size_mb: u64,
}

fn load_and_validate_config(
    config_path: &Path,
) -> Result<SafeExtractorConfig, Box<dyn std::error::Error>> {
    let config_str = std::fs::read_to_string(config_path)?;

    // First deserialize to raw config (untrusted strings)
    let raw_config: RawExtractorConfig = serde_json::from_str(&config_str)?;

    // Convert default_output from String to VirtualPath using serde
    let safe_default_output = if let Some(default_output_str) = &raw_config.default_output {
        // Create boundary for the default output
        let boundary = strict_path::PathBoundary::try_new_create(default_output_str)?;
        let vroot = boundary.virtualize();

        // Use serde to deserialize the string INTO a VirtualPath!
        let json_str = format!("\"{}\"", default_output_str);
        let mut de = serde_json::Deserializer::from_str(&json_str);
        let validated_path: VirtualPath<ExtractionOutput> = WithVirtualRoot(&vroot)
            .deserialize(&mut de)
            .map_err(|e| format!("Invalid default output '{}': {}", default_output_str, e))?;

        println!(
            "✅ Deserialized default_output to VirtualPath: {}",
            validated_path.virtualpath_display()
        );
        Some(validated_path)
    } else {
        None
    };

    // Convert allowed_outputs from Vec<String> to Vec<VirtualPath> using serde
    let safe_allowed_outputs = if let Some(allowed_outputs_strs) = &raw_config.allowed_outputs {
        let mut validated_outputs = Vec::new();

        for output_str in allowed_outputs_strs {
            // Create boundary for this allowed output
            let boundary = strict_path::PathBoundary::try_new_create(output_str)?;
            let vroot = boundary.virtualize();

            // Use serde to deserialize the string INTO a VirtualPath!
            let json_str = format!("\"{}\"", output_str);
            let mut de = serde_json::Deserializer::from_str(&json_str);
            let validated_path: VirtualPath<ExtractionOutput> = WithVirtualRoot(&vroot)
                .deserialize(&mut de)
                .map_err(|e| format!("Invalid allowed output '{}': {}", output_str, e))?;

            println!(
                "✅ Deserialized allowed_output to VirtualPath: {}",
                validated_path.virtualpath_display()
            );
            validated_outputs.push(validated_path);
        }

        Some(validated_outputs)
    } else {
        None
    };

    // Return safe config with actual VirtualPath types!
    Ok(SafeExtractorConfig {
        default_output: safe_default_output,
        max_files: raw_config.max_files,
        max_size_mb: raw_config.max_size_mb,
        allowed_outputs: safe_allowed_outputs,
    })
}

fn resolve_extraction_settings(
    cli: &Cli,
) -> Result<ExtractionSettings, Box<dyn std::error::Error>> {
    // Load config file if provided (now returns SafeExtractorConfig with VirtualPath types!)
    let config = if let Some(config_path) = &cli.config {
        Some(load_and_validate_config(config_path)?)
    } else {
        None
    };

    // Resolve output directory (CLI > config > default)
    let output_root = if let Some(cli_output) = &cli.output {
        // CLI argument takes precedence
        cli_output.clone()
    } else if let Some(config) = &config {
        if let Some(default_output_vpath) = &config.default_output {
            // Config already has a VirtualPath! Get its VirtualRoot
            println!(
                "📋 Using config default output: {}",
                default_output_vpath.virtualpath_display()
            );
            // VirtualPath<ExtractionOutput> -> VirtualRoot<ExtractionOutput>
            VirtualRoot::try_new_create(default_output_vpath.interop_path())?
        } else {
            VirtualRoot::try_new_create("./extracted")?
        }
    } else {
        VirtualRoot::try_new_create("./extracted")?
    };

    // Resolve limits (CLI > config > defaults)
    let max_files = cli
        .max_files
        .or(config.as_ref().and_then(|c| c.max_files))
        .unwrap_or(10000);

    let max_size_mb = cli
        .max_size_mb
        .or(config.as_ref().and_then(|c| c.max_size_mb))
        .unwrap_or(1000);

    // Validate output against allowed outputs if configured
    if let Some(config) = &config {
        if let Some(allowed_outputs) = &config.allowed_outputs {
            let output_path = output_root.interop_path().to_string_lossy();
            let is_allowed = allowed_outputs.iter().any(|allowed_vpath| {
                // Now comparing against VirtualPath types, not strings!
                let allowed_path = allowed_vpath.interop_path().to_string_lossy();
                output_path.starts_with(&*allowed_path)
            });

            if !is_allowed {
                let allowed_displays: Vec<_> = allowed_outputs
                    .iter()
                    .map(|vp| vp.virtualpath_display().to_string())
                    .collect();
                return Err(format!(
                    "Output directory '{}' not in allowed outputs: {:?}",
                    output_path, allowed_displays
                )
                .into());
            }

            println!(
                "🛡️  Output validated against {} allowed VirtualPath outputs",
                allowed_outputs.len()
            );
        }
    }

    Ok(ExtractionSettings {
        output_root,
        max_files,
        max_size_mb,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    println!("🔒 Secure Archive Extractor (Clap + Serde Config)");
    println!("Archive: {}", cli.archive.display());

    // Validate archive exists
    if !cli.archive.exists() {
        return Err(format!("Archive file not found: {}", cli.archive.display()).into());
    }

    // Load settings from CLI + config file with serde validation
    let settings = resolve_extraction_settings(&cli)?;

    println!("Output: {}", settings.output_root);
    println!(
        "Security limits: {} files, {} MB",
        settings.max_files, settings.max_size_mb
    );

    // Detect format
    let format = cli
        .format
        .unwrap_or_else(|| detect_archive_format(&cli.archive).unwrap_or(ArchiveFormat::Zip));
    println!("Format: {format:?}");
    println!();

    // Extract (simplified - would use the existing extraction logic)
    println!("✅ Extraction completed with validated settings!");

    // Example config file that works with this system
    if cli.config.is_none() {
        println!("\n📄 Example config file (config.json):");
        println!(
            "{{{{
    \"default_output\": \"/tmp/extractions\",
    \"max_files\": 5000,
    \"max_size_mb\": 500,
    \"allowed_outputs\": [
        \"/tmp/extractions\",
        \"/home/user/safe-extractions\",
        \"./local-extractions\"
    ]
}}}}"
        );
        println!("\nUsage: --config config.json");
    }

    Ok(())
}

fn detect_archive_format(path: impl AsRef<Path>) -> Option<ArchiveFormat> {
    let path_lower = path.as_ref().to_string_lossy().to_lowercase();
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
