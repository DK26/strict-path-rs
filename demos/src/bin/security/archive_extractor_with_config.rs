// Example: Archive extractor with serde config validation
use clap::Parser;
use serde::Deserialize;
use std::collections::HashMap;
use strict_path::VirtualRoot;

#[derive(Clone, Default)]
struct ExtractionOutput;

// Raw config structure (untrusted paths)
#[derive(Deserialize)]
struct RawConfig {
    extraction_profiles: HashMap<String, RawExtractionProfile>,
}

#[derive(Deserialize)]
struct RawExtractionProfile {
    base_dir: String, // Untrusted path from config
    allowed_patterns: Vec<String>,
    max_files: usize,
    max_size_mb: u64,
}

// Safe config structure (validated paths)
struct SafeConfig {
    extraction_profiles: HashMap<String, SafeExtractionProfile>,
}

struct SafeExtractionProfile {
    base_dir: VirtualRoot<ExtractionOutput>, // Validated safe root directory
    allowed_patterns: Vec<String>,
    max_files: usize,
    max_size_mb: u64,
}

impl SafeConfig {
    /// Load and validate config from JSON/TOML
    fn from_config_str(config_str: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let raw: RawConfig = serde_json::from_str(config_str)?;

        let mut safe_profiles = HashMap::new();

        for (name, raw_profile) in raw.extraction_profiles {
            // Create and validate the base directory as a VirtualRoot
            let safe_base_dir: VirtualRoot<ExtractionOutput> = raw_profile.base_dir.parse()?;

            let safe_profile = SafeExtractionProfile {
                base_dir: safe_base_dir,
                allowed_patterns: raw_profile.allowed_patterns,
                max_files: raw_profile.max_files,
                max_size_mb: raw_profile.max_size_mb,
            };

            safe_profiles.insert(name, safe_profile);
        }

        Ok(SafeConfig {
            extraction_profiles: safe_profiles,
        })
    }
}

#[derive(Parser)]
#[command(name = "secure-extract")]
#[command(about = "Archive extractor with configuration profiles")]
struct Cli {
    /// Archive file to extract
    archive: std::path::PathBuf,

    /// Configuration file with extraction profiles
    #[arg(short, long)]
    config: Option<std::path::PathBuf>,

    /// Extraction profile to use (from config)
    #[arg(short, long, default_value = "default")]
    profile: String,

    /// Override output directory (uses VirtualRoot FromStr we kept)
    #[arg(short, long)]
    output: Option<VirtualRoot<ExtractionOutput>>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    println!("🔒 Secure Archive Extractor with Config");

    // Load configuration if provided
    let config = if let Some(config_path) = &cli.config {
        let config_str = std::fs::read_to_string(config_path)?;
        Some(SafeConfig::from_config_str(&config_str)?)
    } else {
        None
    };

    // Determine extraction settings
    let extraction_root = if let Some(override_output) = cli.output {
        // User provided direct output via clap (uses our VirtualRoot FromStr)
        override_output
    } else if let Some(config) = &config {
        // Use profile from config (paths already validated via serde)
        let profile = config
            .extraction_profiles
            .get(&cli.profile)
            .ok_or_else(|| format!("Profile '{}' not found in config", cli.profile))?;

        println!(
            "Using profile '{}' with {} allowed patterns",
            cli.profile,
            profile.allowed_patterns.len()
        );
        println!(
            "Max files: {}, Max size: {}MB",
            profile.max_files, profile.max_size_mb
        );

        // Use the VirtualRoot from config
        profile.base_dir.clone()
    } else {
        // Default: current directory
        let boundary = strict_path::PathBoundary::try_new(".")?;
        boundary.virtualize()
    };

    println!("Extraction root: {}", extraction_root);

    // Example config JSON that would work:
    let example_config = r#"
    {
        "extraction_profiles": {
            "default": {
                "base_dir": "/tmp/extractions",
                "allowed_patterns": ["*.txt", "*.md"],
                "max_files": 1000,
                "max_size_mb": 100
            },
            "secure": {
                "base_dir": "/var/secure/extractions",
                "allowed_patterns": ["*.log"],
                "max_files": 100,
                "max_size_mb": 10
            }
        }
    }
    "#;

    println!("\nExample config file:");
    println!("{}", example_config);

    Ok(())
}
