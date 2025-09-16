//! Ingest-and-Copy CLI (Manifest-driven)
//!
//! Demonstrates copying files from a local staging area into a restricted
//! workspace using an untrusted manifest of relative paths. This models a
//! realistic scenario where the list of files comes from an external/third-party
//! system (downloaded manifest, job queue, etc.). We validate each manifest
//! entry into StrictPath values for both the source (staging) and destination
//! (workspace) to prevent directory traversal.

use std::env;
use strict_path::PathBoundary;

#[derive(Clone)]
struct Staging;
#[derive(Clone)]
struct Workspace;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 4 {
        println!(
            "Usage: {} <staging_dir> <workspace_dir> <manifest.txt>",
            args[0]
        );
        println!("No args provided — running offline demo setup...\n");

        // Offline demo: create a tiny staging area + manifest
        let staging_dir = "./demo_staging";
        let workspace_dir = "./demo_workspace";
        let manifest_file = "./demo_manifest.txt";

        std::fs::create_dir_all(format!("{staging_dir}/docs"))?;
        std::fs::create_dir_all(format!("{staging_dir}/images"))?;
        std::fs::write(format!("{staging_dir}/docs/readme.md"), b"# Hello\n")?;
        std::fs::write(format!("{staging_dir}/images/logo.png"), b"PNG")?;

        // The manifest is considered untrusted (could contain attempts like ../../etc/passwd)
        std::fs::write(
            manifest_file,
            b"docs/readme.md\nimages/logo.png\n../../etc/passwd\n",
        )?;

        run_ingest(staging_dir, workspace_dir, manifest_file)?;
        println!("\nDemo complete. Inspect '{workspace_dir}' and then cleanup:");
        println!("  rm -rf demo_staging demo_workspace demo_manifest.txt");
        return Ok(());
    }

    let staging_dir = &args[1];
    let workspace_dir = &args[2];
    let manifest_file = &args[3];
    run_ingest(staging_dir, workspace_dir, manifest_file)
}

fn run_ingest(
    staging_dir: &str,
    workspace_dir: &str,
    manifest_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔒 Ingesting manifest of files into restricted workspace\n");

    // Set up secure boundaries
    let staging: PathBoundary<Staging> = PathBoundary::try_new_create(staging_dir)?;
    let workspace: PathBoundary<Workspace> = PathBoundary::try_new_create(workspace_dir)?;

    println!("Staging:   {}", staging.strictpath_display());
    println!("Workspace: {}", workspace.strictpath_display());

    // Load untrusted manifest (list of relative paths)
    let manifest = std::fs::read_to_string(manifest_file)?;
    let mut copied = 0usize;
    let mut blocked = 0usize;

    for (i, line) in manifest.lines().enumerate() {
        let entry = line.trim();
        if entry.is_empty() {
            continue;
        }

        // Validate entry for both source and destination
        let source = match staging.strict_join(entry) {
            Ok(p) => p,
            Err(e) => {
                println!("{i:>4}: 🚫 Invalid source '{entry}': {e}");
                blocked += 1;
                continue;
            }
        };

        let dest = match workspace.strict_join(entry) {
            Ok(p) => p,
            Err(e) => {
                println!("{i:>4}: 🚫 Invalid destination '{entry}': {e}");
                blocked += 1;
                continue;
            }
        };

        if source.is_dir() {
            // Create directory in workspace
            dest.create_dir_all()?;
            println!("{i:>4}: 📁 Dir  -> {}", dest.strictpath_display());
            continue;
        }

        if source.is_file() {
            // Copy file contents using built-in helpers
            dest.create_parent_dir_all()?;
            let bytes = source.read_bytes()?;
            dest.write_bytes(&bytes)?;
            copied += 1;
            println!(
                "{i:>4}: 📄 File -> {} ({} bytes)",
                dest.strictpath_display(),
                bytes.len()
            );
            continue;
        }

        println!(
            "{i:>4}: ⚠️  Skipped unknown entry type: {}",
            source.strictpath_display()
        );
    }

    println!("\n✅ Done. Copied: {copied}, Blocked: {blocked}");
    Ok(())
}
