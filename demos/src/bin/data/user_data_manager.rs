use anyhow::Result;
use std::fs;
use strict_path::{PathBoundary, StrictPath};

// --- Marker Types for Different Data Contexts //
/// Marker for user-provided data that needs processing.
#[derive(Clone)]
struct Ingest;

/// Marker for data that has been processed and stored securely.
struct Storage;

fn main() -> Result<()> {
    // --- Setup: Create directories for our data pipeline //
    fs::create_dir_all("data/ingest")?;
    fs::create_dir_all("data/storage")?;

    // Create some dummy user files to be processed.
    fs::write("data/ingest/user1_config.txt", "config_data_1")?;
    fs::write("data/ingest/user2_report.pdf", "report_data_2")?;

    // --- Security Setup: Create jails for each stage of the pipeline //
    let ingest_dir = PathBoundary::<Ingest>::try_new("data/ingest")
        .map_err(|e| anyhow::anyhow!("PathBoundary error: {e}"))?;

    let storage_dir = PathBoundary::<Storage>::try_new("data/storage")
        .map_err(|e| anyhow::anyhow!("PathBoundary error: {e}"))?;

    // --- Discover files to process from the ingest jail (external FS input) //
    // Use strict_read_dir() directly on PathBoundary for auto-validated StrictPath entries.
    println!("--- Starting User Data Processing ---");
    for entry in ingest_dir.strict_read_dir()? {
        // strict_read_dir returns StrictPath entries directly - no manual re-validation needed!
        let ingest_file = entry?;
        if !ingest_file.is_file() {
            continue;
        }
        let file_name = ingest_file.strictpath_file_name().unwrap_or_default();
        let fname_disp = file_name.to_string_lossy();
        println!("\nProcessing: {fname_disp}");
        match process_and_store_data(&ingest_file, &storage_dir) {
            Ok(stored_path) => {
                let disp = stored_path.strictpath_display();
                println!("  -> Successfully processed and stored at: {disp}");
                // Use try_exists() for fallible check (distinguishes permission errors)
                match stored_path.try_exists() {
                    Ok(true) => println!("  -> Verified file exists"),
                    Ok(false) => println!("  -> Warning: file not found"),
                    Err(e) => println!("  -> Permission error: {e}"),
                }
            }
            Err(e) => {
                println!("  -> Error: {e}");
            }
        }
    }
    println!("\n--- Processing Complete ---");

    // --- Verification //
    let _stored_file = storage_dir
        .strict_join("user1_config.txt.processed")
        .unwrap();

    println!("\nDemonstrated compile-time safety (see code comments).");

    // Cleanup
    fs::remove_dir_all("data")?;

    Ok(())
}

fn process_and_store_data(
    ingest_path: &StrictPath<Ingest>, // Already validated by strict_read_dir!
    storage_dir: &PathBoundary<Storage>,
) -> Result<StrictPath<Storage>> {
    // Path already validated by strict_read_dir - no re-validation needed
    let ingest_disp = ingest_path.strictpath_display();
    println!("  -> Processing validated path: {ingest_disp}");
    // Get filename for storage path
    let file_name = ingest_path
        .strictpath_file_name()
        .ok_or_else(|| anyhow::anyhow!("No filename"))?;

    let data = ingest_path.read_to_string()?;
    let processed_data = format!("[PROCESSED] {data}\n");

    // Create target path by joining the original file name and changing its extension
    let storage_path = storage_dir
        .strict_join(file_name)
        .map_err(|e| anyhow::anyhow!("PathBoundary error: {e}"))?
        .strictpath_with_extension("processed")
        .map_err(|e| anyhow::anyhow!("PathBoundary error: {e}"))?;
    let storage_disp = storage_path.strictpath_display();
    println!("  -> Target storage path: {storage_disp}");

    storage_path.write(&processed_data)?;

    archive_ingested_file(ingest_path)?;

    Ok(storage_path)
}

fn archive_ingested_file(path_to_archive: &StrictPath<Ingest>) -> Result<()> {
    let archive_name = path_to_archive
        .strictpath_with_extension("archived")
        .map_err(|e| anyhow::anyhow!("PathBoundary error: {e}"))?;

    let arch_disp = archive_name.strictpath_display();
    println!("  -> Archiving ingest file to: {arch_disp}");
    // strict_rename validates the destination path stays within boundary.
    // We pass interop_path() because strict_rename expects AsRef<Path>.
    path_to_archive.strict_rename(archive_name.interop_path())?;
    Ok(())
}
