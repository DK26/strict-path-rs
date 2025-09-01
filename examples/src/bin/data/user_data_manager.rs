use anyhow::Result;
use jailed_path::{Jail, JailedPath};
use std::fs;

// --- Marker Types for Different Data Contexts //
/// Marker for user-provided data that needs processing.
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
    let ingest_jail =
        Jail::<Ingest>::try_new("data/ingest").map_err(|e| anyhow::anyhow!("Jail error: {e}"))?;

    let storage_jail =
        Jail::<Storage>::try_new("data/storage").map_err(|e| anyhow::anyhow!("Jail error: {e}"))?;

    // --- Simulate Processing User Files //
    let user_files_to_process = ["user1_config.txt", "user2_report.pdf"];

    println!("--- Starting User Data Processing ---");
    for file_name in &user_files_to_process {
        println!("\nProcessing: {file_name}");
        match process_and_store_data(&ingest_jail, &storage_jail, file_name) {
            Ok(stored_path) => {
                println!("  -> Successfully processed and stored at: {stored_path}");
                if stored_path.is_file() { println!("  -> Verified file exists"); }
            }
            Err(e) => {
                println!("  -> Error: {e}");
            }
        }
    }
    println!("\n--- Processing Complete ---");

    // --- Verification //
    let _stored_file = storage_jail.systempath_join("user1_config.txt.processed").unwrap();

    println!("\nDemonstrated compile-time safety (see code comments).");

    // Cleanup
    fs::remove_dir_all("data")?;

    Ok(())
}

fn process_and_store_data(
    ingest_jail: &Jail<Ingest>,
    storage_jail: &Jail<Storage>,
    file_name: &str,
) -> Result<JailedPath<Storage>> {
    let ingest_path = ingest_jail
        .systempath_join(file_name)
        .map_err(|e| anyhow::anyhow!("Jail error: {e}"))?;
    println!("  -> Validated ingest path: {ingest_path}");

    let data = ingest_path.read_to_string()?;
    let processed_data = format!("[PROCESSED] {data}\n");

    let stored_file_name = format!("{file_name}.processed");
    let storage_path = storage_jail
        .systempath_join(stored_file_name)
        .map_err(|e| anyhow::anyhow!("Jail error: {e}"))?;
    println!("  -> Target storage path: {storage_path}");

    storage_path.write_string(&processed_data)?;

    archive_ingested_file(&ingest_path)?;

    Ok(storage_path)
}

fn archive_ingested_file(path_to_archive: &JailedPath<Ingest>) -> Result<()> {
    let archive_name = path_to_archive
        .systempath_with_extension("archived")
        .map_err(|e| anyhow::anyhow!("Jail error: {e}"))?;

    println!("  -> Archiving ingest file to: {archive_name}");
    fs::rename(
        path_to_archive.systempath_as_os_str(),
        archive_name.systempath_as_os_str(),
    )?;
    Ok(())
}



