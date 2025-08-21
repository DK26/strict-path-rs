use anyhow::Result;
use jailed_path::{Jail, JailedPath};
use std::fs;

// --- Marker Types for Different Data Contexts //
// By using unique, empty structs, we can create distinct `JailedPath` types
// at compile time. This prevents accidental mixing of paths from different jails.

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
                assert!(stored_path.is_file());
            }
            Err(e) => {
                println!("  -> Error: {e}");
            }
        }
    }
    println!("\n--- Processing Complete ---");

    // --- Verification //
    // Let's try to call a function with the wrong type of JailedPath.
    // This demonstrates the compile-time safety.
    let _stored_file = storage_jail.try_path("user1_config.txt.processed").unwrap();

    // The following line would cause a compile error because `archive_ingested_file`
    // expects a `JailedPath<Ingest>`, but we are giving it a `JailedPath<Storage>`.
    // archive_ingested_file(&stored_file).unwrap_err();
    println!("\nDemonstrated compile-time safety (see code comments).");

    // Cleanup
    fs::remove_dir_all("data")?;

    Ok(())
}

/// Processes a file from the ingest jail and stores it in the storage jail.
fn process_and_store_data(
    ingest_jail: &Jail<Ingest>,
    storage_jail: &Jail<Storage>,
    file_name: &str,
) -> Result<JailedPath<Storage>> {
    // 1. Get a safe path in the ingest jail.
    let ingest_path = ingest_jail
        .try_path(file_name)
        .map_err(|e| anyhow::anyhow!("Jail error: {e}"))?;
    println!("  -> Validated ingest path: {ingest_path}");

    // 2. Read the data (simulating processing).
    let data = ingest_path.read_to_string()?;
    let processed_data = format!("[PROCESSED] {data}\n");

    // 3. Create a safe path in the storage jail for the output.
    let stored_file_name = format!("{file_name}.processed");
    let storage_path = storage_jail
        .try_path(stored_file_name)
        .map_err(|e| anyhow::anyhow!("Jail error: {e}"))?;
    println!("  -> Target storage path: {storage_path}");

    // 4. Write the processed data to the storage jail.
    storage_path.write_string(&processed_data)?;

    // 5. Archive the original file (demonstrates using a function with a specific marker).
    archive_ingested_file(&ingest_path)?;

    Ok(storage_path)
}

/// This function will ONLY accept paths that have been validated by the `Ingest` jail.
fn archive_ingested_file(path_to_archive: &JailedPath<Ingest>) -> Result<()> {
    let archive_name = path_to_archive
        .with_extension_real("archived")
        .map_err(|e| anyhow::anyhow!("Jail error: {e}"))?;

    println!("  -> Archiving ingest file to: {archive_name}");
    fs::rename(
        path_to_archive.realpath_to_string(),
        archive_name.realpath_to_string(),
    )?;
    Ok(())
}
