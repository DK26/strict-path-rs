//! An example of a safe archive extractor that uses a jail to prevent
//! "zip slip" vulnerabilities. A zip slip vulnerability occurs when a
//! malicious archive contains entries with traversal paths (e.g., `../../evil.sh`)
//! that, when extracted, would write files outside the intended extraction directory.
//!
//! This example demonstrates how `jailed-path` can be used to safely handle
//! archive entries, ensuring that all extracted files are contained within
//! the designated jail.

use anyhow::Result;
use jailed_path::Jail;
use std::fs;
use std::io::{self, Write};
use zip::ZipArchive;

// --- Marker Type for the Extraction Context ---

/// Marker for the archive extraction jail.
#[derive(Clone)]
struct Extraction;

// --- Archive Extraction Logic ---

/// Safely extracts a zip archive to the specified directory.
///
/// # Arguments
/// * `archive_path` - The path to the zip archive to extract.
/// * `extract_dir` - The directory where the archive contents should be extracted.
///
/// # Returns
/// An `io::Result` indicating the success or failure of the extraction.
fn safe_extract(archive_path: &str, extract_dir: &str) -> Result<()> {
    println!("[Extractor] Extracting '{archive_path}' to '{extract_dir}'");

    // 1. Create the jail for the extraction directory.
    let jail = Jail::<Extraction>::try_new_create(extract_dir)?;

    // 2. Open the archive.
    let archive_file = fs::File::open(archive_path)?;
    let mut archive = ZipArchive::new(archive_file)?;

    // 3. Iterate over each entry in the archive.
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let entry_name = entry.name().to_string();

        // 4. Validate the entry's path against the jail.
        // This is the crucial security step. Any traversal paths will be
        // neutralized here.
        let safe_path = match jail.systempath_join(&entry_name) {
            Ok(path) => path,
            Err(e) => {
                println!("  -> Skipping malicious or invalid path: {entry_name} ({e})");
                continue;
            }
        };

        println!("  -> Processing: {safe_path}");

        // 5. Handle directories and files.
        if entry.is_dir() {
            // It's a directory, so create it.
            safe_path.create_dir_all()?;
        } else {
            // It's a file; ensure the parent directory exists (recursive)
            safe_path.create_parent_dir_all()?;

            // Create the file and write the entry's content to it.
            // Prefer passing &OsStr (implements AsRef<Path>) instead of taking ownership.
            let mut outfile = fs::File::create(safe_path.systempath_as_os_str())?;
            io::copy(&mut entry, &mut outfile)?;
        }
    }

    println!("[Extractor] Extraction complete.");
    Ok(())
}

// --- Main Simulation ---

/// Creates a dummy zip archive for testing purposes.
///
/// The archive will contain:
/// - A legitimate file: `data/file.txt`
/// - A malicious file with a traversal path: `../../evil.txt`
fn create_test_archive(archive_path: &str) -> Result<()> {
    let file = fs::File::create(archive_path)?;
    let mut zip = zip::ZipWriter::new(file);

    let options: zip::write::FileOptions<()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);

    // Add a legitimate file.
    zip.start_file("data/file.txt", options)?;
    zip.write_all(b"This is a safe file.")?;

    // Add a malicious file.
    zip.start_file("../../evil.txt", options)?;
    zip.write_all(b"This should not be written outside the extraction dir.")?;

    zip.finish()?;
    Ok(())
}

fn main() -> Result<()> {
    let archive_path = "test_archive.zip";
    let extract_dir = "extracted_files";

    // --- Setup: Create the test archive ---
    create_test_archive(archive_path)?;

    println!("--- Safe Archive Extractor Simulation ---");

    // --- Run the safe extraction process ---
    if let Err(e) = safe_extract(archive_path, extract_dir) {
        eprintln!("Error during extraction: {e}");
    }

    println!("--- Simulation Complete ---");

    // --- Verification ---
    // Check that the legitimate file was created.
    let safe_file_path = format!("{extract_dir}/data/file.txt");
    if fs::metadata(&safe_file_path).is_ok() {
        println!("[Verify] OK: Safe file was created at '{safe_file_path}'.");
    } else {
        eprintln!("[Verify] FAIL: Safe file was NOT created at '{safe_file_path}'.");
    }

    // Check that the malicious file was NOT created at the root.
    let evil_file_path = "evil.txt";
    if fs::metadata(evil_file_path).is_err() {
        println!("[Verify] OK: Malicious file was not created at the root.");
    } else {
        eprintln!("[Verify] FAIL: Malicious file was created at '{evil_file_path}'.");
    }

    // --- Cleanup ---
    fs::remove_file(archive_path).ok();
    fs::remove_dir_all(extract_dir).ok();
    Ok(())
}



