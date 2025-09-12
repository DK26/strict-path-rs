//! An example of a temporary file manager that creates and manages files
//! within a securely jailed temporary directory. This is useful for applications
//! that need to process data in temporary files without risking writing to
//! sensitive locations.

use anyhow::Result;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use strict_path::{PathBoundary, StrictPath};

// --- Marker Type for the Temporary Directory ---

/// Marker for the temporary files PathBoundary.
struct TempFiles;

// --- Temporary File Manager Logic ---

/// Manages temporary files within a secure PathBoundary.
struct TempFileManager {
    temp_dir: PathBoundary<TempFiles>,
}

impl TempFileManager {
    /// Creates a new `TempFileManager` with a unique, jailed temporary directory.
    pub fn new() -> Result<Self> {
        let temp_dir = std::env::temp_dir().join(format!(
            "my_app_temp_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));

        let temp_dir_boundary = PathBoundary::<TempFiles>::try_new_create(temp_dir)
            .map_err(|e| anyhow::anyhow!("PathBoundary error: {e}"))?;

        println!(
            "[TempManager] Created temporary PathBoundary at: {}",
            temp_dir_boundary.strictpath_display()
        );
        Ok(Self { temp_dir: temp_dir_boundary })
    }

    /// Creates a new temporary file with the given content.
    pub fn new_temp_file(&self, file_name: &str, content: &str) -> Result<StrictPath<TempFiles>> {
        println!("[TempManager] Creating temp file: {file_name}");

        let temp_path = self
            .temp_dir
            .strict_join(file_name)
            .map_err(|e| anyhow::anyhow!("PathBoundary error: {e}"))?;

        temp_path.write_string(content)?;

        println!(
            "  -> Wrote {} bytes to {}",
            content.len(),
            temp_path.strictpath_display()
        );
        Ok(temp_path)
    }

    /// Cleans up the entire temporary directory.
    pub fn cleanup(&self) -> Result<()> {
        println!("[TempManager] Cleaning up temporary directory...");
        fs::remove_dir_all(self.temp_dir.interop_path())?;
        Ok(())
    }
}

// --- Main Simulation ---

fn main() -> Result<()> {
    println!("--- Temporary File Manager Simulation ---");

    // --- Create and use the manager ---
    let temp_manager = TempFileManager::new()?;

    // --- Create some temporary files ---
    let file1 = temp_manager.new_temp_file("session_data.json", "{ \"user_id\": 123 }")?;
    let file2 = temp_manager.new_temp_file("upload.tmp", "some binary data")?;

    // --- Verify files were created ---
    if file1.exists() && file2.exists() {
        println!("[Verify] OK: Both temporary files exist.");
    } else {
        eprintln!("[Verify] FAIL: One or more temporary files were not created.");
    }

    // --- Attempt to create a file outside the PathBoundary (will be contained) ---
    // This demonstrates that even with a traversal path, the file is created
    // safely inside the PathBoundary.
    let malicious_path_str = "../../../important_system_file.txt";
    println!("[TempManager] Attempting to create a malicious file at: {malicious_path_str}");
    match temp_manager.new_temp_file(malicious_path_str, "malicious content") {
        Ok(contained_path) => {
            println!(
                "  -> Contained path: {}",
                contained_path.strictpath_display()
            );
            if contained_path.strictpath_starts_with(temp_manager.temp_dir.interop_path()) {
                println!("[Verify] OK: Malicious path was successfully contained within the PathBoundary.");
            } else {
                eprintln!("[Verify] FAIL: Malicious path escaped the PathBoundary.");
            }
        }
        Err(e) => {
            eprintln!("  -> Error creating malicious file: {e}");
        }
    }

    println!("---------------------------------");

    // --- Clean up ---
    temp_manager.cleanup()?;
    if !temp_manager.temp_dir.exists() {
        println!("[Verify] OK: Temporary directory successfully removed.");
    } else {
        eprintln!("[Verify] FAIL: Temporary directory was not removed.");
    }

    println!("--- Simulation Complete ---");

    Ok(())
}
