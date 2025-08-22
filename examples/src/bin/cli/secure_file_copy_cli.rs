//! A command-line tool that securely copies files from various sources
//! into a designated "safe" directory. This example demonstrates how to
//! handle command-line arguments and use a jail to ensure that all file
//! write operations are contained within a secure boundary.

use jailed_path::{Jail, JailedPath};
use std::env;
use std::fs;
use std::io;
use std::path::Path;

// --- Marker Type for the Safe Directory ---

/// Marker for the destination directory jail.
#[derive(Clone)]
struct SafeDestination;

// --- File Copy Logic ---

/// Securely copies a file to a destination directory.
///
/// # Arguments
/// * `source_path` - The path to the source file.
/// * `dest_jail` - The jail representing the safe destination directory.
///
/// # Returns
/// An `io::Result` containing the `JailedPath` of the copied file on success.
fn secure_copy(
    source_path: &Path,
    dest_jail: &Jail<SafeDestination>,
) -> io::Result<JailedPath<SafeDestination>> {
    if !source_path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "Source file not found or is not a file: {}",
                source_path.display()
            ),
        ));
    }

    // Get the file name from the source path.
    let file_name = source_path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "Source path has no file name.")
    })?;

    println!("[Copy] Preparing to copy '{}'", source_path.display());

    // Create a safe destination path within the jail.
    let dest_path = dest_jail
        .try_path(file_name)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    println!("  -> Secure destination: {dest_path}");

    // Perform the file copy.
    fs::copy(source_path, dest_path.clone().unjail())?;

    println!("  -> Successfully copied to destination.");
    Ok(dest_path)
}

// --- Main Application Logic ---

fn main() {
    // --- Setup ---
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "Usage: {} <destination_directory> <source_file_1> [<source_file_2> ...]",
            args[0]
        );
        eprintln!(
            "Example: {} ./safe_zone /etc/hosts ./my_document.txt",
            args[0]
        );
        return;
    }

    let dest_dir = &args[1];
    let source_files = &args[2..];

    // --- Security Setup: Create the jail for the destination directory ---
    let dest_jail = match Jail::<SafeDestination>::try_new_create(dest_dir) {
        Ok(jail) => jail,
        Err(e) => {
            eprintln!("Error creating destination directory '{dest_dir}': {e}");
            return;
        }
    };

    println!("--- Secure File Copy Utility ---");
    println!("Destination jail: {}", dest_jail.path().display());
    println!("---------------------------------");

    // --- Process each source file ---
    for source_str in source_files {
        let source_path = Path::new(source_str);
        match secure_copy(source_path, &dest_jail) {
            Ok(copied_path) => {
                if copied_path.exists() {
                    println!(
                        "[Success] Verified that '{}' exists in the safe directory.",
                        copied_path.file_name_real().unwrap().to_string_lossy()
                    );
                } else {
                    eprintln!(
                        "[Error] File copy reported success, but destination '{copied_path}' does not exist."
                    );
                }
            }
            Err(e) => {
                eprintln!("[Error] Failed to copy '{source_str}': {e}");
            }
        }
        println!("---------------------------------");
    }

    println!("--- All operations complete ---");

    // Note: In a real CLI, you might not want to clean up the destination directory.
    // For this example, we'll leave it so the user can inspect the output.
    // To clean up, you could add:
    // fs::remove_dir_all(dest_dir).unwrap();
}
