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

/// Securely copies a file to a destination path inside the jail.
///
/// Signature encodes the guarantee: destination must be a JailedPath.
fn copy_to(source_path: &Path, dest_path: &JailedPath<SafeDestination>) -> io::Result<()> {
    if !source_path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "Source file not found or is not a file: {}",
                source_path.display()
            ),
        ));
    }

    let src_disp = source_path.display();
    let dst_disp = dest_path.jailedpath_display();
    println!("[Copy] Preparing to copy '{src_disp}'");
    println!("  -> Secure destination: {dst_disp}");
    // Perform the file copy using `AsRef<Path>` interop via &OsStr.
    fs::copy(source_path, dest_path.interop_path())?;
    println!("  -> Successfully copied to destination.");
    Ok(())
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
    let jail_disp = dest_jail.jailedpath_display();
    println!("Destination jail: {jail_disp}");
    println!("---------------------------------");

    // --- Process each source file ---
    for source_str in source_files {
        let source_path = Path::new(source_str);
        // Build destination path inside the jail from the source filename
        let file_name = match source_path.file_name() {
            Some(n) => n,
            None => {
                eprintln!(
                    "[Error] Source path has no file name: {}",
                    source_path.display()
                );
                continue;
            }
        };
        let dest_path = match dest_jail.jailed_join(file_name) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[Error] Invalid destination path: {e}");
                continue;
            }
        };

        match copy_to(source_path, &dest_path) {
            Ok(()) => {
                if dest_path.exists() {
                    let name = dest_path
                        .jailedpath_file_name()
                        .unwrap()
                        .to_string_lossy();
                    println!("[Success] Verified that '{name}' exists in the safe directory.");
                } else {
                    let dst = dest_path.jailedpath_display();
                    eprintln!(
                        "[Error] File copy reported success, but destination '{dst}' does not exist."
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
