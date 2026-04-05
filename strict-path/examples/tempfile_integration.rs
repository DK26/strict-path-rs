//! Tempfile Integration Example
//!
//! Demonstrates composing strict-path with the tempfile crate for secure
//! temporary directory operations with automatic RAII cleanup. Shows the value
//! of combining tempfile's lifecycle management with strict-path's security.
//!
//! The `validate_uploaded_files` function shows the core security pattern:
//! filenames arriving from HTTP multipart uploads are validated through
//! `strict_join()` before any I/O occurs in the staging directory.
//!
//! Integration with tempfile v3.22: https://crates.io/crates/tempfile
//!
//! Run with: cargo run --example tempfile_integration

use strict_path::PathBoundary;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Tempfile Integration Examples ===\n");
    println!("Pattern: tempfile::tempdir() -> PathBoundary::try_new() -> secure operations\n");

    // Example 1: Basic temporary directory
    println!("1. Basic Temporary Directory with RAII Cleanup:");
    basic_tempdir()?;

    // Example 2: Untrusted upload filenames validated against a staging directory
    println!("\n2. Validating Untrusted Upload Filenames (HTTP multipart / CLI args):");
    validate_uploaded_files()?;

    // Example 3: Archive extraction with attack detection
    println!("\n3. Archive Extraction with Malicious Path Detection:");
    archive_extraction_staging()?;

    // Example 4: Test fixture pattern
    println!("\n4. Test Fixture Pattern:");
    test_fixture_pattern()?;

    println!("\nAll examples completed successfully!");
    println!("\nKey benefit: tempfile handles cleanup, strict-path handles security");
    Ok(())
}

/// Basic temporary directory with RAII cleanup
fn basic_tempdir() -> Result<(), Box<dyn std::error::Error>> {
    // Create temporary directory - auto-cleaned on drop
    let temp_dir = tempfile::tempdir()?;
    println!("   Created temp dir: {}", temp_dir.path().display());

    // Establish strict boundary
    let work_dir: PathBoundary = PathBoundary::try_new(temp_dir.path())?;

    // Safe operations within boundary
    let data_file = work_dir.strict_join("data/file.txt")?;
    data_file.create_parent_dir_all()?;
    data_file.write(b"temporary content")?;

    println!("   Wrote file: {}", data_file.strictpath_display());
    println!("   Content: {}", data_file.read_to_string()?);

    Ok(())
    // temp_dir automatically deleted when dropped here
}

/// Validate filenames from an HTTP multipart upload (or CLI args) before staging them.
///
/// The staging directory is a trusted tempfile boundary; the *filenames* are untrusted.
/// `strict_join()` enforces that no filename can escape the staging directory.
fn validate_uploaded_files() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::Builder::new()
        .prefix("upload-staging-")
        .tempdir()?;

    println!("   Staging dir: {}", temp_dir.path().display());

    let upload_staging_dir: PathBoundary = PathBoundary::try_new(temp_dir.path())?;

    // Filenames as received from an HTTP multipart request body or CLI positional args.
    // In a real handler: let uploaded_filename = multipart_field.filename();
    let incoming_uploads: &[&str] = &[
        // From HTTP multipart upload headers, CLI args, or form data
        "report.pdf",
        "../../etc/passwd",       // traversal attack — must be blocked
        "../outside_staging.txt", // escape attempt — must be blocked
        "data/user_files/notes.txt", // valid nested filename
    ];

    println!("   Validating filenames from HTTP multipart upload:");
    for uploaded_filename in incoming_uploads {
        // uploaded_filename is untrusted external input — strict_join() validates it
        match upload_staging_dir.strict_join(uploaded_filename) {
            Ok(safe_staged_file) => {
                safe_staged_file.create_parent_dir_all()?;
                safe_staged_file.write(b"uploaded data")?;
                println!(
                    "   OK      '{}' -> {}",
                    uploaded_filename,
                    safe_staged_file.strictpath_display()
                );
            }
            Err(_) => {
                println!(
                    "   BLOCKED '{}' (traversal / escape attempt rejected)",
                    uploaded_filename
                );
            }
        }
    }

    Ok(())
    // temp_dir auto-cleaned on drop — no manual cleanup needed
}

/// Archive extraction with automatic malicious path detection
fn archive_extraction_staging() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::Builder::new()
        .prefix("archive-extract-")
        .tempdir()?;

    let extract_dir: PathBoundary = PathBoundary::try_new(temp_dir.path())?;

    // Simulate archive entries (including malicious ones).
    // In production these come from an archive library (zip, tar, etc.) — external data.
    let archive_entries: &[(&str, &str)] = &[
        // Entry paths as decoded from the archive — untrusted external data
        ("README.md", "# Project README"),
        ("docs/guide.md", "# User Guide"),
        ("../../etc/passwd", "root:x:0:0"), // traversal attack
        ("data/config.json", r#"{"setting": true}"#),
        ("../../../root/.ssh/id_rsa", "PRIVATE KEY"), // SSH key theft attempt
        ("images/logo.png", "PNG binary data"),
    ];

    println!("   Extracting {} archive entries:", archive_entries.len());
    let mut safe_count = 0;
    let mut blocked_count = 0;

    for (entry_path, content) in archive_entries {
        // entry_path is untrusted data from the archive — strict_join() validates it
        match extract_dir.strict_join(entry_path) {
            Ok(safe_path) => {
                safe_path.create_parent_dir_all()?;
                safe_path.write(content.as_bytes())?;
                println!("   OK      {entry_path}");
                safe_count += 1;
            }
            Err(_) => {
                println!(
                    "   BLOCKED '{}' - {}",
                    entry_path,
                    if entry_path.contains("..") {
                        "path traversal attack"
                    } else {
                        "escape attempt"
                    }
                );
                blocked_count += 1;
            }
        }
    }

    println!("\n   Results: {safe_count} safe, {blocked_count} blocked");

    Ok(())
}

/// Test fixture pattern - common in test suites
fn test_fixture_pattern() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let fixture_dir: PathBoundary = PathBoundary::try_new(temp.path())?;

    println!("   Setting up test fixture...");

    // Setup test files
    let input = fixture_dir.strict_join("input.txt")?;
    input.write(b"test data")?;
    println!("   Created input.txt");

    // Simulate processing
    let output = fixture_dir.strict_join("output.txt")?;
    let data = input.read_to_string()?;
    output.write(data.to_uppercase().as_bytes())?;
    println!("   Processed -> output.txt");

    // Verify results
    assert_eq!(output.read_to_string()?, "TEST DATA");
    println!("   Test passed");

    Ok(())
    // temp auto-cleans on drop - no manual cleanup needed!
}
