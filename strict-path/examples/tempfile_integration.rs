//! Tempfile Integration Example
//!
//! Demonstrates composing strict-path with the tempfile crate for secure
//! temporary directory operations with automatic RAII cleanup. Shows the value
//! of combining tempfile's lifecycle management with strict-path's security.
//!
//! Integration with tempfile v3.22: https://crates.io/crates/tempfile
//!
//! Run with: cargo run --example tempfile_integration

use strict_path::PathBoundary;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Tempfile Integration Examples ===\n");
    println!("Pattern: tempfile::tempdir() → PathBoundary::try_new() → secure operations\n");

    // Example 1: Basic temporary directory
    println!("1️⃣  Basic Temporary Directory with RAII Cleanup:");
    basic_tempdir()?;

    // Example 2: Custom prefix for identification
    println!("\n2️⃣  Custom Prefix for Identifiable Temp Directories:");
    custom_prefix_tempdir()?;

    // Example 3: Archive extraction with attack detection
    println!("\n3️⃣  Archive Extraction with Malicious Path Detection:");
    archive_extraction_staging()?;

    // Example 4: Test fixture pattern
    println!("\n4️⃣  Test Fixture Pattern:");
    test_fixture_pattern()?;

    println!("\n✅ All examples completed successfully!");
    println!("\n💡 Key benefit: tempfile handles cleanup, strict-path handles security");
    Ok(())
}

/// Basic temporary directory with RAII cleanup
fn basic_tempdir() -> Result<(), Box<dyn std::error::Error>> {
    // Create temporary directory - auto-cleaned on drop
    let temp_dir = tempfile::tempdir()?;
    println!("   Created temp dir: {}", temp_dir.path().display());

    // Establish strict boundary
    let boundary: PathBoundary = PathBoundary::try_new(temp_dir.path())?;

    // Safe operations within boundary
    let data_file = boundary.strict_join("data/file.txt")?;
    data_file.create_parent_dir_all()?;
    data_file.write(b"temporary content")?;

    println!("   ✓ Wrote file: {}", data_file.strictpath_display());
    println!("   ✓ Content: {}", data_file.read_to_string()?);

    Ok(())
    // temp_dir automatically deleted when dropped here
}

/// Temporary directory with identifiable prefix for debugging
fn custom_prefix_tempdir() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::Builder::new()
        .prefix("upload-staging-")
        .tempdir()?;

    println!("   Created temp dir: {}", temp_dir.path().display());

    let boundary: PathBoundary = PathBoundary::try_new(temp_dir.path())?;

    // Process uploaded files
    for filename in &["file1.txt", "file2.txt", "file3.txt"] {
        let file = boundary.strict_join(filename)?;
        file.write(b"uploaded data")?;
        println!("   ✓ Staged: {}", filename);
    }

    Ok(())
}

/// Archive extraction with automatic malicious path detection
fn archive_extraction_staging() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::Builder::new()
        .prefix("archive-extract-")
        .tempdir()?;

    let extract_boundary: PathBoundary = PathBoundary::try_new(temp_dir.path())?;

    // Simulate archive entries (including malicious ones)
    let entries = vec![
        ("README.md", "# Project README"),
        ("docs/guide.md", "# User Guide"),
        ("../../etc/passwd", "root:x:0:0"), // ❌ Traversal attack
        ("data/config.json", r#"{"setting": true}"#),
        ("../../../root/.ssh/id_rsa", "PRIVATE KEY"), // ❌ SSH key theft
        ("images/logo.png", "PNG binary data"),
    ];

    println!("   Extracting {} archive entries:", entries.len());
    let mut safe_count = 0;
    let mut blocked_count = 0;

    for (entry_name, content) in entries {
        match extract_boundary.strict_join(entry_name) {
            Ok(safe_path) => {
                safe_path.create_parent_dir_all()?;
                safe_path.write(content.as_bytes())?;
                println!("   ✅ Extracted: {}", entry_name);
                safe_count += 1;
            }
            Err(_) => {
                println!(
                    "   🛡️  BLOCKED: '{}' - {}",
                    entry_name,
                    if entry_name.contains("..") {
                        "Path traversal attack"
                    } else {
                        "Escape attempt"
                    }
                );
                blocked_count += 1;
            }
        }
    }

    println!(
        "\n   📊 Results: {} safe, {} blocked",
        safe_count, blocked_count
    );

    Ok(())
}

/// Test fixture pattern - common in test suites
fn test_fixture_pattern() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let boundary: PathBoundary = PathBoundary::try_new(temp.path())?;

    println!("   Setting up test fixture...");

    // Setup test files
    let input = boundary.strict_join("input.txt")?;
    input.write(b"test data")?;
    println!("   ✓ Created input.txt");

    // Simulate processing
    let output = boundary.strict_join("output.txt")?;
    let data = input.read_to_string()?;
    output.write(data.to_uppercase().as_bytes())?;
    println!("   ✓ Processed → output.txt");

    // Verify results
    assert_eq!(output.read_to_string()?, "TEST DATA");
    println!("   ✓ Test passed");

    Ok(())
    // temp auto-cleans on drop - no manual cleanup needed!
}
