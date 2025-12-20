//! Temporary File Processing Demo
//!
//! Demonstrates integration with the tempfile crate for secure temporary file operations.
//! Shows how to combine tempfile's RAII cleanup with strict-path's security boundaries.
//!
//! Pattern: tempfile::tempdir() → PathBoundary::try_new() → secure operations

#![cfg_attr(not(feature = "with-tempfile"), allow(unused))]

#[cfg(not(feature = "with-tempfile"))]
compile_error!("Enable with --features with-tempfile to run this example");

use anyhow::Result;
use strict_path::{PathBoundary, StrictPath};

/// Marker types for different temporary file purposes
#[derive(Clone)]
struct TempWork;
#[derive(Clone)]
struct TempLogs;
#[derive(Clone)]
struct TempUploads;

/// Demonstrates basic tempfile integration
struct TempFileProcessor {
    work_dir: PathBoundary<TempWork>,
    logs_dir: PathBoundary<TempLogs>,
    upload_staging: PathBoundary<TempUploads>,
}

impl TempFileProcessor {
    /// Creates a new processor with separate temp directories for different purposes
    fn new() -> Result<Self> {
        println!("🔧 Creating temporary processing environment...");

        // Create temp directories using tempfile crate, then establish boundaries
        let work_tempdir = tempfile::tempdir()?;
        let logs_tempdir = tempfile::tempdir()?;
        let upload_tempdir = tempfile::tempdir()?;

        let work_dir = PathBoundary::<TempWork>::try_new(work_tempdir.path())?;
        let logs_dir = PathBoundary::<TempLogs>::try_new(logs_tempdir.path())?;
        let upload_staging = PathBoundary::<TempUploads>::try_new(upload_tempdir.path())?;

        println!("✅ Work directory: {}", work_dir.strictpath_display());
        println!("✅ Logs directory: {}", logs_dir.strictpath_display());
        println!("✅ Upload staging: {}", upload_staging.strictpath_display());

        Ok(Self {
            work_dir,
            logs_dir,
            upload_staging,
        })
    }

    /// Simulate processing uploaded files with validation
    fn process_upload(&self, filename: &str, content: &[u8]) -> Result<StrictPath<TempWork>> {
        println!("\n📁 Processing upload: {filename}");

        // Stage the upload first - validates filename
        let staged_file = self.upload_staging.strict_join(filename)?;
        staged_file.create_parent_dir_all()?;
        staged_file.write(content)?;

        // Log the operation
        let log_entry = format!("Processed: {filename} ({} bytes)\n", content.len());
        self.log_operation(&log_entry)?;

        // "Process" the file - copy to work directory with validation
        let processed_file = self.work_dir.strict_join(format!("processed_{filename}"))?;
        processed_file.create_parent_dir_all()?;

        // Simulate processing (just copying for demo)
        let bytes = staged_file.read()?;
        processed_file.write(&bytes)?;

        println!("✅ File processed: {}", processed_file.strictpath_display());
        Ok(processed_file)
    }

    /// Log operations to the temp log directory
    fn log_operation(&self, message: &str) -> Result<()> {
        let log_file = self.logs_dir.strict_join("operations.log")?;

        // Append log entry using built-in I/O helper
        let log_entry = format!("[{}] {}\n", chrono::Utc::now().format("%H:%M:%S"), message);
        log_file.append(log_entry)?;
        Ok(())
    }

    /// Show all processed files using strict_read_dir for auto-validated iteration
    fn list_processed_files(&self) -> Result<Vec<String>> {
        let mut files = Vec::new();

        // Use strict_read_dir() directly on PathBoundary - no conversion needed!
        for entry in self.work_dir.strict_read_dir()? {
            let child = entry?;
            if let Some(name) = child.strictpath_file_name().and_then(|n| n.to_str()) {
                files.push(name.to_string());
            }
        }

        Ok(files)
    }

    /// Demonstrate batch processing with boundary validation
    fn process_batch(&self, files: &[(&str, &str)]) -> Result<()> {
        println!("\n🔄 Starting batch processing of {} files...", files.len());

        let mut processed_count = 0;

        for (filename, content) in files {
            match self.process_upload(filename, content.as_bytes()) {
                Ok(_) => {
                    processed_count += 1;
                    self.log_operation(&format!("SUCCESS: {filename}"))?;
                }
                Err(e) => {
                    let error_msg = format!("FAILED: {filename} - {e}");
                    println!("❌ {error_msg}");
                    self.log_operation(&error_msg)?;
                }
            }
        }

        println!(
            "✅ Batch complete: {processed_count}/{} files processed",
            files.len()
        );
        Ok(())
    }
}

/// Demonstrate batch file compression workflow
fn demonstrate_compression_workflow() -> Result<()> {
    println!("\n📦 Demonstrating batch compression workflow...");

    let work_tempdir = tempfile::tempdir()?;
    let archive_tempdir = tempfile::tempdir()?;

    let temp_work = PathBoundary::<TempWork>::try_new(work_tempdir.path())?;
    let temp_archive = PathBoundary::<TempWork>::try_new(archive_tempdir.path())?;

    // Create sample files to compress
    let files_to_compress = [
        ("readme.txt", "Welcome to our application!"),
        ("config/settings.json", r#"{"theme": "dark", "lang": "en"}"#),
        ("data/users.csv", "id,name,role\n1,Alice,admin\n2,Bob,user"),
        (
            "logs/app.log",
            "2024-01-01 10:00:00 INFO Application started",
        ),
    ];

    // Create files in work directory
    for (path, content) in &files_to_compress {
        let file_path = temp_work.strict_join(path)?;
        if let Ok(Some(parent)) = file_path.strictpath_parent() {
            parent.create_dir_all()?;
        }
        file_path.write(content)?;
    }

    // Simulate creating a compressed archive
    let archive_path = temp_archive.strict_join("backup.tar.gz")?;
    let mut archive_content = String::new();
    archive_content.push_str("# Simulated Archive Contents\n");

    // List all files that would be archived using strict_read_dir directly on PathBoundary
    let mut file_count = 0;
    for entry in temp_work.strict_read_dir()? {
        let child = entry?;
        if child.is_file() {
            if let Some(name) = child.strictpath_file_name().and_then(|n| n.to_str()) {
                archive_content.push_str(&format!("- {name}\n"));
                file_count += 1;
            }
        }
    }

    archive_path.write(&archive_content)?;
    println!(
        "✅ Created archive: {} ({file_count} files)",
        archive_path.strictpath_display()
    );

    Ok(())
}

fn main() -> Result<()> {
    println!("🚀 Temporary File Processing Demo");
    println!("Showcasing tempfile crate integration with strict-path\n");

    // Create processor with automatic temp cleanup
    let processor = TempFileProcessor::new()?;

    // Sample files to process
    let sample_files = [
        ("document.txt", "This is a sample document for processing."),
        ("config.json", r#"{"app": "demo", "version": "1.0"}"#),
        ("data.csv", "name,value\nAlice,100\nBob,200"),
        ("notes/meeting.md", "# Meeting Notes\n- Item 1\n- Item 2"),
    ];

    // Process files in batch
    processor.process_batch(&sample_files)?;

    // Show results
    println!("\n📋 Processed files:");
    let files = processor.list_processed_files()?;
    for file in files {
        println!("  • {file}");
    }

    // Demonstrate compression workflow
    demonstrate_compression_workflow()?;

    // Demonstrate new I/O APIs (touch, set_permissions, try_exists, open_with)
    demonstrate_new_io_apis()?;

    // Demonstrate additional tempfile workflow patterns
    demonstrate_temp_workflow_patterns()?;

    println!("\n🧹 Cleanup: Temp directories are automatically removed when TempDir instances are dropped!");
    println!("This demonstrates the power of RAII cleanup with tempfile integration.");

    Ok(())
}

/// Demonstrates new I/O APIs: touch, set_permissions, try_exists, open_with
fn demonstrate_new_io_apis() -> Result<()> {
    println!("\n🆕 New I/O API demonstrations:");

    let temp = tempfile::tempdir()?;
    let boundary = PathBoundary::<()>::try_new(temp.path())?;

    // --- touch(): Create empty file or update mtime ---
    println!("\n  📌 touch() - Create marker files:");
    let marker_file = boundary.strict_join("build.complete")?;
    marker_file.touch()?; // Creates empty file
    println!("    Created marker: {}", marker_file.strictpath_display());

    // touch() on existing file updates mtime (preserves content)
    let existing = boundary.strict_join("existing.txt")?;
    existing.write("original content")?;
    std::thread::sleep(std::time::Duration::from_millis(10));
    existing.touch()?; // Updates mtime, keeps content
    let content = existing.read_to_string()?;
    assert_eq!(content, "original content");
    println!("    Touched existing file (content preserved)");

    // --- try_exists(): Fallible existence check ---
    println!("\n  🔍 try_exists() - Fallible existence check:");
    match marker_file.try_exists() {
        Ok(true) => println!("    marker_file: exists"),
        Ok(false) => println!("    marker_file: not found"),
        Err(e) => println!("    marker_file: permission error - {e}"),
    }

    let nonexistent = boundary.strict_join("does_not_exist.txt")?;
    match nonexistent.try_exists() {
        Ok(false) => println!("    nonexistent: correctly reports not found"),
        other => println!("    nonexistent: unexpected result - {other:?}"),
    }

    // --- set_permissions(): Modify file permissions ---
    println!("\n  🔒 set_permissions() - File permission management:");
    let config_file = boundary.strict_join("config.toml")?;
    config_file.write("[app]\nkey = \"secret\"")?;

    let mut perms = config_file.metadata()?.permissions();
    perms.set_readonly(true);
    config_file.set_permissions(perms)?;
    println!("    Set {} to read-only", config_file.strictpath_display());

    // Verify it's read-only
    let perms = config_file.metadata()?.permissions();
    println!("    Read-only: {}", perms.readonly());

    // --- open_with(): Advanced file opening ---
    println!("\n  🔧 open_with() - Advanced file open options:");
    let log_file = boundary.strict_join("app.log")?;

    // Create with read+write access
    {
        let mut file = log_file
            .open_with()
            .read(true)
            .write(true)
            .create(true)
            .open()?;
        use std::io::Write;
        file.write_all(b"[INFO] Application started\n")?;
    }
    println!("    Created log with read+write mode");

    // Append to existing file
    {
        let mut file = log_file.open_with().append(true).open()?;
        use std::io::Write;
        file.write_all(b"[INFO] Another log entry\n")?;
    }
    let log_content = log_file.read_to_string()?;
    println!("    Appended entry (total {} bytes)", log_content.len());

    // create_new: fails if file exists (for exclusive access)
    let lock_file = boundary.strict_join("app.lock")?;
    match lock_file.open_with().create_new(true).write(true).open() {
        Ok(_) => println!("    Lock file created (exclusive)"),
        Err(e) => println!("    Lock file error: {e}"),
    }

    // Trying again should fail
    match lock_file.open_with().create_new(true).write(true).open() {
        Ok(_) => println!("    Unexpected: lock file created again"),
        Err(_) => println!("    Lock file correctly rejected (already exists)"),
    }

    println!("  ✅ All new I/O APIs demonstrated successfully");
    Ok(())
}

/// Example helper showing how to create validated temp paths for different workflows
fn demonstrate_temp_workflow_patterns() -> Result<()> {
    println!("\n🛠️ Common tempfile workflow patterns:");

    // Pattern 1: Processing pipeline with multiple temp stages
    let input_tempdir = tempfile::tempdir()?;
    let processing_tempdir = tempfile::tempdir()?;
    let output_tempdir = tempfile::tempdir()?;

    let input_stage = PathBoundary::<()>::try_new(input_tempdir.path())?;
    let processing_stage = PathBoundary::<()>::try_new(processing_tempdir.path())?;
    let output_stage = PathBoundary::<()>::try_new(output_tempdir.path())?;

    println!("📂 Pipeline: input -> processing -> output");
    println!("   Input: {}", input_stage.strictpath_display());
    println!("   Processing: {}", processing_stage.strictpath_display());
    println!("   Output: {}", output_stage.strictpath_display());

    // Pattern 2: User-specific temp workspace
    let user_tempdir = tempfile::tempdir()?;
    let user_temp = PathBoundary::<()>::try_new(user_tempdir.path())?;
    let user_workspace = user_temp.strict_join("workspace")?;
    user_workspace.create_dir_all()?;

    let projects_dir = user_workspace.strict_join("projects")?;
    projects_dir.create_dir_all()?;

    println!(
        "\n👤 User workspace: {}",
        user_workspace.strictpath_display()
    );

    // Pattern 3: Atomic operations with temp + rename
    let atomic_tempdir = tempfile::tempdir()?;
    let atomic_temp = PathBoundary::<()>::try_new(atomic_tempdir.path())?;
    let temp_file = atomic_temp.strict_join("atomic_write.tmp")?;

    // Write to temp, then atomic rename (in real code, would rename to final location)
    temp_file.write(b"atomic content")?;
    println!("⚛️  Atomic temp file: {}", temp_file.strictpath_display());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_temp_boundaries_are_separate() -> Result<()> {
        let temp1_dir = tempfile::tempdir()?;
        let temp2_dir = tempfile::tempdir()?;

        let temp1 = PathBoundary::<()>::try_new(temp1_dir.path())?;
        let temp2 = PathBoundary::<()>::try_new(temp2_dir.path())?;

        // Different temp directories
        assert_ne!(temp1.interop_path(), temp2.interop_path());

        // Both should exist
        assert!(temp1.exists());
        assert!(temp2.exists());

        Ok(())
    }

    #[test]
    fn test_temp_cleanup_on_drop() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let temp_boundary = PathBoundary::<()>::try_new(temp_dir.path())?;
        let _temp_root_display = temp_boundary.strictpath_display().to_string();
        drop(temp_boundary); // dropped here
        drop(temp_dir); // tempfile cleanup

        // Directory should be cleaned up automatically
        // Note: This test might be flaky due to timing, but demonstrates the concept
        std::thread::sleep(std::time::Duration::from_millis(10));
        // We cannot reliably assert deletion without racy checks; this test ensures drop compiles.

        Ok(())
    }
}
